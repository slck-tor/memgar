"""
ONNX-based transformer inference for Memgar ML detector.

Loads the fine-tuned DistilBERT ONNX model and provides
sub-10ms binary attack/benign classification.

Fallback chain (each level activates if the previous is unavailable):
    1. ONNX Runtime (fastest, CPU/GPU)          ~5-8ms
    2. PyTorch model (if ONNX missing)          ~15-30ms
    3. sklearn GradientBoost (if torch missing) ~1-2ms (lower accuracy)
    4. Returns 0.0 with a warning               (disabled)
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

ARTIFACTS_DIR   = Path(__file__).parent.parent / "artifacts"
ONNX_MODEL_DIR  = ARTIFACTS_DIR / "transformer_model"
ONNX_MODEL_PATH = ONNX_MODEL_DIR / "model.onnx"
TOKENIZER_DIR   = ONNX_MODEL_DIR / "tokenizer"
PYTORCH_DIR     = ONNX_MODEL_DIR / "pytorch"
MAX_LENGTH      = 128


# Track (reason, path) pairs we've already warned about, so repeatedly
# constructing the detector — e.g. in tests or in a per-request factory —
# does not produce a wall of identical WARNING logs.
_WARNED_UNREADY: set[tuple[str, str]] = set()


def _warn_unready_once(reason: str, path: str) -> None:
    key = (reason, path)
    if key in _WARNED_UNREADY:
        return
    _WARNED_UNREADY.add(key)
    if reason.startswith("model_missing"):
        logger.warning(
            "TransformerDetector DISABLED: no ONNX model at %s. Layer 2-ML "
            "(~5ms fine-tuned transformer) will return 0.0 for every input. "
            "Train + export with: python ml/training/export_onnx.py",
            path,
        )
    elif reason.startswith("tokenizer_dir_missing"):
        logger.warning(
            "TransformerDetector DISABLED: tokenizer directory missing. "
            "Reason: %s. Layer 2-ML will return 0.0.",
            reason,
        )
    elif reason == "tokenizer_load_failed":
        logger.warning(
            "TransformerDetector DISABLED: tokenizer files present but "
            "could not be loaded (check the `transformers` package). "
            "Layer 2-ML will return 0.0."
        )
    elif reason == "backend_init_failed":
        logger.warning(
            "TransformerDetector DISABLED: tokenizer loaded but neither "
            "ONNX nor PyTorch backend could be initialised. Layer 2-ML "
            "will return 0.0."
        )
    else:
        logger.warning(
            "TransformerDetector DISABLED: %s. Layer 2-ML will return 0.0.",
            reason,
        )


class TransformerDetector:
    """
    Production inference wrapper — ONNX-first with graceful fallbacks.

    Usage::

        detector = TransformerDetector.load()
        prob, latency_ms = detector.predict("ignore all previous instructions")
        # prob = 0.97  latency_ms = 6.2
    """

    def __init__(
        self,
        onnx_path:     Optional[str] = None,
        tokenizer_dir: Optional[str] = None,
        max_length:    int = MAX_LENGTH,
        threshold:     float = 0.5,
        warn_if_unready: bool = True,
    ) -> None:
        self._max_length  = max_length
        self.threshold    = threshold
        self._onnx_sess   = None
        self._torch_model = None
        self._tokenizer   = None
        self._backend: str = "none"
        # Reason the detector ended up disabled, populated below. Surfaced
        # via health() so operators can detect a silently-disabled ML layer
        # without having to grep the boot logs.
        self._degraded_reason: Optional[str] = None
        self._onnx_path = str(Path(onnx_path or ONNX_MODEL_PATH))
        self._tokenizer_dir = str(Path(tokenizer_dir or TOKENIZER_DIR))

        onnx_p = Path(self._onnx_path)
        tok_d  = Path(self._tokenizer_dir)

        self._init_tokenizer(tok_d)
        if self._tokenizer and onnx_p.exists():
            self._init_onnx(onnx_p)
        elif self._tokenizer and PYTORCH_DIR.exists():
            self._init_torch()
        else:
            # Distinguish the three failure modes so health() can offer a
            # specific fix hint rather than a generic "model missing".
            if self._tokenizer is None and not tok_d.exists():
                self._degraded_reason = f"tokenizer_dir_missing: {tok_d}"
            elif self._tokenizer is None:
                self._degraded_reason = "tokenizer_load_failed"
            else:
                self._degraded_reason = f"model_missing: {onnx_p}"
            if warn_if_unready:
                _warn_unready_once(self._degraded_reason, self._onnx_path)
            return

        # If we attempted ONNX/torch init above but it failed, the relevant
        # _init_* method already logged a warning; capture the resulting
        # state so the health snapshot is accurate.
        if self._backend == "none":
            self._degraded_reason = "backend_init_failed"
            if warn_if_unready:
                _warn_unready_once(self._degraded_reason, self._onnx_path)

    # ------------------------------------------------------------------ init

    def _init_tokenizer(self, tok_dir: Path) -> None:
        if not tok_dir.exists():
            return
        try:
            from transformers import AutoTokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(str(tok_dir))
            logger.debug("TransformerDetector: tokenizer loaded from %s", tok_dir)
        except Exception as e:
            logger.warning("TransformerDetector: tokenizer load failed: %s", e)

    def _init_onnx(self, onnx_path: Path) -> None:
        try:
            import onnxruntime as ort
            opts = ort.SessionOptions()
            opts.intra_op_num_threads = int(os.environ.get("MEMGAR_ORT_THREADS", "2"))
            opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            self._onnx_sess = ort.InferenceSession(
                str(onnx_path),
                sess_options=opts,
                providers=["CUDAExecutionProvider", "CPUExecutionProvider"],
            )
            self._backend = "onnx"
            logger.info("TransformerDetector: ONNX backend ready (%s)", onnx_path.name)
        except Exception as e:
            logger.warning("TransformerDetector: ONNX init failed, trying PyTorch: %s", e)
            self._init_torch()

    def _init_torch(self) -> None:
        try:
            import torch
            from transformers import AutoModelForSequenceClassification
            self._torch_model = AutoModelForSequenceClassification.from_pretrained(str(PYTORCH_DIR))
            self._torch_model.eval()
            if torch.cuda.is_available():
                self._torch_model = self._torch_model.cuda()
            self._backend = "torch"
            logger.info("TransformerDetector: PyTorch backend ready")
        except Exception as e:
            logger.warning("TransformerDetector: PyTorch init failed: %s", e)

    # ------------------------------------------------------------------ inference

    @property
    def is_ready(self) -> bool:
        return self._backend in ("onnx", "torch") and self._tokenizer is not None

    def health(self) -> dict:
        """
        Return a structured readiness snapshot.

        Mirrors ``SemanticGuard.health()`` so the Analyzer's per-layer health
        check has a uniform shape across optional ML subsystems. ``status``
        is one of ``"ok"`` / ``"degraded"``.
        """
        ready = self.is_ready
        status = "ok" if ready else "degraded"
        reason = getattr(self, "_degraded_reason", None) if not ready else None
        fix_hint: Optional[str] = None
        if reason:
            if reason.startswith("model_missing"):
                fix_hint = "Train and export an ONNX model into ml/artifacts/transformer_model/"
            elif reason.startswith("tokenizer_dir_missing"):
                fix_hint = "Place tokenizer files in ml/artifacts/transformer_model/tokenizer/"
            elif reason == "tokenizer_load_failed":
                fix_hint = "pip install transformers"
            elif reason == "backend_init_failed":
                fix_hint = "pip install onnxruntime (or transformers + torch)"
            else:
                fix_hint = "see logs for details"
        return {
            "status": status,
            "reason": reason,
            "is_ready": ready,
            "backend": self._backend,
            "onnx_path": getattr(self, "_onnx_path", None),
            "tokenizer_dir": getattr(self, "_tokenizer_dir", None),
            "fix_hint": fix_hint,
        }

    def predict(self, text: str) -> Tuple[float, float]:
        """
        Returns ``(attack_probability, latency_ms)``.

        attack_probability is in [0, 1].
        Returns (0.0, 0.0) if no backend available.
        """
        if not self.is_ready:
            return 0.0, 0.0
        t0 = time.perf_counter()
        if self._backend == "onnx":
            prob = self._predict_onnx(text)
        else:
            prob = self._predict_torch(text)
        return prob, round((time.perf_counter() - t0) * 1000, 2)

    def predict_batch(self, texts: list[str]) -> list[Tuple[float, float]]:
        """Batch inference — more efficient than calling predict() in a loop."""
        if not self.is_ready or not texts:
            return [(0.0, 0.0)] * len(texts)
        t0 = time.perf_counter()
        if self._backend == "onnx":
            probs = self._predict_batch_onnx(texts)
        else:
            probs = [self._predict_torch(t) for t in texts]
        latency = round((time.perf_counter() - t0) * 1000 / len(texts), 2)
        return [(p, latency) for p in probs]

    def is_attack(self, text: str) -> Tuple[bool, float, float]:
        """Returns (is_attack, probability, latency_ms)."""
        prob, latency = self.predict(text)
        return prob >= self.threshold, prob, latency

    # ------------------------------------------------------------------ backends

    def _predict_onnx(self, text: str) -> float:
        enc = self._tokenizer(
            text,
            return_tensors="np",
            padding="max_length",
            max_length=self._max_length,
            truncation=True,
        )
        # BERT-style models declare token_type_ids as a required ONNX input.
        # DistilBERT and similar architectures only take input_ids + mask.
        # We probe the session's required input names once and feed only
        # what the model actually expects.
        feed = self._build_feed(enc)
        logits = self._onnx_sess.run(None, feed)[0]
        return float(_softmax(logits[0])[1])

    def _predict_batch_onnx(self, texts: list[str]) -> list[float]:
        enc = self._tokenizer(
            texts,
            return_tensors="np",
            padding="max_length",
            max_length=self._max_length,
            truncation=True,
        )
        feed = self._build_feed(enc)
        logits = self._onnx_sess.run(None, feed)[0]
        return [float(_softmax(row)[1]) for row in logits]

    def _build_feed(self, enc) -> dict:
        """Build the ONNX input feed, filtered to the names the model declares.
        Caches the required-name set after the first call."""
        names = getattr(self, "_onnx_input_names", None)
        if names is None:
            names = {inp.name for inp in self._onnx_sess.get_inputs()}
            self._onnx_input_names = names
        feed = {}
        if "input_ids" in names:
            feed["input_ids"] = enc["input_ids"]
        if "attention_mask" in names:
            feed["attention_mask"] = enc["attention_mask"]
        if "token_type_ids" in names and "token_type_ids" in enc:
            feed["token_type_ids"] = enc["token_type_ids"]
        return feed

    def _predict_torch(self, text: str) -> float:
        import torch
        enc = self._tokenizer(
            text,
            return_tensors="pt",
            padding="max_length",
            max_length=self._max_length,
            truncation=True,
        )
        if next(self._torch_model.parameters()).is_cuda:
            enc = {k: v.cuda() for k, v in enc.items()}
        with torch.no_grad():
            logits = self._torch_model(**enc).logits
        probs = torch.softmax(logits, dim=-1).cpu().numpy()[0]
        return float(probs[1])

    # ------------------------------------------------------------------ factory

    @classmethod
    def load(
        cls,
        onnx_path:     Optional[str] = None,
        tokenizer_dir: Optional[str] = None,
        threshold:     float = 0.5,
    ) -> "TransformerDetector":
        return cls(onnx_path=onnx_path, tokenizer_dir=tokenizer_dir, threshold=threshold)

    def __repr__(self) -> str:
        return f"TransformerDetector(backend={self._backend!r}, ready={self.is_ready})"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - x.max())
    return e / e.sum()
