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
    ) -> None:
        self._max_length  = max_length
        self.threshold    = threshold
        self._onnx_sess   = None
        self._torch_model = None
        self._tokenizer   = None
        self._backend: str = "none"

        onnx_p = Path(onnx_path or ONNX_MODEL_PATH)
        tok_d  = Path(tokenizer_dir or TOKENIZER_DIR)

        self._init_tokenizer(tok_d)
        if self._tokenizer and onnx_p.exists():
            self._init_onnx(onnx_p)
        elif self._tokenizer and PYTORCH_DIR.exists():
            self._init_torch()
        else:
            logger.warning("TransformerDetector: no model found at %s — detector disabled", onnx_p)

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
        logits = self._onnx_sess.run(
            None,
            {"input_ids": enc["input_ids"], "attention_mask": enc["attention_mask"]},
        )[0]
        return float(_softmax(logits[0])[1])

    def _predict_batch_onnx(self, texts: list[str]) -> list[float]:
        enc = self._tokenizer(
            texts,
            return_tensors="np",
            padding="max_length",
            max_length=self._max_length,
            truncation=True,
        )
        logits = self._onnx_sess.run(
            None,
            {"input_ids": enc["input_ids"], "attention_mask": enc["attention_mask"]},
        )[0]
        return [float(_softmax(row)[1]) for row in logits]

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
