"""
Memgar Semantic Embedding Layer
=================================

Pluggable embedding backends for SecureMemoryRetriever.
Replaces the keyword-overlap fallback with real semantic similarity.

Backend priority (auto-selection):
    1. AnthropicEmbedding  - voyage-3-lite via Anthropic API (best quality)
    2. SklearnTFIDF        - TF-IDF + char n-grams, sklearn (offline, no key)
    3. KeywordFallback     - word-overlap (always available, no deps)

LedgerEmbeddingIndex wraps a backend and provides an incremental index
over MemoryLedger entries with optional disk persistence.

Usage::

    from memgar.secure_retriever import create_retriever
    from memgar.memory_ledger import MemoryLedger
    from memgar.secure_embeddings import build_similarity_fn

    ledger = MemoryLedger("./memory.json")
    sim_fn = build_similarity_fn(ledger, backend="auto")
    retriever = create_retriever(ledger, similarity_fn=sim_fn)
"""

from __future__ import annotations

import hashlib
import math
import os
import pickle
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


class _EmbeddingUnpickler(pickle.Unpickler):
    """Allowlist-based unpickler for the embedding index (builtins + this module)."""

    def find_class(self, module: str, name: str):
        root = module.split(".")[0]
        if root not in ("builtins", "memgar") and not module.startswith("numpy"):
            raise pickle.UnpicklingError(f"Forbidden pickle class: {module}.{name}")
        return super().find_class(module, name)


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class EmbeddingBackend(ABC):
    """Abstract embedding backend. Subclasses implement embed()."""

    @abstractmethod
    def embed(self, text: str) -> List[float]:
        """Return float embedding vector for text."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend identifier string."""

    def similarity(self, a: str, b: str) -> float:
        """Cosine similarity between two texts, range [0, 1]."""
        return _cosine(self.embed(a), self.embed(b))

    def as_similarity_fn(self) -> Callable[[str, str], float]:
        """Return a (query, content) -> float callable."""
        return self.similarity

    @classmethod
    def is_available(cls) -> bool:
        return False


# ---------------------------------------------------------------------------
# Backend 1: Anthropic voyage-3-lite
# ---------------------------------------------------------------------------

class AnthropicEmbedding(EmbeddingBackend):
    """
    Voyage-3-lite embeddings via the Anthropic API.

    Requires:
        pip install anthropic
        ANTHROPIC_API_KEY set in environment (or passed as api_key)

    Model:      voyage-3-lite  (512-dim, fast, optimised for retrieval)
    Batch API:  up to 128 texts per request
    Cache:      in-memory LRU, avoids re-embedding identical content

    Args:
        api_key:    Anthropic API key (falls back to ANTHROPIC_API_KEY)
        model:      Voyage model name
        cache_size: Max cached embeddings (default: 1000)
    """

    def __init__(
        self,
        api_key:    Optional[str] = None,
        model:      str = "voyage-3-lite",
        cache_size: int = 1000,
    ) -> None:
        self._api_key    = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self._model      = model
        self._cache:     Dict[str, List[float]] = {}
        self._cache_size = cache_size
        self._client     = None

    @property
    def name(self) -> str:
        return f"anthropic/{self._model}"

    def _client_instance(self):
        if self._client is None:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self._api_key)
            except ImportError as exc:
                raise ImportError(
                    "anthropic package required. Install: pip install anthropic"
                ) from exc
        return self._client

    def _cache_get(self, text: str) -> Optional[List[float]]:
        return self._cache.get(hashlib.sha256(text.encode()).hexdigest()[:24])

    def _cache_set(self, text: str, vec: List[float]) -> None:
        if len(self._cache) >= self._cache_size:
            self._cache.pop(next(iter(self._cache)))
        self._cache[hashlib.sha256(text.encode()).hexdigest()[:24]] = vec

    def embed(self, text: str) -> List[float]:
        cached = self._cache_get(text)
        if cached is not None:
            return cached
        client = self._client_instance()
        response = client.embeddings.create(
            model=self._model, input=[text[:8000]]
        )
        vec = response.embeddings[0].embedding
        self._cache_set(text, vec)
        return vec

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Embed multiple texts in one API call (max 128)."""
        result: List[Optional[List[float]]] = [None] * len(texts)
        uncached: List[int] = []
        for i, t in enumerate(texts):
            c = self._cache_get(t)
            if c is not None:
                result[i] = c
            else:
                uncached.append(i)
        if uncached:
            batch = [texts[i][:8000] for i in uncached]
            client = self._client_instance()
            response = client.embeddings.create(model=self._model, input=batch)
            for j, idx in enumerate(uncached):
                vec = response.embeddings[j].embedding
                self._cache_set(texts[idx], vec)
                result[idx] = vec
        return result  # type: ignore[return-value]

    @classmethod
    def is_available(cls) -> bool:
        try:
            import anthropic  # noqa: F401
            return bool(os.environ.get("ANTHROPIC_API_KEY"))
        except ImportError:
            return False


# ---------------------------------------------------------------------------
# Backend 2: Sklearn TF-IDF (offline)
# ---------------------------------------------------------------------------

class SklearnTFIDF(EmbeddingBackend):
    """
    Hybrid TF-IDF: word (1,2)-grams + character (3,5)-grams.

    No API key required. Works fully offline.
    Handles lexical and morphological similarity.
    Re-fits vocabulary when significant new content is encountered.

    Args:
        word_weight:  Weight for word-level cosine (default: 0.65)
        char_weight:  Weight for char-level cosine (default: 0.35)
        max_features: Vocabulary cap per vectorizer (default: 20000)
    """

    def __init__(
        self,
        word_weight:  float = 0.65,
        char_weight:  float = 0.35,
        max_features: int = 20_000,
    ) -> None:
        self._ww       = word_weight
        self._cw       = char_weight
        self._maxf     = max_features
        self._wvec     = None
        self._cvec     = None
        self._corpus:  List[str] = []
        self._fitted   = False

    @property
    def name(self) -> str:
        return "sklearn/tfidf-hybrid"

    def train(self, texts: List[str]) -> None:
        """Fit both vectorizers on corpus. Call before embed() for best results."""
        from sklearn.feature_extraction.text import TfidfVectorizer
        self._wvec = TfidfVectorizer(
            ngram_range=(1, 2), sublinear_tf=True,
            max_features=self._maxf, analyzer="word", min_df=1,
        )
        self._cvec = TfidfVectorizer(
            ngram_range=(3, 5), sublinear_tf=True,
            max_features=self._maxf, analyzer="char_wb", min_df=1,
        )
        self._wvec.fit(texts)
        self._cvec.fit(texts)
        self._corpus = list(texts)
        self._fitted = True

    def _ensure(self, text: str) -> None:
        if not self._fitted:
            self.train([text, "initial placeholder document"])

    def embed(self, text: str) -> List[float]:
        """Weighted concatenation of word and char TF-IDF dense vectors."""
        self._ensure(text)
        wv = self._wvec.transform([text]).toarray()[0].tolist()
        cv = self._cvec.transform([text]).toarray()[0].tolist()
        return [x * self._ww for x in wv] + [x * self._cw for x in cv]

    def similarity(self, a: str, b: str) -> float:
        """
        Compute word-sim and char-sim separately then combine.
        More efficient than embedding both to full concat vectors.
        """
        self._ensure(a)
        self._ensure(b)
        from sklearn.metrics.pairwise import cosine_similarity as sk_cos
        wa = self._wvec.transform([a])
        wb = self._wvec.transform([b])
        ca = self._cvec.transform([a])
        cb = self._cvec.transform([b])
        w_sim = float(sk_cos(wa, wb)[0][0])
        c_sim = float(sk_cos(ca, cb)[0][0])
        return round(max(0.0, min(1.0, self._ww * w_sim + self._cw * c_sim)), 4)

    @classmethod
    def is_available(cls) -> bool:
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: F401
            return True
        except ImportError:
            return False


# ---------------------------------------------------------------------------
# Backend 3: Keyword fallback (zero deps)
# ---------------------------------------------------------------------------

class KeywordFallback(EmbeddingBackend):
    """Word-overlap Jaccard similarity. Zero dependencies. Always available."""

    _STOP = frozenset({
        "the","a","an","is","are","was","were","in","on","at","to","for",
        "of","and","or","it","this","that","with","be","by","as","has",
        "have","had","will","would","can","could","do","does","did","not",
        "but","from","its",
    })

    @property
    def name(self) -> str:
        return "keyword/overlap"

    def embed(self, text: str) -> List[float]:
        return [1.0]  # not meaningful; similarity() is overridden

    def similarity(self, a: str, b: str) -> float:
        stop = self._STOP
        aw = {w.lower().strip(".,;:!?") for w in a.split()} - stop
        bw = {w.lower().strip(".,;:!?") for w in b.split()} - stop
        if not aw:
            return 0.5
        return round(min(1.0, len(aw & bw) / (len(aw) + 0.5)), 4)

    @classmethod
    def is_available(cls) -> bool:
        return True


# ---------------------------------------------------------------------------
# LedgerEmbeddingIndex
# ---------------------------------------------------------------------------

@dataclass
class _IndexEntry:
    entry_id:  str
    content:   str
    vector:    List[float]
    indexed_at: float = field(default_factory=time.time)


class LedgerEmbeddingIndex:
    """
    Incremental embedding index over a MemoryLedger.

    Build once, update incrementally as new entries are written.
    Optional disk persistence avoids re-embedding on restart.

    Args:
        backend:    EmbeddingBackend to use
        ledger:     MemoryLedger instance
        index_path: Pickle path for persistence (optional)

    Usage::

        index = LedgerEmbeddingIndex(SklearnTFIDF(), ledger)
        index.build()                    # vectorize all entries

        results = index.search("user preferences", top_k=5)
        # -> [(entry_id, score), ...]

        index.update("eid_new", "new content")  # incremental
        sim_fn = index.as_similarity_fn()
        retriever = create_retriever(ledger, similarity_fn=sim_fn)
    """

    def __init__(
        self,
        backend:    EmbeddingBackend,
        ledger:     Any,
        index_path: Optional[str] = None,
    ) -> None:
        self._b     = backend
        self._l     = ledger
        self._path  = index_path
        self._idx:  Dict[str, _IndexEntry] = {}

    def build(self, batch_size: int = 64) -> int:
        """
        Vectorize all current ledger entries.
        Returns number of entries indexed.
        """
        entries = self._l.get_range(0, None) or []
        if not entries:
            return 0

        # Pre-fit sklearn vocabulary on full corpus
        if isinstance(self._b, SklearnTFIDF):
            self._b.train([e.content for e in entries])

        # Batch embed if supported (Anthropic)
        if hasattr(self._b, "embed_batch"):
            texts = [e.content for e in entries]
            vecs  = self._b.embed_batch(texts)
            for entry, vec in zip(entries, vecs):
                self._idx[entry.entry_id] = _IndexEntry(
                    entry_id=entry.entry_id, content=entry.content, vector=vec
                )
        else:
            for entry in entries:
                self._idx[entry.entry_id] = _IndexEntry(
                    entry_id=entry.entry_id,
                    content=entry.content,
                    vector=self._b.embed(entry.content),
                )

        if self._path:
            self._save()
        return len(self._idx)

    def update(self, entry_id: str, content: str) -> None:
        """Add or re-index a single entry."""
        self._idx[entry_id] = _IndexEntry(
            entry_id=entry_id, content=content,
            vector=self._b.embed(content),
        )
        if self._path:
            self._save()

    def search(
        self,
        query:     str,
        top_k:     int = 10,
        min_score: float = 0.0,
    ) -> List[Tuple[str, float]]:
        """Return [(entry_id, score)] sorted descending."""
        if not self._idx:
            return []
        q_vec = self._b.embed(query)
        scored = [
            (eid, _cosine(q_vec, e.vector))
            for eid, e in self._idx.items()
        ]
        scored = [(eid, s) for eid, s in scored if s >= min_score]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def as_similarity_fn(self) -> Callable[[str, str], float]:
        """
        Return (query, content) -> float for SecureMemoryRetriever.

        Looks up pre-computed content vectors from the index.
        Falls back to live embedding for unseen content.
        """
        # Snapshot content->vector map at call time
        content_vec: Dict[str, List[float]] = {
            e.content: e.vector for e in self._idx.values()
        }
        backend = self._b

        def sim_fn(query: str, content: str) -> float:
            q_vec = backend.embed(query)
            c_vec = content_vec.get(content) or backend.embed(content)
            return _cosine(q_vec, c_vec)

        return sim_fn

    def load(self) -> bool:
        """Load persisted index from disk. Returns True if successful."""
        if not self._path or not os.path.exists(self._path):
            return False
        try:
            with open(self._path, "rb") as f:
                self._idx = _EmbeddingUnpickler(f).load()
            return True
        except Exception:
            return False

    def _save(self) -> None:
        try:
            with open(self._path, "wb") as f:
                pickle.dump(self._idx, f)
        except Exception:
            pass

    @property
    def size(self) -> int:
        return len(self._idx)

    def stats(self) -> Dict[str, Any]:
        return {
            "backend":   self._b.name,
            "entries":   self.size,
            "persisted": self._path is not None,
        }


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def get_best_backend(
    prefer:  Optional[str] = None,
    api_key: Optional[str] = None,
) -> EmbeddingBackend:
    """
    Return the best available backend.

    prefer: None/"auto" | "anthropic" | "sklearn" | "keyword"
    """
    want = prefer if prefer not in (None, "auto") else None

    if want == "anthropic" or (want is None and AnthropicEmbedding.is_available()):
        return AnthropicEmbedding(api_key=api_key)
    if want == "sklearn" or (want is None and SklearnTFIDF.is_available()):
        return SklearnTFIDF()
    return KeywordFallback()


def build_similarity_fn(
    ledger:     Any,
    backend:    str = "auto",
    api_key:    Optional[str] = None,
    index_path: Optional[str] = None,
    preload:    bool = True,
) -> Callable[[str, str], float]:
    """
    Build a similarity function ready for SecureMemoryRetriever.

    Selects the best available backend, builds an index over the ledger,
    and returns a (query, content) -> float callable.

    Args:
        ledger:     MemoryLedger instance
        backend:    "auto" | "anthropic" | "sklearn" | "keyword"
        api_key:    Anthropic API key (backend="anthropic" only)
        index_path: Pickle path for index persistence
        preload:    Build/load index immediately (default True)

    Usage::

        from memgar.secure_embeddings import build_similarity_fn
        from memgar.secure_retriever import create_retriever

        sim_fn    = build_similarity_fn(ledger, backend="sklearn")
        retriever = create_retriever(ledger, similarity_fn=sim_fn)
    """
    be    = get_best_backend(prefer=backend, api_key=api_key)
    index = LedgerEmbeddingIndex(backend=be, ledger=ledger, index_path=index_path)

    if preload:
        if index_path and index.load():
            pass  # restored from disk
        else:
            index.build()

    return index.as_similarity_fn()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cosine(a: List[float], b: List[float]) -> float:
    if not a or not b:
        return 0.0
    if len(a) != len(b):
        diff = len(a) - len(b)
        if diff > 0:
            b = b + [0.0] * diff
        else:
            a = a + [0.0] * (-diff)
    dot   = sum(x * y for x, y in zip(a, b))
    na    = math.sqrt(sum(x * x for x in a))
    nb    = math.sqrt(sum(y * y for y in b))
    if na < 1e-12 or nb < 1e-12:
        return 0.0
    return round(max(0.0, min(1.0, dot / (na * nb))), 4)
