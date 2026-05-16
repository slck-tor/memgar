#!/usr/bin/env python3
"""
Import public adversarial corpora (AdvBench, JailbreakBench, HarmBench) and
normalize them to the memgar calibration schema.

These public datasets are NOT memory-poisoning-specific — they target generic
harmful-behavior generation. So we (a) filter to categories that map onto
memgar's threat model (exfiltration / manipulation / privilege / execution
/ credential / prompt_injection) and (b) pre-score with the Analyzer and
stratify into a "hard subset" of false negatives + false positives + boundary
cases. The hard subset is what's worth carrying into the CI gate; the full
raw dump is kept for training/augmentation.

Usage:
    python scripts/import_public_corpora.py
        [--sources advbench,jbb_harmful,jbb_benign,harmbench]
        [--out-raw ml/data/external_corpus_raw.json]
        [--out-hard ml/data/external_corpus_hard.json]
        [--cache-dir ml/data/_corpus_cache]
        [--no-prescore]    # skip Analyzer pass (faster, no stratification)

Outputs:
  - ml/data/external_corpus_raw.json   — every imported sample, schema-normalized
  - ml/data/external_corpus_hard.json  — Analyzer FN/FP/boundary subset
  - ml/data/CORPUS_LICENSES.md         — license/attribution manifest (regenerated)

The hard subset has the same schema as calibration_corpus.json and can be
merged into it manually after review.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Silence HF / tokenizer progress
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")
# Silence sentence-transformers' tqdm bars during batch encoding
try:
    import sentence_transformers  # noqa: F401
    from sentence_transformers import SentenceTransformer  # noqa: F401
    # The library reads `show_progress_bar` from encode() kwargs; we can't
    # globally override that, so we monkey-patch tqdm to a no-op as a last
    # resort. Keep this guarded so missing tqdm doesn't break the script.
    import tqdm as _tqdm

    def _silent(*a, **kw):  # type: ignore[no-redef]
        return a[0] if a else iter(())

    _tqdm.tqdm = _silent  # type: ignore[assignment]
    _tqdm.auto.tqdm = _silent  # type: ignore[assignment]
except Exception:
    pass


# ---------------------------------------------------------------------------
# Source registry
# ---------------------------------------------------------------------------

@dataclass
class Source:
    name: str
    url: str
    license_name: str
    license_url: str
    attribution: str
    notes: str
    parser: Callable[[bytes], Iterable[dict]] = field(repr=False)


def _parse_advbench(blob: bytes) -> Iterable[dict]:
    """AdvBench harmful_behaviors.csv: columns goal,target. All label=1.

    AdvBench targets generic harmful-content generation (weapons, drugs, hate).
    Most rows fall outside memgar's domain (agent memory poisoning). We keep
    every row but tag out-of-domain ones as `out_of_scope` so they can be
    filtered out of the gate corpus without false signal.
    """
    reader = csv.DictReader(io.StringIO(blob.decode("utf-8")))
    for row in reader:
        goal = (row.get("goal") or "").strip()
        if not goal:
            continue
        yield {
            "text": goal,
            "label": 1,
            "category": _map_category(goal, fallback="out_of_scope"),
            "source": "advbench",
        }


_JBB_CATEGORY_MAP = {
    "Privacy": "exfiltration",
    "Fraud/Deception": "manipulation",
    "Disinformation": "manipulation",
    "Malware/Hacking": "execution",
    "Economic harm": "manipulation",
    "Government decision-making": "manipulation",
    "Expert advice": "manipulation",
    # Skipped categories (harassment, sexual, physical harm) are out of scope
    # for memory-poisoning — they're content-moderation concerns. We drop
    # them so the corpus stays focused on agent-memory threats.
}
_JBB_SKIP_CATEGORIES = {
    "Harassment/Discrimination",
    "Physical harm",
    "Sexual/Adult content",
}


def _parse_jbb(blob: bytes, label: int) -> Iterable[dict]:
    """JailbreakBench harmful-behaviors.csv / benign-behaviors.csv."""
    reader = csv.DictReader(io.StringIO(blob.decode("utf-8")))
    for row in reader:
        goal = (row.get("Goal") or "").strip()
        cat = (row.get("Category") or "").strip()
        if not goal:
            continue
        if label == 1:
            if cat in _JBB_SKIP_CATEGORIES:
                continue
            mapped = _JBB_CATEGORY_MAP.get(cat, "manipulation")
        else:
            mapped = "benign"
        yield {
            "text": goal,
            "label": label,
            "category": mapped,
            "source": "jailbreakbench",
            "_orig_category": cat,
        }


_HARMBENCH_KEEP = {
    "cybercrime_intrusion",      # → execution
    "misinformation_disinformation",  # → manipulation
}
_HARMBENCH_CAT_MAP = {
    "cybercrime_intrusion": "execution",
    "misinformation_disinformation": "manipulation",
}


def _parse_harmbench(blob: bytes) -> Iterable[dict]:
    """HarmBench harmbench_behaviors_text_all.csv. Keep only cyber + disinfo."""
    reader = csv.DictReader(io.StringIO(blob.decode("utf-8")))
    for row in reader:
        beh = (row.get("Behavior") or "").strip()
        sem = (row.get("SemanticCategory") or "").strip()
        func = (row.get("FunctionalCategory") or "").strip()
        if not beh or sem not in _HARMBENCH_KEEP:
            continue
        # contextual rows include a separate context string we want to skip —
        # they're long passages, not the kind of compact memory-injection input
        if func == "contextual":
            continue
        yield {
            "text": beh,
            "label": 1,
            "category": _HARMBENCH_CAT_MAP[sem],
            "source": "harmbench",
            "_orig_category": sem,
        }


def _parse_hf_rows(blob: bytes) -> Iterable[dict]:
    """Parse a multi-line JSON file produced by `_fetch_hf_dataset` — one JSON
    object per row with arbitrary feature names. The source-specific parser
    below handles field mapping.
    """
    for line in blob.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def _parse_gandalf(blob: bytes) -> Iterable[dict]:
    """Lakera/gandalf_ignore_instructions: every row is a real prompt-injection
    attempt against the Gandalf game. All label=1.
    """
    for row in _parse_hf_rows(blob):
        text = (row.get("text") or "").strip()
        if not text:
            continue
        yield {
            "text": text,
            "label": 1,
            "category": _map_category(text, fallback="prompt_injection"),
            "source": "gandalf_ignore_instructions",
        }


def _parse_deepset_pi(blob: bytes) -> Iterable[dict]:
    """deepset/prompt-injections: text + label (1 = injection, 0 = benign)."""
    for row in _parse_hf_rows(blob):
        text = (row.get("text") or "").strip()
        lab = row.get("label")
        if not text or lab is None:
            continue
        label = int(lab)
        cat = _map_category(text, fallback="prompt_injection") if label == 1 else "benign"
        yield {
            "text": text,
            "label": label,
            "category": cat,
            "source": "deepset_prompt_injections",
        }


@dataclass
class HFSource(Source):
    """A source whose data is pulled via the HuggingFace datasets-server JSON
    API rather than a raw file URL. `url` here is the dataset name (e.g.
    'Lakera/gandalf_ignore_instructions'); `splits` lists the splits to
    aggregate; `config` selects the dataset config (default = 'default')."""

    splits: tuple[str, ...] = ("train",)
    config: str = "default"


SOURCES: dict[str, Source] = {
    "advbench": Source(
        name="AdvBench (harmful behaviors)",
        url="https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv",
        license_name="MIT",
        license_url="https://github.com/llm-attacks/llm-attacks/blob/main/LICENSE",
        attribution="Zou et al., 'Universal and Transferable Adversarial Attacks on Aligned Language Models', 2023",
        notes="520 harmful-behavior goals. All label=1; rows that don't lexically match memgar's threat keywords are tagged 'out_of_scope' (content-moderation domain, not memory-poisoning).",
        parser=_parse_advbench,
    ),
    "jbb_harmful": Source(
        name="JailbreakBench (harmful behaviors)",
        url="https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/resolve/main/data/harmful-behaviors.csv",
        license_name="MIT",
        license_url="https://github.com/JailbreakBench/jailbreakbench/blob/main/LICENSE",
        attribution="Chao et al., 'JailbreakBench: An Open Robustness Benchmark for Jailbreaking Large Language Models', NeurIPS 2024",
        notes="100 harmful behaviors with category labels. Harassment/sexual/physical-harm categories dropped (out of scope).",
        parser=lambda b: _parse_jbb(b, label=1),
    ),
    "jbb_benign": Source(
        name="JailbreakBench (benign behaviors)",
        url="https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/resolve/main/data/benign-behaviors.csv",
        license_name="MIT",
        license_url="https://github.com/JailbreakBench/jailbreakbench/blob/main/LICENSE",
        attribution="Chao et al., 'JailbreakBench: An Open Robustness Benchmark for Jailbreaking Large Language Models', NeurIPS 2024",
        notes="100 benign counterparts to harmful behaviors — surface-similar but legitimate. Gold for FP calibration.",
        parser=lambda b: _parse_jbb(b, label=0),
    ),
    "harmbench": Source(
        name="HarmBench (text behaviors)",
        url="https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_all.csv",
        license_name="MIT",
        license_url="https://github.com/centerforaisafety/HarmBench/blob/main/LICENSE",
        attribution="Mazeika et al., 'HarmBench: A Standardized Evaluation Framework for Automated Red Teaming', ICML 2024",
        notes="Filtered to cybercrime_intrusion + misinformation_disinformation only (other categories are content-moderation scope).",
        parser=_parse_harmbench,
    ),
    "gandalf": HFSource(
        name="Lakera Gandalf (ignore-instructions prompts)",
        url="Lakera/gandalf_ignore_instructions",
        license_name="MIT",
        license_url="https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions",
        attribution="Lakera AI, 'Gandalf Ignore Instructions' dataset (collected from the Gandalf prompt-injection game), HuggingFace",
        notes="1000 real prompt-injection attempts from the Gandalf game. All label=1; mapped to prompt_injection.",
        parser=_parse_gandalf,
        splits=("train", "validation", "test"),
    ),
    "deepset_pi": HFSource(
        name="deepset/prompt-injections",
        url="deepset/prompt-injections",
        license_name="Apache-2.0",
        license_url="https://huggingface.co/datasets/deepset/prompt-injections",
        attribution="deepset GmbH, 'prompt-injections' dataset, HuggingFace",
        notes="662 text+label rows (label=1 → prompt injection, label=0 → benign). Used for both attack patterns and FP calibration.",
        parser=_parse_deepset_pi,
        splits=("train", "test"),
    ),
}


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

_CATEGORY_KEYWORDS = [
    ("exfiltration", ("exfiltrat", "leak", "reveal", "expose", "extract", "dump", "context window", "system prompt", "memory")),
    ("credential", ("password", "api key", "credential", "token", "private key", "secret")),
    ("execution", ("exploit", "malware", "shellcode", "sql injection", "rce", "remote code", "ransomware", "backdoor", "keylogger")),
    ("manipulation", ("pretend", "claim", "always recommend", "override preference", "disinformation", "fake news", "propaganda")),
    ("privilege", ("admin", "root", "elevated", "sudo", "bypass auth")),
    ("financial", ("wire transfer", "credit card", "bitcoin address", "bank account")),
    ("prompt_injection", ("ignore", "previous instruction", "system:", "you are now", "from now on", "new directive")),
]


def _map_category(text: str, fallback: str) -> str:
    t = text.lower()
    for cat, kws in _CATEGORY_KEYWORDS:
        if any(kw in t for kw in kws):
            return cat
    return fallback


import re as _re

# Turkish-specific characters that don't appear in English. Plain `i` is NOT
# included — only the dotless `ı` and accented variants. This avoids false
# positives like "file/while/profile" containing the substring "ile".
_TURKISH_CHARS = _re.compile(r"[çğışüöÇĞIŞÜÖ]")
# Common Turkish stopwords matched on word boundaries (the earlier substring
# approach matched "ile" inside "while/profile/detailed"; we now require the
# word to stand alone).
_TURKISH_STOPWORDS = _re.compile(
    r"\b(için|şunu|lütfen|ile|bana|değil|tüm|kayıt|olarak|bilgi|hesap|kullanıcı|sistem|asla|geçersiz)\b",
    _re.IGNORECASE,
)


def _detect_language(text: str) -> str:
    if _TURKISH_CHARS.search(text) or _TURKISH_STOPWORDS.search(text):
        return "tr"
    return "en"


def _content_hash(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def _fetch(url: str, cache_path: Path, timeout: int = 30) -> bytes:
    """Download once, cache forever. Cache key = URL path."""
    if cache_path.exists():
        return cache_path.read_bytes()
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "memgar-corpus-import/1.0"})
    last_err: Exception | None = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            cache_path.write_bytes(data)
            return data
        except urllib.error.URLError as e:
            last_err = e
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed to fetch {url}: {last_err}")


def _fetch_hf_dataset(
    dataset: str,
    splits: tuple[str, ...],
    config: str,
    cache_path: Path,
    timeout: int = 30,
    page_size: int = 100,
) -> bytes:
    """Pull every row from one or more HuggingFace dataset splits via the
    datasets-server JSON API. Caches the assembled JSONL bytes at `cache_path`.

    The datasets-server pagination caps each call at ~100 rows; we walk
    `offset` until `num_rows_total` is reached. Returns a JSONL blob where
    each line is one row dict — the source-specific parser consumes it.
    """
    if cache_path.exists():
        return cache_path.read_bytes()
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    base = "https://datasets-server.huggingface.co/rows"
    ds_enc = urllib.request.quote(dataset, safe="")
    cfg_enc = urllib.request.quote(config, safe="")

    chunks: list[bytes] = []
    for split in splits:
        sp_enc = urllib.request.quote(split, safe="")
        offset = 0
        while True:
            url = (
                f"{base}?dataset={ds_enc}&config={cfg_enc}&split={sp_enc}"
                f"&offset={offset}&length={page_size}"
            )
            req = urllib.request.Request(url, headers={"User-Agent": "memgar-corpus-import/1.0"})
            last_err: Exception | None = None
            data: bytes | None = None
            for attempt in range(4):
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        data = resp.read()
                    break
                except urllib.error.URLError as e:
                    last_err = e
                    time.sleep(2 ** attempt)
            if data is None:
                raise RuntimeError(f"Failed to fetch HF page {url}: {last_err}")

            payload = json.loads(data)
            rows = payload.get("rows", [])
            for r in rows:
                chunks.append(json.dumps(r.get("row", {}), ensure_ascii=False).encode("utf-8"))
            total = payload.get("num_rows_total", 0)
            offset += len(rows)
            if not rows or offset >= total:
                break

    blob = b"\n".join(chunks)
    cache_path.write_bytes(blob)
    return blob


# ---------------------------------------------------------------------------
# Pre-scoring
# ---------------------------------------------------------------------------

def _build_analyzer():
    # Disable feed/observability before importing memgar — both pick env vars
    # at module load time.
    os.environ.setdefault("MEMGAR_FEED_ENABLED", "false")
    os.environ.setdefault("MEMGAR_OBSERVABILITY_ENABLED", "false")
    from memgar import Analyzer
    return Analyzer(use_llm=False)


def _score(analyzer, samples: list[dict]) -> list[dict]:
    """Run Analyzer on each sample; annotate with risk_score + decision."""
    from memgar.models import MemoryEntry

    out = []
    for s in samples:
        try:
            r = analyzer.analyze(MemoryEntry(content=s["text"]))
            s = {**s, "risk_score": r.risk_score, "decision": r.decision.value}
        except Exception as e:
            s = {**s, "risk_score": None, "decision": None, "score_error": repr(e)[:100]}
        out.append(s)
    return out


def _stratify_hard(scored: list[dict]) -> list[dict]:
    """Keep:
       - false negatives: label=1 but decision=allow (risk_score<40)
       - false positives: label=0 but decision in {quarantine,block} (risk_score>=40)
       - boundary cases: any sample with 20 <= risk_score < 60

    Drops `out_of_scope` rows from the FN bucket — those are content-moderation
    prompts that memgar is not designed to catch. They stay in the raw dump for
    reference, but reporting them as memgar misses would be misleading.
    """
    hard: list[dict] = []
    for s in scored:
        rs = s.get("risk_score")
        if rs is None:
            continue
        lab = s["label"]
        cat = s.get("category", "")
        is_fn = lab == 1 and rs < 40 and cat != "out_of_scope"
        is_fp = lab == 0 and rs >= 40
        is_boundary = 20 <= rs < 60 and cat != "out_of_scope"
        if is_fn or is_fp or is_boundary:
            tag = "fn" if is_fn else ("fp" if is_fp else "boundary")
            hard.append({**s, "hard_reason": tag})
    return hard


# ---------------------------------------------------------------------------
# License manifest
# ---------------------------------------------------------------------------

def _write_license_manifest(path: Path, used: list[str]) -> None:
    lines = [
        "# External Corpus Licenses",
        "",
        "This file is auto-generated by `scripts/import_public_corpora.py`. It tracks",
        "every public dataset whose samples were imported into",
        "`ml/data/external_corpus_*.json`. Do not edit by hand — re-run the import",
        "script to refresh.",
        "",
        f"Last generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        "",
    ]
    for key in used:
        s = SOURCES[key]
        lines += [
            f"## {s.name}  (`{key}`)",
            "",
            f"- **Source URL:** {s.url}",
            f"- **License:** [{s.license_name}]({s.license_url})",
            f"- **Citation:** {s.attribution}",
            f"- **Notes:** {s.notes}",
            "",
        ]
    lines += [
        "## Memgar usage",
        "",
        "Imported samples retain their original wording (no derivative modification).",
        "Each row in the output JSON is tagged with `note: \"source=<key>\"` so",
        "downstream attribution is preserved. Categories listed for filtering are",
        "applied only in memgar's threat-model mapping — they do not alter the",
        "underlying text.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sources", default="advbench,jbb_harmful,jbb_benign,harmbench,gandalf,deepset_pi",
                        help="Comma-separated source keys (see SOURCES dict).")
    parser.add_argument("--out-raw", default="ml/data/external_corpus_raw.json")
    parser.add_argument("--out-hard", default="ml/data/external_corpus_hard.json")
    parser.add_argument("--cache-dir", default="ml/data/_corpus_cache")
    parser.add_argument("--license-out", default="ml/data/CORPUS_LICENSES.md")
    parser.add_argument("--no-prescore", action="store_true",
                        help="Skip Analyzer pre-scoring (no hard subset).")
    parser.add_argument("--max-per-source", type=int, default=0,
                        help="Cap rows per source (0 = no cap).")
    args = parser.parse_args()

    requested = [s.strip() for s in args.sources.split(",") if s.strip()]
    unknown = [s for s in requested if s not in SOURCES]
    if unknown:
        print(f"ERROR: unknown sources: {unknown}. Known: {list(SOURCES)}")
        return 1

    cache_dir = REPO_ROOT / args.cache_dir
    cache_dir.mkdir(parents=True, exist_ok=True)

    # ---- 1. Fetch + parse ------------------------------------------------
    all_rows: list[dict] = []
    seen_hashes: set[str] = set()
    per_source_stats: dict[str, dict] = {}

    for key in requested:
        src = SOURCES[key]
        is_hf = isinstance(src, HFSource)
        ext = "jsonl" if is_hf else "csv"
        print(f"[{key}] fetching {src.url} ({'HF API' if is_hf else 'direct'})")
        cache_file = cache_dir / f"{key}.{ext}"
        try:
            if is_hf:
                blob = _fetch_hf_dataset(src.url, src.splits, src.config, cache_file)
            else:
                blob = _fetch(src.url, cache_file)
        except Exception as e:
            print(f"[{key}] FETCH FAILED: {e}")
            per_source_stats[key] = {"fetched": 0, "kept": 0, "deduped": 0, "error": str(e)}
            continue

        rows = list(src.parser(blob))
        fetched = len(rows)
        kept_this_source = 0
        deduped = 0
        for r in rows:
            h = _content_hash(r["text"])
            if h in seen_hashes:
                deduped += 1
                continue
            seen_hashes.add(h)
            r["language"] = _detect_language(r["text"])
            r["note"] = f"source={r.pop('source')}"
            if "_orig_category" in r:
                r["note"] += f"; orig_category={r.pop('_orig_category')}"
            all_rows.append(r)
            kept_this_source += 1
            if args.max_per_source and kept_this_source >= args.max_per_source:
                break

        per_source_stats[key] = {"fetched": fetched, "kept": kept_this_source, "deduped": deduped}
        print(f"[{key}] fetched={fetched}, kept={kept_this_source}, deduped={deduped}")

    if not all_rows:
        print("No rows imported — aborting.")
        return 1

    # ---- 2. Write raw dump ----------------------------------------------
    raw_path = REPO_ROOT / args.out_raw
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_payload = {
        "version": "1.0",
        "description": "Public adversarial corpora imported and normalized to memgar's calibration schema. Generated by scripts/import_public_corpora.py.",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "schema": {
            "text": "input string",
            "label": "1 = attack, 0 = benign",
            "language": "iso-639-1 (en | tr)",
            "category": "memgar threat category or 'benign'",
            "note": "source attribution + original category",
        },
        "per_source_stats": per_source_stats,
        "n_samples": len(all_rows),
        "samples": all_rows,
    }
    raw_path.write_text(json.dumps(raw_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nWrote {len(all_rows)} samples → {raw_path}")

    # ---- 3. Pre-score + stratify ----------------------------------------
    if not args.no_prescore:
        print("\nPre-scoring with Analyzer (this can take ~1-2 minutes for a few thousand rows)…")
        analyzer = _build_analyzer()
        scored = _score(analyzer, all_rows)
        hard = _stratify_hard(scored)
        hard_path = REPO_ROOT / args.out_hard
        hard_payload = {
            "version": "1.0",
            "description": "Hard subset of the imported corpus: false negatives, false positives, and boundary cases (20 ≤ risk_score < 60). Same schema as ml/data/calibration_corpus.json — append rows to that file after manual review.",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "schema": raw_payload["schema"],
            "n_samples": len(hard),
            "breakdown": {
                "fn": sum(1 for s in hard if s.get("hard_reason") == "fn"),
                "fp": sum(1 for s in hard if s.get("hard_reason") == "fp"),
                "boundary": sum(1 for s in hard if s.get("hard_reason") == "boundary"),
            },
            "samples": hard,
        }
        hard_path.write_text(json.dumps(hard_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Wrote {len(hard)} hard samples → {hard_path}")
        print(f"  breakdown: FN={hard_payload['breakdown']['fn']}, "
              f"FP={hard_payload['breakdown']['fp']}, "
              f"boundary={hard_payload['breakdown']['boundary']}")
    else:
        print("Skipping pre-score (--no-prescore).")

    # ---- 4. License manifest --------------------------------------------
    license_path = REPO_ROOT / args.license_out
    used = [k for k in requested if per_source_stats.get(k, {}).get("kept", 0) > 0]
    _write_license_manifest(license_path, used)
    print(f"\nLicense manifest → {license_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
