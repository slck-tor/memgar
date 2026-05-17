#!/usr/bin/env python3
"""
Memory-context attack augmentation.

Memgar's distinct threat model is **memory poisoning** — adversarial content
planted into an LLM agent's persistent memory (RAG store, conversation
history, user-preference cache) so the agent recalls it later as trusted
context. Most public corpora (AdvBench, JailbreakBench, Gandalf, deepset)
are direct prompt-injection text — they don't reflect the wrapping that
attackers use when the content has to survive a round-trip through a
memory store.

This script takes labelled attack seeds and wraps each one in 8 realistic
memory-injection envelopes (EN + TR). The output is an auxiliary corpus
file that calibrate_fpfn.py merges with calibration_corpus.json at scoring
time. Auto-generated rows are tagged with `note: "augmented=memory_context;
template=<id>; seed_id=<n>"` so any FN/FP can be traced back to its seed.

Usage:
    python scripts/augment_memory_context.py
        [--seeds ml/data/calibration_corpus.json]
        [--out ml/data/augmented_memory_context.json]
        [--max-per-seed 8]
        [--language all|en|tr]

Output schema (compatible with calibration_corpus.json):
    {text, label, language, category, note}
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))


# ---------------------------------------------------------------------------
# Memory-context envelope templates
# ---------------------------------------------------------------------------
#
# Each template wraps the raw attack seed in a phrasing that mimics how
# adversarial content lands inside an agent's memory store. The wrapper is
# part of memgar's threat model — without it, the seeds look like ordinary
# prompts (which competitors already cover).
#
# {SEED} is substituted with the raw attack text. Wrappers deliberately span
# several memory-injection vectors:
#   - explicit memory markers     ([Memory note], AI memory:, Stored:)
#   - conversation-history fakes  (User previously said:, From chat history:)
#   - preference-cache injection  (Saved preference:, User preference:)
#   - assistant self-note fakes   (Note to self:, Reminder for next turn:)
#   - background-context fakes    (Background:, Context: ...)

_TEMPLATES_EN: list[tuple[str, str]] = [
    ("memnote",     "[Memory note] {SEED}"),
    ("aimemory",    "AI memory: {SEED}"),
    ("stored",      "Stored: {SEED}"),
    ("prev_said",   "User previously said: \"{SEED}\""),
    ("chat_hist",   "From chat history: {SEED}"),
    ("pref_saved", "Saved preference: {SEED}"),
    ("self_note",  "Note to self for next turn: {SEED}"),
    ("background", "Background context: {SEED}"),
]

_TEMPLATES_TR: list[tuple[str, str]] = [
    ("memnote_tr",   "[Bellek notu] {SEED}"),
    ("aimemory_tr",  "AI hafızası: {SEED}"),
    ("stored_tr",    "Kayıtlı: {SEED}"),
    ("prev_said_tr", "Kullanıcı daha önce şöyle dedi: \"{SEED}\""),
    ("chat_hist_tr", "Sohbet geçmişinden: {SEED}"),
    ("pref_saved_tr","Kayıtlı tercih: {SEED}"),
    ("self_note_tr", "Bir sonraki tur için kendine not: {SEED}"),
    ("background_tr","Arka plan bağlamı: {SEED}"),
]


def _wrap(seed_text: str, language: str) -> list[tuple[str, str]]:
    """Return (template_id, wrapped_text) tuples for the given language."""
    if language == "tr":
        return [(tid, tpl.replace("{SEED}", seed_text)) for tid, tpl in _TEMPLATES_TR]
    if language == "en":
        return [(tid, tpl.replace("{SEED}", seed_text)) for tid, tpl in _TEMPLATES_EN]
    # mixed/unknown: apply both (template language matches seed's detected lang)
    detected = "tr" if any(c in seed_text for c in "çğışüöÇĞIŞÜÖ") else "en"
    return _wrap(seed_text, detected)


def _load_seeds(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("samples") or payload.get("rows") or []
    # Only attack seeds (label=1) become memory-context-wrapped. Wrapping a
    # benign seed inside a memory envelope doesn't make it adversarial, so
    # we'd just be inflating the corpus with synthetic benigns.
    return [r for r in rows if int(r.get("label", 0)) == 1]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--seeds", default="ml/data/calibration_corpus.json",
                   help="JSON file with attack seeds (label=1 rows kept).")
    p.add_argument("--out", default="ml/data/augmented_memory_context.json")
    p.add_argument("--max-per-seed", type=int, default=8,
                   help="Cap on wrapper variants per seed (default: all 8).")
    p.add_argument("--language", choices=("all", "en", "tr"), default="en",
                   help="Template language. Default 'en' (memgar is English-primary for "
                        "global use). 'all' includes Turkish templates as a bonus.")
    args = p.parse_args()

    seed_path = REPO_ROOT / args.seeds
    if not seed_path.exists():
        print(f"ERROR: seeds file not found: {seed_path}")
        return 1

    seeds = _load_seeds(seed_path)
    if not seeds:
        print("No attack seeds found (label=1). Aborting.")
        return 1

    out_rows: list[dict] = []
    template_stats: dict[str, int] = {}

    for idx, seed in enumerate(seeds):
        text = (seed.get("text") or "").strip()
        if not text:
            continue
        seed_lang = (seed.get("language") or "en").lower()
        seed_cat = seed.get("category") or "prompt_injection"

        if args.language == "tr":
            wraps = _wrap(text, "tr")
        elif args.language == "en":
            wraps = _wrap(text, "en")
        else:
            # `all` → wrap in both EN + TR templates; consumer side
            # benefits from the cross-lingual variety.
            wraps = _wrap(text, "en") + _wrap(text, "tr")

        wraps = wraps[: args.max_per_seed * (2 if args.language == "all" else 1)]

        for tid, wrapped in wraps:
            template_lang = "tr" if tid.endswith("_tr") else "en"
            out_rows.append({
                "text": wrapped,
                "label": 1,
                "language": template_lang,
                "category": seed_cat,
                "note": f"augmented=memory_context; template={tid}; seed_id={idx}; seed_lang={seed_lang}",
            })
            template_stats[tid] = template_stats.get(tid, 0) + 1

    out_path = REPO_ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({
        "version": "1.0",
        "description": (
            "Memory-context-wrapped attack seeds. Auto-generated by "
            "scripts/augment_memory_context.py from labelled attack seeds. "
            "Each row is a known attack wrapped in a memory-injection envelope "
            "to simulate memgar's distinct threat model (persistent agent memory). "
            "Audit any FN/FP via the `seed_id` field in `note`."
        ),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "schema": {
            "text": "memory-wrapped attack input",
            "label": "always 1 (these are attacks)",
            "language": "iso-639-1 (en | tr)",
            "category": "inherited from seed",
            "note": "audit trail: template id + seed id + original language",
        },
        "n_samples": len(out_rows),
        "template_stats": template_stats,
        "n_seeds_used": len(seeds),
        "samples": out_rows,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Generated {len(out_rows)} memory-context-wrapped samples from {len(seeds)} seeds")
    print(f"  templates: {sorted(template_stats)}")
    print(f"  output: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
