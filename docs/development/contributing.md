# Contributing

Memgar welcomes contributions. This page captures the local dev setup and
the contribution workflow.

## Setup

```bash
git clone https://github.com/slcxtor/memgar
cd memgar
pip install -e ".[dev,feed,observability,graph,gateway,adversarial]"
```

## Run tests

```bash
pytest -q                              # full suite (~1500 tests)
pytest tests/test_analyzer.py -v       # Layer 3+4 integration
pytest tests/test_feed.py -v           # Feed verify/cache/loader
pytest tests/test_adversarial.py -v    # Red-team
pytest tests/test_observability.py -v  # Prometheus/drift
```

Crypto tests require system `cryptography` package; they skip gracefully
when missing.

## Pattern PRs

To add a new threat pattern:

1. Append the `Threat(...)` dataclass to `memgar/patterns.py`.
2. Add positive examples (calibration) to `ml/data/calibration_corpus.json`.
3. Run the gold gate locally:
   ```bash
   python scripts/calibrate_fpfn.py \
       --corpus ml/data/calibration_corpus.json \
       --output ml/artifacts/fpfn_calibration.json --no-llm
   python scripts/check_calibration_gate.py
   ```
4. CI re-runs the gate on PR — all 8 thresholds must PASS.

## Corpus PRs

Public corpus PRs go through `scripts/import_public_corpora.py`:

```bash
# Add your source loader to SOURCES dict
# Document the license in CORPUS_LICENSES.md
python scripts/import_public_corpora.py --sources newsource --no-prescore
```

## Commit conventions

- Subject line ≤72 chars, imperative ("Add INJ-004 pattern")
- Body explains the **why**, not the what
- Reference related issues / PRs
- Don't commit the model checkpoint (only ONNX inference artifact)

## Style

- Python 3.9+ compat
- Type hints encouraged but not enforced
- `ruff` for linting (see `pyproject.toml`)
- Black-compatible formatting (88-char lines)

## Reporting security issues

Do NOT open a public issue. See [SECURITY.md](../security.md) for the
private reporting channel and embargo policy.
