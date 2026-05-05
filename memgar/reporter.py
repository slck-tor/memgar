"""Generate HTML and JSON reports from scan results."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from .models import AnalysisResult, BatchResult, Decision


@dataclass
class ReportMetadata:
    title: str = "Memgar Security Report"
    generated_at: str = ""
    version: str = "0.2.0"
    source_file: Optional[str] = None


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


class ReportGenerator:
    """Generate security reports from scan results."""

    def __init__(self):
        self.metadata = ReportMetadata()

    def generate_html(self, results: List[AnalysisResult], output_path: str,
                      title: str = "Memgar Security Report",
                      source_file: Optional[str] = None) -> str:
        html_report = self._generate_html_template(title, source_file, results)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_report)
        return output_path

    def generate_json(self, results: List[AnalysisResult], output_path: str,
                      source_file: Optional[str] = None) -> str:
        total = len(results)
        blocked = sum(1 for r in results if r.decision == Decision.BLOCK)
        quarantined = sum(1 for r in results if r.decision == Decision.QUARANTINE)
        allowed = sum(1 for r in results if r.decision == Decision.ALLOW)
        report = {
            "metadata": {
                "title": "Memgar Security Report",
                "generated_at": datetime.now().isoformat(),
                "version": "0.2.0",
                "source_file": source_file,
            },
            "summary": {
                "total": total,
                "blocked": blocked,
                "quarantined": quarantined,
                "allowed": allowed,
                "block_rate": f"{(blocked / total * 100):.1f}%" if total else "0%",
            },
            "results": [r.to_dict() for r in results],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return output_path

    def _generate_html_template(self, title: str, source_file: Optional[str],
                                results: List[AnalysisResult]) -> str:
        total = len(results)
        blocked = sum(1 for r in results if r.decision == Decision.BLOCK)
        quarantined = sum(1 for r in results if r.decision == Decision.QUARANTINE)
        allowed = sum(1 for r in results if r.decision == Decision.ALLOW)
        high = sum(1 for r in results if r.risk_score >= 80)
        medium = sum(1 for r in results if 40 <= r.risk_score < 80)
        low = sum(1 for r in results if r.risk_score < 40)
        categories: Dict[str, int] = {}
        for r in results:
            if r.category:
                categories[str(r.category)] = categories.get(str(r.category), 0) + 1

        rows = []
        for i, r in enumerate(results, 1):
            css = {Decision.ALLOW: "allow", Decision.BLOCK: "block",
                   Decision.QUARANTINE: "quarantine"}.get(r.decision, "")
            threat = f"{r.threat_type}: {r.threat_name}" if r.threat_type else "-"
            rows.append(
                f'<tr class="{_e(css)}"><td>{i}</td><td>{_e(r.decision.value)}</td>'
                f'<td>{int(r.risk_score)}</td><td>{_e(threat)}</td>'
                f'<td>{_e(r.category or "-")}</td><td>{_e(r.severity or "-")}</td></tr>'
            )
        category_tags = "".join(
            f'<span class="tag">{_e(k)} <b>{v}</b></span>'
            for k, v in sorted(categories.items(), key=lambda item: -item[1])
        )
        source = f'<span>Source: {_e(source_file)}</span>' if source_file else ""
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title><style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;margin:0;padding:24px;background:#111827;color:#e5e7eb}}
.container{{max-width:1100px;margin:auto}}.header{{text-align:center;margin-bottom:24px}}.meta{{color:#9ca3af;display:flex;gap:16px;justify-content:center;flex-wrap:wrap}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0}}.card,.section{{background:#1f2937;border:1px solid #374151;border-radius:8px;padding:16px}}
.num{{font-size:2rem;font-weight:700}}.block .num,.block{{color:#f87171}}.quarantine .num,.quarantine{{color:#fbbf24}}.allow .num,.allow{{color:#34d399}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid #374151;text-align:left}}th{{background:#111827}}.tag{{display:inline-block;background:#111827;border-radius:999px;padding:6px 10px;margin:4px}}
</style></head><body><div class="container"><div class="header"><h1>{_e(title)}</h1><div class="meta"><span>{_e(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</span>{source}<span>{total} entries</span></div></div>
<div class="grid"><div class="card"><div class="num">{total}</div>Total</div><div class="card block"><div class="num">{blocked}</div>Blocked</div><div class="card quarantine"><div class="num">{quarantined}</div>Quarantined</div><div class="card allow"><div class="num">{allowed}</div>Allowed</div></div>
<div class="section"><h2>Risk</h2><p>High: {high} | Medium: {medium} | Low: {low}</p></div><div class="section"><h2>Categories</h2>{category_tags or '-'}</div>
<div class="section"><h2>Detailed Results</h2><table><thead><tr><th>#</th><th>Decision</th><th>Risk</th><th>Threat</th><th>Category</th><th>Severity</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
</div></body></html>"""


def generate_report(results: List[AnalysisResult], output_path: str,
                    format: str = "html", **kwargs) -> str:
    generator = ReportGenerator()
    if format == "json":
        return generator.generate_json(results, output_path, **kwargs)
    return generator.generate_html(results, output_path, **kwargs)


HTMLReporter = ReportGenerator
