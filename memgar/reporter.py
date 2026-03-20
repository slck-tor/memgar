"""
Memgar Report Generator
=======================

Generate HTML and JSON reports from scan results.

Usage:
    from memgar.reporter import ReportGenerator
    
    # Generate HTML report
    generator = ReportGenerator()
    generator.generate_html(results, "report.html")
    
    # CLI usage
    memgar scan-file memories.txt --output report.html
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .models import AnalysisResult, Decision, BatchResult


@dataclass
class ReportMetadata:
    """Report metadata."""
    title: str = "Memgar Security Report"
    generated_at: str = ""
    version: str = "0.2.0"
    source_file: Optional[str] = None
    

class ReportGenerator:
    """
    Generate security reports from scan results.
    
    Supports HTML and JSON output formats.
    """
    
    def __init__(self):
        self.metadata = ReportMetadata()
    
    def generate_html(
        self,
        results: List[AnalysisResult],
        output_path: str,
        title: str = "Memgar Security Report",
        source_file: Optional[str] = None,
    ) -> str:
        """
        Generate HTML report.
        
        Args:
            results: List of analysis results
            output_path: Output file path
            title: Report title
            source_file: Source file name (optional)
            
        Returns:
            Path to generated report
        """
        # Calculate stats
        total = len(results)
        blocked = sum(1 for r in results if r.decision == Decision.BLOCK)
        quarantined = sum(1 for r in results if r.decision == Decision.QUARANTINE)
        allowed = sum(1 for r in results if r.decision == Decision.ALLOW)
        
        # Risk distribution
        high_risk = sum(1 for r in results if r.risk_score >= 80)
        medium_risk = sum(1 for r in results if 40 <= r.risk_score < 80)
        low_risk = sum(1 for r in results if r.risk_score < 40)
        
        # Threat categories
        categories: Dict[str, int] = {}
        for r in results:
            if r.category:
                categories[r.category] = categories.get(r.category, 0) + 1
        
        # Generate HTML
        html = self._generate_html_template(
            title=title,
            source_file=source_file,
            total=total,
            blocked=blocked,
            quarantined=quarantined,
            allowed=allowed,
            high_risk=high_risk,
            medium_risk=medium_risk,
            low_risk=low_risk,
            categories=categories,
            results=results,
        )
        
        # Write file
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        
        return output_path
    
    def generate_json(
        self,
        results: List[AnalysisResult],
        output_path: str,
        source_file: Optional[str] = None,
    ) -> str:
        """
        Generate JSON report.
        
        Args:
            results: List of analysis results
            output_path: Output file path
            source_file: Source file name
            
        Returns:
            Path to generated report
        """
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
                "block_rate": f"{(blocked/total*100):.1f}%" if total > 0 else "0%",
            },
            "results": [r.to_dict() for r in results],
        }
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        
        return output_path
    
    def _generate_html_template(
        self,
        title: str,
        source_file: Optional[str],
        total: int,
        blocked: int,
        quarantined: int,
        allowed: int,
        high_risk: int,
        medium_risk: int,
        low_risk: int,
        categories: Dict[str, int],
        results: List[AnalysisResult],
    ) -> str:
        """Generate HTML template."""
        
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Generate results rows
        results_html = ""
        for i, r in enumerate(results, 1):
            decision_class = {
                Decision.ALLOW: "allow",
                Decision.BLOCK: "block",
                Decision.QUARANTINE: "quarantine",
            }.get(r.decision, "")
            
            decision_icon = {
                Decision.ALLOW: "✅",
                Decision.BLOCK: "🚫",
                Decision.QUARANTINE: "⚠️",
            }.get(r.decision, "")
            
            threat_info = f"{r.threat_type}: {r.threat_name}" if r.threat_type else "-"
            category = r.category or "-"
            severity = r.severity or "-"
            
            results_html += f"""
            <tr class="{decision_class}">
                <td>{i}</td>
                <td><span class="badge {decision_class}">{decision_icon} {r.decision.value}</span></td>
                <td>{r.risk_score}</td>
                <td>{threat_info}</td>
                <td>{category}</td>
                <td>{severity}</td>
            </tr>
            """
        
        # Generate category chart data
        category_labels = list(categories.keys()) if categories else ["None"]
        category_values = list(categories.values()) if categories else [0]
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e4e4e4;
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            padding: 30px 0;
            border-bottom: 1px solid #333;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            color: #fff;
            margin-bottom: 10px;
        }}
        
        .header .logo {{
            font-size: 3em;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            color: #888;
            font-size: 1.1em;
        }}
        
        .meta {{
            display: flex;
            justify-content: center;
            gap: 30px;
            margin-top: 15px;
            color: #666;
            font-size: 0.9em;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .stat-card.block {{
            border-color: #e74c3c;
            background: rgba(231, 76, 60, 0.1);
        }}
        
        .stat-card.quarantine {{
            border-color: #f39c12;
            background: rgba(243, 156, 18, 0.1);
        }}
        
        .stat-card.allow {{
            border-color: #2ecc71;
            background: rgba(46, 204, 113, 0.1);
        }}
        
        .stat-number {{
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-card.block .stat-number {{ color: #e74c3c; }}
        .stat-card.quarantine .stat-number {{ color: #f39c12; }}
        .stat-card.allow .stat-number {{ color: #2ecc71; }}
        
        .stat-label {{
            color: #888;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }}
        
        .section {{
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }}
        
        .section h2 {{
            font-size: 1.4em;
            margin-bottom: 20px;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        th {{
            background: rgba(255, 255, 255, 0.05);
            color: #fff;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }}
        
        tr:hover {{
            background: rgba(255, 255, 255, 0.03);
        }}
        
        tr.block {{
            background: rgba(231, 76, 60, 0.05);
        }}
        
        tr.quarantine {{
            background: rgba(243, 156, 18, 0.05);
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        
        .badge.block {{
            background: rgba(231, 76, 60, 0.2);
            color: #e74c3c;
        }}
        
        .badge.quarantine {{
            background: rgba(243, 156, 18, 0.2);
            color: #f39c12;
        }}
        
        .badge.allow {{
            background: rgba(46, 204, 113, 0.2);
            color: #2ecc71;
        }}
        
        .risk-bar {{
            display: flex;
            gap: 5px;
            margin-top: 15px;
        }}
        
        .risk-segment {{
            height: 8px;
            border-radius: 4px;
        }}
        
        .risk-high {{ background: #e74c3c; }}
        .risk-medium {{ background: #f39c12; }}
        .risk-low {{ background: #2ecc71; }}
        
        .category-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 15px;
        }}
        
        .category-tag {{
            background: rgba(255, 255, 255, 0.1);
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.9em;
        }}
        
        .category-tag span {{
            background: rgba(255, 255, 255, 0.2);
            padding: 2px 8px;
            border-radius: 10px;
            margin-left: 8px;
            font-weight: bold;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px 0;
            color: #666;
            font-size: 0.9em;
        }}
        
        .footer a {{
            color: #3498db;
            text-decoration: none;
        }}
        
        @media (max-width: 768px) {{
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
            
            table {{
                font-size: 0.9em;
            }}
            
            th, td {{
                padding: 8px 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️</div>
            <h1>{title}</h1>
            <p class="subtitle">AI Agent Memory Security Report</p>
            <div class="meta">
                <span>📅 {generated_at}</span>
                {f'<span>📁 {source_file}</span>' if source_file else ''}
                <span>🔢 {total} entries scanned</span>
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{total}</div>
                <div class="stat-label">Total Scanned</div>
            </div>
            <div class="stat-card block">
                <div class="stat-number">{blocked}</div>
                <div class="stat-label">🚫 Blocked</div>
            </div>
            <div class="stat-card quarantine">
                <div class="stat-number">{quarantined}</div>
                <div class="stat-label">⚠️ Quarantined</div>
            </div>
            <div class="stat-card allow">
                <div class="stat-number">{allowed}</div>
                <div class="stat-label">✅ Allowed</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📊 Risk Distribution</h2>
            <div class="risk-bar">
                <div class="risk-segment risk-high" style="flex: {high_risk};" title="High Risk: {high_risk}"></div>
                <div class="risk-segment risk-medium" style="flex: {medium_risk};" title="Medium Risk: {medium_risk}"></div>
                <div class="risk-segment risk-low" style="flex: {low_risk};" title="Low Risk: {low_risk}"></div>
            </div>
            <p style="margin-top: 15px; color: #888;">
                🔴 High Risk: {high_risk} &nbsp;&nbsp;
                🟡 Medium Risk: {medium_risk} &nbsp;&nbsp;
                🟢 Low Risk: {low_risk}
            </p>
        </div>
        
        {'<div class="section"><h2>📂 Threat Categories</h2><div class="category-list">' + ''.join(f'<div class="category-tag">{cat}<span>{count}</span></div>' for cat, count in sorted(categories.items(), key=lambda x: -x[1])) + '</div></div>' if categories else ''}
        
        <div class="section">
            <h2>📋 Detailed Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Decision</th>
                        <th>Risk</th>
                        <th>Threat</th>
                        <th>Category</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {results_html}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by <a href="https://github.com/slck-tor/memgar">Memgar</a> v0.2.0</p>
            <p>AI Agent Memory Security</p>
        </div>
    </div>
</body>
</html>
"""
        return html


def generate_report(
    results: List[AnalysisResult],
    output_path: str,
    format: str = "html",
    **kwargs
) -> str:
    """
    Quick function to generate report.
    
    Args:
        results: List of analysis results
        output_path: Output file path
        format: Output format (html, json)
        **kwargs: Additional arguments
        
    Returns:
        Path to generated report
    """
    generator = ReportGenerator()
    
    if format == "json":
        return generator.generate_json(results, output_path, **kwargs)
    else:
        return generator.generate_html(results, output_path, **kwargs)
