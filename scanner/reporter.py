"""
Multi-format Reporting Engine.
Generates visually compelling Console tables (Rich), executive HTML dashboards,
machine-readable JSON outputs, and GitHub-flavored Markdown reports.
"""

import json
import os
import sys
from typing import Optional
from .models import ScanResult, Severity, Grade

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class ReportGenerator:
    """Handles multi-format reporting for audit results."""

    def __init__(self, result: ScanResult):
        self.result = result
        self.console = Console() if RICH_AVAILABLE else None

    def print_console(self, verbose: bool = False):
        """Print audit summary to the terminal with rich colors and formatting."""
        if not RICH_AVAILABLE:
            self._print_plain_console(verbose)
            return

        # 1. Header / Banner
        banner_text = Text()
        banner_text.append("🛡️  WEB SECURITY AUDIT REPORT\n", style="bold cyan")
        banner_text.append(f"Target: {self.result.target_url}  |  Scanned at: {self.result.timestamp}\n", style="dim")
        banner_text.append(f"Grade: ", style="bold")
        banner_text.append(f" {self.result.grade.value} ", style=f"bold white on {self._get_grade_style(self.result.grade)}")
        banner_text.append(f"  Score: ", style="bold")
        banner_text.append(f"{self.result.score}/100\n", style="bold yellow")
        
        self.console.print(Panel(banner_text, box=box.ROUNDED, expand=False))

        # 2. Executive Metrics Summary Table
        summary_table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold magenta")
        summary_table.add_column("Metric", style="bold")
        summary_table.add_column("Value")
        
        summary_table.add_row("HTTP Status", f"[green]{self.result.status_code}[/green]" if self.result.status_code < 400 else f"[red]{self.result.status_code}[/red]")
        summary_table.add_row("Server Banner", self.result.server_banner or "[dim]Hidden / Not Disclosed[/dim]")
        summary_table.add_row("Response Latency", f"{self.result.response_time_ms:.1f} ms")
        summary_table.add_row("Target IP", self.result.ip_address or "Unknown")
        summary_table.add_row("Total Findings", str(len(self.result.findings)))
        summary_table.add_row("Critical Findings", f"[bold red]{sum(1 for f in self.result.findings if f.severity == Severity.CRITICAL)}[/bold red]")
        summary_table.add_row("High Findings", f"[red]{sum(1 for f in self.result.findings if f.severity == Severity.HIGH)}[/red]")
        summary_table.add_row("Medium Findings", f"[yellow]{sum(1 for f in self.result.findings if f.severity == Severity.MEDIUM)}[/yellow]")
        summary_table.add_row("Low / Info Findings", f"[blue]{sum(1 for f in self.result.findings if f.severity in (Severity.LOW, Severity.INFO))}[/blue]")
        self.console.print(summary_table)

        # 3. Security Findings Table
        if self.result.findings:
            self.console.print("\n[bold red]🚨 IDENTIFIED VULNERABILITIES & MISCONFIGURATIONS[/bold red]")
            f_table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
            f_table.add_column("ID", style="bold dim", width=14)
            f_table.add_column("Severity", width=11)
            f_table.add_column("Category", width=22)
            f_table.add_column("Title & Remediation", overflow="fold")

            for f in self.result.findings:
                sev_badge = f"[{f.severity.color}]{f.severity.value}[/{f.severity.color}]"
                desc_text = f"[bold]{f.title}[/bold]\n[dim]{f.description}[/dim]\n[green]Fix: {f.remediation}[/green]"
                f_table.add_row(f.id, sev_badge, f.category, desc_text)

            self.console.print(f_table)
        else:
            self.console.print("\n[bold green]✅ No high or critical security misconfigurations identified![/bold green]")

        # 4. Security Headers Breakdown Table
        self.console.print("\n[bold blue]📋 HTTP SECURITY HEADERS AUDIT[/bold blue]")
        h_table = Table(box=box.ROUNDED, show_header=True, header_style="bold blue")
        h_table.add_column("Header", style="bold", width=26)
        h_table.add_column("Status", width=10)
        h_table.add_column("Analysis & Details", overflow="fold")

        status_colors = {
            "PASS": "[bold green]PASS[/bold green]",
            "WARN": "[bold yellow]WARN[/bold yellow]",
            "FAIL": "[bold red]FAIL[/bold red]",
            "INFO": "[bold cyan]INFO[/bold cyan]",
        }

        for h in self.result.headers_audit:
            badge = status_colors.get(h.status, h.status)
            details = h.details
            if h.recommendation and h.status != "PASS":
                details += f"\n[dim italic]💡 {h.recommendation}[/dim italic]"
            h_table.add_row(h.name, badge, details)

        self.console.print(h_table)

        # 5. CORS Probes Matrix Table
        self.console.print("\n[bold magenta]🌐 CORS (CROSS-ORIGIN RESOURCE SHARING) AUDIT MATRIX[/bold magenta]")
        c_table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        c_table.add_column("Test Probe", width=30)
        c_table.add_column("Origin Sent", width=28)
        c_table.add_column("ACAO Returned", width=22)
        c_table.add_column("Credentials (ACAC)", width=14)
        c_table.add_column("Outcome", overflow="fold")

        for c in self.result.cors_probes:
            status = "[bold red]VULNERABLE[/bold red]" if c.vulnerable else "[green]SAFE[/green]"
            acao_disp = f"[yellow]{c.acao_received}[/yellow]" if c.acao_received else "[dim]None[/dim]"
            acac_disp = f"[bold red]{c.acac_received}[/bold red]" if c.acac_received == "true" else (c.acac_received or "[dim]None[/dim]")
            c_table.add_row(c.name, c.probe_origin, acao_disp, acac_disp, f"{status} - {c.details}")

        self.console.print(c_table)

        # 6. Verbose raw headers view
        if verbose:
            self.console.print("\n[bold dim]🔍 RAW HTTP HEADERS RETURNED[/bold dim]")
            raw_table = Table(box=box.SIMPLE, show_header=True, header_style="dim")
            raw_table.add_column("Header Key", style="cyan")
            raw_table.add_column("Value", style="dim")
            for k, v in self.result.raw_headers.items():
                raw_table.add_row(k, v)
            self.console.print(raw_table)

    def _print_plain_console(self, verbose: bool):
        """Fallback plaintext printing when rich is not installed."""
        r = self.result
        print("=" * 70)
        print(f"WEB SECURITY AUDIT REPORT: {r.target_url}")
        print(f"Timestamp: {r.timestamp} | Grade: {r.grade.value} | Score: {r.score}/100")
        print("=" * 70)
        print(f"Status Code: {r.status_code} | Server: {r.server_banner or 'Hidden'}")
        print("-" * 70)
        print(f"FINDINGS ({len(r.findings)}):")
        for f in r.findings:
            print(f"[{f.severity.value}] {f.id} - {f.title}")
            print(f"  Description: {f.description}")
            print(f"  Remediation: {f.remediation}\n")
        print("-" * 70)
        print("SECURITY HEADERS:")
        for h in r.headers_audit:
            print(f"  [{h.status}] {h.name}: {h.details}")
        print("-" * 70)
        print("CORS PROBES:")
        for c in r.cors_probes:
            vuln_str = "VULNERABLE" if c.vulnerable else "SAFE"
            print(f"  [{vuln_str}] {c.name} (Origin: {c.probe_origin}) -> ACAO: {c.acao_received}")
        print("=" * 70)

    def _get_grade_style(self, grade: Grade) -> str:
        styles = {
            Grade.A_PLUS: "green",
            Grade.A: "dark_green",
            Grade.B: "blue",
            Grade.C: "yellow",
            Grade.D: "dark_orange",
            Grade.F: "red",
        }
        return styles.get(grade, "white")

    def save_json(self, filepath: str):
        """Save results to structured JSON file."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.result.to_dict(), f, indent=2, ensure_ascii=False)

    def save_markdown(self, filepath: str):
        """Save results to GitHub Flavored Markdown."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        r = self.result
        md = []
        md.append(f"# Web Security Audit Report - `{r.target_url}`")
        md.append(f"\n**Date:** {r.timestamp}  \n**Security Grade:** `{r.grade.value}` ({r.score}/100)  \n**Server:** {r.server_banner or 'Undisclosed'}  \n**Status:** {r.status_code}\n")
        
        md.append("## Executive Summary\n")
        md.append("| Severity | Count |")
        md.append("| :--- | :--- |")
        md.append(f"| **CRITICAL** | {sum(1 for x in r.findings if x.severity == Severity.CRITICAL)} |")
        md.append(f"| **HIGH** | {sum(1 for x in r.findings if x.severity == Severity.HIGH)} |")
        md.append(f"| **MEDIUM** | {sum(1 for x in r.findings if x.severity == Severity.MEDIUM)} |")
        md.append(f"| **LOW** | {sum(1 for x in r.findings if x.severity == Severity.LOW)} |")
        md.append(f"| **INFO** | {sum(1 for x in r.findings if x.severity == Severity.INFO)} |\n")

        md.append("## Identified Findings\n")
        if not r.findings:
            md.append("No security misconfigurations identified.")
        else:
            for f in r.findings:
                md.append(f"### `[{f.severity.value}]` {f.title} ({f.id})")
                md.append(f"- **Category:** {f.category} | **OWASP:** {f.owasp_category} | **CWE:** {f.cwe_id}")
                md.append(f"- **Description:** {f.description}")
                md.append(f"- **Evidence:**\n```\n{f.evidence}\n```")
                md.append(f"- **Impact:** {f.impact}")
                md.append(f"- **Remediation:** {f.remediation}\n")

        md.append("## Security Headers Status\n")
        md.append("| Header | Status | Details |")
        md.append("| :--- | :--- | :--- |")
        for h in r.headers_audit:
            md.append(f"| `{h.name}` | **{h.status}** | {h.details} |")

        md.append("\n## CORS Security Matrix\n")
        md.append("| Probe Name | Sent Origin | ACAO Returned | ACAC | Status |")
        md.append("| :--- | :--- | :--- | :--- | :--- |")
        for c in r.cors_probes:
            vuln_badge = "CRITICAL / VULNERABLE" if c.vulnerable else "SAFE"
            md.append(f"| {c.name} | `{c.probe_origin}` | `{c.acao_received or '-'}` | `{c.acac_received or '-'}` | {vuln_badge} |")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(md))

    def save_html(self, filepath: str):
        """Generate a modern, responsive executive HTML dashboard."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        r = self.result

        crit_count = sum(1 for f in r.findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in r.findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in r.findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in r.findings if f.severity == Severity.LOW)

        findings_html = ""
        for f in r.findings:
            findings_html += f"""
            <div class="card finding-card border-{f.severity.value.lower()}">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <div>
                        <span class="badge badge-{f.severity.value.lower()}">{f.severity.value}</span>
                        <span class="badge badge-secondary">{f.id}</span>
                        <strong class="ml-2">{f.title}</strong>
                    </div>
                    <span class="text-muted small">{f.owasp_category}</span>
                </div>
                <div class="card-body">
                    <p class="mb-2"><strong>Description:</strong> {f.description}</p>
                    <div class="evidence-box mb-2">
                        <small class="text-muted font-weight-bold">EVIDENCE:</small>
                        <pre><code>{f.evidence}</code></pre>
                    </div>
                    <p class="mb-2 text-danger"><strong>Impact:</strong> {f.impact}</p>
                    <div class="remediation-box">
                        <strong>🛠️ Recommended Remediation:</strong>
                        <p class="mb-0 text-success">{f.remediation}</p>
                    </div>
                </div>
            </div>
            """

        headers_rows = ""
        for h in r.headers_audit:
            status_class = "success" if h.status == "PASS" else ("danger" if h.status == "FAIL" else "warning")
            headers_rows += f"""
            <tr>
                <td><code>{h.name}</code></td>
                <td><span class="badge badge-{status_class}">{h.status}</span></td>
                <td>{h.details}</td>
                <td class="small text-muted">{h.recommendation or '—'}</td>
            </tr>
            """

        cors_rows = ""
        for c in r.cors_probes:
            status_badge = '<span class="badge badge-danger">VULNERABLE</span>' if c.vulnerable else '<span class="badge badge-success">SAFE</span>'
            cors_rows += f"""
            <tr>
                <td><strong>{c.name}</strong></td>
                <td><code>{c.probe_origin}</code></td>
                <td><code>{c.acao_received or 'None'}</code></td>
                <td><code>{c.acac_received or 'None'}</code></td>
                <td>{status_badge}</td>
                <td class="small">{c.details}</td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Security Audit: {r.target_url}</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --pass: #22c55e;
            --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: var(--font-family);
            line-height: 1.6;
            padding: 2rem 1rem;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1.5rem;
        }}
        .header-title h1 {{
            font-size: 1.8rem;
            color: #fff;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .header-title p {{
            color: var(--text-secondary);
            font-size: 0.95rem;
        }}
        .score-box {{
            text-align: center;
            background: #0b1120;
            padding: 1.25rem 2rem;
            border-radius: 12px;
            border: 2px solid {r.grade.hex_color};
            box-shadow: 0 0 20px {r.grade.hex_color}33;
        }}
        .score-grade {{
            font-size: 3rem;
            font-weight: 800;
            color: {r.grade.hex_color};
            line-height: 1;
        }}
        .score-num {{
            font-size: 1rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .stat-card {{
            background: var(--surface);
            padding: 1.25rem;
            border-radius: 8px;
            border: 1px solid #334155;
        }}
        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .stat-card .val {{
            font-size: 1.75rem;
            font-weight: 700;
            margin-top: 0.25rem;
        }}
        .section-title {{
            font-size: 1.4rem;
            margin: 2rem 0 1rem;
            color: #38bdf8;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            border-bottom: 2px solid #1e293b;
            padding-bottom: 0.5rem;
        }}
        .finding-card {{
            background: var(--surface);
            border-left: 6px solid #64748b;
            border-radius: 8px;
            padding: 1.25rem;
            margin-bottom: 1rem;
            border-top: 1px solid #334155;
            border-right: 1px solid #334155;
            border-bottom: 1px solid #334155;
        }}
        .border-critical {{ border-left-color: var(--critical); }}
        .border-high {{ border-left-color: var(--high); }}
        .border-medium {{ border-left-color: var(--medium); }}
        .border-low {{ border-left-color: var(--low); }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.6rem;
            font-size: 0.75rem;
            font-weight: 700;
            border-radius: 4px;
            text-transform: uppercase;
            margin-right: 0.5rem;
        }}
        .badge-critical {{ background: var(--critical); color: #fff; }}
        .badge-high {{ background: var(--high); color: #fff; }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); color: #fff; }}
        .badge-success {{ background: var(--pass); color: #000; font-weight: bold; }}
        .badge-danger {{ background: var(--critical); color: #fff; }}
        .badge-warning {{ background: var(--medium); color: #000; }}
        .badge-secondary {{ background: #475569; color: #fff; }}
        .evidence-box {{
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 0.75rem;
            margin: 0.75rem 0;
            overflow-x: auto;
        }}
        .evidence-box pre {{
            color: #f1f5f9;
            font-family: monospace;
            font-size: 0.85rem;
            white-space: pre-wrap;
        }}
        .remediation-box {{
            background: #064e3b33;
            border-left: 4px solid #10b981;
            padding: 0.75rem;
            border-radius: 4px;
            margin-top: 0.5rem;
            font-size: 0.9rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 2rem;
            font-size: 0.9rem;
        }}
        th, td {{
            padding: 0.85rem 1rem;
            text-align: left;
            border-bottom: 1px solid #334155;
        }}
        th {{
            background: #1e293b;
            color: var(--accent);
            text-transform: uppercase;
            font-size: 0.8rem;
            letter-spacing: 0.05em;
        }}
        tr:hover td {{
            background: var(--surface-hover);
        }}
        code {{
            background: #0b1120;
            color: #38bdf8;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.85rem;
        }}
        footer {{
            text-align: center;
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid #334155;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .header, .stat-card, .finding-card, table {{ background: #fff; border-color: #ccc; color: #000; }}
            .score-box {{ border-color: #000; }}
            code, pre {{ background: #eee; color: #000; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-title">
                <h1>🛡️ Web Security Audit Report</h1>
                <p>Target: <strong>{r.target_url}</strong> &bull; Scanned: {r.timestamp}</p>
                <p>Status: <strong>HTTP {r.status_code}</strong> &bull; Latency: <strong>{r.response_time_ms:.1f}ms</strong> &bull; Server: <strong>{r.server_banner or 'Hidden'}</strong></p>
            </div>
            <div class="score-box">
                <div class="score-grade">{r.grade.value}</div>
                <div class="score-num">{r.score} / 100 Score</div>
            </div>
        </header>

        <section class="stats-grid">
            <div class="stat-card">
                <div class="label">Critical Findings</div>
                <div class="val" style="color: var(--critical);">{crit_count}</div>
            </div>
            <div class="stat-card">
                <div class="label">High Risk</div>
                <div class="val" style="color: var(--high);">{high_count}</div>
            </div>
            <div class="stat-card">
                <div class="label">Medium Risk</div>
                <div class="val" style="color: var(--medium);">{med_count}</div>
            </div>
            <div class="stat-card">
                <div class="label">Low / Informational</div>
                <div class="val" style="color: var(--low);">{low_count}</div>
            </div>
        </section>

        <section>
            <h2 class="section-title">🚨 Identified Vulnerabilities & Misconfigurations ({len(r.findings)})</h2>
            {findings_html if findings_html else '<p style="color: var(--pass);">✅ Excellent! No high or critical security misconfigurations identified.</p>'}
        </section>

        <section>
            <h2 class="section-title">📋 HTTP Security Headers Audit</h2>
            <table>
                <thead>
                    <tr>
                        <th>Header</th>
                        <th>Status</th>
                        <th>Analysis</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {headers_rows}
                </tbody>
            </table>
        </section>

        <section>
            <h2 class="section-title">🌐 CORS (Cross-Origin Resource Sharing) Matrix</h2>
            <table>
                <thead>
                    <tr>
                        <th>Test Probe</th>
                        <th>Sent Origin</th>
                        <th>ACAO Response</th>
                        <th>Credentials (ACAC)</th>
                        <th>Status</th>
                        <th>Analysis</th>
                    </tr>
                </thead>
                <tbody>
                    {cors_rows}
                </tbody>
            </table>
        </section>

        <footer>
            <p>Generated by <strong>CyberSecurity Bootcamp Automated Web Scanner</strong> &bull; OWASP Top 10 Aligned &bull; RFC 6454 CORS Compliant</p>
        </footer>
    </div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
