"""
Unit tests for CLI Argument Parser and Report Output Generation.
"""

import os
import tempfile
from scanner.cli import create_parser
from scanner.models import ScanResult, Grade, Finding, Severity, HeaderAuditItem, CorsTestProbe
from scanner.reporter import ReportGenerator


def test_cli_parser_defaults():
    """Ensure parser sets expected default flags."""
    parser = create_parser()
    args = parser.parse_args(["scan", "https://example.com"])
    assert args.command == "scan"
    assert args.url == "https://example.com"
    assert args.timeout == 10
    assert not args.insecure


def test_cli_parser_custom_options():
    """Ensure custom options are correctly parsed."""
    parser = create_parser()
    args = parser.parse_args([
        "scan", "https://api.domain.local",
        "--timeout", "15",
        "--insecure",
        "--html", "audit.html",
        "--fail-on", "HIGH"
    ])
    assert args.timeout == 15
    assert args.insecure is True
    assert args.html == "audit.html"
    assert args.fail_on == "HIGH"


def test_reporter_generation():
    """Ensure JSON, Markdown, and HTML report files are created successfully."""
    dummy_result = ScanResult(
        target_url="https://testbed.local",
        timestamp="2026-10-20 12:00:00 UTC",
        ip_address="127.0.0.1",
        status_code=200,
        response_time_ms=45.2,
        server_banner="nginx/1.20",
        score=85,
        grade=Grade.A,
        findings=[
            Finding(
                id="HDR-XCTO-01",
                title="Missing X-Content-Type-Options",
                category="Security Headers",
                severity=Severity.LOW,
                description="Nosniff is missing",
                evidence="Header not found",
                impact="MIME sniffing",
                remediation="Add nosniff"
            )
        ],
        headers_audit=[
            HeaderAuditItem(name="X-Content-Type-Options", present=False, value=None, status="FAIL", details="Missing")
        ],
        cors_probes=[
            CorsTestProbe(
                name="Arbitrary Reflection",
                probe_origin="https://evil.com",
                status_code=200,
                acao_received=None,
                acac_received=None,
                acam_received=None,
                acah_received=None,
                vulnerable=False,
                severity=Severity.INFO,
                details="Safe"
            )
        ],
        raw_headers={"Server": "nginx/1.20"}
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = os.path.join(tmpdir, "report.json")
        html_path = os.path.join(tmpdir, "report.html")
        md_path = os.path.join(tmpdir, "report.md")

        reporter = ReportGenerator(dummy_result)
        reporter.save_json(json_path)
        reporter.save_html(html_path)
        reporter.save_markdown(md_path)

        assert os.path.exists(json_path)
        assert os.path.exists(html_path)
        assert os.path.exists(md_path)

        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()
            assert "https://testbed.local" in content
            assert "Missing X-Content-Type-Options" in content
            assert "score-grade" in content
