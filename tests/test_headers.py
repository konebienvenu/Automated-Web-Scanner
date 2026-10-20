"""
Unit tests for HTTP Security Headers Auditor.
"""

import pytest
from scanner.headers_auditor import HeadersAuditor
from scanner.models import Severity


@pytest.fixture
def auditor():
    return HeadersAuditor()


def test_missing_hsts_on_https(auditor):
    """Ensure missing HSTS on an HTTPS target generates a HIGH finding."""
    url = "https://example.com"
    headers = {"Content-Type": "text/html"}
    items, findings = auditor.audit(url, headers)

    hsts_finding = next((f for f in findings if f.id == "HDR-HSTS-01"), None)
    assert hsts_finding is not None
    assert hsts_finding.severity == Severity.HIGH
    assert "Strict Transport Security" in hsts_finding.title or "HSTS" in hsts_finding.title


def test_valid_hsts(auditor):
    """Ensure valid HSTS passes with max-age >= 31536000 and includeSubDomains."""
    url = "https://example.com"
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
    }
    items, findings = auditor.audit(url, headers)
    hsts_finding = next((f for f in findings if "HSTS" in f.id), None)
    assert hsts_finding is None

    hsts_item = next(i for i in items if i.name == "Strict-Transport-Security")
    assert hsts_item.status == "PASS"


def test_low_max_age_hsts(auditor):
    """Ensure low max-age (< 1 year) generates a LOW warning finding."""
    url = "https://example.com"
    headers = {
        "Strict-Transport-Security": "max-age=86400"
    }
    items, findings = auditor.audit(url, headers)
    hsts_finding = next((f for f in findings if f.id == "HDR-HSTS-02"), None)
    assert hsts_finding is not None
    assert hsts_finding.severity == Severity.LOW


def test_missing_csp(auditor):
    """Ensure missing Content-Security-Policy generates a HIGH finding."""
    url = "https://example.com"
    headers = {}
    items, findings = auditor.audit(url, headers)

    csp_finding = next((f for f in findings if f.id == "HDR-CSP-01"), None)
    assert csp_finding is not None
    assert csp_finding.severity == Severity.HIGH


def test_csp_with_unsafe_inline_and_eval(auditor):
    """Ensure unsafe-inline and unsafe-eval directives are flagged as MEDIUM findings."""
    url = "https://example.com"
    headers = {
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval';"
    }
    items, findings = auditor.audit(url, headers)

    inline_finding = next((f for f in findings if f.id == "HDR-CSP-02"), None)
    eval_finding = next((f for f in findings if f.id == "HDR-CSP-03"), None)
    assert inline_finding is not None
    assert eval_finding is not None
    assert inline_finding.severity == Severity.MEDIUM
    assert eval_finding.severity == Severity.MEDIUM


def test_missing_clickjacking_protection(auditor):
    """Ensure missing X-Frame-Options and frame-ancestors flags a MEDIUM finding."""
    url = "https://example.com"
    headers = {}
    items, findings = auditor.audit(url, headers)

    xfo_finding = next((f for f in findings if f.id == "HDR-XFO-01"), None)
    assert xfo_finding is not None
    assert xfo_finding.severity == Severity.MEDIUM


def test_server_banner_leakage(auditor):
    """Ensure technology headers like Server and X-Powered-By are flagged."""
    url = "https://example.com"
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3"
    }
    items, findings = auditor.audit(url, headers)

    leak_findings = [f for f in findings if "LEAK" in f.id]
    assert len(leak_findings) >= 2
    assert any("Apache" in f.evidence for f in leak_findings)
