"""
Unit tests for CORS (Cross-Origin Resource Sharing) Auditor.
"""

from unittest.mock import MagicMock
import pytest
import requests
from scanner.cors_auditor import CorsAuditor
from scanner.models import Severity


class MockResponse:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


def test_cors_origin_reflection_with_credentials():
    """Ensure arbitrary origin reflection with ACAC: true triggers a CRITICAL finding."""
    session = MagicMock()
    # Mock GET response that reflects the request origin and sends credentials true
    def mock_get(url, headers=None, **kwargs):
        req_origin = (headers or {}).get("Origin", "")
        return MockResponse(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": req_origin,
                "Access-Control-Allow-Credentials": "true"
            }
        )
    session.get.side_effect = mock_get
    session.options.return_value = MockResponse(status_code=200)

    auditor = CorsAuditor(session=session)
    probes, findings = auditor.audit("https://target.com/api")

    crit_finding = next((f for f in findings if f.severity == Severity.CRITICAL), None)
    assert crit_finding is not None
    assert "Reflected Origin with Credentials" in crit_finding.title
    assert crit_finding.owasp_category == "A01:2021-Broken Access Control"


def test_cors_null_origin_trust():
    """Ensure trusting 'Origin: null' generates a HIGH or CRITICAL finding."""
    session = MagicMock()
    def mock_get(url, headers=None, **kwargs):
        req_origin = (headers or {}).get("Origin", "")
        if req_origin == "null":
            return MockResponse(
                status_code=200,
                headers={"Access-Control-Allow-Origin": "null"}
            )
        return MockResponse(status_code=200, headers={})
    
    session.get.side_effect = mock_get
    session.options.return_value = MockResponse(status_code=200)

    auditor = CorsAuditor(session=session)
    probes, findings = auditor.audit("https://target.com/api")

    null_finding = next((f for f in findings if "null" in f.title.lower() or "CORS-NULL" in f.id), None)
    assert null_finding is not None
    assert null_finding.severity in (Severity.HIGH, Severity.MEDIUM)


def test_cors_safe_whitelist():
    """Ensure properly whitelisted origins with no arbitrary reflection produce no CORS findings."""
    session = MagicMock()
    # Server strictly returns fixed company domain or no ACAO
    session.get.return_value = MockResponse(
        status_code=200,
        headers={"Access-Control-Allow-Origin": "https://trusted-portal.target.com"}
    )
    session.options.return_value = MockResponse(status_code=200)

    auditor = CorsAuditor(session=session)
    probes, findings = auditor.audit("https://target.com/api")

    assert len(findings) == 0
    assert not any(p.vulnerable for p in probes)
