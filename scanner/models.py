"""
Data models and enumeration definitions for the Web Security Scanner.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Optional, Any


class Severity(str, Enum):
    """Vulnerability severity levels aligned with CVSS v3.1 and OWASP standards."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        """Terminal / Rich color code."""
        colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "INFO": "cyan",
        }
        return colors.get(self.value, "white")

    @property
    def hex_color(self) -> str:
        """Hex color for HTML reports."""
        colors = {
            "CRITICAL": "#e53e3e",
            "HIGH": "#dd6b20",
            "MEDIUM": "#d69e2e",
            "LOW": "#3182ce",
            "INFO": "#319795",
        }
        return colors.get(self.value, "#718096")

    @property
    def weight(self) -> int:
        """Penalty points for scoring deduction."""
        weights = {
            "CRITICAL": 35,
            "HIGH": 20,
            "MEDIUM": 10,
            "LOW": 5,
            "INFO": 0,
        }
        return weights.get(self.value, 0)


class Grade(str, Enum):
    """Overall security posture letter grade."""
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"

    @property
    def hex_color(self) -> str:
        colors = {
            "A+": "#38a169",
            "A": "#48bb78",
            "B": "#3182ce",
            "C": "#d69e2e",
            "D": "#dd6b20",
            "F": "#e53e3e",
        }
        return colors.get(self.value, "#718096")


@dataclass
class Finding:
    """Security finding detected during audit."""
    id: str
    title: str
    category: str
    severity: Severity
    description: str
    evidence: str
    impact: str
    remediation: str
    owasp_category: str = "A05:2021-Security Misconfiguration"
    cwe_id: str = "CWE-16"
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class HeaderAuditItem:
    """Audit status of a specific HTTP response header."""
    name: str
    present: bool
    value: Optional[str]
    status: str  # PASS, WARN, FAIL, INFO
    details: str
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorsTestProbe:
    """Result of an individual CORS active probe test."""
    name: str
    probe_origin: str
    status_code: int
    acao_received: Optional[str]
    acac_received: Optional[str]
    acam_received: Optional[str]
    acah_received: Optional[str]
    vulnerable: bool
    severity: Severity
    details: str
    test_type: str = "GET"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class ScanResult:
    """Comprehensive aggregated result of a target security scan."""
    target_url: str
    timestamp: str
    ip_address: Optional[str]
    status_code: int
    response_time_ms: float
    server_banner: Optional[str]
    score: int
    grade: Grade
    findings: List[Finding] = field(default_factory=list)
    headers_audit: List[HeaderAuditItem] = field(default_factory=list)
    cors_probes: List[CorsTestProbe] = field(default_factory=list)
    raw_headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "timestamp": self.timestamp,
            "ip_address": self.ip_address,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "server_banner": self.server_banner,
            "score": self.score,
            "grade": self.grade.value,
            "summary": {
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            },
            "findings": [f.to_dict() for f in self.findings],
            "headers_audit": [h.to_dict() for h in self.headers_audit],
            "cors_probes": [c.to_dict() for c in self.cors_probes],
            "raw_headers": self.raw_headers,
            "metadata": self.metadata,
        }
