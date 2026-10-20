"""
Unit tests for Scoring and Grading Engine.
"""

from scanner.grading import GradingEngine
from scanner.models import Finding, Grade, Severity


def test_perfect_score():
    """Ensure zero findings result in a 100 score and Grade A+."""
    score, grade = GradingEngine.calculate_score_and_grade([])
    assert score == 100
    assert grade == Grade.A_PLUS


def test_critical_finding_caps_grade():
    """Ensure any critical finding drops grade to F or D regardless of remaining score."""
    finding = Finding(
        id="CORS-CRIT",
        title="Critical CORS Exploit",
        category="CORS",
        severity=Severity.CRITICAL,
        description="Test",
        evidence="Test",
        impact="Test",
        remediation="Test"
    )
    score, grade = GradingEngine.calculate_score_and_grade([finding])
    assert score == 65
    assert grade in (Grade.D, Grade.F)


def test_multiple_high_findings():
    """Ensure multiple high findings progressively decrease score and grade."""
    f1 = Finding(id="H1", title="H1", category="H", severity=Severity.HIGH, description="", evidence="", impact="", remediation="")
    f2 = Finding(id="H2", title="H2", category="H", severity=Severity.HIGH, description="", evidence="", impact="", remediation="")
    f3 = Finding(id="H3", title="H3", category="H", severity=Severity.HIGH, description="", evidence="", impact="", remediation="")

    score, grade = GradingEngine.calculate_score_and_grade([f1, f2, f3])
    # 100 - (3 * 20) = 40
    assert score == 40
    assert grade == Grade.D
