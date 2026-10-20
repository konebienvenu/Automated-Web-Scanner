"""
Security Scoring and Grading Engine.
Computes numeric posture score (0-100) and letter grades (A+ to F)
based on vulnerability severity deductions and security controls.
"""

from typing import List, Tuple
from .models import Finding, Grade, Severity


class GradingEngine:
    """
    Evaluates scan findings and calculates security score and grade.
    """

    @staticmethod
    def calculate_score_and_grade(findings: List[Finding]) -> Tuple[int, Grade]:
        """
        Calculate security posture score from 0 to 100 and assign grade.
        
        Rules:
        - Base score: 100 points
        - CRITICAL finding: -35 points (caps maximum grade to F or D)
        - HIGH finding: -20 points
        - MEDIUM finding: -10 points
        - LOW finding: -5 points
        - INFO finding: 0 points
        """
        total_deduction = 0
        has_critical = False
        has_high = False

        for f in findings:
            total_deduction += f.severity.weight
            if f.severity == Severity.CRITICAL:
                has_critical = True
            elif f.severity == Severity.HIGH:
                has_high = True

        score = max(0, 100 - total_deduction)

        # Grade determination
        if has_critical:
            # Any critical vulnerability immediately drops site to F or D
            grade = Grade.F if score < 45 else Grade.D
        elif score >= 95 and not has_high:
            grade = Grade.A_PLUS
        elif score >= 85 and not has_high:
            grade = Grade.A
        elif score >= 70:
            grade = Grade.B
        elif score >= 55:
            grade = Grade.C
        elif score >= 40:
            grade = Grade.D
        else:
            grade = Grade.F

        return score, grade

    @staticmethod
    def get_risk_label(score: int, grade: Grade) -> str:
        """Return human-readable risk classification."""
        if grade in (Grade.A_PLUS, Grade.A):
            return "EXCELLENT / MINIMAL RISK"
        elif grade == Grade.B:
            return "MODERATE / LOW RISK"
        elif grade == Grade.C:
            return "ELEVATED / MEDIUM RISK"
        elif grade == Grade.D:
            return "HIGH RISK"
        else:
            return "CRITICAL RISK / ACTION REQUIRED"
