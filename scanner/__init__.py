"""
CyberSecurity Bootcamp Capstone Project
Automated Web Scanner: Audit sites for secure headers and CORS flaws.
"""

__version__ = "1.0.0"
__author__ = "CyberSecurity Bootcamp Graduate"
__license__ = "MIT"

from .core import WebSecurityScanner
from .models import Finding, Severity, Grade, ScanResult

__all__ = ["WebSecurityScanner", "Finding", "Severity", "Grade", "ScanResult"]
