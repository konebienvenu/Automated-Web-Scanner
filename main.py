#!/usr/bin/env python3
"""
CyberSecurity Bootcamp Capstone Project
Automated Web Scanner: Audits websites for secure HTTP headers and CORS misconfigurations.

Usage:
    python main.py scan https://example.com --html report.html
    python main.py demo-server --port 8888
    python main.py batch targets.txt
"""

import sys
from scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
