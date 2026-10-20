"""
Core Scanner Orchestrator.
Manages network sessions, runs headers & CORS auditors, aggregates findings,
and computes final security scores.
"""

from datetime import datetime, timezone
import socket
import time
from typing import List, Optional
from urllib.parse import urlparse
import requests
import urllib3

# Suppress insecure HTTPS warnings if user explicitly disables verification
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .models import ScanResult, Severity, Grade
from .headers_auditor import HeadersAuditor
from .cors_auditor import CorsAuditor
from .grading import GradingEngine


class WebSecurityScanner:
    """
    Main scanner engine that coordinates HTTP requests, header security analysis,
    and active CORS vulnerability probing.
    """

    def __init__(
        self,
        timeout: int = 10,
        verify_ssl: bool = True,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        custom_headers: Optional[dict] = None
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or "WebSec-Bootcamp-Scanner/1.0 (Cybersecurity Research)"
        self.proxy = proxy
        self.custom_headers = custom_headers or {}

        # Configure requests session
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        if self.custom_headers:
            self.session.headers.update(self.custom_headers)

        if self.proxy:
            self.session.proxies = {
                "http": self.proxy,
                "https": self.proxy,
            }

        # Sub-auditors
        self.headers_auditor = HeadersAuditor()
        self.cors_auditor = CorsAuditor(
            session=self.session,
            timeout=self.timeout,
            verify_ssl=self.verify_ssl
        )

    def scan(self, url: str) -> ScanResult:
        """
        Execute comprehensive security audit against a target URL.
        """
        # Ensure scheme is specified
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"

        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0]

        # DNS resolution to get target IP
        ip_address = None
        try:
            ip_address = socket.gethostbyname(hostname)
        except (socket.gaierror, socket.herror):
            pass

        start_time = time.time()

        # Step 1: Base HTTP request
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            response_time_ms = (time.time() - start_time) * 1000
            status_code = resp.status_code
            raw_headers = dict(resp.headers)
        except requests.RequestException as e:
            # If target unreachable, return minimal failure result
            return ScanResult(
                target_url=url,
                timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                ip_address=ip_address,
                status_code=0,
                response_time_ms=0.0,
                server_banner=None,
                score=0,
                grade=Grade.F,
                findings=[],
                headers_audit=[],
                cors_probes=[],
                raw_headers={},
                metadata={"error": f"Connection failed: {str(e)}"}
            )

        server_banner = raw_headers.get("Server") or raw_headers.get("server")

        # Step 2: Audit Security Headers
        headers_items, headers_findings = self.headers_auditor.audit(url, raw_headers)

        # Step 3: Audit CORS Misconfigurations
        cors_probes, cors_findings = self.cors_auditor.audit(url)

        # Step 4: Aggregate findings & Compute Score
        all_findings = headers_findings + cors_findings
        score, grade = GradingEngine.calculate_score_and_grade(all_findings)

        return ScanResult(
            target_url=url,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            ip_address=ip_address,
            status_code=status_code,
            response_time_ms=response_time_ms,
            server_banner=server_banner,
            score=score,
            grade=grade,
            findings=all_findings,
            headers_audit=headers_items,
            cors_probes=cors_probes,
            raw_headers=raw_headers,
            metadata={
                "redirect_history": [r.url for r in resp.history],
                "final_url": resp.url,
            }
        )

    def scan_batch(self, urls: List[str]) -> List[ScanResult]:
        """Scan a list of URLs sequentially and return results."""
        results = []
        for u in urls:
            u_clean = u.strip()
            if u_clean and not u_clean.startswith("#"):
                results.append(self.scan(u_clean))
        return results
