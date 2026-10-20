"""
CORS (Cross-Origin Resource Sharing) Vulnerability Auditor.
Tests for origin reflection, credential exposure, null origin bypass,
regex prefix/suffix flaws, and insecure preflight configurations.
"""

from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests
from .models import Finding, CorsTestProbe, Severity


class CorsAuditor:
    """
    Active probe auditor for detecting CORS (Cross-Origin Resource Sharing) vulnerabilities.
    Based on RFC 6454, W3C CORS recommendations, and OWASP testing guides.
    """

    def __init__(self, session: Optional[requests.Session] = None, timeout: int = 10, verify_ssl: bool = True):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def audit(self, url: str) -> Tuple[List[CorsTestProbe], List[Finding]]:
        """
        Execute active CORS security probes against target URL.
        Returns:
            Tuple of (List of CorsTestProbe, List of Finding)
        """
        parsed = urlparse(url)
        target_scheme = parsed.scheme or "http"
        target_host = parsed.netloc.split(":")[0]  # strip port if present

        probes: List[CorsTestProbe] = []
        findings: List[Finding] = []

        # Generate test probe origins
        probe_definitions = [
            {
                "name": "Arbitrary Third-Party Origin Reflection",
                "origin": "https://evil-attacker.com",
                "type": "reflection",
                "description": "Tests if server reflects an arbitrary untrusted domain in Access-Control-Allow-Origin."
            },
            {
                "name": "Null Origin Trust (Sandboxed iframe / data: URI)",
                "origin": "null",
                "type": "null_origin",
                "description": "Tests if server accepts 'Origin: null', exploitable via sandboxed iframes."
            },
            {
                "name": "Regex Suffix Bypass (Attacker domain as suffix)",
                "origin": f"{target_scheme}://{target_host}.attacker.com",
                "type": "suffix_bypass",
                "description": "Tests for weak regex anchor ($) matching domain as subdomain of attacker."
            },
            {
                "name": "Regex Prefix Bypass (Prepend attacker name)",
                "origin": f"{target_scheme}://attacker-{target_host}",
                "type": "prefix_bypass",
                "description": "Tests for weak regex anchor (^) allowing prefixed attacker domain."
            },
            {
                "name": "HTTP Scheme Downgrade on HTTPS Target",
                "origin": f"http://{target_host}",
                "type": "scheme_downgrade",
                "description": "Tests if secure HTTPS endpoint trusts unencrypted HTTP origin (MITM risk)."
            } if target_scheme == "https" else None,
        ]
        # Filter None
        probe_definitions = [p for p in probe_definitions if p is not None]

        # 1. Run GET Probes with custom Origins
        for pdef in probe_definitions:
            probe, finding = self._test_origin_probe(url, pdef["name"], pdef["origin"], pdef["type"])
            probes.append(probe)
            if finding:
                findings.append(finding)

        # 2. Test Preflight OPTIONS Request
        options_probe, options_finding = self._test_preflight_options(url, target_host)
        if options_probe:
            probes.append(options_probe)
        if options_finding:
            findings.append(options_finding)

        # 3. Test Baseline Wildcard
        wildcard_finding = self._check_wildcard_policy(probes, url)
        if wildcard_finding:
            findings.append(wildcard_finding)

        return probes, findings

    def _test_origin_probe(self, url: str, test_name: str, test_origin: str, probe_type: str) -> Tuple[CorsTestProbe, Optional[Finding]]:
        """Send a GET request with a specific Origin header and analyze response."""
        headers = {
            "Origin": test_origin,
            "User-Agent": "CyberSecurity-Bootcamp-WebSec-Scanner/1.0"
        }

        try:
            resp = self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            resp_headers = {k.lower(): v.strip() for k, v in resp.headers.items()}
            acao = resp_headers.get("access-control-allow-origin")
            acac = resp_headers.get("access-control-allow-credentials")

            # Check vulnerability condition
            is_vulnerable = False
            finding = None
            severity = Severity.INFO
            details = "No CORS headers returned or origin rejected."

            if acao:
                has_creds = acac and acac.lower() == "true"
                reflects_origin = (acao == test_origin) or (test_origin == "null" and acao == "null")

                if reflects_origin and has_creds:
                    # CRITICAL: Origin reflection WITH credentials
                    is_vulnerable = True
                    severity = Severity.CRITICAL
                    details = f"VULNERABLE: Reflects '{acao}' WITH credentials enabled (ACAC: true)!"

                    finding = Finding(
                        id=f"CORS-CRIT-{probe_type.upper()}",
                        title=f"Critical CORS Vulnerability: Reflected Origin with Credentials ({test_name})",
                        category="CORS Misconfiguration",
                        severity=Severity.CRITICAL,
                        description=(
                            f"The endpoint dynamically reflects the provided Origin header '{test_origin}' "
                            f"in 'Access-Control-Allow-Origin' AND explicitly enables 'Access-Control-Allow-Credentials: true'. "
                            "This effectively disables the browser Same-Origin Policy (SOP)."
                        ),
                        evidence=(
                            f"Request Origin: {test_origin}\n"
                            f"Response Access-Control-Allow-Origin: {acao}\n"
                            f"Response Access-Control-Allow-Credentials: {acac}"
                        ),
                        impact=(
                            "An attacker hosting malicious JavaScript on an external site can make authenticated "
                            "XMLHttpRequest / Fetch requests to this endpoint using the victim's session cookies "
                            "or HTTP auth headers, and read sensitive confidential responses."
                        ),
                        remediation=(
                            "Do NOT dynamically reflect the Origin header. Maintain a strict server-side whitelist "
                            "of authorized domains. Never set Access-Control-Allow-Credentials: true unless "
                            "the origin is strictly verified."
                        ),
                        owasp_category="A01:2021-Broken Access Control",
                        cwe_id="CWE-942",
                        references=[
                            "https://portswigger.net/web-security/cors",
                            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html"
                        ]
                    )

                elif reflects_origin and not has_creds:
                    # HIGH or MEDIUM: Origin reflection without credentials
                    is_vulnerable = True
                    severity = Severity.HIGH if probe_type in ("null_origin", "suffix_bypass", "prefix_bypass") else Severity.MEDIUM
                    details = f"VULNERABLE: Arbitrarily reflects '{acao}' (without credentials)."

                    finding = Finding(
                        id=f"CORS-REFL-{probe_type.upper()}",
                        title=f"Insecure CORS Origin Reflection: {test_name}",
                        category="CORS Misconfiguration",
                        severity=severity,
                        description=(
                            f"The server reflects the untrusted request Origin '{test_origin}' in "
                            f"'Access-Control-Allow-Origin: {acao}'."
                        ),
                        evidence=f"Request Origin: {test_origin} -> Response ACAO: {acao}",
                        impact=(
                            "Allows cross-origin websites to read unauthenticated endpoint data or sensitive API responses."
                        ),
                        remediation="Validate Origin against a strict whitelist of known legitimate origins before issuing ACAO.",
                        owasp_category="A01:2021-Broken Access Control",
                        cwe_id="CWE-942",
                        references=["https://portswigger.net/web-security/cors"]
                    )

                elif acao == "*":
                    details = f"Wildcard origin allowed: Access-Control-Allow-Origin: *"
                    is_vulnerable = False  # Evaluated separately for credentials or sensitive context

                elif test_origin == "null" and acao == "null":
                    is_vulnerable = True
                    severity = Severity.HIGH
                    details = "VULNERABLE: Server explicitly trusts 'null' origin."
                    finding = Finding(
                        id="CORS-NULL-01",
                        title="Insecure CORS Policy: Trust of 'null' Origin",
                        category="CORS Misconfiguration",
                        severity=Severity.HIGH,
                        description=(
                            "The server responds with 'Access-Control-Allow-Origin: null'. "
                            "Browsers emit an Origin of 'null' for sandboxed iframes and data: URIs."
                        ),
                        evidence="Request Origin: null -> Response Access-Control-Allow-Origin: null",
                        impact=(
                            "An attacker can deliver an exploit payload inside a sandboxed iframe (<iframe sandbox='allow-scripts'>) "
                            "or data URI from any domain to read responses."
                        ),
                        remediation="Do not trust 'null' as an allowed origin. Reject or omit ACAO for null origins.",
                        owasp_category="A01:2021-Broken Access Control",
                        cwe_id="CWE-942",
                        references=["https://portswigger.net/web-security/cors#null-origin"]
                    )
                else:
                    details = f"Origin evaluated: ACAO returned '{acao}'."

            probe = CorsTestProbe(
                name=test_name,
                probe_origin=test_origin,
                status_code=resp.status_code,
                acao_received=acao,
                acac_received=acac,
                acam_received=resp_headers.get("access-control-allow-methods"),
                acah_received=resp_headers.get("access-control-allow-headers"),
                vulnerable=is_vulnerable,
                severity=severity,
                details=details,
                test_type="GET"
            )
            return probe, finding

        except requests.RequestException as e:
            probe = CorsTestProbe(
                name=test_name,
                probe_origin=test_origin,
                status_code=0,
                acao_received=None,
                acac_received=None,
                acam_received=None,
                acah_received=None,
                vulnerable=False,
                severity=Severity.INFO,
                details=f"Network error during probe: {str(e)}",
                test_type="GET"
            )
            return probe, None

    def _test_preflight_options(self, url: str, target_host: str) -> Tuple[Optional[CorsTestProbe], Optional[Finding]]:
        """Send a preflight OPTIONS request to inspect ACAM, ACAH, and ACMA."""
        headers = {
            "Origin": "https://evil-attacker.com",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "X-Custom-Auth, Authorization, Content-Type",
            "User-Agent": "CyberSecurity-Bootcamp-WebSec-Scanner/1.0"
        }

        try:
            resp = self.session.options(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            resp_headers = {k.lower(): v.strip() for k, v in resp.headers.items()}
            acao = resp_headers.get("access-control-allow-origin")
            acac = resp_headers.get("access-control-allow-credentials")
            acam = resp_headers.get("access-control-allow-methods")
            acah = resp_headers.get("access-control-allow-headers")
            max_age = resp_headers.get("access-control-max-age")

            if not any([acao, acam, acah]):
                return None, None

            vulnerable = False
            finding = None
            details_list = []

            if acao == "https://evil-attacker.com":
                vulnerable = True
                details_list.append("Preflight reflects attacker origin")

            if acam and any(m in acam.upper() for m in ["DELETE", "PUT", "*"]):
                details_list.append(f"Permissive preflight methods ({acam})")

            if max_age:
                try:
                    age_val = int(max_age)
                    if age_val > 86400:
                        details_list.append(f"Excessive preflight cache max-age: {age_val}s")
                except ValueError:
                    pass

            probe = CorsTestProbe(
                name="Preflight OPTIONS Inspection",
                probe_origin="https://evil-attacker.com",
                status_code=resp.status_code,
                acao_received=acao,
                acac_received=acac,
                acam_received=acam,
                acah_received=acah,
                vulnerable=vulnerable,
                severity=Severity.MEDIUM if vulnerable else Severity.INFO,
                details=" | ".join(details_list) if details_list else f"Preflight responded ({resp.status_code})",
                test_type="OPTIONS"
            )
            return probe, finding

        except requests.RequestException:
            return None, None

    def _check_wildcard_policy(self, probes: List[CorsTestProbe], url: str) -> Optional[Finding]:
        """Check if any probe returned wildcard ACAO with credentials or on API endpoint."""
        for p in probes:
            if p.acao_received == "*":
                if p.acac_received and p.acac_received.lower() == "true":
                    return Finding(
                        id="CORS-WILD-CREDS",
                        title="Invalid/Dangerous CORS Wildcard with Credentials",
                        category="CORS Misconfiguration",
                        severity=Severity.HIGH,
                        description="Access-Control-Allow-Origin is set to '*' with Access-Control-Allow-Credentials: true.",
                        evidence="Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                        impact="While modern browsers block this combination, older clients or custom clients may expose credentials.",
                        remediation="Do not combine wildcard '*' with credentials. Specify exact whitelist origin.",
                        owasp_category="A01:2021-Broken Access Control",
                        cwe_id="CWE-942",
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials"]
                    )
        return None
