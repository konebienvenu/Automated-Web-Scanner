"""
Security Headers Auditor Module.
Audits HTTP response headers based on OWASP Secure Headers Project best practices.
"""

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse
from .models import Finding, HeaderAuditItem, Severity


class HeadersAuditor:
    """
    Analyzes HTTP response headers for missing defenses and information leakage.
    Implements OWASP Secure Headers Best Practices.
    """

    def __init__(self):
        # Canonical lowercase lookup mapping
        self.sensitive_leakage_headers = [
            ("server", "Server Software & Version", Severity.LOW),
            ("x-powered-by", "Application Technology / Framework", Severity.LOW),
            ("x-aspnet-version", "ASP.NET Version", Severity.LOW),
            ("x-aspnetmvc-version", "ASP.NET MVC Version", Severity.LOW),
            ("x-runtime", "Application Execution Runtime", Severity.LOW),
            ("x-version", "Internal Application Version", Severity.LOW),
            ("x-generator", "Content Management System (CMS)", Severity.LOW),
            ("via", "Intermediate Proxy / Gateway Information", Severity.INFO),
        ]

    def audit(self, url: str, headers: Dict[str, str]) -> Tuple[List[HeaderAuditItem], List[Finding]]:
        """
        Run all header audits against target URL and raw response headers.
        Returns:
            Tuple of (List of HeaderAuditItem for table view, List of Finding for security reports)
        """
        # Normalize header keys to lowercase for case-insensitive matching
        norm_headers = {k.lower(): v.strip() for k, v in headers.items()}
        is_https = url.lower().startswith("https://")

        audit_items: List[HeaderAuditItem] = []
        findings: List[Finding] = []

        # 1. Strict-Transport-Security (HSTS)
        hsts_item, hsts_findings = self._audit_hsts(norm_headers, is_https)
        audit_items.append(hsts_item)
        findings.extend(hsts_findings)

        # 2. Content-Security-Policy (CSP)
        csp_item, csp_findings = self._audit_csp(norm_headers)
        audit_items.append(csp_item)
        findings.extend(csp_findings)

        # 3. X-Frame-Options
        xfo_item, xfo_findings = self._audit_x_frame_options(norm_headers)
        audit_items.append(xfo_item)
        findings.extend(xfo_findings)

        # 4. X-Content-Type-Options
        xcto_item, xcto_findings = self._audit_x_content_type_options(norm_headers)
        audit_items.append(xcto_item)
        findings.extend(xcto_findings)

        # 5. Referrer-Policy
        ref_item, ref_findings = self._audit_referrer_policy(norm_headers)
        audit_items.append(ref_item)
        findings.extend(ref_findings)

        # 6. Permissions-Policy
        perm_item, perm_findings = self._audit_permissions_policy(norm_headers)
        audit_items.append(perm_item)
        findings.extend(perm_findings)

        # 7. Cross-Origin-Opener-Policy (COOP) & Cross-Origin-Embedder-Policy (COEP)
        coop_item, coop_findings = self._audit_coop_coep(norm_headers)
        audit_items.append(coop_item)
        findings.extend(coop_findings)

        # 8. Information Leakage Headers
        leak_items, leak_findings = self._audit_information_leakage(norm_headers)
        audit_items.extend(leak_items)
        findings.extend(leak_findings)

        return audit_items, findings

    def _audit_hsts(self, headers: Dict[str, str], is_https: bool) -> Tuple[HeaderAuditItem, List[Finding]]:
        """Audit HTTP Strict Transport Security."""
        findings = []
        header_val = headers.get("strict-transport-security")

        if not is_https:
            return HeaderAuditItem(
                name="Strict-Transport-Security",
                present=False,
                value=None,
                status="INFO",
                details="Not applicable on plain HTTP endpoints. HSTS should be enforced once redirected to HTTPS.",
                recommendation="Enforce HTTPS redirect and configure Strict-Transport-Security."
            ), findings

        if not header_val:
            findings.append(Finding(
                id="HDR-HSTS-01",
                title="Missing HTTP Strict Transport Security (HSTS) Header",
                category="Security Headers",
                severity=Severity.HIGH,
                description=(
                    "The HTTP Strict-Transport-Security response header tells browsers that the site "
                    "should only be accessed using HTTPS, protecting against SSL-stripping and man-in-the-middle attacks."
                ),
                evidence="Header 'Strict-Transport-Security' was not returned by server.",
                impact="Attackers on the same network (e.g. public Wi-Fi) can downgrade connection to unencrypted HTTP.",
                remediation="Add header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-319",
                references=[
                    "https://owasp.org/www-project-secure-headers/#strict-transport-security",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                ]
            ))
            return HeaderAuditItem(
                name="Strict-Transport-Security",
                present=False,
                value=None,
                status="FAIL",
                details="HSTS header is missing on HTTPS endpoint.",
                recommendation="Set max-age >= 31536000 (1 year) with includeSubDomains."
            ), findings

        # Header is present; analyze directives
        max_age_match = re.search(r"max-age\s*=\s*(\d+)", header_val, re.IGNORECASE)
        max_age = int(max_age_match.group(1)) if max_age_match else 0
        has_subdomains = "includesubdomains" in header_val.lower()
        has_preload = "preload" in header_val.lower()

        if max_age < 31536000:
            findings.append(Finding(
                id="HDR-HSTS-02",
                title="Low HSTS max-age Duration",
                category="Security Headers",
                severity=Severity.LOW,
                description=f"HSTS max-age is set to {max_age} seconds, which is less than the recommended 1 year (31,536,000s).",
                evidence=f"Strict-Transport-Security: {header_val}",
                impact="Short HSTS cache duration allows a smaller window of cryptographic enforcement.",
                remediation="Increase max-age to at least 31536000 seconds (1 year).",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-319",
                references=["https://hstspreload.org/"]
            ))
            status = "WARN"
            details = f"Present with low max-age ({max_age}s)."
        elif not has_subdomains:
            status = "WARN"
            details = f"Present ({max_age}s) but lacks 'includeSubDomains'."
        else:
            status = "PASS"
            details = f"Configured properly (max-age={max_age}s" + (", preload" if has_preload else "") + ")."

        return HeaderAuditItem(
            name="Strict-Transport-Security",
            present=True,
            value=header_val,
            status=status,
            details=details,
            recommendation="Include 'includeSubDomains' and consider 'preload' submission."
        ), findings

    def _audit_csp(self, headers: Dict[str, str]) -> Tuple[HeaderAuditItem, List[Finding]]:
        """Audit Content Security Policy."""
        findings = []
        csp_val = headers.get("content-security-policy")

        if not csp_val:
            findings.append(Finding(
                id="HDR-CSP-01",
                title="Missing Content-Security-Policy (CSP) Header",
                category="Security Headers",
                severity=Severity.HIGH,
                description=(
                    "Content Security Policy (CSP) is an effective layer of defense against Cross-Site Scripting (XSS), "
                    "data injection, and unauthorized frame embedding."
                ),
                evidence="Header 'Content-Security-Policy' was not found in response.",
                impact="Leaves client vulnerable to Stored, Reflected, and DOM-based Cross-Site Scripting (XSS).",
                remediation="Define a restrictive CSP such as: default-src 'self'; script-src 'self'; object-src 'none';",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-79",
                references=[
                    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                    "https://csp-evaluator.withgoogle.com/"
                ]
            ))
            return HeaderAuditItem(
                name="Content-Security-Policy",
                present=False,
                value=None,
                status="FAIL",
                details="Missing. Target provides no CSP mitigation against Cross-Site Scripting.",
                recommendation="Implement a robust CSP policy restricting script and object sources."
            ), findings

        csp_lower = csp_val.lower()
        flaws = []

        if "'unsafe-inline'" in csp_lower:
            flaws.append("'unsafe-inline' detected in scripts/styles")
            findings.append(Finding(
                id="HDR-CSP-02",
                title="Insecure CSP Directive: 'unsafe-inline' Permitted",
                category="Security Headers",
                severity=Severity.MEDIUM,
                description=(
                    "Using 'unsafe-inline' disables CSP protection against inline script execution, "
                    "greatly reducing defense against Cross-Site Scripting (XSS)."
                ),
                evidence=f"CSP contains 'unsafe-inline': {csp_val[:120]}...",
                impact="Attackers can execute injected JavaScript payloads directly in page context.",
                remediation="Replace 'unsafe-inline' with cryptographic nonces (nonce-...) or SHA-256 hashes.",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-79",
                references=["https://content-security-policy.com/unsafe-inline/"]
            ))

        if "'unsafe-eval'" in csp_lower:
            flaws.append("'unsafe-eval' detected")
            findings.append(Finding(
                id="HDR-CSP-03",
                title="Insecure CSP Directive: 'unsafe-eval' Permitted",
                category="Security Headers",
                severity=Severity.MEDIUM,
                description="The 'unsafe-eval' directive allows dynamic code evaluation (eval, Function, setTimeout strings).",
                evidence=f"CSP contains 'unsafe-eval': {csp_val[:120]}...",
                impact="Allows code execution via dynamic string evaluation vectors.",
                remediation="Refactor code to avoid eval() and remove 'unsafe-eval' from script-src.",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-79",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"]
            ))

        if "object-src 'none'" not in csp_lower and "object-src" in csp_lower:
            flaws.append("object-src not locked to 'none'")

        status = "WARN" if flaws else "PASS"
        details = f"Configured ({', '.join(flaws)})" if flaws else "Properly defined with strict directives."

        return HeaderAuditItem(
            name="Content-Security-Policy",
            present=True,
            value=csp_val,
            status=status,
            details=details,
            recommendation="Enforce nonce-based CSP and disallow 'unsafe-inline' and 'unsafe-eval'."
        ), findings

    def _audit_x_frame_options(self, headers: Dict[str, str]) -> Tuple[HeaderAuditItem, List[Finding]]:
        """Audit Clickjacking defense via X-Frame-Options or CSP frame-ancestors."""
        findings = []
        xfo = headers.get("x-frame-options")
        csp = headers.get("content-security-policy", "").lower()
        has_frame_ancestors = "frame-ancestors" in csp

        if not xfo and not has_frame_ancestors:
            findings.append(Finding(
                id="HDR-XFO-01",
                title="Missing Clickjacking Defense (X-Frame-Options / frame-ancestors)",
                category="Security Headers",
                severity=Severity.MEDIUM,
                description="Neither X-Frame-Options nor CSP frame-ancestors is present to restrict iframe embedding.",
                evidence="Neither X-Frame-Options nor frame-ancestors found in response headers.",
                impact="Allows malicious sites to embed target inside hidden iframes to conduct Clickjacking attacks.",
                remediation="Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP 'frame-ancestors' directive.",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-1021",
                references=[
                    "https://owasp.org/www-community/attacks/Clickjacking",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                ]
            ))
            return HeaderAuditItem(
                name="X-Frame-Options",
                present=False,
                value=None,
                status="FAIL",
                details="Missing Clickjacking protection.",
                recommendation="Set X-Frame-Options: SAMEORIGIN or DENY."
            ), findings

        if xfo:
            val_upper = xfo.upper()
            if val_upper in ("DENY", "SAMEORIGIN"):
                return HeaderAuditItem(
                    name="X-Frame-Options",
                    present=True,
                    value=xfo,
                    status="PASS",
                    details=f"Configured securely as '{val_upper}'.",
                    recommendation=None
                ), findings
            elif "ALLOW-FROM" in val_upper:
                return HeaderAuditItem(
                    name="X-Frame-Options",
                    present=True,
                    value=xfo,
                    status="WARN",
                    details="Uses deprecated 'ALLOW-FROM' syntax (unsupported by modern browsers).",
                    recommendation="Migrate to CSP frame-ancestors directive."
                ), findings

        return HeaderAuditItem(
            name="X-Frame-Options",
            present=bool(xfo),
            value=xfo or "Protected via CSP frame-ancestors",
            status="PASS",
            details="Protected against clickjacking.",
            recommendation=None
        ), findings

    def _audit_x_content_type_options(self, headers: Dict[str, str]) -> Tuple[HeaderAuditItem, List[Finding]]:
        """Audit MIME-sniffing protection."""
        findings = []
        xcto = headers.get("x-content-type-options")

        if not xcto:
            findings.append(Finding(
                id="HDR-XCTO-01",
                title="Missing X-Content-Type-Options Header",
                category="Security Headers",
                severity=Severity.LOW,
                description=(
                    "The X-Content-Type-Options: nosniff header prevents the browser from MIME-sniffing a response "
                    "away from the declared content-type, preventing executable content execution in non-executable formats."
                ),
                evidence="Header 'X-Content-Type-Options' is missing.",
                impact="Browsers may execute malicious user-uploaded content (e.g. SVG or images parsed as HTML/JS).",
                remediation="Add header: 'X-Content-Type-Options: nosniff'",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-430",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"]
            ))
            return HeaderAuditItem(
                name="X-Content-Type-Options",
                present=False,
                value=None,
                status="FAIL",
                details="Missing. MIME sniffing protection is disabled.",
                recommendation="Set X-Content-Type-Options: nosniff"
            ), findings

        if xcto.lower() == "nosniff":
            return HeaderAuditItem(
                name="X-Content-Type-Options",
                present=True,
                value=xcto,
                status="PASS",
                details="Configured correctly ('nosniff').",
                recommendation=None
            ), findings

        return HeaderAuditItem(
            name="X-Content-Type-Options",
            present=True,
            value=xcto,
            status="WARN",
            details=f"Unexpected value '{xcto}' (expected 'nosniff').",
            recommendation="Ensure exact value 'nosniff'."
        ), findings

    def _audit_referrer_policy(self, headers: Dict[str, str]) -> Tuple[HeaderAuditItem, List[Finding]]:
        """Audit Referrer-Policy header."""
        findings = []
        rp = headers.get("referrer-policy")

        if not rp:
            findings.append(Finding(
                id="HDR-RP-01",
                title="Missing Referrer-Policy Header",
                category="Security Headers",
                severity=Severity.LOW,
                description=(
                    "Referrer-Policy governs what referrer information sent in the Referer header should be included "
                    "with requests made."
                ),
                evidence="Header 'Referrer-Policy' is missing.",
                impact="Sensitive URL query parameters (tokens, session IDs) may be leaked to third-party domains.",
                remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"]
            ))
            return HeaderAuditItem(
                name="Referrer-Policy",
                present=False,
                value=None,
                status="FAIL",
                details="Missing. Default browser fallback will be used.",
                recommendation="Set Referrer-Policy: strict-origin-when-cross-origin"
            ), findings

        if rp.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
            findings.append(Finding(
                id="HDR-RP-02",
                title="Insecure Referrer-Policy Configuration",
                category="Security Headers",
                severity=Severity.LOW,
                description=f"Referrer-Policy is set to '{rp}', which leaks full URLs to unencrypted or cross-origin targets.",
                evidence=f"Referrer-Policy: {rp}",
                impact="Leaking full query strings to external resources.",
                remediation="Change policy to 'strict-origin-when-cross-origin'.",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-200",
                references=["https://web.dev/referrer-best-practices/"]
            ))
            return HeaderAuditItem(
                name="Referrer-Policy",
                present=True,
                value=rp,
                status="WARN",
                details=f"Insecure value '{rp}' leaks complete path/queries.",
                recommendation="Change to strict-origin-when-cross-origin."
            ), findings

        return HeaderAuditItem(
            name="Referrer-Policy",
            present=True,
            value=rp,
            status="PASS",
            details=f"Configured securely as '{rp}'.",
            recommendation=None
        ), findings

    def _audit_permissions_policy(self, headers: Dict[str, str]) -> Tuple[HeaderAuditItem, List[Finding]]:
        """Audit Permissions-Policy (Feature-Policy)."""
        findings = []
        pp = headers.get("permissions-policy") or headers.get("feature-policy")

        if not pp:
            findings.append(Finding(
                id="HDR-PP-01",
                title="Missing Permissions-Policy Header",
                category="Security Headers",
                severity=Severity.LOW,
                description=(
                    "Permissions-Policy allows site administrators to declare which browser features and APIs "
                    "(e.g., geolocation, camera, microphone, payment) can be used by the page and embedded iframes."
                ),
                evidence="Header 'Permissions-Policy' is not returned.",
                impact="Third-party embedded scripts or iframes could attempt to access sensitive hardware APIs.",
                remediation="Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                owasp_category="A05:2021-Security Misconfiguration",
                cwe_id="CWE-16",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"]
            ))
            return HeaderAuditItem(
                name="Permissions-Policy",
                present=False,
                value=None,
                status="WARN",
                details="Missing modern browser hardware/API restriction header.",
                recommendation="Specify explicit permissions (e.g. camera=(), microphone=())."
            ), findings

        return HeaderAuditItem(
            name="Permissions-Policy",
            present=True,
            value=pp,
            status="PASS",
            details="Configured.",
            recommendation=None
        ), findings

    def _audit_coop_coep(self, headers: Dict[str, str]) -> Tuple[HeaderAuditItem, List[Finding]]:
        """Audit Cross-Origin Isolation (COOP/COEP)."""
        findings = []
        coop = headers.get("cross-origin-opener-policy")
        coep = headers.get("cross-origin-embedder-policy")

        if not coop and not coep:
            return HeaderAuditItem(
                name="Cross-Origin-Isolation (COOP/COEP)",
                present=False,
                value=None,
                status="INFO",
                details="Not configured. Modern defense against Spectre side-channel attacks and tab-nabbing.",
                recommendation="Consider adding Cross-Origin-Opener-Policy: same-origin."
            ), findings

        details = f"COOP: {coop or 'none'} | COEP: {coep or 'none'}"
        return HeaderAuditItem(
            name="Cross-Origin-Isolation (COOP/COEP)",
            present=True,
            value=details,
            status="PASS",
            details="Cross-origin process isolation is defined.",
            recommendation=None
        ), findings

    def _audit_information_leakage(self, headers: Dict[str, str]) -> Tuple[List[HeaderAuditItem], List[Finding]]:
        """Audit headers that leak server technologies and versions."""
        items: List[HeaderAuditItem] = []
        findings: List[Finding] = []

        for header_key, desc, sev in self.sensitive_leakage_headers:
            val = headers.get(header_key)
            if val:
                has_version = bool(re.search(r"\d+\.\d+", val))
                finding_sev = sev if not has_version else Severity.LOW

                findings.append(Finding(
                    id=f"HDR-LEAK-{header_key.upper().replace('-', '_')}",
                    title=f"Server Technology Information Disclosure ({header_key.title()})",
                    category="Information Disclosure",
                    severity=finding_sev,
                    description=f"Server exposes technology header '{header_key}' containing '{val}'.",
                    evidence=f"{header_key}: {val}",
                    impact=(
                        "Revealing backend software frameworks and versions assists attackers in fingerprinting "
                        "known CVE vulnerabilities and tailoring exploit payloads."
                    ),
                    remediation=f"Disable, strip, or mask the '{header_key}' header in reverse proxy or web server config.",
                    owasp_category="A05:2021-Security Misconfiguration",
                    cwe_id="CWE-200",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"]
                ))

                items.append(HeaderAuditItem(
                    name=header_key.title(),
                    present=True,
                    value=val,
                    status="WARN",
                    details=f"Banner leakage: exposes {desc}.",
                    recommendation=f"Remove or mask '{header_key}'."
                ))

        return items, findings
