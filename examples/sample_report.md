# 🛡️ Web Security Audit Report - `http://127.0.0.1:8889/vulnerable/cors-reflected-creds`

**Date:** 2026-10-20 04:14:21 UTC  
**Security Grade:** `F` (0/100)  
**Server:** BaseHTTP/0.6 Python/3.13.6, Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1  
**Status:** 200

## 📊 Executive Summary

| Severity | Count |
| :--- | :--- |
| **CRITICAL** | 4 |
| **HIGH** | 1 |
| **MEDIUM** | 1 |
| **LOW** | 5 |
| **INFO** | 0 |

## 🚨 Identified Findings

### `[HIGH]` Missing Content-Security-Policy (CSP) Header (HDR-CSP-01)
- **Category:** Security Headers | **OWASP:** A05:2021-Security Misconfiguration | **CWE:** CWE-79
- **Description:** Content Security Policy (CSP) is an effective layer of defense against Cross-Site Scripting (XSS), data injection, and unauthorized frame embedding.
- **Evidence:**
```
Header 'Content-Security-Policy' was not found in response.
```
- **Impact:** Leaves client vulnerable to Stored, Reflected, and DOM-based Cross-Site Scripting (XSS).
- **Remediation:** Define a restrictive CSP such as: default-src 'self'; script-src 'self'; object-src 'none';

### `[MEDIUM]` Missing Clickjacking Defense (X-Frame-Options / frame-ancestors) (HDR-XFO-01)
- **Category:** Security Headers | **OWASP:** A05:2021-Security Misconfiguration | **CWE:** CWE-1021
- **Description:** Neither X-Frame-Options nor CSP frame-ancestors is present to restrict iframe embedding.
- **Evidence:**
```
Neither X-Frame-Options nor frame-ancestors found in response headers.
```
- **Impact:** Allows malicious sites to embed target inside hidden iframes to conduct Clickjacking attacks.
- **Remediation:** Set 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use CSP 'frame-ancestors' directive.

### `[LOW]` Missing X-Content-Type-Options Header (HDR-XCTO-01)
- **Category:** Security Headers | **OWASP:** A05:2021-Security Misconfiguration | **CWE:** CWE-430
- **Description:** The X-Content-Type-Options: nosniff header prevents the browser from MIME-sniffing a response away from the declared content-type, preventing executable content execution in non-executable formats.
- **Evidence:**
```
Header 'X-Content-Type-Options' is missing.
```
- **Impact:** Browsers may execute malicious user-uploaded content (e.g. SVG or images parsed as HTML/JS).
- **Remediation:** Add header: 'X-Content-Type-Options: nosniff'

### `[LOW]` Missing Referrer-Policy Header (HDR-RP-01)
- **Category:** Security Headers | **OWASP:** A05:2021-Security Misconfiguration | **CWE:** CWE-200
- **Description:** Referrer-Policy governs what referrer information sent in the Referer header should be included with requests made.
- **Evidence:**
```
Header 'Referrer-Policy' is missing.
```
- **Impact:** Sensitive URL query parameters (tokens, session IDs) may be leaked to third-party domains.
- **Remediation:** Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.

### `[LOW]` Missing Permissions-Policy Header (HDR-PP-01)
- **Category:** Security Headers | **OWASP:** A05:2021-Security Misconfiguration | **CWE:** CWE-16
- **Description:** Permissions-Policy allows site administrators to declare which browser features and APIs (e.g., geolocation, camera, microphone, payment) can be used by the page and embedded iframes.
- **Evidence:**
```
Header 'Permissions-Policy' is not returned.
```
- **Impact:** Third-party embedded scripts or iframes could attempt to access sensitive hardware APIs.
- **Remediation:** Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()

### `[LOW]` Server Technology Information Disclosure (Server) (HDR-LEAK-SERVER)
- **Category:** Information Disclosure | **OWASP:** A05:2021-Security Misconfiguration | **CWE:** CWE-200
- **Description:** Server exposes technology header 'server' containing 'BaseHTTP/0.6 Python/3.13.6, Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1'.
- **Evidence:**
```
server: BaseHTTP/0.6 Python/3.13.6, Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1
```
- **Impact:** Revealing backend software frameworks and versions assists attackers in fingerprinting known CVE vulnerabilities and tailoring exploit payloads.
- **Remediation:** Disable, strip, or mask the 'server' header in reverse proxy or web server config.

### `[LOW]` Server Technology Information Disclosure (X-Powered-By) (HDR-LEAK-X_POWERED_BY)
- **Category:** Information Disclosure | **OWASP:** A05:2021-Security Misconfiguration | **CWE:** CWE-200
- **Description:** Server exposes technology header 'x-powered-by' containing 'PHP/7.4.3'.
- **Evidence:**
```
x-powered-by: PHP/7.4.3
```
- **Impact:** Revealing backend software frameworks and versions assists attackers in fingerprinting known CVE vulnerabilities and tailoring exploit payloads.
- **Remediation:** Disable, strip, or mask the 'x-powered-by' header in reverse proxy or web server config.

### `[CRITICAL]` Critical CORS Vulnerability: Reflected Origin with Credentials (Arbitrary Third-Party Origin Reflection) (CORS-CRIT-REFLECTION)
- **Category:** CORS Misconfiguration | **OWASP:** A01:2021-Broken Access Control | **CWE:** CWE-942
- **Description:** The endpoint dynamically reflects the provided Origin header 'https://evil-attacker.com' in 'Access-Control-Allow-Origin' AND explicitly enables 'Access-Control-Allow-Credentials: true'. This effectively disables the browser Same-Origin Policy (SOP).
- **Evidence:**
```
Request Origin: https://evil-attacker.com
Response Access-Control-Allow-Origin: https://evil-attacker.com
Response Access-Control-Allow-Credentials: true
```
- **Impact:** An attacker hosting malicious JavaScript on an external site can make authenticated XMLHttpRequest / Fetch requests to this endpoint using the victim's session cookies or HTTP auth headers, and read sensitive confidential responses.
- **Remediation:** Do NOT dynamically reflect the Origin header. Maintain a strict server-side whitelist of authorized domains. Never set Access-Control-Allow-Credentials: true unless the origin is strictly verified.

### `[CRITICAL]` Critical CORS Vulnerability: Reflected Origin with Credentials (Null Origin Trust (Sandboxed iframe / data: URI)) (CORS-CRIT-NULL_ORIGIN)
- **Category:** CORS Misconfiguration | **OWASP:** A01:2021-Broken Access Control | **CWE:** CWE-942
- **Description:** The endpoint dynamically reflects the provided Origin header 'null' in 'Access-Control-Allow-Origin' AND explicitly enables 'Access-Control-Allow-Credentials: true'. This effectively disables the browser Same-Origin Policy (SOP).
- **Evidence:**
```
Request Origin: null
Response Access-Control-Allow-Origin: null
Response Access-Control-Allow-Credentials: true
```
- **Impact:** An attacker hosting malicious JavaScript on an external site can make authenticated XMLHttpRequest / Fetch requests to this endpoint using the victim's session cookies or HTTP auth headers, and read sensitive confidential responses.
- **Remediation:** Do NOT dynamically reflect the Origin header. Maintain a strict server-side whitelist of authorized domains. Never set Access-Control-Allow-Credentials: true unless the origin is strictly verified.

### `[CRITICAL]` Critical CORS Vulnerability: Reflected Origin with Credentials (Regex Suffix Bypass (Attacker domain as suffix)) (CORS-CRIT-SUFFIX_BYPASS)
- **Category:** CORS Misconfiguration | **OWASP:** A01:2021-Broken Access Control | **CWE:** CWE-942
- **Description:** The endpoint dynamically reflects the provided Origin header 'http://127.0.0.1.attacker.com' in 'Access-Control-Allow-Origin' AND explicitly enables 'Access-Control-Allow-Credentials: true'. This effectively disables the browser Same-Origin Policy (SOP).
- **Evidence:**
```
Request Origin: http://127.0.0.1.attacker.com
Response Access-Control-Allow-Origin: http://127.0.0.1.attacker.com
Response Access-Control-Allow-Credentials: true
```
- **Impact:** An attacker hosting malicious JavaScript on an external site can make authenticated XMLHttpRequest / Fetch requests to this endpoint using the victim's session cookies or HTTP auth headers, and read sensitive confidential responses.
- **Remediation:** Do NOT dynamically reflect the Origin header. Maintain a strict server-side whitelist of authorized domains. Never set Access-Control-Allow-Credentials: true unless the origin is strictly verified.

### `[CRITICAL]` Critical CORS Vulnerability: Reflected Origin with Credentials (Regex Prefix Bypass (Prepend attacker name)) (CORS-CRIT-PREFIX_BYPASS)
- **Category:** CORS Misconfiguration | **OWASP:** A01:2021-Broken Access Control | **CWE:** CWE-942
- **Description:** The endpoint dynamically reflects the provided Origin header 'http://attacker-127.0.0.1' in 'Access-Control-Allow-Origin' AND explicitly enables 'Access-Control-Allow-Credentials: true'. This effectively disables the browser Same-Origin Policy (SOP).
- **Evidence:**
```
Request Origin: http://attacker-127.0.0.1
Response Access-Control-Allow-Origin: http://attacker-127.0.0.1
Response Access-Control-Allow-Credentials: true
```
- **Impact:** An attacker hosting malicious JavaScript on an external site can make authenticated XMLHttpRequest / Fetch requests to this endpoint using the victim's session cookies or HTTP auth headers, and read sensitive confidential responses.
- **Remediation:** Do NOT dynamically reflect the Origin header. Maintain a strict server-side whitelist of authorized domains. Never set Access-Control-Allow-Credentials: true unless the origin is strictly verified.

## 📋 Security Headers Status

| Header | Status | Details |
| :--- | :--- | :--- |
| `Strict-Transport-Security` | **INFO** | Not applicable on plain HTTP endpoints. HSTS should be enforced once redirected to HTTPS. |
| `Content-Security-Policy` | **FAIL** | Missing. Target provides no CSP mitigation against Cross-Site Scripting. |
| `X-Frame-Options` | **FAIL** | Missing Clickjacking protection. |
| `X-Content-Type-Options` | **FAIL** | Missing. MIME sniffing protection is disabled. |
| `Referrer-Policy` | **FAIL** | Missing. Default browser fallback will be used. |
| `Permissions-Policy` | **WARN** | Missing modern browser hardware/API restriction header. |
| `Cross-Origin-Isolation (COOP/COEP)` | **INFO** | Not configured. Modern defense against Spectre side-channel attacks and tab-nabbing. |
| `Server` | **WARN** | Banner leakage: exposes Server Software & Version. |
| `X-Powered-By` | **WARN** | Banner leakage: exposes Application Technology / Framework. |

## 🌐 CORS Security Matrix

| Probe Name | Sent Origin | ACAO Returned | ACAC | Status |
| :--- | :--- | :--- | :--- | :--- |
| Arbitrary Third-Party Origin Reflection | `https://evil-attacker.com` | `https://evil-attacker.com` | `true` | 🔴 VULNERABLE |
| Null Origin Trust (Sandboxed iframe / data: URI) | `null` | `null` | `true` | 🔴 VULNERABLE |
| Regex Suffix Bypass (Attacker domain as suffix) | `http://127.0.0.1.attacker.com` | `http://127.0.0.1.attacker.com` | `true` | 🔴 VULNERABLE |
| Regex Prefix Bypass (Prepend attacker name) | `http://attacker-127.0.0.1` | `http://attacker-127.0.0.1` | `true` | 🔴 VULNERABLE |
| Preflight OPTIONS Inspection | `https://evil-attacker.com` | `https://evil-attacker.com` | `true` | 🔴 VULNERABLE |