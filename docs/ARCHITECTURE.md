# System Architecture & Design Specification

## Overview

The **Web Security Scanner** is an automated auditing tool designed to evaluate web applications against **OWASP Secure Headers** and **CORS (Cross-Origin Resource Sharing) misconfigurations** (RFC 6454). It is architected around modularity, testability, extensibility, and defense-in-depth security principles.

---

## Architectural Diagram

```
+---------------------------------------------------------------------------------+
|                                    CLI / API                                    |
|              (main.py / scanner.cli - Arguments, Flags, Banners)                 |
+---------------------------------------+-----------------------------------------+
                                        |
                                        v
+---------------------------------------------------------------------------------+
|                          WebSecurityScanner (core.py)                           |
|        - Configures Network Session (Timeouts, SSL verify, Proxy, User-Agent)   |
|        - DNS resolution & latency measurement                                   |
|        - Coordinates audit sub-modules                                          |
+-------------------+-----------------------------------------+-------------------+
                    |                                         |
                    v                                         v
+-------------------------------------+   +-------------------------------------+
|    HeadersAuditor (headers_auditor) |   |       CorsAuditor (cors_auditor)    |
| - HSTS (Strict-Transport-Security)  |   | - Arbitrary Origin Reflection       |
| - CSP (Content-Security-Policy)     |   | - Credential Exposure (ACAC: true)  |
| - X-Frame-Options (Clickjacking)    |   | - Null Origin Trust                 |
| - X-Content-Type-Options (nosniff)  |   | - Regex Prefix/Suffix Bypasses      |
| - Referrer-Policy & Permissions     |   | - Wildcard & Preflight (OPTIONS)    |
| - Information Disclosure Leaks      |   |                                     |
+-------------------+-----------------+   +-------------------+-----------------+
                    \                                         /
                     \                                       /
                      v                                     v
+---------------------------------------------------------------------------------+
|                           GradingEngine (grading.py)                            |
|             - Deductive CVSS-weighted scoring algorithm (0 to 100)              |
|             - Security Posture Letter Grade determination (A+ to F)             |
|             - Critical finding cap logic                                        |
+---------------------------------------+-----------------------------------------+
                                        |
                                        v
+---------------------------------------------------------------------------------+
|                          ReportGenerator (reporter.py)                          |
|             +-------------------+-------------------+-------------------+       |
|             | Rich Terminal     | HTML Dashboard    | JSON Export       |       |
|             | Table Output      | (Executive View)  | (CI/CD Pipeline)  |       |
|             +-------------------+-------------------+-------------------+       |
+---------------------------------------------------------------------------------+
```

---

## Core Components

### 1. `scanner.models` (Data Layer)
- Defines immutable, strongly-typed data structures:
  - `Severity` Enum: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` with dedicated CVSS weights and presentation colors.
  - `Grade` Enum: `A+`, `A`, `B`, `C`, `D`, `F`.
  - `Finding`: Comprehensive vulnerability model storing title, description, evidence, impact, remediation, OWASP category, and CWE identifiers.
  - `HeaderAuditItem`: Individual audit item for tabular analysis.
  - `CorsTestProbe`: Complete trace of sent probe origin, HTTP response status, received CORS headers, and vulnerability assessment.
  - `ScanResult`: Aggregated scan report payload supporting native JSON serialization.

### 2. `scanner.headers_auditor` (Passive Audit Engine)
- Inspects response headers against modern industry benchmarks:
  - **OWASP Secure Headers Project**
  - **RFC 6797** (HSTS)
  - **W3C Content Security Policy Level 3**
  - **RFC 7034** (X-Frame-Options)
- Implements deep heuristic checks (e.g. checking HSTS `max-age` thresholds, flagging unsafe CSP keywords `'unsafe-inline'` and `'unsafe-eval'`).

### 3. `scanner.cors_auditor` (Active Probing Engine)
- Unlike passive header scanners that only inspect static responses, the `CorsAuditor` sends targeted, active test vectors:
  - Sends untrusted origin `https://evil-attacker.com` to test for dynamic origin reflection.
  - Checks if `Access-Control-Allow-Credentials: true` is returned (Critical SOP bypass).
  - Sends `Origin: null` to test for sandboxed iframe vulnerabilities.
  - Tests regex boundary issues by probing suffix (`target.com.attacker.com`) and prefix patterns.
  - Dispatches preflight `OPTIONS` requests to audit allowed HTTP methods (`PUT`, `DELETE`, `*`) and cache duration (`Access-Control-Max-Age`).

### 4. `scanner.grading` (Risk & Scoring Algorithm)
- Evaluates security posture using a transparent 100-point deduction formula:
  - Base Score = 100
  - Deductions:
    - `CRITICAL`: -35 points (immediately caps grade at D or F)
    - `HIGH`: -20 points
    - `MEDIUM`: -10 points
    - `LOW`: -5 points
    - `INFO`: 0 points
- Provides executive risk mapping (`A+` to `F`).

### 5. `scanner.reporter` (Multi-Format Deliverables)
- **Rich Terminal Console**: Colored tables, status badges, and executive metrics.
- **HTML Executive Dashboard**: Standalone single-page report with responsive layout, CSS gauges, and print-ready stylesheet for penetration testing deliverables.
- **Machine-readable JSON**: Compatible with DevSecOps ingestion and automated CI/CD gating.
- **Markdown Export**: Ready for GitHub issues, PR comments, and technical writeups.

### 6. `scanner.demo_server` (Self-Contained Testbed)
- Built on Python's standard `http.server` with zero external dependencies.
- Simulates intentional CORS vulnerabilities, weak CSP configs, missing headers, and fully hardened `A+` configurations.
