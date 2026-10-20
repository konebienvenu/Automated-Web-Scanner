# 🎓 Bootcamp Oral Defense Cheat Sheet

> This document is designed to prepare you for presenting and defending this cybersecurity capstone project before an examination jury, mentor, or hiring manager.

---

## 1. Executive Pitch (2-3 Minutes Introduction)

**"Good morning / afternoon everyone,**

As part of my cybersecurity bootcamp capstone evaluation, I developed **Automated Web Security Scanner**, an automated security auditing tool built in Python focused on two critical web security areas:
1. **Defensive HTTP Security Headers Audit** based on the **OWASP Secure Headers Project**.
2. **Active CORS (Cross-Origin Resource Sharing) Misconfiguration Probing** based on the **W3C / RFC 6454** standard.

While standard scanners often perform passive header lookups, this tool features an **Active Probing Engine**. It dynamically dispatches controlled test vectors (untrusted external origins, `null` origins, and unanchored regex bypasses) to observe whether the server improperly allows authenticated cross-origin data exposure via `Access-Control-Allow-Credentials: true`.

The scanner calculates a CVSS-weighted risk score from 0 to 100, assigns an overall security grade from **A+ to F**, and exports multi-format deliverables: **Rich terminal tables**, modern executive **HTML dashboards**, CI/CD-ready **JSON** schemas, and GitHub **Markdown** reports. Finally, an embedded **mock testbed server** is included to demonstrate and reproduce all vulnerability detection scenarios offline."

---

## 2. Step-by-Step Live Demonstration Script

For your live demonstration, open **two terminal windows**:

### Step 1: Start the Local Testbed Server (Terminal 1)
```bash
python main.py demo-server --port 8888
```
*Talking point for the jury:*  
*"I am spinning up our embedded testbed server which simulates both vulnerable endpoints and hardened enterprise endpoints."*

### Step 2: Audit the Critical CORS Vulnerable Endpoint (Terminal 2)
```bash
python main.py scan http://127.0.0.1:8888/vulnerable/cors-reflected-creds --html report_vuln.html
```
*Point out to the jury:*
- The **CRITICAL** finding: Origin reflection combined with `Access-Control-Allow-Credentials: true`.
- Missing defensive headers (CSP, HSTS, X-Frame-Options).
- The final score: **Grade F** (Score 0/100).
- Open `report_vuln.html` in your browser to showcase the executive dashboard.

### Step 3: Audit the Hardened Endpoint (Grade A+)
```bash
python main.py scan http://127.0.0.1:8888/secure/hardened
```
*Point out to the jury:*
- Complete OWASP defense-in-depth compliance (HSTS preload, strict CSP, nosniff, frame protection).
- Untrusted cross-origin requests are rejected by whitelist.
- The final score: **Grade A+** (Score 100/100).

### Step 4: Run the Automated Unit Test Suite
```bash
python -m pytest tests/ -v
```
*Talking point for the jury:*  
*"The tool includes an automated test suite with pytest covering 100% of audit rules, validated by GitHub Actions for CI/CD."*

---

## 3. Anticipated Jury Questions & Expert Answers

### Q1: "Why did you implement active CORS probing instead of only passive header inspection?"
> **Answer:**  
> *"Passive analysis only reads headers on a standard GET request without knowing how the server handles specific origins. The most critical CORS flaws occur when server-side logic dynamically reflects the incoming `Origin` header into `Access-Control-Allow-Origin`. Without sending active probes with untrusted origins (such as `https://evil-attacker.com` or `Origin: null`), it is impossible to detect whether the server dynamically reflects unauthorized domains."*

### Q2: "Why is `Access-Control-Allow-Origin: *` with credentials invalid in modern browsers?"
> **Answer:**  
> *"The W3C Fetch specification explicitly forbids combining wildcard `*` with `Access-Control-Allow-Credentials: true`. Browsers automatically block reading the response if this combination is received. To work around this restriction, developers frequently write insecure code that dynamically reflects the received origin, which reintroduces the critical vulnerability of authenticated credential theft."*

### Q3: "How does CSP `frame-ancestors` improve upon `X-Frame-Options`?"
> **Answer:**  
> *"`X-Frame-Options` (RFC 7034) is a legacy header limited to `DENY` or `SAMEORIGIN` (the `ALLOW-FROM` directive is deprecated and unsupported across modern browsers). CSP `frame-ancestors` (Level 2 and 3) provides granular control, allowing multiple whitelisted domains, specific schemes (HTTPS only), and subdomain wildcards."*

### Q4: "What is the security risk of trusting the `null` origin?"
> **Answer:**  
> *"The browser assigns an `Origin: null` in specific contexts, such as sandboxed iframes (`<iframe sandbox='allow-scripts'>`) or `data:` URIs. If a server trusts `null`, an attacker hosting malicious JavaScript on any domain can wrap their exploit inside a sandboxed iframe to masquerade with an origin of `null` and steal confidential data."*

### Q5: "How does this scanner integrate into a DevSecOps CI/CD pipeline?"
> **Answer:**  
> *"The scanner provides the `--fail-on <SEVERITY>` flag (e.g., `--fail-on HIGH`) and structured JSON output. In GitLab CI or GitHub Actions, the pipeline executes the scanner against staging. If a critical or high-risk misconfiguration is found, the script returns exit code 1, automatically stopping the build and preventing security regressions from reaching production."*
