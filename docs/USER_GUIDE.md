# Web Security Scanner - User Guide & CLI Manual

## Table of Contents
1. [Prerequisites & Installation](#1-prerequisites--installation)
2. [Command-Line Reference](#2-command-line-reference)
3. [Running Single URL Audits](#3-running-single-url-audits)
4. [Running Batch Audits from a Target List](#4-running-batch-audits-from-a-target-list)
5. [Using the Built-In Testbed Server](#5-using-the-built-in-testbed-server)
6. [CI/CD Integration & Security Gating](#6-cicd-integration--security-gating)
7. [Proxy Support (Burp Suite / OWASP ZAP)](#7-proxy-support-burp-suite--owasp-zap)

---

## 1. Prerequisites & Installation

### Requirements
- Python 3.8+ (tested on Python 3.10, 3.11, 3.12, 3.13)
- Windows, macOS, or Linux

### Setup Instructions
1. Clone or extract the project repository:
   ```bash
   cd cybersecuritt-bootcamp-project
   ```

2. (Optional but recommended) Create and activate a virtual environment:
   ```bash
   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

4. Install the package in editable mode (enables `websec-scanner` system command):
   ```bash
   pip install -e .
   ```

---

## 2. Command-Line Reference

```
usage: websec-scanner [-h] [-v] {scan,batch,demo-server} ...
```

### Global Commands
| Command | Description |
| :--- | :--- |
| `scan <URL>` | Audit a single web application or API endpoint. |
| `batch <FILE>` | Audit a list of URLs supplied in a line-delimited text file. |
| `demo-server` | Spin up a local mock server containing vulnerable & hardened test endpoints. |
| `-v, --version` | Print tool version and metadata. |

### Shared Audit Flags
| Flag | Description | Default |
| :--- | :--- | :--- |
| `--html <PATH>` | Output an interactive executive HTML report. | None |
| `--json <PATH>` | Output machine-readable JSON results. | None |
| `--markdown <PATH>` | Output formatted GitHub Flavored Markdown. | None |
| `-t, --timeout <SEC>` | HTTP timeout in seconds per request. | `10` |
| `-k, --insecure` | Disable SSL/TLS certificate verification. | False |
| `-u, --user-agent <UA>` | Custom User-Agent header string. | Default Scanner UA |
| `-p, --proxy <URL>` | Proxy URL (e.g. `http://127.0.0.1:8080`). | None |
| `--verbose` | Print raw HTTP response headers to console. | False |
| `--fail-on <LEVEL>` | Non-zero exit code if findings meet threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`). | None |

---

## 3. Running Single URL Audits

### Basic Scan
```bash
python main.py scan https://example.com
```

### Full Report Generation
Generate HTML, JSON, and Markdown deliverables simultaneously:
```bash
python main.py scan https://example.com --html reports/audit.html --json reports/audit.json --markdown reports/audit.md
```

### Verbose Mode with Raw Header Inspection
```bash
python main.py scan https://example.com --verbose
```

---

## 4. Running Batch Audits from a Target List

For multi-site auditing, create a text file listing your targets (one per line):
```text
# targets.txt
https://example.com
https://owasp.org
https://api.github.com
```

Execute batch audit:
```bash
python main.py batch targets.txt --output-dir audit_reports --html --json
```

Individual reports will be automatically saved under `audit_reports/<target_name>.html` and `.json`.

---

## 5. Using the Built-In Testbed Server

For live demonstrations, oral exams, or offline testing without external internet access:

1. **Terminal 1**: Start the mock testbed server:
   ```bash
   python main.py demo-server --port 8888
   ```

2. **Terminal 2**: Scan the deliberately vulnerable endpoints:
   ```bash
   # Test CRITICAL CORS Reflection with Credentials
   python main.py scan http://127.0.0.1:8888/vulnerable/cors-reflected-creds --html report_vuln.html

   # Test Hardened A+ Endpoint
   python main.py scan http://127.0.0.1:8888/secure/hardened --html report_secure.html
   ```

---

## 6. CI/CD Integration & Security Gating

In DevSecOps pipelines, you can block pull requests or deployment jobs if the website exposes critical or high-risk flaws:

```bash
python main.py scan https://staging.mycompany.com --fail-on HIGH
```
- If findings include **CRITICAL** or **HIGH**, `main.py` returns **exit code 1**, halting the CI pipeline.
- If only Medium/Low/Pass, returns **exit code 0**.

---

## 7. Proxy Support (Burp Suite / OWASP ZAP)

Route the scanner's requests through Burp Suite or OWASP ZAP to inspect traffic:
```bash
python main.py scan https://example.com -p http://127.0.0.1:8080 -k
```
*(The `-k` flag ignores Burp's self-signed CA certificate).*
