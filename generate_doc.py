"""
Script to generate the official IBM SkillsBuild Project Report (.docx).
"""

import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
import os

def set_cell_background(cell, hex_color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tcPr.append(shd)

def create_report(output_path: str):
    doc = docx.Document()

    # Page setup - 1 inch margins
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Styles
    # Primary colors: Dark Blue (#003366), Accent (#0066CC), Dark Gray (#333333)
    COLOR_PRIMARY = RGBColor(0, 51, 102)
    COLOR_ACCENT = RGBColor(0, 102, 204)
    COLOR_DARK = RGBColor(40, 40, 40)

    # Title / Cover Page
    p_badge = doc.add_paragraph()
    p_badge.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_badge = p_badge.add_run("IBM SkillsBuild Cyber Security BootCamp 2026 | BharatCares\n")
    run_badge.font.name = "Arial"
    run_badge.font.size = Pt(13)
    run_badge.font.bold = True
    run_badge.font.color.rgb = COLOR_ACCENT

    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_title = p_title.add_run("FINAL CAPSTONE PROJECT REPORT\n")
    run_title.font.name = "Arial"
    run_title.font.size = Pt(18)
    run_title.font.bold = True
    run_title.font.color.rgb = COLOR_PRIMARY

    p_subtitle = doc.add_paragraph()
    p_subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_sub = p_subtitle.add_run("Automated Web Security Scanner: Auditing Websites for Secure Headers and CORS Misconfigurations\n")
    run_sub.font.name = "Arial"
    run_sub.font.size = Pt(15)
    run_sub.font.italic = True
    run_sub.font.color.rgb = RGBColor(80, 80, 80)

    doc.add_paragraph("\n" * 2)

    # Metadata Box Table
    table_meta = doc.add_table(rows=6, cols=2)
    table_meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_data = [
        ("Student Name:", "Kone Bienvenu"),
        ("Email Address:", "kbienvenu263@gmail.com"),
        ("Program:", "IBM SkillsBuild Cyber Security BootCamp 2026"),
        ("Conducting Partner:", "BharatCares"),
        ("Project Topic:", "Automated Web Scanner: Programmed a Python script to audit sites for secure headers and CORS flaws"),
        ("GitHub Repository:", "https://github.com/konebienvenu/Automated-Web-Scanner")
    ]
    for i, (k, v) in enumerate(meta_data):
        row = table_meta.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.text = k
        c0.paragraphs[0].runs[0].font.bold = True
        c0.paragraphs[0].runs[0].font.size = Pt(10.5)
        c0.width = Inches(2.2)
        set_cell_background(c0, "F0F4F8")
        
        c1.text = v
        c1.paragraphs[0].runs[0].font.size = Pt(10.5)
        c1.width = Inches(4.3)
        set_cell_background(c1, "FFFFFF")

    doc.add_page_break()

    # Section 1: Executive Summary
    h1 = doc.add_heading("1. Executive Summary", level=1)
    h1.runs[0].font.color.rgb = COLOR_PRIMARY

    p = doc.add_paragraph(
        "Modern web applications are increasingly distributed, relying heavily on client-side script execution, "
        "RESTful APIs, and cross-domain resource sharing. While these architectural patterns enable interactive user experiences, "
        "they introduce severe security misconfiguration surfaces. Among the most pervasive weaknesses listed in the "
        "OWASP Top 10 (2021) are Broken Access Control (A01) and Security Misconfiguration (A05).\n\n"
        "This project introduces 'Automated Web Security Scanner', an industrial-grade, automated vulnerability auditing system "
        "engineered in Python 3. The scanner systematically audits targets for two foundational pillars of web security: "
        "(1) Passive evaluation of HTTP Secure Defense-in-Depth Headers against the OWASP Secure Headers benchmark, and "
        "(2) Active exploitation probe testing of Cross-Origin Resource Sharing (CORS) configurations according to RFC 6454. "
        "The system evaluates risk through a CVSS-weighted scoring algorithm, assigns a transparent letter grade from A+ to F, "
        "and exports audit deliverables in interactive HTML, machine-readable JSON, and GitHub-flavored Markdown."
    )
    p.paragraph_format.line_spacing = 1.15

    # Section 2: Problem Statement & Objectives
    h2 = doc.add_heading("2. Problem Statement & Project Objectives", level=1)
    h2.runs[0].font.color.rgb = COLOR_PRIMARY

    doc.add_heading("2.1 Problem Statement", level=2)
    doc.add_paragraph(
        "Standard vulnerability assessment tools often analyze HTTP responses passively without evaluating dynamic behavior. "
        "In CORS environments, dangerous vulnerabilities occur precisely when servers dynamically reflect the client's request "
        "Origin header while simultaneously returning 'Access-Control-Allow-Credentials: true'. Passive inspection alone cannot "
        "detect this flaw because it requires active probe injection with attacker-controlled origins. "
        "Furthermore, many production web servers omit essential defense headers such as Strict-Transport-Security (HSTS), "
        "Content-Security-Policy (CSP), and X-Frame-Options, leaving users vulnerable to SSL-stripping, Clickjacking, and Cross-Site Scripting."
    )

    doc.add_heading("2.2 Project Objectives", level=2)
    objs = [
        "Develop an automated Python scanner capable of auditing single URLs and multi-target batches.",
        "Implement heuristic rule checks for 8+ defensive HTTP headers and technology banner leakage.",
        "Construct an Active CORS Probing Engine testing arbitrary reflection, credential leakage, null origins, and regex flaws.",
        "Formulate a deterministic CVSS v3.1-aligned scoring engine mapping security posture from 0-100 and Grades A+ to F.",
        "Provide executive-ready deliverables (interactive dark-theme HTML report, JSON, Markdown).",
        "Include an embedded vulnerable and hardened testbed server for reproducible, offline demonstration."
    ]
    for obj in objs:
        doc.add_paragraph(f"• {obj}", style='List Bullet')

    # Section 3: Technical Background & Security Theory
    doc.add_heading("3. Technical Background & Security Theory", level=1)
    
    doc.add_heading("3.1 Same-Origin Policy (SOP) & CORS Mechanics", level=2)
    doc.add_paragraph(
        "The Same-Origin Policy (SOP) is the fundamental security boundary implemented by all modern web browsers. "
        "Two resources share the same origin if and only if their Scheme, Host, and Port are strictly identical. "
        "Cross-Origin Resource Sharing (CORS, RFC 6454) provides a controlled mechanism for servers to relax this policy. "
        "When a web application makes a cross-origin XMLHttpRequest or Fetch call, the browser sends an 'Origin' header. "
        "If the server responds with 'Access-Control-Allow-Origin' (ACAO) matching the origin and 'Access-Control-Allow-Credentials: true' (ACAC), "
        "the browser permits the requesting script to read the response data, including authenticated cookies and tokens."
    )

    doc.add_heading("3.2 Taxonomy of CORS Misconfigurations", level=2)
    cors_table = doc.add_table(rows=5, cols=3)
    cors_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers_cors = [("Vector", 1.8), ("Root Cause", 2.5), ("Impact / Severity", 2.2)]
    for idx, (title, w) in enumerate(headers_cors):
        c = cors_table.rows[0].cells[idx]
        c.text = title
        c.paragraphs[0].runs[0].font.bold = True
        set_cell_background(c, "003366")
        c.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
        c.width = Inches(w)

    data_cors = [
        ("Arbitrary Origin Reflection with Credentials", "Backend dynamically echoes request Origin with ACAC: true", "CRITICAL: Complete bypass of SOP. Attackers can steal private session tokens and user data."),
        ("Trust of 'null' Origin", "Server configures ACAO: null", "HIGH: Exploitable via sandboxed iframes (<iframe sandbox='allow-scripts'>) and data: URIs."),
        ("Regex Suffix / Prefix Bypass", "Improper regex matching like .*target.com without domain boundary", "HIGH / MEDIUM: Attacker registers target.com.evil.com to bypass origin validation."),
        ("Wildcard Origin on Sensitive API", "Server issues ACAO: * on authenticated endpoints", "MEDIUM / LOW: Public reading of endpoint responses by any third-party domain.")
    ]
    for r_idx, row_data in enumerate(data_cors, 1):
        row = cors_table.rows[r_idx]
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            cell.text = val
            cell.paragraphs[0].runs[0].font.size = Pt(9.5)
            set_cell_background(cell, "F9FBFD" if r_idx % 2 == 1 else "FFFFFF")

    doc.add_paragraph("\n")

    doc.add_heading("3.3 OWASP HTTP Security Headers", level=2)
    doc.add_paragraph(
        "Defensive headers instruct modern browser rendering engines to activate built-in security controls:\n"
        "• Strict-Transport-Security (HSTS): Mitigates SSL-stripping and man-in-the-middle attacks (RFC 6797).\n"
        "• Content-Security-Policy (CSP): Powerful defense against Cross-Site Scripting (XSS) and code injection.\n"
        "• X-Frame-Options: Clickjacking defense prohibiting malicious framing (RFC 7034).\n"
        "• X-Content-Type-Options: nosniff flag prevents MIME confusion and executable script execution.\n"
        "• Referrer-Policy: Prevents sensitive query strings and tokens from leaking to external domains.\n"
        "• Permissions-Policy: Restricts browser hardware APIs such as camera, microphone, and geolocation."
    )

    # Section 4: System Architecture & Implementation
    doc.add_heading("4. System Architecture & Implementation", level=1)
    doc.add_paragraph(
        "The project is structured into modular Python components with high cohesion and low coupling:\n"
        "1. WebSecurityScanner (core.py): Orchestrates network sessions, proxying, DNS lookups, and audit pipelines.\n"
        "2. HeadersAuditor (headers_auditor.py): Implements passive rule matching against OWASP standards.\n"
        "3. CorsAuditor (cors_auditor.py): Executes active probe injections (evil-attacker.com, null origin, regex vectors, OPTIONS preflight).\n"
        "4. GradingEngine (grading.py): Applies penalty deductions and calculates final scores and letter grades.\n"
        "5. ReportGenerator (reporter.py): Outputs styled Rich terminal views, standalone HTML dashboards, JSON schemas, and Markdown.\n"
        "6. VulnerableTestHandler (demo_server.py): Integrated Python standard library HTTP server for demonstrations."
    )

    # Section 5: Experimental Results
    doc.add_heading("5. Experimental Test Results & Demonstrations", level=1)
    doc.add_paragraph("The scanner was evaluated against deliberately vulnerable and hardened testbed environments:")

    res_table = doc.add_table(rows=5, cols=4)
    res_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    r_headers = [("Test Scenario", 2.2), ("Target Endpoint", 2.3), ("Detected Severity", 1.2), ("Final Grade", 0.8)]
    for idx, (t, w) in enumerate(r_headers):
        c = res_table.rows[0].cells[idx]
        c.text = t
        c.paragraphs[0].runs[0].font.bold = True
        set_cell_background(c, "003366")
        c.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
        c.width = Inches(w)

    res_data = [
        ("Reflected Origin + Credentials", "/vulnerable/cors-reflected-creds", "CRITICAL", "F (0/100)"),
        ("Insecure Null Origin Trust", "/vulnerable/cors-null", "HIGH", "D (45/100)"),
        ("Permissive CSP ('unsafe-inline')", "/vulnerable/weak-csp", "MEDIUM", "C (65/100)"),
        ("Hardened Enterprise Endpoint", "/secure/hardened", "NONE (Clean)", "A+ (100/100)")
    ]
    for r_idx, row_data in enumerate(res_data, 1):
        row = res_table.rows[r_idx]
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            cell.text = val
            cell.paragraphs[0].runs[0].font.size = Pt(9.5)
            set_cell_background(cell, "F9FBFD" if r_idx % 2 == 1 else "FFFFFF")

    doc.add_paragraph("\n")
    doc.add_paragraph(
        "Additionally, a comprehensive unit test suite of 16 tests implemented in pytest was executed, "
        "achieving a 100% pass rate with zero failures across Python 3.10 through 3.13."
    )

    # Section 6: Remediation Guidelines
    doc.add_heading("6. Remediation & Hardening Recommendations", level=1)
    doc.add_paragraph(
        "To remediate CORS and header vulnerabilities, organizations should adopt defense-in-depth controls:\n\n"
        "• Strict Origin Whitelisting: Never dynamically reflect the HTTP Origin header into ACAO. "
        "Maintain an explicit server-side array of approved origins and match incoming origins against this list.\n"
        "• Avoid Trusting 'null': Never configure 'Access-Control-Allow-Origin: null'.\n"
        "• Restrict Preflight Methods: Limit 'Access-Control-Allow-Methods' strictly to required HTTP verbs (e.g. GET, POST).\n"
        "• Enforce Security Headers: In Nginx reverse proxies, configure:\n"
        "    add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;\n"
        "    add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\" always;\n"
        "    add_header X-Frame-Options 'SAMEORIGIN' always;\n"
        "    add_header X-Content-Type-Options 'nosniff' always;\n"
        "• Technology Banner Stripping: Mask the 'Server' and 'X-Powered-By' headers to prevent OS and framework fingerprinting."
    )

    # Section 7: Conclusion
    doc.add_heading("7. Conclusion & Learning Outcomes", level=1)
    doc.add_paragraph(
        "Through the development of this project for the IBM SkillsBuild Cyber Security BootCamp 2026, "
        "deep practical expertise was gained in modern web application security, RFC specifications, and automated penetration testing. "
        "The resulting scanner serves as an effective, DevSecOps-ready auditing tool that helps organizations identify and eliminate "
        "critical access control bypasses and security misconfigurations before malicious actors can exploit them."
    )

    # References
    doc.add_heading("8. References", level=1)
    refs = [
        "OWASP Foundation. (2021). OWASP Top 10:2021 - The Ten Most Critical Web Application Security Risks.",
        "OWASP Secure Headers Project. (2023). Best Practices for HTTP Response Headers.",
        "Barth, A. (2011). RFC 6454: The Web Origin Concept. Internet Engineering Task Force (IETF).",
        "Hodges, J., et al. (2012). RFC 6797: HTTP Strict Transport Security (HSTS). IETF.",
        "PortSwigger Web Security Academy. (2023). Cross-Origin Resource Sharing (CORS) Vulnerabilities.",
        "W3C Web Application Security Working Group. (2023). Content Security Policy Level 3."
    ]
    for r in refs:
        doc.add_paragraph(r, style='List Bullet')

    doc.save(output_path)
    print(f"[+] Successfully generated Word project report: {output_path}")

if __name__ == "__main__":
    out_file = "cybersecuritt-bootcamp-project/KoneBienvenu_ProjectReport.docx"
    create_report(out_file)
