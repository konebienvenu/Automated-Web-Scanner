"""
Command-Line Interface (CLI) for Web Security Scanner.
Provides interactive terminal commands, batch processing, and CI/CD gating.
"""

import argparse
import sys
from typing import List, Optional

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from . import __version__
from .core import WebSecurityScanner
from .reporter import ReportGenerator
from .demo_server import run_demo_server
from .models import Severity


BANNER = r"""
   __      __      ___.    _________              _________                                           
  /  \    /  \ ____\_ |__ /   _____/ ____   ____ /   _____/ ____ _____    ____   ____   ___________  
  \   \/\/   // __ \| __ \\_____  \_/ __ \_/ ___\\_____  \_/ ___\\__  \  /    \ /    \_/ __ \_  __ \ 
   \        /\  ___/| \_\ \/        \  ___/\  \___/        \  \___ / __ \|   |  \   |  \  ___/|  | \/ 
    \__/\  /  \___  >___  /_______  /\___  >\___  >_______  /\___  >____  /___|  /___|  /\___  >__|    
         \/       \/    \/        \/     \/     \/        \/     \/     \/     \/     \/     \/        
           ⚡ Automated Security Headers & CORS Flaw Audit Scanner v1.0.0 ⚡
           🎓 Cybersecurity Bootcamp Capstone Project
"""


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="websec-scanner",
        description="Automated Web Security Scanner: Audit sites for secure headers and CORS flaws.",
        epilog="Bootcamp Capstone Project - Designed for penetration testing and compliance auditing."
    )
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Audit a single target URL")
    scan_parser.add_argument("url", help="Target URL to audit (e.g., https://example.com)")
    _add_shared_options(scan_parser)

    # Command: batch
    batch_parser = subparsers.add_parser("batch", help="Audit multiple target URLs from a text file")
    batch_parser.add_argument("file", help="Path to file containing URLs (one per line)")
    batch_parser.add_argument("--output-dir", default="reports", help="Directory to save individual reports")
    _add_shared_options(batch_parser)

    # Command: demo-server
    demo_parser = subparsers.add_parser("demo-server", help="Launch local testbed server with vulnerable/hardened endpoints")
    demo_parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    demo_parser.add_argument("--port", type=int, default=8888, help="Port to listen on (default: 8888)")

    return parser


def _add_shared_options(parser: argparse.ArgumentParser):
    """Add shared scan configuration flags."""
    parser.add_argument("--html", help="Path to save HTML executive dashboard report")
    parser.add_argument("--json", help="Path to save machine-readable JSON report")
    parser.add_argument("--markdown", "--md", dest="markdown", help="Path to save GitHub Markdown report")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL/TLS certificate verification")
    parser.add_argument("-u", "--user-agent", help="Custom User-Agent header")
    parser.add_argument("-p", "--proxy", help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output including raw headers")
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Exit with non-zero code if findings equal or exceed this severity (for CI/CD gating)"
    )


def handle_scan(args: argparse.Namespace) -> int:
    """Execute single scan."""
    scanner = WebSecurityScanner(
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        user_agent=args.user_agent,
        proxy=args.proxy
    )

    result = scanner.scan(args.url)
    reporter = ReportGenerator(result)

    # Console display
    reporter.print_console(verbose=args.verbose)

    # Save outputs if requested
    if args.html:
        reporter.save_html(args.html)
        print(f"\n[+] HTML report saved to: {args.html}")
    if args.json:
        reporter.save_json(args.json)
        print(f"[+] JSON report saved to: {args.json}")
    if args.markdown:
        reporter.save_markdown(args.markdown)
        print(f"[+] Markdown report saved to: {args.markdown}")

    # CI/CD exit code checking
    if args.fail_on:
        threshold = Severity[args.fail_on]
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        threshold_idx = severity_order.index(threshold)
        
        has_failure = any(
            severity_order.index(f.severity) <= threshold_idx
            for f in result.findings
        )
        if has_failure:
            print(f"\n[!] CI/CD Gate Failed: Detected findings at or above {args.fail_on} severity.")
            return 1

    return 0


def handle_batch(args: argparse.Namespace) -> int:
    """Execute batch scan from file."""
    try:
        with open(args.file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except OSError as e:
        print(f"[-] Error reading target file {args.file}: {e}", file=sys.stderr)
        return 1

    print(f"[*] Loaded {len(urls)} targets from {args.file}. Starting batch audit...")
    scanner = WebSecurityScanner(
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        user_agent=args.user_agent,
        proxy=args.proxy
    )

    exit_code = 0
    for idx, target in enumerate(urls, 1):
        print(f"\n[{idx}/{len(urls)}] Auditing target: {target}")
        result = scanner.scan(target)
        reporter = ReportGenerator(result)
        reporter.print_console(verbose=args.verbose)

        # Batch report saving
        safe_name = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        if args.html:
            path = f"{args.output_dir}/{safe_name}.html"
            reporter.save_html(path)
            print(f"[+] HTML: {path}")
        if args.json:
            path = f"{args.output_dir}/{safe_name}.json"
            reporter.save_json(path)
            print(f"[+] JSON: {path}")

    return exit_code


def main(argv: Optional[List[str]] = None) -> int:
    """CLI Main Entry Point."""
    if argv is None:
        argv = sys.argv[1:]

    # Display Banner
    print(BANNER)

    # Convenience shortcut: if first arg starts with http or looks like a URL, default to scan
    if argv and (argv[0].startswith("http://") or argv[0].startswith("https://") or ("." in argv[0] and not argv[0].startswith("-"))):
        if argv[0] not in ("scan", "batch", "demo-server"):
            argv = ["scan"] + argv

    parser = create_parser()

    if not argv:
        parser.print_help()
        return 0

    args = parser.parse_args(argv)

    if args.command == "scan":
        return handle_scan(args)
    elif args.command == "batch":
        return handle_batch(args)
    elif args.command == "demo-server":
        run_demo_server(host=args.host, port=args.port)
        return 0
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
