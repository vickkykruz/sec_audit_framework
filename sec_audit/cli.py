"""
Command line argument parsing and validation.

Supports:
--target URL          Target web application
--mode full|quick     Scan scope
--ssh-key PATH        SSH private key for host checks
--docker-host URL     Docker daemon endpoint
--output PATH         PDF report path
--json PATH           JSON export path
"""


# Uses argparse for CLI interface
import argparse
from types import SimpleNamespace

from sec_audit.config import get_layer_totals
from scanners.http_scanner import HttpScanner
from checks.app_checks import check_debug_mode, check_secure_cookies
from checks.webserver_checks import check_hsts_header
from sec_audit.results import CheckResult


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the argument parser."""

    parser = argparse.ArgumentParser(
        prog="sec_audit",
        description="""
        🏛️  SECURITY AUDIT FRAMEWORK
        Automated Web Application Security Configuration Assessment
                
        Scans 24 configuration checks across 4 layers:
        • Web App (Flask/Django): debug mode, CSRF, cookies
        • Web Server (Nginx/Apache): HSTS, security headers, TLS
        • Container (Docker): non-root user, resource limits
        • Host (Linux): SSH hardening, firewall, services
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        🚀 USAGE EXAMPLES:

            BASIC SCAN (HTTP only):
            python sec_audit.py --target https://example.com

            FULL STACK SCAN (HTTP + Docker + SSH):
            python sec_audit.py --target https://lms.example.com --mode full --output report.pdf

            DEVELOPMENT / LOCAL:
            python sec_audit.py --target http://localhost:5000 --json results.json

            CI/CD PIPELINE:
            python sec_audit.py --target $APP_URL --json /tmp/audit.json --mode quick

            📄 Output Formats:
            --output report.pdf    → Professional PDF remediation report
            --json results.json    → Structured JSON for automation
            (stdout)               → Console summary (default)
        """
    )
    
    # Core arguments
    parser.add_argument(
        "--target", "-t", 
        required=True,
        help="""
        Target web application URL.
        Examples: https://example.com, http://localhost:5000, https://staging.lms.internal
        """,
        metavar="URL"
    )
    
    parser.add_argument(
        "--mode", "-m",
        choices=["quick", "full"],
        default="quick",
        help="""
        Scan scope:
        • quick: HTTP checks only (app + webserver layers, ~30 seconds)
        • full:  HTTP + Docker + SSH checks (all 4 layers, ~2 minutes)
        """,
        metavar="MODE"
    )
    
    parser.add_argument(
       "--output", "-o",
        help="""
        Path to PDF remediation report.
        Example: --output security_audit.pdf
        """,
        metavar="PATH"
    )
    
    parser.add_argument(
        "--json", "-j",
        help="""
        Path to JSON results (CI/CD friendly).
        Example: --json /tmp/audit-results.json
        """,
        metavar="PATH"
    )
    
    # ==================== FUTURE ARGUMENTS (Day 3+) ====================
    docker_group = parser.add_argument_group("Docker scanning (full mode)")
    docker_group.add_argument(
        "--docker-host",
        help="Docker daemon endpoint (tcp://host:port or unix:///var/run/docker.sock)",
        metavar="DOCKER_URL"
    )
    
    ssh_group = parser.add_argument_group("SSH host scanning (full mode)") 
    ssh_group.add_argument("--ssh-host", help="SSH target host/IP")
    ssh_group.add_argument("--ssh-key", help="SSH private key path")
    ssh_group.add_argument("--ssh-user", default="root", help="SSH username (default: root)")
    
    # ==================== DEBUG / DEV ====================
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output for debugging"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Security Audit Framework v1.0.0 (MSc Research Prototype)",
        help="Show version information"
    )
    
    return parser


def run_from_args(args: SimpleNamespace) -> None:
    """Execute scan based on parsed arguments."""
    print(f"🏛️  [SEC-AUDIT v1.0.0] Starting scan...")
    print(f"  🎯 Target: {args.target}")
    print(f"  ⚙️  Mode: {args.mode}")
    print(f"  📄 Output: {args.output or 'stdout'}")
    print(f"  💾 JSON: {args.json or 'none'}")
    
    if args.verbose:
        print(f"  🔧 Verbose: enabled")
    print()
    
    # Day 2 Integration Test
    try:
        from sec_audit.config import get_layer_totals
        totals = get_layer_totals()
        print("📊 Check Distribution:")
        for layer, count in totals.items():
            print(f"  {layer:10}: {count} checks")
        print()
    except ImportError:
        print("[INFO] config.py not yet implemented (Day 2 pending)")
        
    # ───────── REAL DAY 3 SCANNING ─────────
    http_scanner = HttpScanner(args.target)

    results: list[CheckResult] = []
    results.append(check_debug_mode(http_scanner))
    results.append(check_secure_cookies(http_scanner))
    results.append(check_hsts_header(http_scanner))

    print("🔎 HTTP Checks (Day 3):")
    for r in results:
        print(f"  [{r.status:5}] {r.id} - {r.name} ({r.severity})")
        print(f"        {r.details}")
    
    print("🚧 [PIPELINE] Scanning would execute here...")
    print("   • Initialize HTTP/Docker/SSH scanners")
    print("   • Execute layer-specific checks")
    print("   • Generate PDF/JSON reports")
    print()
    
    print("✅ CLI working correctly! Ready for Day 2 (check definitions).")