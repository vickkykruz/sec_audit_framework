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


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the argument parser."""

    parser = argparse.ArgumentParser(
        prog="sec_audit",
        description="Security Audit Framework - Web app configuration assessment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
            python sec_audit.py --target https://example.com
            python sec_audit.py --target https://lms.example.com --mode full --output report.pdf
            python sec_audit.py --target http://localhost:5000 --json results.json
        """
    )
    
    # Core arguments
    parser.add_argument(
        "--target", 
        required=True,
        help="Target URL (e.g. https://example.com)"
    )
    
    parser.add_argument(
        "--mode",
        choices=["quick", "full"],
        default="quick",
        help="Scan mode: quick (HTTP only) or full (HTTP+Docker+SSH)"
    )
    
    parser.add_argument(
        "--output", "-o",
        help="Path to PDF report"
    )
    
    parser.add_argument(
        "--json", "-j",
        help="Path to JSON results"
    )
    
    # Future arguments (commented out for Day 1)
    # parser.add_argument("--docker-host", help="Docker daemon endpoint")
    # parser.add_argument("--ssh-host", help="SSH target host")
    # parser.add_argument("--ssh-key", help="SSH private key path")
    
    return parser


def run_from_args(args: SimpleNamespace) -> None:
    """Execute scan based on parsed arguments."""
    print(f"[SEC-AUDIT v1.0.0] Starting scan...")
    print(f"  Target: {args.target}")
    print(f"  Mode: {args.mode}")
    print(f"  Output: {args.output or 'stdout'}")
    print(f"  JSON: {args.json or 'none'}")
    print()
    
    print("[DRY RUN] Scanning pipeline would execute here...")
    print("[DRY RUN] 24 security checks across 4 layers...")
    print()
    
    print("✅ CLI working correctly! Ready for Day 2 (check definitions).")