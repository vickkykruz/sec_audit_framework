#!/usr/bin/env python3


"""
Security Audit Framework CLI - Main entrypoint for web app configuration assessment.

Usage: python sec_audit.py --target http://example.com --output report.pdf
"""


# CLI imports and main execution logic
from types import SimpleNamespace
from sec_audit.cli import build_parser, run_from_args


def main():
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()
    
    try:
        run_from_args(args)
    except KeyboardInterrupt:
        # Graceful termination on Ctrl+C
        print("\n[INFO] Scan interrupted by user (Ctrl+C). Cleaning up and exiting...")
        # Optional: if you have any global cleanup, call it here
    except EOFError:
        # Handles Ctrl+D (Unix) / some EOF conditions
        print("\n[INFO] Input stream closed (EOF). Exiting...")

 
if __name__ == "__main__":
    main()