#!/usr/bin/env python3


"""
Security Audit Framework CLI - Main entrypoint for web app configuration assessment.

Usage: python sec_audit.py --target http://example.com --output report.pdf
"""


# CLI imports and main execution logic
from sec_audit.cli import build_parser, run_from_args


def main():
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args()
    run_from_args(args)

 
if __name__ == "__main__":
    main()