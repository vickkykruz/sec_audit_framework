"""
StackSentry — Automated web application security assessment and remediation.
 
Usage:
    stacksentry --target https://example.com
    stacksentry --target https://example.com --mode full --patch --fix
"""
 
__version__ = "1.0.0"
__author__  = "Victor Chukwuemeka Onwuegbuchulem"
__license__ = "MIT"
 
 
def main() -> None:
    """Entry point for the `stacksentry` CLI command after pip install."""
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
 
    from sec_audit.cli import build_parser, run_from_args
 
    parser = build_parser()
    args   = parser.parse_args()
 
    try:
        run_from_args(args)
    except KeyboardInterrupt:
        print("\n[INFO] Scan interrupted. Exiting...")
    except EOFError:
        print("\n[INFO] Input stream closed. Exiting...")