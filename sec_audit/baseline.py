"""
Baseline models for configuration drift detection.
"""


from dataclasses import dataclass
from typing import Dict


@dataclass
class BaselineProfile:
    """This is Simple Baseline Model Class"""
    name: str
    description: str
    expected_passes: int
    expected_grade: str
    check_statuses: Dict[str, str]  # check_id -> expected status ("PASS"/"FAIL"/"WARN"/"ERROR")
    
    
# Example: Hardened Flask LMS baseline
HARDENED_FLASK_BASELINE = BaselineProfile(
    name="Hardened Flask LMS",
    description="Baseline after applying OWASP/NCSC hardening to a Flask LMS deployment.",
    expected_passes=22,          # you can tune this later
    expected_grade="A",
    check_statuses={
        # Web Application layer (Flask LMS hardened)
        "APP-DEBUG-001": "PASS",  # DEBUG=False in production
        "APP-COOKIE-001": "PASS", # Secure + HttpOnly cookies set
        "APP-CSRF-001": "PASS",   # CSRF tokens enabled
        "APP-ADMIN-001": "PASS",  # Admin endpoints protected / not exposed
        "APP-RATE-001": "PASS",   # Some rate limiting / throttling present
        "APP-PASS-001": "PASS",   # Strong password policy hints shown

        # Web Server layer (Nginx/Apache hardened)
        "WS-HSTS-001": "PASS",    # Strict-Transport-Security present with strong max-age
        "WS-SEC-001": "PASS",     # XFO/XCTO/CSP, etc. mostly present
        "WS-TLS-001": "PASS",     # TLS 1.2+/modern ciphers
        "WS-SRV-001": "PASS",     # Server tokens minimized, no version disclosure
        "WS-DIR-001": "PASS",     # No directory listing exposed
        "WS-LIMIT-001": "PASS",   # Reasonable request limits configured

        # Container layer (after proper Docker hardening)
        "CONT-USER-001": "PASS",  # Non-root user in container
        "CONT-PORT-001": "PASS",  # Only required ports exposed
        "CONT-RES-001": "PASS",   # CPU/memory limits set
        "CONT-HEALTH-001": "PASS",# HEALTHCHECK in Dockerfile
        "CONT-REG-001": "PASS",   # Images from trusted registry
        "CONT-SEC-001": "PASS",   # No secrets in docker-compose/Dockerfile

        # Host layer (after host hardening)
        "HOST-SSH-001": "PASS",   # PermitRootLogin no, PasswordAuthentication no
        "HOST-SVC-001": "PASS",   # Minimal unnecessary services
        "HOST-UPDATE-001": "PASS",# Unattended security updates enabled
        "HOST-PERM-001": "PASS",  # No world-writable sensitive files
        "HOST-FW-001": "PASS",    # Firewall enabled and limited
        "HOST-LOG-001": "PASS",   # Logging service active & writing
    },
)