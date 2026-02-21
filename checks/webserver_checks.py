"""
Web Server Layer Checks - Nginx/Apache (6 checks)

1. HSTS header present and strong
2. Security headers (CSP, XFO, XCTO)
3. TLS 1.2+ with strong ciphers
4. No server version disclosure
5. Directory listing disabled
6. Request size limits set
"""


from sec_audit.results import CheckResult, Status, Severity
from scanners.http_scanner import HttpScanner
from sec_audit.config import CHECKS


def _meta(check_id: str):
    for c in CHECKS:
        if c["id"] == check_id:
            return c
    raise KeyError(f"Unknown check id: {check_id}")


def check_hsts_header(http_scanner: HttpScanner) -> CheckResult:
    """
    WS-HSTS-001: HSTS header enabled.

    Logic:
    - Send GET (or HEAD) to root.
    - Look for Strict-Transport-Security header.
    - Parse max-age directive if present; expect >= 31536000 (1 year). [web:249][web:252]
    """
    meta = _meta("WS-HSTS-001")
    try:
        resp = http_scanner.get_root()
        sts = resp.headers.get("Strict-Transport-Security")

        if not sts:
            status = Status.FAIL
            details = "Strict-Transport-Security header is missing."
        else:
            sts_lower = sts.lower()
            max_age_value = None
            for part in sts_lower.split(";"):
                part = part.strip()
                if part.startswith("max-age"):
                    try:
                        _, value = part.split("=")
                        max_age_value = int(value)
                    except Exception:
                        pass

            if max_age_value is not None and max_age_value >= 31536000:
                status = Status.PASS
                details = f"HSTS present with strong max-age={max_age_value}."
            else:
                status = Status.WARN
                details = f"HSTS present but max-age appears weak or unparseable: {sts!r}"
    except Exception as e:
        status = Status.ERROR
        details = f"HTTP error while checking HSTS header: {e!r}"

    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=status,
        severity=Severity[meta["severity"]],
        details=details,
    )