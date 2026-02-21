"""
Web Application Layer Security Checks (6 checks)

1. Debug mode disabled
2. Secure session cookies (HttpOnly/Secure/SameSite)
3. CSRF protection enabled
4. No exposed admin/debug endpoints
5. Rate limiting configured
6. Strong password policy
"""


from sec_audit.results import CheckResult
from scanners.http_scanner import HttpScanner
from sec_audit.config import CHECKS


def _meta(check_id: str):
    """Helper to pull metadata from CHECKS by id."""
    for c in CHECKS:
        if c["id"] == check_id:
            return c
    raise KeyError(f"Unknown check id: {check_id}")


def check_debug_mode(http_scanner: HttpScanner) -> CheckResult:
    """
    APP-DEBUG-001: Heuristic debug mode detection.

    Logic (simple but real):
    - Fetch root page.
    - Look for typical traceback/debug strings in HTML body, such as:
      "Traceback (most recent call last)", "Exception Type", etc. [web:244][web:248][web:251]
    """
    meta = _meta("APP-DEBUG-001")
    try:
        resp = http_scanner.get_root()
        body = resp.text or ""
        debug_markers = [
            "Traceback (most recent call last)",
            "Exception Type:",
            "Django Debug",
            "Werkzeug Debugger",
        ]
        if any(marker in body for marker in debug_markers):
            status = "FAIL"
            details = "Debug-style error/traceback content detected in root response."
        else:
            status = "PASS"
            details = "No obvious debug/traceback content in root response."
    except Exception as e:
        status = "ERROR"
        details = f"HTTP error while checking debug mode: {e!r}"

    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=status,
        severity=meta["severity"],
        details=details,
    )
    
    
def check_secure_cookies(http_scanner: HttpScanner) -> CheckResult:
    """
    APP-COOKIE-001: Secure session cookies.

    Logic:
    - Fetch root page.
    - Inspect response.cookies (Set-Cookie headers).
    - PASS if at least one cookie has BOTH HttpOnly and Secure flags.
    - WARN if cookies exist but lack one of the flags.
    - FAIL if cookies exist and none have any security flags. [web:250][web:253]
    """
    meta = _meta("APP-COOKIE-001")
    try:
        resp = http_scanner.get_root()
        cookies = resp.cookies  # RequestsCookieJar

        if not cookies:
            status = "WARN"
            details = "No cookies observed on root response; cannot assess session cookie security."
        else:
            # requests cookies only expose some flags; we inspect headers for full detail
            set_cookie_headers = resp.headers.get("Set-Cookie", "")
            # In case of multiple Set-Cookie, requests concatenates; this is still usable for heuristics.
            set_cookie_combined = set_cookie_headers.lower()

            has_secure = "secure" in set_cookie_combined
            has_httponly = "httponly" in set_cookie_combined

            if has_secure and has_httponly:
                status = "PASS"
                details = "At least one cookie appears to use both Secure and HttpOnly flags."
            elif has_secure or has_httponly:
                status = "WARN"
                details = "Cookies present but missing one of Secure/HttpOnly flags."
            else:
                status = "FAIL"
                details = "Cookies present but no Secure or HttpOnly flags detected in Set-Cookie."
    except Exception as e:
        status = "ERROR"
        details = f"HTTP error while checking secure cookies: {e!r}"

    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=status,
        severity=meta["severity"],
        details=details,
    )