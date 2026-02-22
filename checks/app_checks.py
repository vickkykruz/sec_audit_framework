"""
Web Application Layer Security Checks (6 checks)

1. Debug mode disabled
2. Secure session cookies (HttpOnly/Secure/SameSite)
3. CSRF protection enabled
4. No exposed admin/debug endpoints
5. Rate limiting configured
6. Strong password policy
"""


from sec_audit.results import CheckResult, Status, Severity
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
            status = Status.FAIL
            details = "Debug-style error/traceback content detected in root response."
        else:
            status = Status.PASS
            details = "No obvious debug/traceback content in root response."
    except Exception as e:
        status = Status.ERROR
        details = f"HTTP error while checking debug mode: {e!r}"

    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=status,
        severity=Severity[meta["severity"]],
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
            status = Status.WARN
            details = "No cookies observed on root response; cannot assess session cookie security."
        else:
            # requests cookies only expose some flags; we inspect headers for full detail
            set_cookie_headers = resp.headers.get("Set-Cookie", "")
            # In case of multiple Set-Cookie, requests concatenates; this is still usable for heuristics.
            set_cookie_combined = set_cookie_headers.lower()

            has_secure = "secure" in set_cookie_combined
            has_httponly = "httponly" in set_cookie_combined

            if has_secure and has_httponly:
                status = Status.PASS
                details = "At least one cookie appears to use both Secure and HttpOnly flags."
            elif has_secure or has_httponly:
                status = Status.WARN
                details = "Cookies present but missing one of Secure/HttpOnly flags."
            else:
                status = Status.FAIL
                details = "Cookies present but no Secure or HttpOnly flags detected in Set-Cookie."
    except Exception as e:
        status = Status.ERROR
        details = f"HTTP error while checking secure cookies: {e!r}"

    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=status,
        severity=Severity[meta["severity"]],
        details=details,
    )
    
    
def check_csrf_protection(http_scanner: HttpScanner) -> CheckResult:
    """APP-CSRF-001: CSRF protection enabled."""
    meta = _meta("APP-CSRF-001")
    try:
        resp = http_scanner.get_root()
        # Simple heuristic: look for CSRF token fields in forms
        has_csrf_patterns = any(pattern in resp.text.lower() 
                              for pattern in ["csrf", "token", "_token"])
        status = Status.PASS if has_csrf_patterns else Status.FAIL
        details = f"CSRF patterns {'detected' if status == Status.PASS else 'missing'}."
    except Exception as e:
        status = Status.ERROR
        details = f"HTTP error: {e}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_admin_endpoints(http_scanner: HttpScanner) -> CheckResult:
    """APP-ADMIN-001: No exposed admin endpoints."""
    meta = _meta("APP-ADMIN-001")
    admin_paths = ["/admin", "/debug", "/test", "/wp-admin"]
    exposed = []
    
    for path in admin_paths:
        try:
            resp = http_scanner.session.get(f"{http_scanner.base_url}{path}", 
                                          timeout=3)
            if resp.status_code == 200:
                exposed.append(path)
        except:
            pass
    
    status = Status.FAIL if exposed else Status.PASS
    details = f"Admin paths {'exposed: ' + ', '.join(exposed) if exposed else 'none found'}."
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_rate_limiting(http_scanner: HttpScanner) -> CheckResult:
    """APP-RATE-001: Rate limiting configured."""
    meta = _meta("APP-RATE-001")
    # Simple test: make 5 rapid requests, expect 429 on some
    responses = []
    for i in range(5):
        try:
            resp = http_scanner.session.get(http_scanner.base_url, timeout=2)
            responses.append(resp.status_code)
        except:
            responses.append(0)
    
    throttled = 429 in responses
    status = Status.PASS if throttled else Status.WARN
    details = f"Rate limiting {'detected (429)' if throttled else 'not evident'}."
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_password_policy(http_scanner: HttpScanner) -> CheckResult:
    """APP-PASS-001: Strong password policy."""
    meta = _meta("APP-PASS-001")
    # Heuristic: look for password complexity hints in HTML
    complexity_hints = ["12 characters", "uppercase", "lowercase", "special", "number"]
    hints_found = sum(1 for hint in complexity_hints if hint in http_scanner.get_root().text.lower())
    
    status = Status.PASS if hints_found >= 2 else Status.WARN
    details = f"Password hints: {hints_found}/5 complexity requirements mentioned."
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )