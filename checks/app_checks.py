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
 
 
def check_debug_mode(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
    """
    APP-DEBUG-001: Heuristic debug mode detection.
 
    Logic (simple but real):
    - Fetch root page.
    - Look for typical traceback/debug strings in HTML body, such as:
      "Traceback (most recent call last)", "Exception Type", etc. [web:244][web:248][web:251]
    """
    meta = _meta("APP-DEBUG-001")
    try:
        if verbose:
            print("[DEBUG] APP-DEBUG-001: fetching root URL to inspect for debug markers...")
        resp = http_scanner.get_root()
        body = resp.text or ""
        if verbose:
            print(f"[DEBUG] APP-DEBUG-001: status={resp.status_code}, body_len={len(body)}")
        
        debug_markers = [
            "Traceback (most recent call last)",
            "Exception Type:",
            "Django Debug",
            "Werkzeug Debugger",
        ]
        if any(marker in body for marker in debug_markers):
            status = Status.FAIL
            details = "DEBUG=True detected. → Set DEBUG=False in config.py or environment"
        else:
            status = Status.PASS
            details = "No obvious debug/traceback content in root response."
    except Exception as e:
        if verbose:
            print(f"[DEBUG] APP-DEBUG-001: exception {e!r}")
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
    
    
def check_secure_cookies(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
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
        if verbose:
            print("[DEBUG] APP-COOKIE-001: fetching root URL to inspect cookies...")
        resp = http_scanner.get_root()
        cookies = resp.cookies  # RequestsCookieJar
        set_cookie_headers = resp.headers.get("Set-Cookie", "")
        combined = set_cookie_headers.lower()
        
        if verbose:
            print(
                f"[DEBUG] APP-COOKIE-001: cookies={list(cookies.keys())}, "
                f"Set-Cookie='{set_cookie_headers}'"
            )
 
        if not cookies:
            status = Status.WARN
            details = "No cookies observed on root response; cannot assess session cookie security."
        else:
            has_secure = "secure" in combined
            has_httponly = "httponly" in combined
 
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
        if verbose:
            print(f"[DEBUG] APP-COOKIE-001: exception {e!r}")
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
    
    
def check_csrf_protection(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
    """APP-CSRF-001: CSRF protection enabled.
 
    Uses three detection strategies to cover traditional and SPA frameworks:
 
    Strategy 1 — Form tokens (Django, Flask-WTF, Laravel):
      Looks for csrfmiddlewaretoken, csrf_token fields in the HTML body.
 
    Strategy 2 — Response headers (API-first apps):
      Looks for X-CSRF-Token, X-Frame-Options (indirect CSRF mitigation).
 
    Strategy 3 — Cookie-based XSRF (Angular, React, Vue SPAs):
      Angular sets XSRF-TOKEN cookie. Any cookie name/value containing
      'xsrf' or 'csrf' indicates SPA-framework CSRF protection.
      This is the standard approach for all modern SPA frameworks.
    """
    meta = _meta("APP-CSRF-001")
    try:
        if verbose:
            print("[DEBUG] APP-CSRF-001: fetching root URL to look for CSRF hints...")
        resp = http_scanner.get_root()
        text = resp.text.lower()
 
        # Strategy 1: HTML form token patterns
        form_indicators = [
            'name="csrf_token"',
            "csrfmiddlewaretoken",
            "x-csrftoken",
            "csrf-token",
            "_token",           # Laravel
            "authenticity_token",  # Rails
        ]
        strategy1 = any(ind in text for ind in form_indicators)
        if verbose and strategy1:
            matched = [i for i in form_indicators if i in text]
            print(f"[DEBUG] APP-CSRF-001: Strategy 1 (form token) matched: {matched}")
 
        # Strategy 2: Response headers indicating CSRF protection
        resp_headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        header_indicators  = ["x-csrf-token", "x-xsrf-token"]
        strategy2 = any(h in resp_headers_lower for h in header_indicators)
        if verbose and strategy2:
            print(f"[DEBUG] APP-CSRF-001: Strategy 2 (response header) matched")
 
        # Strategy 3: Cookie-based XSRF token (Angular, Vue, React SPAs)
        strategy3        = False
        xsrf_cookie_name = None
        for cookie in resp.cookies:
            if "xsrf" in cookie.name.lower() or "csrf" in cookie.name.lower():
                strategy3        = True
                xsrf_cookie_name = cookie.name
                break
        # Also check Set-Cookie header directly (covers httponly xsrf tokens)
        set_cookie = resp.headers.get("Set-Cookie", "").lower()
        if not strategy3 and ("xsrf" in set_cookie or "csrf" in set_cookie):
            strategy3        = True
            xsrf_cookie_name = "xsrf/csrf cookie in Set-Cookie header"
        if verbose:
            print(f"[DEBUG] APP-CSRF-001: Strategy 3 (XSRF cookie) found={strategy3}"
                  f"{f', cookie={xsrf_cookie_name!r}' if xsrf_cookie_name else ''}")
 
        has_protection = strategy1 or strategy2 or strategy3
 
        if has_protection:
            methods = []
            if strategy1: methods.append("form token")
            if strategy2: methods.append("response header")
            if strategy3: methods.append(f"XSRF cookie ({xsrf_cookie_name})")
            status  = Status.PASS
            details = f"CSRF protection detected via: {', '.join(methods)}."
        else:
            status  = Status.FAIL
            details = ("No CSRF protection detected. No form tokens, CSRF headers, "
                       "or XSRF cookies found. Enable CSRF middleware.")
 
        if verbose:
            print(f"[DEBUG] APP-CSRF-001: result={status.value}, {details}")
 
    except Exception as e:
        if verbose:
            print(f"[DEBUG] APP-CSRF-001: exception {e!r}")
        status  = Status.ERROR
        details = f"HTTP error while checking CSRF protection: {e}"
 
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_admin_endpoints(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
    """APP-ADMIN-001: No exposed admin endpoints.
 
    SPA-aware: Single Page Applications (React, Angular, Vue) return HTTP 200
    for every route because routing is handled client-side. A 200 response with
    the same body as the homepage is the SPA shell, not a real admin page.
 
    Logic:
      - 200 + unique content  → FAIL  (real admin page is accessible)
      - 200 + same as homepage → WARN  (SPA shell, likely just login wall)
      - 403 / 401 / 404 / redirect → PASS (properly blocked or absent)
    """
    meta = _meta("APP-ADMIN-001")
    # PHP/CMS-aware admin paths — covers WordPress, Joomla, phpMyAdmin,
    # cPanel shared hosting, and generic PHP admin conventions
    admin_paths = [
        "/admin",           # generic
        "/admin/index.php", # generic PHP
        "/debug",           # dev endpoints
        "/test",            # dev endpoints
        "/wp-admin",        # WordPress
        "/wp-login.php",    # WordPress login
        "/administrator",   # Joomla
        "/phpmyadmin",      # phpMyAdmin (most attacked PHP path)
        "/pma",             # phpMyAdmin alias
        "/cpanel",          # cPanel shared hosting
    ]
 
    # Step 1: Get homepage body length as SPA baseline
    homepage_len = None
    try:
        home_resp = http_scanner.get_root()
        homepage_len = len(home_resp.content)
        if verbose:
            print(f"[DEBUG] APP-ADMIN-001: homepage baseline body_len={homepage_len}")
    except Exception:
        pass
 
    confirmed_exposed = []   # 200 + unique body — genuinely accessible
    spa_ambiguous     = []   # 200 + same as homepage — SPA shell, unclear
    responded         = []   # paths that gave ANY HTTP response
    errored           = []   # paths that threw connection exceptions
 
    for path in admin_paths:
        url = f"{getattr(http_scanner, 'scan_root', http_scanner.base_url).rstrip('/')}{path}"
        try:
            if verbose:
                print(f"[DEBUG] APP-ADMIN-001: GET {url}")
            resp = http_scanner.session.get(url, timeout=3, allow_redirects=False)
            body_len = len(resp.content)
            if verbose:
                print(
                    f"[DEBUG] APP-ADMIN-001: {path} status={resp.status_code}, "
                    f"body_len={body_len}, Location={resp.headers.get('Location')!r}"
                )
 
            if resp.status_code == 200:
                # Check if this is a SPA returning the same shell as homepage
                if homepage_len is not None and body_len == homepage_len:
                    spa_ambiguous.append(path)
                    if verbose:
                        print(f"[DEBUG] APP-ADMIN-001: {path} matches SPA homepage — likely login wall")
                else:
                    confirmed_exposed.append(path)
                    if verbose:
                        print(f"[DEBUG] APP-ADMIN-001: {path} has unique content — likely real endpoint")
            # 401, 403, 404, 3xx all indicate the path is properly handled
            responded.append(path)
        except Exception as e:
            if verbose:
                print(f"[DEBUG] APP-ADMIN-001: exception on {path}: {e!r}")
            errored.append(path)
            continue
 
    all_failed = len(responded) == 0 and len(errored) > 0
 
    if confirmed_exposed:
        status  = Status.FAIL
        details = (f"Admin endpoint(s) with unique content exposed: "
                   f"{', '.join(confirmed_exposed)}. Verify and restrict access.")
    elif spa_ambiguous:
        status  = Status.WARN
        details = (f"Admin path(s) return 200 with SPA shell content "
                   f"({', '.join(spa_ambiguous)}). Likely a login wall — "
                   f"verify these paths are properly authenticated.")
    elif all_failed:
        status  = Status.WARN
        details = (f"Could not connect to any of {len(errored)} admin path(s). "
                   "Server may be blocking requests. Verify manually.")
    else:
        status  = Status.PASS
        details = "Admin paths not accessible (404/403/redirect). No exposure detected."
 
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_rate_limiting(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
    """APP-RATE-001: Rate limiting configured."""
    meta = _meta("APP-RATE-001")
    # Simple test: make 5 rapid requests, expect 429 on some
    responses = []
    for i in range(5):
        try:
            if verbose:
                print(f"[DEBUG] APP-RATE-001: request {i+1}/5 to {http_scanner.base_url}")
            resp = http_scanner.session.get(http_scanner.base_url, timeout=2)
            responses.append(resp.status_code)
            if verbose:
                print(f"[DEBUG] APP-RATE-001: status={resp.status_code}")
        except Exception as e:
            if verbose:
                print(f"[DEBUG] APP-RATE-001: exception on request {i+1}: {e!r}")
            responses.append(0)
    
    throttled = 429 in responses
    status = Status.PASS if throttled else Status.WARN
    details = f"Rate limiting {'detected (429)' if throttled else 'not evident'}."
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_password_policy(http_scanner: HttpScanner, verbose: bool = False) -> CheckResult:
    """APP-PASS-001: Strong password policy."""
    meta = _meta("APP-PASS-001")
    try:
        # Heuristic: look for password complexity hints in HTML
        if verbose:
            print("[DEBUG] APP-PASS-001: fetching root URL to look for password hints...")
        
        text = http_scanner.get_root().text.lower()
        complexity_hints = ["12 characters", "uppercase", "lowercase", "special", "number"]
        hints_found = sum(1 for hint in complexity_hints if hint in text)
        
        if verbose:
            print(f"[DEBUG] APP-PASS-001: hints_found={hints_found}")
    
        status = Status.PASS if hints_found >= 2 else Status.WARN
        details = f"Password hints: {hints_found}/5 complexity requirements mentioned."
    except Exception as e:
        if verbose:
            print(f"[DEBUG] APP-PASS-001: exception {e!r}")
        status = Status.ERROR
        details = f"HTTP error while checking password policy hints: {e!r}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )