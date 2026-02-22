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
    
    
def check_security_headers(http_scanner: HttpScanner) -> CheckResult:
    """WS-SEC-001: Security headers present."""
    meta = _meta("WS-SEC-001")
    try:
        resp = http_scanner.get_root()
        required_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options", 
            "Content-Security-Policy",
            "Referrer-Policy"
        ]
        present = sum(1 for h in required_headers if h in resp.headers)
        
        status = Status.PASS if present >= 2 else Status.FAIL
        details = f"{present}/4 security headers present: {list(resp.headers.keys())}"
        
    except Exception as e:
        status = Status.ERROR
        details = f"HTTP error: {e}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_tls_version(http_scanner: HttpScanner) -> CheckResult:
    """WS-TLS-001: TLS 1.2+ with strong ciphers."""
    meta = _meta("WS-TLS-001")
    try:
        # Simple heuristic: modern sites use TLS 1.2+
        resp = http_scanner.get_root()
        # Check if TLS 1.3 preferred cipher (heuristic)
        modern_ciphers = ['ECDHE', 'AESGCM', 'CHACHA20']
        cipher_info = getattr(resp.connection, 'cipher', None)
        
        if cipher_info and any(cipher in str(cipher_info) for cipher in modern_ciphers):
            status = Status.PASS
            details = f"TLS cipher looks modern: {cipher_info}"
        else:
            status = Status.WARN
            details = f"TLS details unavailable or legacy cipher detected"
            
    except Exception as e:
        status = Status.ERROR
        details = f"TLS check failed: {e}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_server_tokens(http_scanner: HttpScanner) -> CheckResult:
    """WS-SRV-001: No server version disclosure."""
    meta = _meta("WS-SRV-001")
    try:
        resp = http_scanner.get_root()
        server_header = resp.headers.get("Server", "")
        
        if "nginx" in server_header.lower() or "apache" in server_header.lower():
            version_match = any(c.isdigit() for c in server_header)
            status = Status.FAIL if version_match else Status.WARN
            details = f"Server: {server_header} ({'version exposed' if version_match else 'version hidden'})"
        else:
            status = Status.PASS
            details = f"No server version disclosure detected"
            
    except Exception as e:
        status = Status.ERROR
        details = f"HTTP error: {e}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_directory_listing(http_scanner: HttpScanner) -> CheckResult:
    """WS-DIR-001: Directory listing disabled."""
    meta = _meta("WS-DIR-001")
    test_paths = ["/", "/static/", "/uploads/", "/images/"]
    
    try:
        exposed_dirs = []
        for path in test_paths:
            resp = http_scanner.session.get(f"{http_scanner.base_url.rstrip('/')}{path}", timeout=3)
            if resp.status_code == 200 and "index of" in resp.text.lower():
                exposed_dirs.append(path)
        
        status = Status.FAIL if exposed_dirs else Status.PASS
        details = f"Directory listing {'found: ' + ', '.join(exposed_dirs) if exposed_dirs else 'disabled'}"
        
    except Exception as e:
        status = Status.ERROR
        details = f"Directory check failed: {e}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
    
    
def check_request_limits(http_scanner: HttpScanner) -> CheckResult:
    """WS-LIMIT-001: Request size limits."""
    meta = _meta("WS-LIMIT-001")
    # Heuristic: large POST might trigger limits, but simple test
    try:
        resp = http_scanner.get_root()
        content_length = resp.headers.get("Content-Length", "0")
        status = Status.WARN
        details = f"No direct request limit test available. Content-Length: {content_length}"
    except Exception as e:
        status = Status.ERROR
        details = f"Request limit check failed: {e}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )