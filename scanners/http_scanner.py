"""
HTTP Client for web app and webserver checks.
 
Uses requests library for:
- Header inspection
- TLS/cipher analysis
- Cookie flag checking
- Endpoint discovery
"""
 
 
from typing import Optional
import requests
 
from sec_audit.results import ScanResult
 
 
class HttpScanner:
    """Simple HTTP scanner wrapper around requests."""
 
    def __init__(self, base_url: str, timeout: int = 5, scan_result: Optional[ScanResult] = None) -> None:
        # Strip query strings and fragments from base_url so path construction
        # works correctly. e.g. https://example.com/index.php?page → https://example.com/index.php
        from urllib.parse import urlparse, urlunparse
        parsed   = urlparse(base_url)
        clean    = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        self.base_url    = clean.rstrip("/")
        self.raw_url     = base_url   # preserve original for display
        self.timeout     = timeout
        self.session     = requests.Session()
        # Use a realistic browser User-Agent.
        # Many shared hosting servers and WAFs (mod_security, Cloudflare)
        # silently drop requests with the default python-requests UA string.
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.5",
        })
        self.scan_result = scan_result
 
        # scan_root: base used for path construction in checks.
        # When the URL ends in a filename (e.g. /index.php), paths like
        # /admin must be appended to the directory, not to the filename.
        # e.g. https://example.com/app/index.php → scan_root = https://example.com/app
        _last_segment = parsed.path.rstrip("/").split("/")[-1]
        if "." in _last_segment:  # ends in a file (index.php, page.html, etc.)
            _dir_path = "/".join(parsed.path.rstrip("/").split("/")[:-1])
            self.scan_root = urlunparse(
                (parsed.scheme, parsed.netloc, _dir_path, "", "", "")
            ).rstrip("/")
        else:
            self.scan_root = self.base_url  # no filename — use as-is
 
    def detect_stack(self) -> dict:
        """
        Detect the application stack from HTTP response headers and URL patterns.
        Returns a dict with keys: language, framework, webserver, is_php, is_python, is_shared_hosting
        Used by patch generator to produce language-appropriate remediation.
        """
        result = {
            "language":           "unknown",
            "framework":          "unknown",
            "webserver":          "unknown",
            "is_php":             False,
            "is_python":          False,
            "is_shared_hosting":  False,
        }
        try:
            resp = self.get_root()
            headers = {k.lower(): v for k, v in resp.headers.items()}
 
            # Detect webserver
            server = headers.get("server", "").lower()
            if "nginx"   in server: result["webserver"] = "nginx"
            elif "apache" in server: result["webserver"] = "apache"
            elif "iis"    in server: result["webserver"] = "iis"
            elif "cloudflare" in server: result["webserver"] = "cloudflare"
 
            # Detect language from X-Powered-By
            powered_by = headers.get("x-powered-by", "").lower()
            if "php" in powered_by:
                result["language"] = "php"
                result["is_php"]   = True
            elif "express" in powered_by or "node" in powered_by:
                result["language"] = "nodejs"
            elif "asp.net" in powered_by:
                result["language"] = "dotnet"
 
            # Detect PHP from URL pattern even without header
            if not result["is_php"] and ".php" in self.raw_url.lower():
                result["language"] = "php"
                result["is_php"]   = True
 
            # Detect PHP from session cookie
            for cookie in resp.cookies:
                if "phpsessid" in cookie.name.lower():
                    result["language"] = "php"
                    result["is_php"]   = True
                    break
 
            # Detect Python frameworks
            if not result["is_php"]:
                if "wsgi" in server or "gunicorn" in server or "uvicorn" in server:
                    result["is_python"] = True
                    result["language"]  = "python"
                # Check for Django/Flask tells
                for cookie in resp.cookies:
                    if cookie.name in ("csrftoken", "sessionid"):
                        result["is_python"]  = True
                        result["language"]   = "python"
                        result["framework"]  = "django"
 
            # Detect shared hosting (Apache + PHP, no gunicorn/uwsgi tells)
            if result["is_php"] and result["webserver"] in ("apache", "unknown"):
                result["is_shared_hosting"] = True
 
        except Exception:
            pass
 
        # URL-based PHP detection — runs even when connection fails
        # so detect_stack() is useful even on unreachable targets
        if not result["is_php"] and ".php" in self.raw_url.lower():
            result["language"] = "php"
            result["is_php"]   = True
            if result["is_shared_hosting"] is False and result["webserver"] in ("apache", "unknown"):
                result["is_shared_hosting"] = True
 
        return result
 
 
    def get_root(self) -> requests.Response:
        """
        Perform a GET request to the root URL.
 
        Returns:
            requests.Response object with text, status_code, headers, cookies, etc.
        """
        response = self.session.get(
            self.base_url,
            timeout=self.timeout,
            allow_redirects=True,
        )
        
        # Version fingerprinting (optional, safe no-op if scan_result is None)
        if self.scan_result is not None:
            server_header = response.headers.get("Server", "")
            if server_header:
                self.scan_result._webserver_version = server_header
 
            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by:
                # Simple heuristic: record as app version hint
                self.scan_result._app_version = powered_by
 
        return response
 
    
    def head_root(self) -> requests.Response:
        """
        Perform a HEAD request to the root URL.
 
        Returns:
            requests.Response object with headers and status_code.
        """
        response = self.session.head(
            self.base_url,
            timeout=self.timeout,
            allow_redirects=True,
        )
        return response
  