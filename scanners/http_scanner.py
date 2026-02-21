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


class HttpScanner:
    """Simple HTTP scanner wrapper around requests."""

    def __init__(self, base_url: str, timeout: int = 5) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()


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