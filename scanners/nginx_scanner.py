"""nginx.conf parsing (webserver layer)
    Use a small parser library like nginxparser_eb to avoid regex hell.
    
    Files / structure
    New module: scanners/nginx_scanner.py

    New checks file (or extend existing): e.g. checks/webserver_checks.py plus config-oriented checks.
"""


from typing import Optional
from nginxparser_eb import load


class NginxConfigScanner:
    def __init__(self, path: str, verbose: bool = False):
        self.path = path
        self.verbose = verbose
        self.tree = None

    def load(self):
        if self.verbose:
            print(f"[DEBUG] NGINX: loading config from {self.path!r}")
        with open(self.path, "r", encoding="utf-8") as f:
            self.tree = load(f)
        if self.verbose:
            print(f"[DEBUG] NGINX: parsed config tree with {len(self.tree)} top-level entries")
            
    def _walk(self, block, predicate) -> bool:
        for item in block:
            if isinstance(item, list):
                if predicate(item):
                    return True
                # nested blocks
                if any(isinstance(x, list) for x in item):
                    if self._walk(item, predicate):
                        return True
        return False

    def has_security_header(self, header_name: str) -> bool:
        """Check if add_header <header_name> appears anywhere."""
        if self.tree is None:
            self.load()
            
        def pred(item):
            return len(item) >= 2 and item[0] == "add_header" and header_name in item[1]
        
        return self._walk(self.tree, pred)
    
    def has_csp(self) -> bool:
        """Check for a Content-Security-Policy header."""
        return self.has_header("Content-Security-Policy")