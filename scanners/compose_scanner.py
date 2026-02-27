"""Composer client for container runtime analysis.

"""


from pathlib import Path
from typing import Optional, Dict, Any
import yaml


class ComposeScanner:
    def __init__(self, path: str, verbose: bool = False):
        self.path = Path(path)
        self.verbose = verbose
        self.data: Dict[str, Any] = {}

    def load(self):
        if self.verbose:
            print(f"[DEBUG] COMPOSE: loading from {self.path!r}")
        text = self.path.read_text(encoding="utf-8", errors="ignore")
        self.data = yaml.safe_load(text) or {}
        if self.verbose:
            services = self.data.get("services", {})
            print(f"[DEBUG] COMPOSE: {len(services)} services defined")

    def get_services(self) -> Dict[str, Any]:
        if not self.data:
            self.load()
        return self.data.get("services", {})