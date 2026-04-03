"""
sec_audit/telemetry.py — Anonymous opt-in usage telemetry.
 
PRIVACY CONTRACT (never violated):
  ✅ Opt-in only     — user is asked once on first run, never silently enabled
  ✅ Anonymous       — no target URLs, no credentials, no scan results, no IPs
  ✅ Fire-and-forget — 3s timeout, never blocks, never crashes the scan
  ✅ Transparent     — user can inspect or disable at any time
 
What IS sent (with consent):
  - Event type (tool_installed, scan_started, patch_generated, etc.)
  - Platform (win32 / linux / darwin)
  - Python version (major.minor only, e.g. 3.11)
  - StackSentry version
  - Approximate country/city (from ipinfo.io — same as any website visit)
 
What is NEVER sent:
  - Target URLs, server IPs, SSH credentials
  - Scan results, grades, check details
  - File paths, nginx/Dockerfile contents
  - Any personally identifying information
 
User controls:
  stacksentry --telemetry on
  stacksentry --telemetry off
  stacksentry --telemetry status
 
Config stored at: ~/.stacksentry/config.json
"""
 
from __future__ import annotations
 
import json
import pathlib
import platform
import sys
import threading
import urllib.request
from datetime import datetime, timezone
from typing import Optional
 
 
# ── Constants ─────────────────────────────────────────────────────────────────
 
TELEMETRY_BASE  = "https://api.vickkykruzprogramming.dev/api"
TRACK_URL       = f"{TELEMETRY_BASE}/track"
ACTIVITY_URL    = f"{TELEMETRY_BASE}/activity"
SUBSCRIBE_URL   = f"{TELEMETRY_BASE}/subscribe"
 
CONFIG_DIR      = pathlib.Path.home() / ".stacksentry"
CONFIG_FILE     = CONFIG_DIR / "config.json"
TIMEOUT_SECONDS = 3
VERSION         = "1.0.0"
 
# Location cache — ipinfo.io is called at most once per session
_location_cache: dict = {}
 
 
# ── Config helpers ────────────────────────────────────────────────────────────
 
def _load_config() -> dict:
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}
 
 
def _save_config(cfg: dict) -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass
 
 
def is_telemetry_enabled() -> bool:
    return _load_config().get("telemetry", False)
 
 
def is_first_run() -> bool:
    """True if the user has never been asked about telemetry."""
    return "telemetry" not in _load_config()
 
 
def set_telemetry(enabled: bool) -> None:
    cfg = _load_config()
    cfg["telemetry"] = enabled
    _save_config(cfg)
 
 
def get_subscribed_email() -> Optional[str]:
    return _load_config().get("newsletter_email")
 
 
def set_subscribed_email(email: str) -> None:
    cfg = _load_config()
    cfg["newsletter_email"] = email
    _save_config(cfg)
 
 
# ── Location lookup ───────────────────────────────────────────────────────────
 
def _get_location() -> dict:
    """
    Get approximate location from ipinfo.io.
    Cached after first call — only one lookup per session.
    Returns safe defaults if the call fails or times out.
    """
    global _location_cache
    if _location_cache:
        return _location_cache
 
    defaults = {"country": "Unknown", "country_code": "XX", "city": "Unknown"}
    try:
        req  = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"Accept": "application/json"},
        )
        raw  = urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS).read()
        data = json.loads(raw)
        _location_cache = {
            "country":      data.get("country", "XX"),
            "country_code": data.get("country", "XX"),
            "city":         data.get("city", "Unknown"),
        }
        return _location_cache
    except Exception:
        return defaults
 
 
# ── Low-level HTTP helpers ────────────────────────────────────────────────────
 
def _post(url: str, payload: dict) -> None:
    """Synchronous POST. Silently swallows all errors."""
    try:
        body = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS)
    except Exception:
        pass
 
 
def _fire(url: str, payload: dict) -> None:
    """Background-thread POST. Never blocks. Never raises."""
    t = threading.Thread(target=_post, args=(url, payload), daemon=True)
    t.start()
 
 
# ── First-run consent prompt ──────────────────────────────────────────────────
 
def prompt_first_run() -> None:
    """
    Show the opt-in prompt on first run.
    Called from main() before parse_args() so it fires on any command,
    including --help. Never shown again after the user responds.
    """
    if not is_first_run():
        return
 
    print()
    print("\u2500" * 55)
    print("  Welcome to StackSentry v1.0.0 \U0001f44b")
    print()
    print("  Help improve StackSentry by sharing anonymous")
    print("  usage data. This includes only:")
    print("    \u2022 Which features you use (--patch, --fix, etc.)")
    print("    \u2022 Your platform and Python version")
    print("    \u2022 Approximate country (no IPs stored)")
    print()
    print("  Your scan targets, credentials, and results")
    print("  are NEVER collected.")
    print()
 
    try:
        answer = input("  Allow anonymous telemetry? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"
 
    opted_in = answer in ("y", "yes")
    set_telemetry(opted_in)
 
    if opted_in:
        print()
        print("  Thanks! One more thing \u2014 want to be notified")
        print("  about new StackSentry features and updates?")
        print()
        try:
            email = input("  Your email (or press Enter to skip): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            email = ""
 
        if email and "@" in email and "." in email:
            set_subscribed_email(email)
            # Synchronous — program may exit immediately after this
            _post(SUBSCRIBE_URL, {"email": email, "source": "stacksentry_cli"})
            print(f"  \u2705 Subscribed! We'll notify you at {email}")
        else:
            print("  Skipped \u2014 you can subscribe later at:")
            print("  https://vickkykruzprogramming.dev")
 
        print()
        print("  You can change this setting any time:")
        print("  stacksentry --telemetry off")
    else:
        print()
        print("  No problem \u2014 telemetry stays off.")
        print("  You can enable it later: stacksentry --telemetry on")
 
    print("\u2500" * 55)
    print()
 
    # Log the install event synchronously (program may exit right after)
    if opted_in:
        loc = _get_location()
        _post(ACTIVITY_URL, {
            "type":         "tool_installed",
            "page":         "/cli/install",
            "country":      loc["country"],
            "country_code": loc["country_code"],
            "city":         loc["city"],
            "meta": {
                "version":  VERSION,
                "platform": sys.platform,
                "python":   f"{sys.version_info.major}.{sys.version_info.minor}",
            },
        })
        _post(TRACK_URL, {
            "page":         "/cli/install",
            "country":      loc["country"],
            "country_code": loc["country_code"],
            "city":         loc["city"],
        })
 
 
# ── Telemetry management command ──────────────────────────────────────────────
 
def handle_telemetry_flag(value: str) -> None:
    """Handle --telemetry on/off/status from CLI."""
    value = value.strip().lower()
    if value == "on":
        set_telemetry(True)
        print("\u2705 Telemetry enabled. Thank you for helping improve StackSentry.")
        if not get_subscribed_email():
            try:
                email = input(
                    "Want update notifications? Enter email (or Enter to skip): "
                ).strip().lower()
                if email and "@" in email and "." in email:
                    set_subscribed_email(email)
                    _post(SUBSCRIBE_URL, {"email": email, "source": "stacksentry_cli"})
                    print(f"\u2705 Subscribed at {email}")
            except (EOFError, KeyboardInterrupt):
                pass
    elif value == "off":
        set_telemetry(False)
        print("\u2705 Telemetry disabled.")
    elif value == "status":
        cfg     = _load_config()
        enabled = cfg.get("telemetry", False)
        email   = cfg.get("newsletter_email", "not set")
        print(f"  Telemetry:  {'enabled' if enabled else 'disabled'}")
        print(f"  Newsletter: {email}")
        print(f"  Config at:  {CONFIG_FILE}")
    else:
        print(f"Unknown value '{value}'. Use: on | off | status")
 
 
# ── Event tracking ────────────────────────────────────────────────────────────
 
def track_scan_started(mode: str) -> None:
    """Called when a scan begins — sends no target info."""
    if not is_telemetry_enabled():
        return
 
    def _do() -> None:
        loc = _get_location()
        _post(ACTIVITY_URL, {
            "type":         "scan_started",
            "page":         "/cli/scan",
            "country":      loc["country"],
            "country_code": loc["country_code"],
            "city":         loc["city"],
            "meta": {
                "mode":     mode,
                "version":  VERSION,
                "platform": sys.platform,
                "python":   f"{sys.version_info.major}.{sys.version_info.minor}",
            },
        })
        _post(TRACK_URL, {
            "page":         "/cli/scan",
            "country":      loc["country"],
            "country_code": loc["country_code"],
            "city":         loc["city"],
        })
 
    threading.Thread(target=_do, daemon=True).start()
 
 
def track_patch_generated(count: int, llm_count: int) -> None:
    """Called when --patch completes."""
    if not is_telemetry_enabled():
        return
 
    def _do() -> None:
        loc = _get_location()
        _post(ACTIVITY_URL, {
            "type":         "patch_generated",
            "page":         "/cli/patch",
            "country":      loc["country"],
            "country_code": loc["country_code"],
            "city":         loc["city"],
            "meta": {
                "patch_count": count,
                "llm_count":   llm_count,
                "version":     VERSION,
            },
        })
 
    threading.Thread(target=_do, daemon=True).start()
 
 
def track_fix_applied(fixed: int, failed: int, manual: int) -> None:
    """Called when --fix completes."""
    if not is_telemetry_enabled():
        return
 
    def _do() -> None:
        loc = _get_location()
        _post(ACTIVITY_URL, {
            "type":         "fix_applied",
            "page":         "/cli/fix",
            "country":      loc["country"],
            "country_code": loc["country_code"],
            "city":         loc["city"],
            "meta": {
                "fixed":   fixed,
                "failed":  failed,
                "manual":  manual,
                "version": VERSION,
            },
        })
 
    threading.Thread(target=_do, daemon=True).start()
 
 
def track_report_generated(format_type: str) -> None:
    """Called when a PDF or JSON report is generated."""
    if not is_telemetry_enabled():
        return
 
    def _do() -> None:
        loc = _get_location()
        _post(ACTIVITY_URL, {
            "type":         "report_generated",
            "page":         "/cli/report",
            "country":      loc["country"],
            "country_code": loc["country_code"],
            "city":         loc["city"],
            "meta": {
                "format":  format_type,
                "version": VERSION,
            },
        })
 
    threading.Thread(target=_do, daemon=True).start()
