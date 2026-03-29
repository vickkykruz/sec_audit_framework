"""
Host/Server OS Security Checks (6 checks)

1. SSH hardened (no root login)
2. No unnecessary services running
3. Automatic security updates
4. Correct file permissions
5. Firewall configured
6. Logging/monitoring enabled
"""


from typing import Optional

from sec_audit.results import CheckResult, Status, Severity
from scanners.ssh_scanner import SSHScanner
from sec_audit.results import ScanResult
from sec_audit.config import CHECKS


def _meta(check_id: str):
    for c in CHECKS:
        if c["id"] == check_id:
            return c
    raise KeyError(f"Unknown check id: {check_id}")


def _no_ssh_result(meta: dict) -> CheckResult:
    """Shared early-return for missing SSH credentials."""
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=Status.WARN, severity=Severity[meta["severity"]],
        details="Pending SSH connection - SSH credentials missing (--ssh-host --ssh-user and either --ssh-key or --ssh-password)",
    )


# ==================== HOST CHECKS ====================
def check_ssh_hardening(
    ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
    scan_result: Optional[ScanResult] = None, verbose: bool = False,
) -> CheckResult:
    """HOST-SSH-001: SSH PermitRootLogin disabled."""
    meta = _meta("HOST-SSH-001")

    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SSH-001: missing SSH params")
        return _no_ssh_result(meta)

    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key,
                         password=ssh_password, verbose=verbose)
    try:
        scanner.connect()

        if scan_result is not None:
            os_name = scanner.detect_os_version()
            if os_name:
                scan_result._os_version = os_name

        output, _ = scanner.run_command(
            "grep -i '^PermitRootLogin' /etc/ssh/sshd_config || echo 'no'",
            verbose=verbose,
        )
        scanner.close()

        line = output.strip()
        if verbose:
            print(f"[DEBUG] HOST-SSH-001: PermitRootLogin='{line}'")

        if "yes" in line.lower():
            status = Status.FAIL
            details = (
                f"PermitRootLogin enabled: '{line}'. "
                "→ Edit /etc/ssh/sshd_config → PermitRootLogin no → sudo systemctl restart ssh"
            )
        else:
            status = Status.PASS
            details = f"SSH root login disabled ✓ ({line})"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SSH-001: error {e}")
        status = Status.WARN
        details = str(e)

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_firewall(
    ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
    verbose: bool = False,
) -> CheckResult:
    """HOST-FW-001: Firewall active."""
    meta = _meta("HOST-FW-001")

    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-FW-001: missing SSH params")
        return _no_ssh_result(meta)

    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key,
                         password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command(
            "ufw status 2>/dev/null || iptables -L | wc -l", verbose=verbose
        )
        scanner.close()
        text = output.lower()

        if verbose:
            print(f"[DEBUG] HOST-FW-001: firewall output='{text[:50]}...'")

        if "inactive" in text:
            status = Status.FAIL
            details = "ufw inactive. → sudo ufw enable && sudo ufw allow 22/tcp && sudo ufw status"
        elif "status: active" in text:
            status = Status.PASS
            details = "Firewall appears active ✓"
        else:
            status = Status.WARN
            details = "Could not confirm active firewall (ufw not found). Review iptables/nftables rules."

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-FW-001: error {e}")
        status = Status.WARN
        details = str(e)

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_services(
    ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
    verbose: bool = False,
) -> CheckResult:
    """HOST-SVC-001: No unnecessary services running."""
    meta = _meta("HOST-SVC-001")

    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SVC-001: missing SSH params")
        return _no_ssh_result(meta)

    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key,
                         password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command(
            "systemctl list-units --type=service --state=running | wc -l", verbose=verbose
        )
        scanner.close()
        service_count = int(output.strip())

        if verbose:
            print(f"[DEBUG] HOST-SVC-001: {service_count} services running")

        if service_count > 20:
            status = Status.WARN
            details = f"{service_count} services running. Review with: systemctl list-units"
        else:
            status = Status.PASS
            details = f"{service_count} services running: within acceptable range ✓"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SVC-001: error {e}")
        status = Status.WARN
        details = str(e)

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_auto_updates(
    ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
    verbose: bool = False,
) -> CheckResult:
    """HOST-UPDATE-001: Auto-updates configured."""
    meta = _meta("HOST-UPDATE-001")

    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-UPDATE-001: missing SSH params")
        return _no_ssh_result(meta)

    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key,
                         password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command(
            "systemctl is-enabled --quiet unattended-upgrades 2>/dev/null "
            "&& echo 'enabled' || echo 'disabled'",
            verbose=verbose,
        )
        scanner.close()

        if verbose:
            print(f"[DEBUG] HOST-UPDATE-001: auto-updates='{output.strip()}'")

        if "enabled" in output:
            status = Status.PASS
            details = "Unattended upgrades enabled ✓"
        else:
            status = Status.WARN
            details = "Auto-updates not enabled. Install: apt install unattended-upgrades && systemctl enable unattended-upgrades"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-UPDATE-001: error {e}")
        status = Status.WARN
        details = str(e)

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_permissions(
    ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
    verbose: bool = False,
) -> CheckResult:
    """HOST-PERM-001: Secure file permissions."""
    meta = _meta("HOST-PERM-001")

    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-PERM-001: missing SSH params")
        return _no_ssh_result(meta)

    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key,
                         password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command(
            "find /etc/ssh -perm -o+w 2>/dev/null | wc -l", verbose=verbose
        )
        scanner.close()
        world_writable = int(output.strip())

        if verbose:
            print(f"[DEBUG] HOST-PERM-001: {world_writable} world-writable SSH files")

        if world_writable > 0:
            status = Status.WARN
            details = f"{world_writable} world-writable file(s) found in /etc/ssh. Tighten permissions: chmod o-w <file>"
        else:
            status = Status.PASS
            details = "No world-writable files detected in /etc/ssh ✓"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-PERM-001: error {e}")
        status = Status.WARN
        details = str(e)

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_logging(
    ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
    verbose: bool = False,
) -> CheckResult:
    """HOST-LOG-001: Logging configured."""
    meta = _meta("HOST-LOG-001")

    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-LOG-001: missing SSH params")
        return _no_ssh_result(meta)

    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key,
                         password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command(
            "systemctl is-active rsyslog 2>/dev/null && echo 'active' || echo 'inactive'",
            verbose=verbose,
        )
        scanner.close()

        if verbose:
            print(f"[DEBUG] HOST-LOG-001: rsyslog='{output.strip()}'")

        if "active" in output:
            status = Status.PASS
            details = "rsyslog logging service active ✓"
        else:
            status = Status.WARN
            details = "rsyslog not active. Install: apt install rsyslog && systemctl enable rsyslog"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-LOG-001: error {e}")
        status = Status.WARN
        details = str(e)

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def _check_process_user(
    meta: dict,
    process_grep: str,
    process_name: str,
    not_found_status: Status,
    not_found_detail: str,
    ssh_host: Optional[str], ssh_user: Optional[str],
    ssh_key: Optional[str], ssh_password: Optional[str],
    verbose: bool,
) -> CheckResult:
    """
    Shared helper for process-user checks (Gunicorn, uWSGI, MySQL, Redis).
    Avoids repeating the same SSH connect / grep / root-check logic.
    """
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print(f"[DEBUG] {meta['id']}: missing SSH params")
        return _no_ssh_result(meta)

    scanner = SSHScanner(host=ssh_host, user=ssh_user, key_path=ssh_key,
                         password=ssh_password, verbose=verbose)
    try:
        scanner.connect()
        output, _ = scanner.run_command(process_grep, verbose=verbose)
        scanner.close()

        proc_user = output.strip()
        if verbose:
            print(f"[DEBUG] {meta['id']}: user='{proc_user}'")

        if not proc_user:
            status = not_found_status
            details = not_found_detail
        elif proc_user in ("root", "0"):
            status = Status.FAIL
            details = f"{process_name} runs as root. Use a dedicated non-root service account."
        else:
            status = Status.PASS
            details = f"{process_name} runs as non-root user '{proc_user}' ✓"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] {meta['id']}: error {e}")
        status = Status.WARN
        details = str(e)

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_gunicorn_user(
    ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
    verbose: bool = False,
) -> CheckResult:
    """HOST-SVC-GUNICORN: Gunicorn runs as non-root user."""
    return _check_process_user(
        meta=_meta("HOST-SVC-GUNICORN"),
        process_grep="ps aux | grep '[g]unicorn' | awk '{print $1}' | head -1",
        process_name="Gunicorn",
        not_found_status=Status.WARN,
        not_found_detail="Gunicorn process not found; may not be running.",
        ssh_host=ssh_host, ssh_user=ssh_user,
        ssh_key=ssh_key, ssh_password=ssh_password,
        verbose=verbose,
    )


def check_uwsgi_user(
    ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
    verbose: bool = False,
) -> CheckResult:
    """HOST-SVC-UWSGI: uWSGI runs as non-root user."""
    return _check_process_user(
        meta=_meta("HOST-SVC-UWSGI"),
        process_grep="ps aux | grep '[u]wsgi' | awk '{print $1}' | head -1",
        process_name="uWSGI",
        not_found_status=Status.PASS,
        not_found_detail="uWSGI process not found (not in use) ✓",
        ssh_host=ssh_host, ssh_user=ssh_user,
        ssh_key=ssh_key, ssh_password=ssh_password,
        verbose=verbose,
    )


def check_mysql_user(
    ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
    verbose: bool = False,
) -> CheckResult:
    """HOST-SVC-MYSQL: MySQL runs as non-root user."""
    return _check_process_user(
        meta=_meta("HOST-SVC-MYSQL"),
        process_grep="ps aux | grep '[m]ysqld' | awk '{print $1}' | head -1",
        process_name="MySQL",
        not_found_status=Status.PASS,
        not_found_detail="MySQL process not found (not in use) ✓",
        ssh_host=ssh_host, ssh_user=ssh_user,
        ssh_key=ssh_key, ssh_password=ssh_password,
        verbose=verbose,
    )


def check_redis_user(
    ssh_host: Optional[str] = None, ssh_user: Optional[str] = None,
    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
    verbose: bool = False,
) -> CheckResult:
    """HOST-SVC-REDIS: Redis runs as non-root user."""
    return _check_process_user(
        meta=_meta("HOST-SVC-REDIS"),
        process_grep="ps aux | grep '[r]edis-server' | awk '{print $1}' | head -1",
        process_name="Redis",
        not_found_status=Status.PASS,
        not_found_detail="Redis process not found (not in use) ✓",
        ssh_host=ssh_host, ssh_user=ssh_user,
        ssh_key=ssh_key, ssh_password=ssh_password,
        verbose=verbose,
    )
