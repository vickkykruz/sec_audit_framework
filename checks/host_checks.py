"""
Host/Server OS Security Checks (6 checks)

1. SSH hardened (no root login)
2. No unnecessary services running
3. Automatic security updates
4. Correct file permissions
5. Firewall configured
6. Logging/monitoring enabled
"""


import paramiko
from typing import Optional, Tuple

from sec_audit.results import CheckResult, Status, Severity
from scanners.ssh_scanner import SSHScanner

# ==================== 6 REAL CHECKS ====================
def check_ssh_hardening(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                       ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """HOST-SSH-001: SSH PermitRootLogin disabled."""
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SSH-001: missing SSH params")
        return CheckResult("HOST-SSH-001", "SSH hardening", "Host", Severity.HIGH, Status.WARN,
                          "SSH credentials missing (--ssh-host --ssh-user and either --ssh-key or --ssh-password)")
        
    # Use scanner instead of inline code
    scanner = SSHScanner(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
    try:
        client = scanner.connect(ssh_host, ssh_user, ssh_key, ssh_password)
        output, _ = scanner.run_command(client, "grep -i '^PermitRootLogin' /etc/ssh/sshd_config || echo 'no'")
        scanner.close()
        
        line = output.strip()
        if verbose:
            print(f"[DEBUG] HOST-SSH-001: PermitRootLogin='{line}'")
            
        if "yes" in line.lower():
            return CheckResult("HOST-SSH-001", "SSH hardening", "Host", Severity.HIGH, Status.FAIL,
                              f"PermitRootLogin enabled: '{line}'. Fix: Set 'PermitRootLogin no'")
        return CheckResult("HOST-SSH-001", "SSH hardening", "Host", Severity.HIGH, Status.PASS,
                          f"SSH root login disabled ✓ ({line})")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SSH-001: error {e}")
        return CheckResult("HOST-SSH-001", "SSH hardening", "Host", Severity.HIGH, Status.WARN, str(e))


def check_firewall(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                  ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """HOST-FW-001: Firewall active."""
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-FW-001: missing SSH params")
        return CheckResult("HOST-FW-001", "Firewall enabled", "Host", Severity.HIGH, Status.WARN,
                          "SSH credentials missing")
    
    # Use scanner instead of inline code
    scanner = SSHScanner(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
    try:
        client = scanner.connect(ssh_host, ssh_user, ssh_key, ssh_password)
        output, _ = scanner.run_command(client, "ufw status 2>/dev/null || iptables -L | wc -l")
        scanner.close()
        text = output.lower()
        
        if verbose:
            print(f"[DEBUG] HOST-FW-001: firewall output='{text[:50]}...'")
        
        if "inactive" in text:
            return CheckResult("HOST-FW-001", "Firewall enabled", "Host", Severity.HIGH, Status.FAIL,
                              "ufw inactive. Run: sudo ufw enable")
        if "status: active" in text:
            return CheckResult("HOST-FW-001", "Firewall enabled", "Host", Severity.HIGH, Status.PASS,
                          "Firewall appears active")
        
        return CheckResult("HOST-FW-001", "Firewall enabled", "Host", Severity.HIGH, Status.WARN,
                          "Could not confirm active firewall (ufw not found). Review iptables/nftables rules.")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-FW-001: error {e}")
        return CheckResult("HOST-FW-001", "Firewall enabled", "Host", Severity.HIGH, Status.WARN, str(e))


def check_services(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                  ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """HOST-SVC-001: No unnecessary services running."""
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SVC-001: missing SSH params")
        return CheckResult("HOST-SVC-001", "Minimal services", "Host", Severity.MEDIUM, Status.WARN,
                          "SSH credentials missing")
    
    # Use scanner instead of inline code
    scanner = SSHScanner(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
    try:
        client = scanner.connect(ssh_host, ssh_user, ssh_key, ssh_password)
        output, _ = scanner.run_command(client, "systemctl list-units --type=service --state=running | wc -l")
        scanner.close()
        service_count = int(output.strip())
        
        if verbose:
            print(f"[DEBUG] HOST-SVC-001: {service_count} services running")
        
        if service_count > 20:
            return CheckResult("HOST-SVC-001", "Minimal services", "Host", Severity.MEDIUM, Status.WARN,
                              f"{service_count} services running. Review: systemctl list-units")
        return CheckResult("HOST-SVC-001", "Minimal services", "Host", Severity.MEDIUM, Status.PASS,
                          f"{service_count} services: acceptable")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SVC-001: error {e}")
        return CheckResult("HOST-SVC-001", "Minimal services", "Host", Severity.MEDIUM, Status.WARN, str(e))


def check_auto_updates(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                      ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """HOST-UPDATE-001: Auto-updates configured."""
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-UPDATE-001: missing SSH params")
        return CheckResult("HOST-UPDATE-001", "Auto-updates enabled", "Host", Severity.MEDIUM, Status.WARN,
                          "SSH credentials missing")
    
    # Use scanner instead of inline code
    scanner = SSHScanner(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
    try:
        client = scanner.connect(ssh_host, ssh_user, ssh_key, ssh_password)
        output, _ = scanner.run_command(client, "systemctl is-enabled --quiet unattended-upgrades 2>/dev/null && echo 'enabled' || echo 'disabled'")
        scanner.close()
        
        if verbose:
            print(f"[DEBUG] HOST-UPDATE-001: auto-updates='{output.strip()}'")
        
        if "enabled" in output:
            return CheckResult("HOST-UPDATE-001", "Auto-updates enabled", "Host", Severity.MEDIUM, Status.PASS,
                              "Unattended  upgrades enabled ✓")
        return CheckResult("HOST-UPDATE-001", "Auto-updates enabled", "Host", Severity.MEDIUM, Status.WARN,
                          "Install: apt install unattended-upgrades && systemctl enable")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-UPDATE-001: error {e}")
        return CheckResult("HOST-UPDATE-001", "Auto-updates enabled", "Host", Severity.MEDIUM, Status.WARN, str(e))


def check_permissions(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                     ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """HOST-PERM-001: Secure file permissions."""
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-PERM-001: missing SSH params")
        return CheckResult("HOST-PERM-001", "Secure permissions", "Host", Severity.MEDIUM, Status.WARN,
                          "SSH credentials missing")
    
    # Use scanner instead of inline code
    scanner = SSHScanner(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
    try:
        client = scanner.connect(ssh_host, ssh_user, ssh_key, ssh_password)
        output, _ = scanner.run_command(client, "find /etc/ssh -perm -o+w 2>/dev/null | wc -l")
        scanner.close()
        world_writable = int(output.strip())
        
        if verbose:
            print(f"[DEBUG] HOST-PERM-001: {world_writable} world-writable SSH files")
        
        if world_writable > 0:
            return CheckResult("HOST-PERM-001", "Secure permissions", "Host", Severity.MEDIUM, Status.WARN,
                              f"{world_writable} world-writable files in /etc/ssh")
        return CheckResult("HOST-PERM-001", "Secure permissions", "Host", Severity.MEDIUM, Status.PASS,
                          "No insecure permissions detected")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-PERM-001: error {e}")
        return CheckResult("HOST-PERM-001", "Secure permissions", "Host", Severity.MEDIUM, Status.WARN, str(e))


def check_logging(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                 ssh_key: Optional[str] = None, ssh_password: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """HOST-LOG-001: Logging configured."""
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-LOG-001: missing SSH params")
        return CheckResult("HOST-LOG-001", "Logging configured", "Host", Severity.LOW, Status.WARN,
                          "SSH credentials missing")
    
    # Use scanner instead of inline code
    scanner = SSHScanner(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
    try:
        client = scanner.connect(ssh_host, ssh_user, ssh_key, ssh_password)
        output, _ = scanner.run_command(client, "systemctl is-active rsyslog 2>/dev/null && echo 'active' || echo 'inactive'")
        scanner.close()
        
        if verbose:
            print(f"[DEBUG] HOST-LOG-001: rsyslog='{output.strip()}'")
        
        if "active" in output:
            return CheckResult("HOST-LOG-001", "Logging configured", "Host", Severity.LOW, Status.PASS,
                              "rsyslog logging service active ✓")
        return CheckResult("HOST-LOG-001", "Logging configured", "Host", Severity.LOW, Status.WARN,
                          "Install logging: apt install rsyslog")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-LOG-001: error {e}")
        return CheckResult("HOST-LOG-001", "Logging configured", "Host", Severity.LOW, Status.WARN, str(e))
    
    
def check_gunicorn_user(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                       ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
                       verbose: bool = False) -> CheckResult:
    """HOST-SVC-GUNICORN: Gunicorn runs as non-root user."""
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SVC-GUNICORN: missing SSH params")
        return CheckResult("HOST-SVC-GUNICORN", "Gunicorn non-root", "Host", Severity.HIGH, Status.WARN,
                          "SSH credentials missing")
    
    # Use scanner instead of inline code
    scanner = SSHScanner(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
    try:
        client = scanner.connect(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
        output, _ = scanner.run_command(client, "ps aux | grep '[g]unicorn' | awk '{print $1}' | head -1", verbose)
        scanner.close()
        
        gunicorn_user = output.strip()
        
        if verbose:
            print(f"[DEBUG] HOST-SVC-GUNICORN: user='{gunicorn_user}'")
            
        if not gunicorn_user:
            return CheckResult("HOST-SVC-GUNICORN", "Gunicorn non-root", "Host", Severity.HIGH, Status.WARN,
                              "Gunicorn process not found")
        if gunicorn_user in ("root", "0"):
            return CheckResult("HOST-SVC-GUNICORN", "Gunicorn non-root", "Host", Severity.HIGH, Status.FAIL,
                              f"Gunicorn runs as root (user: {gunicorn_user}). Use non-root systemd user.")
        return CheckResult("HOST-SVC-GUNICORN", "Gunicorn non-root", "Host", Severity.HIGH, Status.PASS,
                          f"Gunicorn runs as non-root user '{gunicorn_user}' ✓")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SVC-GUNICORN: error {e}")
        return CheckResult("HOST-SVC-GUNICORN", "Gunicorn non-root", "Host", Severity.HIGH, Status.WARN, str(e))


def check_uwsgi_user(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
                    verbose: bool = False) -> CheckResult:
    """HOST-SVC-UWSGI: uWSGI runs as non-root user."""
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SVC-UWSGI: missing SSH params")
        return CheckResult("HOST-SVC-UWSGI", "uWSGI non-root", "Host", Severity.HIGH, Status.WARN,
                          "SSH credentials missing")
    
    # Use scanner instead of inline code
    scanner = SSHScanner(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
    try:
        client = scanner.connect(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
        output, _ = scanner.run_command(client, "ps aux | grep '[u]wsgi' | awk '{print $1}' | head -1", verbose)
        scanner.close()
        
        uwsgi_user = output.strip()
        
        if verbose:
            print(f"[DEBUG] HOST-SVC-UWSGI: user='{uwsgi_user}'")
            
        if not uwsgi_user:
            return CheckResult("HOST-SVC-UWSGI", "uWSGI non-root", "Host", Severity.HIGH, Status.PASS,
                              "uWSGI process not found (not in use)")
        if uwsgi_user in ("root", "0"):
            return CheckResult("HOST-SVC-UWSGI", "uWSGI non-root", "Host", Severity.HIGH, Status.FAIL,
                              f"uWSGI runs as root (user: {uwsgi_user}). Use non-root systemd user.")
        return CheckResult("HOST-SVC-UWSGI", "uWSGI non-root", "Host", Severity.HIGH, Status.PASS,
                          f"uWSGI runs as non-root user '{uwsgi_user}' ✓")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SVC-UWSGI: error {e}")
        return CheckResult("HOST-SVC-UWSGI", "uWSGI non-root", "Host", Severity.HIGH, Status.WARN, str(e))


def check_mysql_user(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
                    verbose: bool = False) -> CheckResult:
    """HOST-SVC-MYSQL: MySQL runs as non-root user."""
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SVC-MYSQL: missing SSH params")
        return CheckResult("HOST-SVC-MYSQL", "MySQL non-root", "Host", Severity.HIGH, Status.WARN,
                          "SSH credentials missing")
    
    # Use scanner instead of inline code
    scanner = SSHScanner(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
    try:
        client = scanner.connect(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
        output, _ = scanner.run_command(client, "ps aux | grep '[m]ySQL' | awk '{print $1}' | head -1", verbose)
        scanner.close()
        
        mysql_user = output.strip()
        
        if verbose:
            print(f"[DEBUG] HOST-SVC-MYSQL: user='{mysql_user}'")
            
        if not mysql_user:
            return CheckResult("HOST-SVC-MYSQL", "MySQL non-root", "Host", Severity.HIGH, Status.PASS,
                              "MySQL process not found (not in use)")
        if mysql_user in ("root", "0"):
            return CheckResult("HOST-SVC-MYSQL", "MySQL non-root", "Host", Severity.HIGH, Status.FAIL,
                              f"MySQL runs as root (user: {mysql_user}). Should run as 'mysql' user.")
        return CheckResult("HOST-SVC-MYSQL", "MySQL non-root", "Host", Severity.HIGH, Status.PASS,
                          f"MySQL runs as non-root user '{mysql_user}' ✓")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SVC-MYSQL: error {e}")
        return CheckResult("HOST-SVC-MYSQL", "MySQL non-root", "Host", Severity.HIGH, Status.WARN, str(e))


def check_redis_user(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                    ssh_key: Optional[str] = None, ssh_password: Optional[str] = None,
                    verbose: bool = False) -> CheckResult:
    """HOST-SVC-REDIS: Redis runs as non-root user."""
    if not (ssh_host and ssh_user and (ssh_key or ssh_password)):
        if verbose:
            print("[DEBUG] HOST-SVC-REDIS: missing SSH params")
        return CheckResult("HOST-SVC-REDIS", "Redis non-root", "Host", Severity.HIGH, Status.WARN,
                          "SSH credentials missing")
    
    # Use scanner instead of inline code
    scanner = SSHScanner(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
    try:
        client = scanner.connect(ssh_host, ssh_user, ssh_key, ssh_password, verbose)
        output, _ = scanner.run_command(client, "ps aux | grep '[r]edis-server' | awk '{print $1}' | head -1", verbose)
        scanner.close()
        
        redis_user = output.strip()
        
        if verbose:
            print(f"[DEBUG] HOST-SVC-REDIS: user='{redis_user}'")
            
        if not redis_user:
            return CheckResult("HOST-SVC-REDIS", "Redis non-root", "Host", Severity.HIGH, Status.PASS,
                              "Redis process not found (not in use)")
        if redis_user in ("root", "0"):
            return CheckResult("HOST-SVC-REDIS", "Redis non-root", "Host", Severity.HIGH, Status.FAIL,
                              f"Redis runs as root (user: {redis_user}). Should run as 'redis' user.")
        return CheckResult("HOST-SVC-REDIS", "Redis non-root", "Host", Severity.HIGH, Status.PASS,
                          f"Redis runs as non-root user '{redis_user}' ✓")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] HOST-SVC-REDIS: error {e}")
        return CheckResult("HOST-SVC-REDIS", "Redis non-root", "Host", Severity.HIGH, Status.WARN, str(e))