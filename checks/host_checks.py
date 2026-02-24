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
from sec_audit.config import CHECKS



def _ssh_connect(host: str, user: str, key_path: str) -> paramiko.SSHClient:
    """Establish SSH connection."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=user, key_filename=key_path, timeout=10)
    return client


def _run_ssh_command(client: paramiko.SSHClient, cmd: str) -> Tuple[str, int]:
    """Execute SSH command and return output + exit code."""
    stdin, stdout, stderr = client.exec_command(cmd)
    output = stdout.read().decode("utf-8", errors="ignore").strip()
    return output, stdout.channel.recv_exit_status()


# def _meta(check_id: str):
#     """Helper to pull metadata from CHECKS by id."""
#     for c in CHECKS:
#         if c["id"] == check_id:
#             return c
#     raise KeyError(f"Unknown check id: {check_id}")


# ==================== 6 REAL CHECKS ====================
def check_ssh_hardening(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                       ssh_key: Optional[str] = None) -> CheckResult:
    """HOST-SSH-001: SSH PermitRootLogin disabled."""
    if not all([ssh_host, ssh_user, ssh_key]):
        return CheckResult("HOST-SSH-001", "SSH hardening", "Host", Severity.HIGH, Status.WARN,
                          "SSH credentials missing (--ssh-host --ssh-user --ssh-key)")
    
    try:
        client = _ssh_connect(ssh_host, ssh_user, ssh_key)
        output, _ = _run_ssh_command(client, "grep -i '^PermitRootLogin' /etc/ssh/sshd_config || echo 'no'")
        client.close()
        
        if "yes" in output.lower():
            return CheckResult("HOST-SSH-001", "SSH hardening", "Host", Severity.HIGH, Status.FAIL,
                              f"PermitRootLogin enabled: '{output}'. Fix: Set 'PermitRootLogin no'")
        return CheckResult("HOST-SSH-001", "SSH hardening", "Host", Severity.HIGH, Status.PASS,
                          f"SSH root login disabled ✓ ({output})")
    except Exception as e:
        return CheckResult("HOST-SSH-001", "SSH hardening", "Host", Severity.HIGH, Status.WARN, str(e))


def check_firewall(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                  ssh_key: Optional[str] = None) -> CheckResult:
    """HOST-FW-001: Firewall active."""
    if not all([ssh_host, ssh_user, ssh_key]):
        return CheckResult("HOST-FW-001", "Firewall enabled", "Host", Severity.HIGH, Status.WARN,
                          "SSH credentials missing")
    
    try:
        client = _ssh_connect(ssh_host, ssh_user, ssh_key)
        output, _ = _run_ssh_command(client, "ufw status 2>/dev/null || iptables -L | wc -l")
        client.close()
        
        if "inactive" in output.lower():
            return CheckResult("HOST-FW-001", "Firewall enabled", "Host", Severity.HIGH, Status.FAIL,
                              "ufw inactive. Run: sudo ufw enable")
        return CheckResult("HOST-FW-001", "Firewall enabled", "Host", Severity.HIGH, Status.PASS,
                          "Firewall appears active")
    except Exception as e:
        return CheckResult("HOST-FW-001", "Firewall enabled", "Host", Severity.HIGH, Status.WARN, str(e))


def check_services(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                  ssh_key: Optional[str] = None) -> CheckResult:
    """HOST-SVC-001: No unnecessary services running."""
    if not all([ssh_host, ssh_user, ssh_key]):
        return CheckResult("HOST-SVC-001", "Minimal services", "Host", Severity.MEDIUM, Status.WARN,
                          "SSH credentials missing")
    
    try:
        client = _ssh_connect(ssh_host, ssh_user, ssh_key)
        output, _ = _run_ssh_command(client, "systemctl list-units --type=service --state=running | wc -l")
        client.close()
        service_count = int(output.strip())
        
        if service_count > 20:
            return CheckResult("HOST-SVC-001", "Minimal services", "Host", Severity.MEDIUM, Status.WARN,
                              f"{service_count} services running. Review: systemctl list-units")
        return CheckResult("HOST-SVC-001", "Minimal services", "Host", Severity.MEDIUM, Status.PASS,
                          f"{service_count} services: acceptable")
    except Exception as e:
        return CheckResult("HOST-SVC-001", "Minimal services", "Host", Severity.MEDIUM, Status.WARN, str(e))


def check_auto_updates(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                      ssh_key: Optional[str] = None) -> CheckResult:
    """HOST-UPDATE-001: Auto-updates configured."""
    if not all([ssh_host, ssh_user, ssh_key]):
        return CheckResult("HOST-UPDATE-001", "Auto-updates enabled", "Host", Severity.MEDIUM, Status.WARN,
                          "SSH credentials missing")
    
    try:
        client = _ssh_connect(ssh_host, ssh_user, ssh_key)
        output, _ = _run_ssh_command(client, "systemctl is-enabled --quiet unattended-upgrades 2>/dev/null && echo 'enabled' || echo 'disabled'")
        client.close()
        
        if "enabled" in output:
            return CheckResult("HOST-UPDATE-001", "Auto-updates enabled", "Host", Severity.MEDIUM, Status.PASS,
                              "Unattended upgrades enabled ✓")
        return CheckResult("HOST-UPDATE-001", "Auto-updates enabled", "Host", Severity.MEDIUM, Status.WARN,
                          "Install: apt install unattended-upgrades && systemctl enable")
    except Exception as e:
        return CheckResult("HOST-UPDATE-001", "Auto-updates enabled", "Host", Severity.MEDIUM, Status.WARN, str(e))


def check_permissions(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                     ssh_key: Optional[str] = None) -> CheckResult:
    """HOST-PERM-001: Secure file permissions."""
    if not all([ssh_host, ssh_user, ssh_key]):
        return CheckResult("HOST-PERM-001", "Secure permissions", "Host", Severity.MEDIUM, Status.WARN,
                          "SSH credentials missing")
    
    try:
        client = _ssh_connect(ssh_host, ssh_user, ssh_key)
        output, _ = _run_ssh_command(client, "find /etc/ssh -perm -o+w 2>/dev/null | wc -l")
        client.close()
        world_writable = int(output.strip())
        
        if world_writable > 0:
            return CheckResult("HOST-PERM-001", "Secure permissions", "Host", Severity.MEDIUM, Status.WARN,
                              f"{world_writable} world-writable files in /etc/ssh")
        return CheckResult("HOST-PERM-001", "Secure permissions", "Host", Severity.MEDIUM, Status.PASS,
                          "No insecure permissions detected")
    except Exception as e:
        return CheckResult("HOST-PERM-001", "Secure permissions", "Host", Severity.MEDIUM, Status.WARN, str(e))


def check_logging(ssh_host: Optional[str] = None, ssh_user: Optional[str] = None, 
                 ssh_key: Optional[str] = None) -> CheckResult:
    """HOST-LOG-001: Logging configured."""
    if not all([ssh_host, ssh_user, ssh_key]):
        return CheckResult("HOST-LOG-001", "Logging configured", "Host", Severity.LOW, Status.WARN,
                          "SSH credentials missing")
    
    try:
        client = _ssh_connect(ssh_host, ssh_user, ssh_key)
        output, _ = _run_ssh_command(client, "systemctl is-active rsyslog 2>/dev/null && echo 'active' || echo 'inactive'")
        client.close()
        
        if "active" in output:
            return CheckResult("HOST-LOG-001", "Logging configured", "Host", Severity.LOW, Status.PASS,
                              "rsyslog logging service active ✓")
        return CheckResult("HOST-LOG-001", "Logging configured", "Host", Severity.LOW, Status.WARN,
                          "Install logging: apt install rsyslog")
    except Exception as e:
        return CheckResult("HOST-LOG-001", "Logging configured", "Host", Severity.LOW, Status.WARN, str(e))