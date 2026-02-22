"""
Host/Server OS Security Checks (6 checks)

1. SSH hardened (no root login)
2. No unnecessary services running
3. Automatic security updates
4. Correct file permissions
5. Firewall configured
6. Logging/monitoring enabled
"""


from sec_audit.results import CheckResult, Status, Severity
from sec_audit.config import CHECKS



def _meta(check_id: str):
    """Helper to pull metadata from CHECKS by id."""
    for c in CHECKS:
        if c["id"] == check_id:
            return c
    raise KeyError(f"Unknown check id: {check_id}")


def check_ssh_hardening() -> CheckResult:
    """HOST-SSH-001: SSH configuration hardened."""
    meta = _meta("HOST-SSH-001")
    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=Status.WARN,
        severity=Severity.HIGH,
        details="Pending SSH connection - requires 'cat /etc/ssh/sshd_config | grep PermitRootLogin' (should be 'no')"
    )
    
    
def check_services() -> CheckResult:
    """HOST-SVC-001: No unnecessary services running."""
    meta = _meta("HOST-SVC-001")
    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=Status.WARN,
        severity=Severity.MEDIUM,
        details="Pending SSH - requires 'systemctl list-units --type=service --state=running' to check for risky services"
    )
    
    
def check_auto_updates() -> CheckResult:
    """HOST-UPDATE-001: Automatic security updates enabled."""
    meta = _meta("HOST-UPDATE-001")
    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=Status.WARN,
        severity=Severity.MEDIUM,
        details="Pending SSH - requires 'systemctl is-enabled unattended-upgrades' (should be 'enabled')"
    )
    
    
def check_permissions() -> CheckResult:
    """HOST-PERM-001: Secure file permissions."""
    meta = _meta("HOST-PERM-001")
    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=Status.WARN,
        severity=Severity.HIGH,
        details="Pending SSH - requires 'find /etc -perm -o+w -ls 2>/dev/null' (no world-writable files)"
    )
    

def check_firewall() -> CheckResult:
    """HOST-FW-001: Firewall configured."""
    meta = _meta("HOST-FW-001")
    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=Status.WARN,
        severity=Severity.HIGH,
        details="Pending SSH - requires 'ufw status' or 'iptables -L' (firewall should be active)"
    )
    
    
def check_logging() -> CheckResult:
    """HOST-LOG-001: Logging configured and active."""
    meta = _meta("HOST-LOG-001")
    return CheckResult(
        id=meta["id"],
        layer=meta["layer"],
        name=meta["name"],
        status=Status.WARN,
        severity=Severity.MEDIUM,
        details="Pending SSH - requires 'systemctl is-active rsyslog' and '/var/log/auth.log' writable"
    )