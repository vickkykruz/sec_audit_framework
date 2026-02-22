"""
Container/Docker Runtime Checks (6 checks)

1. Non-root container user
2. Minimal ports exposed
3. Resource limits (CPU/memory)
4. Health checks configured
5. Trusted image registry
6. Secrets not hardcoded
"""


from sec_audit.results import CheckResult, Status, Severity
from sec_audit.config import CHECKS


def _meta(check_id: str):
    for c in CHECKS:
        if c["id"] == check_id: 
            return c
    raise KeyError(f"Unknown check id: {check_id}")


def check_non_root_user() -> CheckResult:
    """CONT-USER-001: Non-root container user."""
    meta = _meta("CONT-USER-001")
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=Status.WARN, severity=Severity.HIGH,
        details="Pending Docker API - requires 'docker inspect' to check USER directive"
    )
    
    
def check_minimal_ports() -> CheckResult:
    """CONT-PORT-001: Minimal ports exposed."""
    meta = _meta("CONT-PORT-001")
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=Status.WARN, severity=Severity.MEDIUM,
        details="Pending Docker API - requires 'docker ps' to check port bindings"
    )
    
    
def check_resource_limits() -> CheckResult:
    """CONT-RES-001: Resource limits configured."""
    meta = _meta("CONT-RES-001")
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=Status.WARN, severity=Severity.MEDIUM,
        details="Pending Docker API - requires docker-compose.yml CPU/memory limits check"
    )
    
    
def check_health_checks() -> CheckResult:
    """CONT-HEALTH-001: Health checks configured."""
    meta = _meta("CONT-HEALTH-001")
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=Status.WARN, severity=Severity.LOW,
        details="Pending Docker API - requires Dockerfile HEALTHCHECK directive"
    )
    
    
def check_image_registry() -> CheckResult:
    """CONT-REG-001: Trusted image registry."""
    meta = _meta("CONT-REG-001")
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=Status.WARN, severity=Severity.MEDIUM,
        details="Pending Docker API - requires image source validation"
    )
    
    
def check_no_secrets() -> CheckResult:
    """CONT-SEC-001: No hardcoded secrets."""
    meta = _meta("CONT-SEC-001")
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=Status.WARN, severity=Severity.CRITICAL,
        details="Pending file parsing - requires docker-compose.yml secret scanning"
    )