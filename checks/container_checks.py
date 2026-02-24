"""
Container/Docker Runtime Checks (6 checks)

1. Non-root container user
2. Minimal ports exposed
3. Resource limits (CPU/memory)
4. Health checks configured
5. Trusted image registry
6. Secrets not hardcoded
"""


import docker
from typing import Optional

from sec_audit.results import CheckResult, Status, Severity
from sec_audit.config import CHECKS


def _get_docker_client(docker_host: Optional[str] = None) -> docker.DockerClient:
    """Get Docker client with graceful fallback."""
    try:
        return docker.from_env(version='auto', base_url=docker_host)
    except Exception:
        raise RuntimeError("Docker daemon not accessible")


def _get_target_container(client: docker.DockerClient) -> docker.models.containers.Container:
    """Find running container (simplest: first running container)."""
    containers = client.containers.list(running=True)
    if not containers:
        raise RuntimeError("No running Docker containers found")
    return containers[0]  # Use first for demo; improve later


# def _meta(check_id: str):
#     for c in CHECKS:
#         if c["id"] == check_id: 
#             return c
#     raise KeyError(f"Unknown check id: {check_id}")


# ==================== 6 REAL CHECKS ====================
def check_non_root_user(docker_host: Optional[str] = None) -> CheckResult:
    """CONT-USER-001: Container runs as non-root user."""
    if not docker_host:
        return CheckResult("CONT-USER-001", "Non-root container user", "Container", Severity.HIGH, Status.WARN,
                          "Docker host not specified (--docker-host required for full mode)")
    
    try:
        client = _get_docker_client(docker_host)
        container = _get_target_container(client)
        user = container.attrs["Config"].get("User", "")
        
        if not user or user == "0" or user.lower() == "root":
            return CheckResult(
                "CONT-USER-001", "Non-root container user", "Container", Severity.HIGH, Status.FAIL,
                "Container runs as root (User: empty/0/root). Fix: Add 'USER 1000' to Dockerfile."
            )
        return CheckResult(
            "CONT-USER-001", "Non-root container user", "Container", Severity.HIGH, Status.PASS,
            f"Container runs as non-root user '{user}' ✓"
        )
    except Exception as e:
        return CheckResult("CONT-USER-001", "Non-root container user", "Container", Severity.HIGH, Status.WARN,
                          f"Docker error: {str(e)}")


def check_minimal_ports(docker_host: Optional[str] = None) -> CheckResult:
    """CONT-PORT-001: Minimize exposed host ports."""
    if not docker_host:
        return CheckResult("CONT-PORT-001", "Minimal exposed ports", "Container", Severity.MEDIUM, Status.WARN,
                          "Docker host not specified")
    
    try:
        client = _get_docker_client(docker_host)
        container = _get_target_container(client)
        port_bindings = container.attrs["HostConfig"].get("PortBindings", {})
        exposed_count = len(port_bindings)
        
        if exposed_count == 0:
            return CheckResult("CONT-PORT-001", "Minimal exposed ports", "Container", Severity.MEDIUM, Status.PASS,
                              "No host ports exposed ✓")
        elif exposed_count <= 2:
            return CheckResult("CONT-PORT-001", "Minimal exposed ports", "Container", Severity.MEDIUM, Status.PASS,
                              f"{exposed_count} ports exposed: acceptable")
        else:
            return CheckResult("CONT-PORT-001", "Minimal exposed ports", "Container", Severity.MEDIUM, Status.WARN,
                              f"{exposed_count} host ports exposed. Review bindings.")
    except Exception as e:
        return CheckResult("CONT-PORT-001", "Minimal exposed ports", "Container", Severity.MEDIUM, Status.WARN, str(e))


def check_health_checks(docker_host: Optional[str] = None) -> CheckResult:
    """CONT-HEALTH-001: Healthcheck configured."""
    if not docker_host:
        return CheckResult("CONT-HEALTH-001", "Healthcheck configured", "Container", Severity.MEDIUM, Status.WARN,
                          "Docker host not specified")
    
    try:
        client = _get_docker_client(docker_host)
        container = _get_target_container(client)
        healthcheck = container.attrs["Config"].get("Healthcheck")
        
        if not healthcheck or not healthcheck.get("Test"):
            return CheckResult("CONT-HEALTH-001", "Healthcheck configured", "Container", Severity.MEDIUM, Status.WARN,
                              "No HEALTHCHECK in Dockerfile. Add: HEALTHCHECK CMD curl -f http://localhost/ || exit 1")
        return CheckResult("CONT-HEALTH-001", "Healthcheck configured", "Container", Severity.MEDIUM, Status.PASS,
                          f"Healthcheck configured ✓")
    except Exception as e:
        return CheckResult("CONT-HEALTH-001", "Healthcheck configured", "Container", Severity.MEDIUM, Status.WARN, str(e))

def check_resource_limits(docker_host: Optional[str] = None) -> CheckResult:
    """CONT-RES-001: CPU/Memory resource limits set."""
    if not docker_host:
        return CheckResult("CONT-RES-001", "Resource limits configured", "Container", Severity.MEDIUM, Status.WARN,
                          "Docker host not specified")
    
    try:
        client = _get_docker_client(docker_host)
        container = _get_target_container(client)
        host_config = container.attrs["HostConfig"]
        
        cpu_limit = host_config.get("CpuQuota") or host_config.get("NanoCpus")
        mem_limit = host_config.get("Memory")
        
        if mem_limit or cpu_limit:
            return CheckResult("CONT-RES-001", "Resource limits configured", "Container", Severity.MEDIUM, Status.PASS,
                              f"Limits detected: Memory={mem_limit}B, CPU={cpu_limit}")
        return CheckResult("CONT-RES-001", "Resource limits configured", "Container", Severity.MEDIUM, Status.WARN,
                          "No CPU/memory limits. Add to docker-compose.yml: deploy.resources.limits")
    except Exception as e:
        return CheckResult("CONT-RES-001", "Resource limits configured", "Container", Severity.MEDIUM, Status.WARN, str(e))

def check_image_registry(docker_host: Optional[str] = None) -> CheckResult:
    """CONT-REG-001: Trusted image registry source."""
    if not docker_host:
        return CheckResult("CONT-REG-001", "Trusted image registry", "Container", Severity.MEDIUM, Status.WARN,
                          "Docker host not specified")
    
    try:
        client = _get_docker_client(docker_host)
        container = _get_target_container(client)
        image_name = container.image.tags[0] if container.image.tags else "unknown"
        
        if "docker.io/library" in image_name or any(trusted in image_name 
            for trusted in ["nginx:alpine", "python:slim", "postgres:"]):
            return CheckResult("CONT-REG-001", "Trusted image registry", "Container", Severity.MEDIUM, Status.PASS,
                              f"Image from trusted source: {image_name}")
        return CheckResult("CONT-REG-001", "Trusted image registry", "Container", Severity.MEDIUM, Status.WARN,
                          f"Image '{image_name}' from unverified registry. Use official images.")
    except Exception as e:
        return CheckResult("CONT-REG-001", "Trusted image registry", "Container", Severity.MEDIUM, Status.WARN, str(e))

def check_no_secrets(docker_host: Optional[str] = None) -> CheckResult:
    """CONT-SEC-001: No secrets in environment."""
    if not docker_host:
        return CheckResult("CONT-SEC-001", "No secrets in environment", "Container", Severity.HIGH, Status.WARN,
                          "Docker host not specified")
    
    try:
        client = _get_docker_client(docker_host)
        container = _get_target_container(client)
        env_vars = container.attrs["Config"]["Env"]
        
        secrets_found = [env for env in env_vars if any(kw in env.lower() 
            for kw in ["password", "key", "secret", "token", "api_key"])]
        
        if secrets_found:
            return CheckResult("CONT-SEC-001", "No secrets in environment", "Container", Severity.HIGH, Status.FAIL,
                              f"Secrets detected: {secrets_found[:2]}. Use Docker secrets.")
        return CheckResult("CONT-SEC-001", "No secrets in environment", "Container", Severity.HIGH, Status.PASS,
                          "No obvious secrets in environment variables ✓")
    except Exception as e:
        return CheckResult("CONT-SEC-001", "No secrets in environment", "Container", Severity.HIGH, Status.WARN, str(e))