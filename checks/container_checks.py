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

from scanners.docker_scanner import DockerScanner
from sec_audit.results import CheckResult, Status, Severity



# ==================== 6 REAL CHECKS ====================
def check_non_root_user(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-USER-001: Container runs as non-root user.

    Why it matters:
    - Running as root in a container increases impact of breakout or misconfigurations.

    Logic:
    - Inspect Config.User of the target container.
    - If empty / "0" / "root" → FAIL.
    - Otherwise PASS.
    """
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-USER-001: docker_host not provided; returning WARN")
        return CheckResult("CONT-USER-001", "Non-root container user", "Container", Severity.HIGH, Status.WARN,
                          "Docker host not specified (--docker-host required for full mode)")
    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        user = info["user"]
        
        if verbose:
            print(f"[DEBUG] CONT-USER-001: Config.User={user!r}")
        
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
        if verbose:
            print(f"[DEBUG] CONT-USER-001: exception {e!r}")
        return CheckResult("CONT-USER-001", "Non-root container user", "Container", Severity.HIGH, Status.WARN,
                          f"Docker error while checking container user: {str(e)}")


def check_minimal_ports(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-PORT-001: Minimize exposed host ports.

    Why it matters:
    - Each published host port is an entry point; minimising them reduces attack surface.

    Logic:
    - Inspect HostConfig.PortBindings of the target container.
    - PASS if 0–2 ports; WARN if more than 2.
    """
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-PORT-001: docker_host not provided; returning WARN")
        return CheckResult("CONT-PORT-001", "Minimal exposed ports", "Container", Severity.MEDIUM, Status.WARN,
                          "Docker host not specified. Cannot inspect published ports.")
    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        
        port_bindings = info["ports"]
        exposed_count = len(port_bindings)
        if verbose:
            print(f"[DEBUG] CONT-PORT-001: PortBindings={port_bindings!r}, count={exposed_count}")
        
        if exposed_count == 0:
            return CheckResult("CONT-PORT-001", "Minimal exposed ports", "Container", Severity.MEDIUM, Status.PASS,
                              "No host ports exposed ✓")
        elif exposed_count <= 2:
            return CheckResult("CONT-PORT-001", "Minimal exposed ports", "Container", Severity.MEDIUM, Status.PASS,
                              f"{exposed_count} host port(s) published: {list(port_bindings.keys())}.")
        else:
            return CheckResult("CONT-PORT-001", "Minimal exposed ports", "Container", Severity.MEDIUM, Status.WARN,
                              f"{exposed_count} host ports published: {list(port_bindings.keys())}. Review and close unused ports.")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-PORT-001: exception {e!r}")
        return CheckResult("CONT-PORT-001", "Minimal exposed ports", "Container", Severity.MEDIUM, Status.WARN, f"Docker error while checking ports: {str(e)}")


def check_health_checks(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-HEALTH-001: Healthcheck configured.

    Why it matters:
    - Healthchecks enable orchestrators to detect and replace unhealthy containers.

    Logic:
    - Inspect Config.Healthcheck.Test in container config.
    - WARN if missing, PASS if present.
    """
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-HEALTH-001: docker_host not provided; returning WARN")
        return CheckResult("CONT-HEALTH-001", "Healthcheck configured", "Container", Severity.MEDIUM, Status.WARN,
                          "Docker host not specified. Cannot inspect container healthcheck.")
    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        
        healthcheck = info["healthcheck"]
        if verbose:
            print(f"[DEBUG] CONT-HEALTH-001: Healthcheck={healthcheck!r}")
        
        if not healthcheck or not healthcheck.get("Test"):
            return CheckResult("CONT-HEALTH-001", "Healthcheck configured", "Container", Severity.MEDIUM, Status.WARN,
                              "No HEALTHCHECK in Dockerfile. Add: HEALTHCHECK CMD curl -f http://localhost/ || exit 1")
        return CheckResult("CONT-HEALTH-001", "Healthcheck configured", "Container", Severity.MEDIUM, Status.PASS,
                          f"Healthcheck configured ✓")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-HEALTH-001: exception {e!r}")
        return CheckResult("CONT-HEALTH-001", "Healthcheck configured", "Container", Severity.MEDIUM, Status.WARN, f"Docker error while checking healthcheck: {str(e)}.")


def check_resource_limits(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-RES-001: CPU/Memory resource limits set.

    Why it matters:
    - Limits help prevent a single container from exhausting host resources.

    Logic:
    - Inspect HostConfig for CpuQuota/NanoCpus and Memory.
    - PASS if any limit is set; WARN otherwise.
    """
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-RES-001: docker_host not provided; returning WARN")
        return CheckResult("CONT-RES-001", "Resource limits configured", "Container", Severity.MEDIUM, Status.WARN,
                          "Docker host not specified. Cannot inspect CPU/memory limits.")
    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        
        
        cpu_limit = info["cpu_limit"]
        mem_limit = info["memory_limit"]
        if verbose:
            print(f"[DEBUG] CONT-RES-001: CpuQuota/NanoCpus={cpu_limit}, Memory={mem_limit}")
        
        if mem_limit or cpu_limit:
            return CheckResult("CONT-RES-001", "Resource limits configured", "Container", Severity.MEDIUM, Status.PASS,
                              f"Limits detected: Memory={mem_limit}B, CPU={cpu_limit}")
        return CheckResult("CONT-RES-001", "Resource limits configured", "Container", Severity.MEDIUM, Status.WARN,
                          "No CPU/memory limits. Add to docker-compose.yml: deploy.resources.limits")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-RES-001: exception {e!r}")
        return CheckResult("CONT-RES-001", "Resource limits configured", "Container", Severity.MEDIUM, Status.WARN, f"Docker error while checking resource limits: {str(e)}.")


def check_image_registry(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-REG-001: Trusted image registry source.

    Why it matters:
    - Pulling from unverified registries increases supply chain risk.

    Logic (heuristic):
    - Check image tag of target container.
    - PASS if from an 'official' or known-good namespace (simple heuristic).
    - WARN otherwise.
    """
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-REG-001: docker_host not provided; returning WARN")
        return CheckResult("CONT-REG-001", "Trusted image registry", "Container", Severity.MEDIUM, Status.WARN,
                          "Docker host not specified. Cannot inspect image source.")
    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        
        image_name = info["image"]
        

        if verbose:
            print(f"[DEBUG] CONT-REG-001: image_name={image_name!r}")
        
         # Simple heuristic for "trusted": official Docker Hub library images or specific known images
        trusted_markers = [
            "docker.io/library/",
            "nginx:",
            "python:",
            "postgres:",
            "redis:",
        ]
        
        if any(marker in image_name for marker in trusted_markers):
            return CheckResult("CONT-REG-001", "Trusted image registry", "Container", Severity.MEDIUM, Status.PASS,
                              f"Image appears to come from a trusted/official source: {image_name}")
        return CheckResult("CONT-REG-001", "Trusted image registry", "Container", Severity.MEDIUM, Status.WARN,
                          f"Image '{image_name}' does not clearly match trusted registries; ensure it comes from an official or verified source.",)
    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-REG-001: exception {e!r}")
        return CheckResult("CONT-REG-001", "Trusted image registry", "Container", Severity.MEDIUM, Status.WARN, f"Docker error while checking image registry: {str(e)}.")


def check_no_secrets(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-SEC-001: No secrets in environment.

    Why it matters:
    - Hardcoded secrets (passwords, API keys) in env or images are a major risk.

    Logic (heuristic):
    - Inspect Config.Env for variables whose names include:
      password, secret, key, token, api_key.
    - If any found, FAIL with a short sample list.
    - Otherwise PASS.
    """
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-SEC-001: docker_host not provided; returning WARN")
        return CheckResult("CONT-SEC-001", "No secrets in environment", "Container", Severity.HIGH, Status.WARN,
                          "Docker host not specified. Cannot inspect container environment.")
    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        
        env_vars = info["env"]
        if verbose:
            print(f"[DEBUG] CONT-SEC-001: found {len(env_vars)} env vars")
        
        suspicious_names = ["password", "secret", "key", "token", "api_key"]
        secrets_found = [
            env
            for env in env_vars
            if any(kw in env.split("=", 1)[0].lower() for kw in suspicious_names)
        ]
        
        if verbose:
            print(f"[DEBUG] CONT-SEC-001: secrets_found={secrets_found!r}")
        
        if secrets_found:
            sample = secrets_found[:2]
            return CheckResult("CONT-SEC-001", "No secrets in environment", "Container", Severity.HIGH, Status.FAIL,
                              f"Environment variables with secret-like names detected (sample: {sample}). "
                                "Move secrets to Docker secrets or a dedicated vault.")
        return CheckResult("CONT-SEC-001", "No secrets in environment", "Container", Severity.HIGH, Status.PASS,
                          "No obvious secrets in environment variables ✓")
    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-SEC-001: exception {e!r}")
        return CheckResult("CONT-SEC-001", "No secrets in environment", "Container", Severity.HIGH, Status.WARN, f"Docker error while checking environment secrets: {str(e)}.")