"""
Configuration definitions for all 24 security checks.

Each check has:
- id: unique identifier (e.g., "APP-DEBUG-001")
- layer: app/webserver/container/host
- name: human readable name
- severity: CRITICAL/HIGH/MEDIUM/LOW
- description: what it checks
- recommendation: fix instructions
"""


# Defines CHECKS list/dict with all 24 checks
from typing import List, Dict, Any


CHECKS: List[Dict[str, str]] = [
    # ═══════════════════════════════════════════════════════════════════════════════
    # WEB APP LAYER (6 checks) - Flask/Django/Node.js framework configuration
    # ═══════════════════════════════════════════════════════════════════════════════
    {
        "id": "APP-DEBUG-001",
        "layer": "app",
        "name": "Debug mode disabled",
        "severity": "HIGH",
        "description": "Checks that web framework debug mode is disabled in production.",
        "recommendation": "Set DEBUG=False in Flask/Django settings. Remove debug banners and error details."
    },
    {
        "id": "APP-COOKIE-001",
        "layer": "app",
        "name": "Secure session cookies",
        "severity": "HIGH",
        "description": "Verifies session cookies have HttpOnly, Secure, and SameSite=Strict/Lax flags.",
        "recommendation": "Configure session cookies with secure flags in framework settings."
    },
    {
        "id": "APP-CSRF-001",
        "layer": "app",
        "name": "CSRF protection enabled",
        "severity": "MEDIUM",
        "description": "Detects CSRF protection tokens in forms or framework-specific CSRF headers.",
        "recommendation": "Enable CSRF middleware in Flask/Django. Validate tokens on state-changing requests."
    },
    {
        "id": "APP-ADMIN-001",
        "layer": "app",
        "name": "No exposed admin endpoints",
        "severity": "MEDIUM",
        "description": "Checks for exposed /admin, /debug, /test endpoints returning 200.",
        "recommendation": "Disable or protect admin/debug endpoints with authentication."
    },
    {
        "id": "APP-RATE-001",
        "layer": "app",
        "name": "Rate limiting configured",
        "severity": "MEDIUM",
        "description": "Tests for rate limiting by sending rapid requests and checking 429 responses.",
        "recommendation": "Implement rate limiting at application level (Flask-Limiter, Django-ratelimit)."
    },
    {
        "id": "APP-PASS-001",
        "layer": "app",
        "name": "Strong password policy",
        "severity": "LOW",
        "description": "Checks password reset/registration forms for complexity requirements.",
        "recommendation": "Enforce minimum 12 chars, mixed case, numbers, symbols in password policy."
    },

    # ═══════════════════════════════════════════════════════════════════════════════
    # WEBSERVER LAYER (6 checks) - Nginx/Apache reverse proxy configuration
    # ═══════════════════════════════════════════════════════════════════════════════
    {
        "id": "WS-HSTS-001",
        "layer": "webserver",
        "name": "HSTS header enabled",
        "severity": "HIGH",
        "description": "Verifies Strict-Transport-Security header with max-age >= 31536000.",
        "recommendation": "Add HSTS header: 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
    },
    {
        "id": "WS-SEC-001",
        "layer": "webserver",
        "name": "Security headers present",
        "severity": "HIGH",
        "description": "Checks CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy headers.",
        "recommendation": "Configure security headers in Nginx/Apache virtual host configuration."
    },
    {
        "id": "WS-TLS-001",
        "layer": "webserver",
        "name": "TLS 1.2+ with strong ciphers",
        "severity": "HIGH",
        "description": "Analyzes TLS version and cipher suite strength via SSL labs heuristics.",
        "recommendation": "Disable TLS 1.0/1.1. Use only strong ciphers (ECDHE + AES-GCM)."
    },
    {
        "id": "WS-SRV-001",
        "layer": "webserver",
        "name": "No server version disclosure",
        "severity": "MEDIUM",
        "description": "Checks Server header doesn't leak Nginx/Apache version information.",
        "recommendation": "Set 'server_tokens off' in Nginx or ServerTokens Prod in Apache."
    },
    {
        "id": "WS-DIR-001",
        "layer": "webserver",
        "name": "Directory listing disabled",
        "severity": "MEDIUM",
        "description": "Attempts access to common directories (/, /static/, /uploads/) expecting 403/404.",
        "recommendation": "Disable autoindex in Nginx ('autoindex off') and DirectoryIndex in Apache."
    },
    {
        "id": "WS-LIMIT-001",
        "layer": "webserver",
        "name": "Request size limits",
        "severity": "LOW",
        "description": "Verifies client_max_body_size and request limits are configured.",
        "recommendation": "Set client_max_body_size 1m; in Nginx location blocks."
    },
    {
        "id": "WS-CONF-HSTS",
        "layer": "webserver",
        "name": "HSTS configured in nginx.conf",
        "severity": "MEDIUM",
        "description": "Checks nginx.conf for a Strict-Transport-Security header configuration.",
        "recommendation": "Add 'add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;' to your HTTPS server block."
    },
    {
        "id": "WS-CONF-CSP",
        "layer": "webserver",
        "name": "CSP configured in nginx.conf",
        "severity": "MEDIUM",
        "description": "Checks nginx.conf for a Content-Security-Policy header.",
        "recommendation": "Define a CSP header in nginx.conf to restrict allowed sources of scripts, styles, and other resources."
    },

    # ═══════════════════════════════════════════════════════════════════════════════
    # CONTAINER LAYER (6 checks) - Docker runtime security
    # ═══════════════════════════════════════════════════════════════════════════════
    {
        "id": "CONT-USER-001",
        "layer": "container", 
        "name": "Non-root container user",
        "severity": "HIGH",
        "description": "Inspects running container Config.User field via docker-py. FAILs if empty, '0', or 'root'.",
        "recommendation": "Add 'USER 1000' (or non-root UID) to Dockerfile. Avoid running containers as root."
    },
    {
        "id": "CONT-PORT-001",
        "layer": "container",
        "name": "Minimal exposed ports", 
        "severity": "MEDIUM",
        "description": "Counts HostConfig.PortBindings in running container. PASS if ≤2 ports, WARN if more.",
        "recommendation": "Minimize published host ports. Use internal container networking where possible."
    },
    {
        "id": "CONT-HEALTH-001",
        "layer": "container",
        "name": "Healthcheck configured",
        "severity": "MEDIUM",
        "description": "Checks Config.Healthcheck.Test in running container. WARN if missing.",
        "recommendation": "Add HEALTHCHECK instruction to Dockerfile (e.g., 'HEALTHCHECK CMD curl -f http://localhost/')."
    },
    {
        "id": "CONT-RES-001",
        "layer": "container",
        "name": "Resource limits configured",
        "severity": "MEDIUM",
        "description": "Inspects HostConfig.Memory and CpuQuota/NanoCpus. PASS if any limit is set.",
        "recommendation": "Set deploy.resources.limits in docker-compose.yml or use docker run --memory --cpus."
    },
    {
        "id": "CONT-REG-001",
        "layer": "container",
        "name": "Trusted image registry",
        "severity": "MEDIUM",
        "description": "Checks container image tag against trusted markers (official Docker Hub images, nginx/python/etc.).",
        "recommendation": "Use official images from docker.io/library/ or verified private registries."
    },
    {
        "id": "CONT-SEC-001",
        "layer": "container",
        "name": "No secrets in environment",
        "severity": "HIGH",
        "description": "Scans Config.Env for variables with names containing 'password', 'secret', 'key', 'token', 'api_key'.",
        "recommendation": "Move secrets to Docker secrets, environment files (.env), or a secrets manager."
    },
    {
        "id": "CONT-CONF-USER",
        "layer": "container",
        "name": "Dockerfile USER instruction",
        "severity": "HIGH",
        "description": "Statically parses Dockerfile for USER instruction presence.",
        "recommendation": "Add 'USER 1000' (or non-root UID:GID) near end of Dockerfile."
    },
    {
        "id": "CONT-CONF-HEALTH",
        "layer": "container",
        "name": "Dockerfile HEALTHCHECK",
        "severity": "MEDIUM",
        "description": "Statically parses Dockerfile for HEALTHCHECK instruction presence.",
        "recommendation": "Add 'HEALTHCHECK CMD curl -f http://localhost/health || exit 1' to Dockerfile."
    },
    {
        "id": "CONT-COMP-RES",
        "layer": "container",
        "name": "Compose resource limits",
        "severity": "MEDIUM",
        "description": "Parses docker-compose.yml services for deploy.resources.limits presence.",
        "recommendation": "Add deploy.resources.limits.cpu: 0.5 and deploy.resources.limits.memory: 256M to services."
    },

    # ═══════════════════════════════════════════════════════════════════════════════
    # HOST LAYER (6 checks) - Linux server hardening
    # ═══════════════════════════════════════════════════════════════════════════════
    {
        "id": "HOST-SSH-001",
        "layer": "host",
        "name": "SSH hardening",
        "severity": "HIGH",
        "description": "Checks /etc/ssh/sshd_config for PermitRootLogin and fails if root login is enabled.",
        "recommendation": "Set 'PermitRootLogin no' in sshd_config and restart the SSH service."
    },
    {
        "id": "HOST-FW-001",
        "layer": "host",
        "name": "Firewall enabled",
        "severity": "HIGH",
        "description": "Uses ufw status or iptables output to infer whether a host firewall is active.",
        "recommendation": "Enable and configure a host firewall (e.g. ufw enable, or nftables/iptables rules)."
    },
    {
        "id": "HOST-SVC-001",
        "layer": "host",
        "name": "Minimal services running",
        "severity": "MEDIUM",
        "description": "Counts running systemd services and warns if the number is unusually high.",
        "recommendation": "Review running services with systemctl and disable those not required for the web stack."
    },
    {
        "id": "HOST-UPDATE-001",
        "layer": "host",
        "name": "Automatic updates configured",
        "severity": "MEDIUM",
        "description": "Checks if unattended-upgrades is enabled to install security updates automatically.",
        "recommendation": "Install and enable unattended-upgrades (or equivalent) for regular security patching."
    },
    {
        "id": "HOST-PERM-001",
        "layer": "host",
        "name": "Secure SSH file permissions",
        "severity": "MEDIUM",
        "description": "Searches /etc/ssh for world-writable files, which may indicate misconfigured permissions.",
        "recommendation": "Tighten permissions in /etc/ssh so that only root can modify SSH configuration files."
    },
    {
        "id": "HOST-LOG-001",
        "layer": "host",
        "name": "Logging service active",
        "severity": "LOW",
        "description": "Checks whether rsyslog (or equivalent) logging service is active on the host.",
        "recommendation": "Ensure a system logging service is installed and enabled to retain audit and error logs."
    },
    {
        "id": "HOST-SVC-GUNICORN",
        "layer": "host",
        "name": "Gunicorn runs as non-root",
        "severity": "HIGH",
        "description": "Inspects Gunicorn processes and fails if they are running as root instead of a non-privileged user.",
        "recommendation": "Run Gunicorn under a dedicated non-root account via systemd or a process manager."
    },
    {
        "id": "HOST-SVC-UWSGI",
        "layer": "host",
        "name": "uWSGI runs as non-root",
        "severity": "HIGH",
        "description": "Inspects uWSGI processes and fails if they run as root instead of a non-privileged user.",
        "recommendation": "Run uWSGI under a non-root service account in its service configuration."
    },
    {
        "id": "HOST-SVC-MYSQL",
        "layer": "host",
        "name": "MySQL runs as non-root",
        "severity": "HIGH",
        "description": "Checks MySQL processes and fails if they run as root instead of the dedicated mysql user.",
        "recommendation": "Ensure the MySQL daemon runs under the 'mysql' user account and not as root."
    },
    {
        "id": "HOST-SVC-REDIS",
        "layer": "host",
        "name": "Redis runs as non-root",
        "severity": "HIGH",
        "description": "Checks Redis processes and fails if they run as root instead of the dedicated redis user.",
        "recommendation": "Run Redis as the 'redis' user (or another non-root user) in the service configuration."
    },
    # ═══════════════════════════════════════════════════════════════════════════════
    # HOST LAYER (6 checks) - Linux server hardening
    # ═══════════════════════════════════════════════════════════════════════════════
]


def get_checks_by_layer(layer: str) -> List[Dict[str, str]]:
    """Filter checks by layer (app, webserver, container, host)."""
    return [check for check in CHECKS if check["layer"] == layer]


def get_layer_totals() -> Dict[str, int]:
    """Return count of checks per layer."""
    layers = {"app": 0, "webserver": 0, "container": 0, "host": 0}
    for check in CHECKS:
        layers[check["layer"]] += 1
    return layers