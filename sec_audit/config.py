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
        "name": "SSH hardened configuration",
        "severity": "HIGH",
        "description": "Verifies PermitRootLogin no, key auth only, no weak ciphers/protocols.",
        "recommendation": "Configure /etc/ssh/sshd_config: PermitRootLogin no, PasswordAuthentication no."
    },
    {
        "id": "HOST-SVC-001",
        "layer": "host",
        "name": "No unnecessary services",
        "severity": "MEDIUM",
        "description": "Checks for common unnecessary services (telnet, ftp, mysql, etc.).",
        "recommendation": "Disable unused services: systemctl disable <service>."
    },
    {
        "id": "HOST-UPDATE-001",
        "layer": "host",
        "name": "Automatic security updates",
        "severity": "MEDIUM",
        "description": "Verifies unattended-upgrades or similar auto-update mechanism.",
        "recommendation": "Install and configure unattended-upgrades on Ubuntu/Debian."
    },
    {
        "id": "HOST-PERM-001",
        "layer": "host",
        "name": "Correct file permissions",
        "severity": "MEDIUM",
        "description": "Checks web root (755), config files (640), SSH keys (600).",
        "recommendation": "chmod 755 /var/www/html, chmod 640 /etc/nginx/sites-available/*."
    },
    {
        "id": "HOST-FW-001",
        "layer": "host",
        "name": "Firewall configured",
        "severity": "HIGH",
        "description": "Verifies ufw/iptables/firewalld allowing only necessary ports.",
        "recommendation": "ufw enable; ufw allow 22,80,443; ufw deny 1024:65535."
    },
    {
        "id": "HOST-LOG-001",
        "layer": "host",
        "name": "Logging and monitoring",
        "severity": "LOW",
        "description": "Checks syslog/journald configuration and log rotation.",
        "recommendation": "Configure rsyslog or systemd-journald with logrotate."
    }
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