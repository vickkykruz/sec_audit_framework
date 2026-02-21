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

    # ═══════════════════════════════════════════════════════════════════════════════
    # CONTAINER LAYER (6 checks) - Docker runtime security
    # ═══════════════════════════════════════════════════════════════════════════════
    {
        "id": "CONT-USER-001",
        "layer": "container",
        "name": "Non-root container user",
        "severity": "HIGH",
        "description": "Verifies containers run as non-root user (USER directive in Dockerfile).",
        "recommendation": "Add 'USER 1000:1000' to Dockerfile. Never run as root."
    },
    {
        "id": "CONT-PORT-001",
        "layer": "container",
        "name": "Minimal ports exposed",
        "severity": "MEDIUM",
        "description": "Counts exposed ports - flags >3 ports or privileged ports (<1024).",
        "recommendation": "Expose only necessary ports. Use high-numbered (>1024) ports."
    },
    {
        "id": "CONT-RES-001",
        "layer": "container",
        "name": "Resource limits configured",
        "severity": "MEDIUM",
        "description": "Checks CPU/memory limits in docker-compose.yml or docker run.",
        "recommendation": "Set deploy.resources.limits in docker-compose.yml."
    },
    {
        "id": "CONT-HEALTH-001",
        "layer": "container",
        "name": "Health checks configured",
        "severity": "LOW",
        "description": "Verifies healthcheck configured in Dockerfile/docker-compose.",
        "recommendation": "Add HEALTHCHECK CMD in Dockerfile with curl/readiness endpoint."
    },
    {
        "id": "CONT-REG-001",
        "layer": "container",
        "name": "Trusted image registry",
        "severity": "MEDIUM",
        "description": "Flags Docker Hub anonymous pulls or untrusted registries.",
        "recommendation": "Use official images or verified private registry."
    },
    {
        "id": "CONT-SEC-001",
        "layer": "container",
        "name": "No hardcoded secrets",
        "severity": "CRITICAL",
        "description": "Scans docker-compose.yml for plaintext secrets/passwords/API keys.",
        "recommendation": "Use Docker secrets or environment variables from secure vault."
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