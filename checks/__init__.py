"""
Security check registry - 24 total configuration checks.

Organized by stack layer:
- app_checks: Web framework configuration
- webserver_checks: Nginx/Apache reverse proxy
- container_checks: Docker runtime security
- host_checks: Linux server hardening

Each check returns standardized Result objects.
"""