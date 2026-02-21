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