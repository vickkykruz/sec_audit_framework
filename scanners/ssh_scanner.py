"""
SSH client for host/server OS checks.

Uses paramiko for safe command execution:
- ss -tlnp (open ports)
- systemctl list-units (services)
- cat /etc/ssh/sshd_config
- find permissions checks
"""