"""
Target interaction scanners for multi-layer assessment.

Provides safe, abstracted clients for:
- HTTP/TLS analysis (web app + webserver layers)
- Docker daemon inspection (container layer)
- SSH command execution (host layer)

All scanners implement consistent error handling and timeout patterns.
"""