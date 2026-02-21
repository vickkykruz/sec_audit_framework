"""
Unit tests for security check modules.

Tests each of the 24 checks with:
- Mocked HTTP responses (debug mode, headers)
- Mocked Docker container data
- Mocked SSH command outputs
- Edge cases and false positives
"""