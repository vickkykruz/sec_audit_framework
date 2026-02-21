"""
Security Audit Result Models and Validation.

Defines standardized data structures for:
- Individual check results (pass/fail + evidence)
- Aggregated scan results (scores, risk levels)
- Report generation data (tables, summaries)

Supports JSON serialization for CI/CD integration.
"""


# Result dataclass, ScoreCalculator, Validation schemas
from dataclasses import dataclass


@dataclass
class CheckResult:
    """Represents the outcome of a single security check."""
    id: str
    layer: str
    name: str
    status: str      # "PASS" | "FAIL" | "WARN" | "ERROR"
    severity: str    # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    details: str