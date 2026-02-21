"""
Security Audit Result Models and Validation.

Defines standardized data structures for:
- Individual check results (pass/fail + evidence)
- Aggregated scan results (scores, risk levels)
- Report generation data (tables, summaries)

Supports JSON serialization for CI/CD integration.
"""


# Result dataclass, ScoreCalculator, Validation schemas