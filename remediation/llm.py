"""
remediation/llm.py — Anthropic API integration for intelligent patch generation.
 
Uses Claude to generate context-aware, stack-specific patch files that go
beyond static templates by incorporating:
  - The actual details from the failed check (e.g. the exact nginx version)
  - The detected stack fingerprint (e.g. Flask + Nginx + Ubuntu)
  - The specific error or misconfiguration found
 
The response is structured JSON that the generator parses into a PatchResult.
"""
 
from __future__ import annotations
import json
import os
import time
from typing import Optional
 
 
# ── Anthropic client (lazy import so the package is optional) ─────────────────
 
def _get_client(api_key: Optional[str] = None):
    """Return an Anthropic client, raising ImportError if not installed."""
    try:
        import anthropic
    except ImportError as e:
        raise ImportError(
            "The 'anthropic' package is required for LLM patch generation. "
            "Install it with: pip install anthropic"
        ) from e
 
    key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        raise ValueError(
            "No Anthropic API key found. Set ANTHROPIC_API_KEY environment "
            "variable or pass --anthropic-key to the CLI."
        )
    return anthropic.Anthropic(api_key=key)
 
 
# ── System prompt ─────────────────────────────────────────────────────────────
 
_SYSTEM_PROMPT = """\
You are StackSentry's remediation engine. Your job is to generate precise,
safe, ready-to-apply patch files for security misconfigurations.
 
You will receive details about a failed security check including:
- The check ID and what it tests
- The exact details from the scan (what was found)
- The detected technology stack
- The recommended fix
 
You must respond with ONLY valid JSON in this exact structure — no prose,
no markdown, no code fences, just raw JSON:
 
{
  "filename": "CHECK-ID.ext",
  "file_type": "python|shell|nginx|dockerfile|yaml",
  "content": "...the complete patch file content...",
  "instructions": "Step-by-step instructions to apply this patch",
  "verification": "A single command to verify the fix was applied"
}
 
Rules for the patch content:
1. Always include a dry-run mode (show what would change without applying)
2. Always create backups before modifying existing files
3. Always validate changes before applying (e.g. nginx -t before reload)
4. Include the check ID and description as a comment at the top
5. Be specific — use the actual values from the check details
6. Shell scripts must start with #!/bin/bash and set -euo pipefail
7. Python scripts must include a --apply flag guard
8. Make patches idempotent — safe to run multiple times
"""
 
 
# ── LLM patch generator ───────────────────────────────────────────────────────
 
def generate_patch_with_llm(
    check_id: str,
    check_name: str,
    layer: str,
    details: str,
    severity: str,
    stack_fingerprint: str,
    recommendation: str,
    api_key: Optional[str] = None,
    max_retries: int = 2,
    retry_delay: float = 3.0,
    verbose: bool = False,
) -> Optional[dict]:
    """
    Call the Anthropic API to generate a context-aware patch.
 
    Retries up to max_retries times on rate-limit errors (HTTP 429)
    or transient server errors (HTTP 529), waiting retry_delay seconds
    between attempts. Returns None after all retries are exhausted so
    the generator can fall back to a static template.
 
    Returns a patch dict on success, None on any failure.
    """
    if verbose:
        print(f"[DEBUG] LLM: generating patch for {check_id} "
              f"(stack: {stack_fingerprint or 'unknown'})")
    try:
        client = _get_client(api_key)
    except (ImportError, ValueError) as e:
        if verbose:
            print(f"[DEBUG] LLM: client unavailable ({e!r}) — skipping")
        return None
 
    user_message = f"""\
Generate a remediation patch for this security check failure:
 
Check ID:    {check_id}
Check Name:  {check_name}
Layer:       {layer}
Severity:    {severity}
Stack:       {stack_fingerprint}
 
What was found:
{details}
 
Recommended fix:
{recommendation}
 
Generate a complete, ready-to-apply patch file that fixes this specific issue.
Use the stack information to make the patch precise — for example, if the stack
includes "Nginx", generate nginx config; if it includes "Flask", generate Python.
"""
 
    for attempt in range(max_retries + 1):
        try:
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )
 
            raw = response.content[0].text.strip()
 
            # Strip markdown code fences if Claude added them despite instructions
            if raw.startswith("```"):
                lines = raw.splitlines()
                raw = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
 
            patch_data = json.loads(raw)
 
            # Validate required keys are present
            required = {"filename", "file_type", "content", "instructions", "verification"}
            if not required.issubset(patch_data.keys()):
                return None
 
            if verbose:
                print(f"[DEBUG] LLM: patch generated for {check_id} "
                      f"→ {patch_data.get('filename', '?')} "
                      f"(attempt {attempt + 1})")
            return patch_data
 
        except Exception as exc:
            exc_str = str(exc).lower()
            is_rate_limit   = "429" in exc_str or "rate_limit" in exc_str or "too many" in exc_str
            is_overloaded   = "529" in exc_str or "overloaded" in exc_str
            is_retryable    = is_rate_limit or is_overloaded
 
            if is_retryable and attempt < max_retries:
                # Exponential back-off: 3s, 6s, 12s ...
                wait = retry_delay * (2 ** attempt)
                if verbose:
                    reason = "rate limit" if is_rate_limit else "server overloaded"
                    print(f"[DEBUG] LLM: {reason} on {check_id} — "
                          f"retrying in {wait:.0f}s "
                          f"(attempt {attempt + 1}/{max_retries})")
                time.sleep(wait)
                continue  # retry
 
            # Non-retryable error or retries exhausted — fall back to template
            if verbose:
                print(f"[DEBUG] LLM: giving up on {check_id} "
                      f"after {attempt + 1} attempt(s) — "
                      f"falling back to static template")
            return None
 
    return None  # should not reach here, but satisfies type checker
 