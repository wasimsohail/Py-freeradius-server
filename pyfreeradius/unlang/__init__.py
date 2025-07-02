from __future__ import annotations

"""Unlang interpreter package (Iteration-1).

Provides `parse_policy(text)` → AST and `evaluate(policy, context)` returning
FreeRADIUS style result codes: `accept`, `reject`, `ok`, `noop`.
"""

from .parser import parse_policy  # noqa: F401
from .interpreter import evaluate_policy, ResultCode  # noqa: F401
