"""Injection shield for text that comes from a hostile sample (built on the content filter in core/guardrails).

Everything a sample prints, every file it contains and every request it makes is untrusted data. Before the analyst model
sees any of it we strip control characters, truncate, redact prompt-injection phrases (guardrail patterns plus verdict-steering
phrases) and fence it so the model can tell data from instructions. The verdict itself never depends on this text.
"""

from __future__ import annotations

import re

from src.app.core.common.logging import logger
from src.app.core.guardrails.content_filter import PROMPT_INJECTION_PATTERNS, check_content_filter

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_STEERING = [
    r"(report|mark|conclude|classify|output|say|declare)\s+(this|the|that)?\s*(package|sample|file|code|script)?\s*(as\s+)?(clean|safe|benign|harmless)",
    r"verdict\s*[:=]\s*(clean|safe|benign)",
    r"(do\s+not|don'?t)\s+(report|flag|mention)",
    r"(system|assistant|developer)\s*:\s*(ignore|you\s+must|new\s+instructions)",
]
_REDACTION = "[REDACTED: prompt-injection text]"


def sanitize_untrusted(text: str, limit: int = 1500, label: str = "sample output", tail: bool = True) -> tuple[str, bool]:
    """Return ``(fenced_text, injection_detected)``."""
    text = _CONTROL.sub("", text or "")
    text = text[-limit:] if tail else text[:limit]
    flagged = check_content_filter(text, banned_keywords=[], check_prompt_injection=True).is_blocked
    for pattern in [*PROMPT_INJECTION_PATTERNS, *_STEERING]:
        text, count = re.subn(pattern, _REDACTION, text, flags=re.IGNORECASE)
        flagged = flagged or count > 0
    if flagged:
        logger.warning("untrusted_text_injection_redacted", label=label)
    note = " (contained injection text, redacted)" if flagged else ""
    return f"<<<UNTRUSTED {label}{note}>>>\n{text}\n<<<END UNTRUSTED>>>", flagged
