"""
Secret and sensitive credential detection engine.
Uses regex patterns and Shannon entropy to catch API keys, tokens, and passwords.
"""

import math
import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class SecretMatch:
    secret_type: str
    match_str: str
    confidence: str
    start: int
    end: int


@dataclass
class DetectionResult:
    is_secret: bool
    matches: List[SecretMatch] = field(default_factory=list)
    masked_content: str = ""

    @property
    def primary_type(self) -> Optional[str]:
        if not self.matches:
            return None
        return self.matches[0].secret_type


# Comprehensive detection rules
SECRET_PATTERNS = [
    {
        "type": "AWS Access Key",
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "confidence": "HIGH",
    },
    {
        "type": "GitHub Token",
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
        "confidence": "HIGH",
    },
    {
        "type": "OpenAI / Anthropic API Key",
        "pattern": r"sk-(?:proj-)?[a-zA-Z0-9_\-]{32,}|sk-ant-[a-zA-Z0-9_\-]{32,}",
        "confidence": "HIGH",
    },
    {
        "type": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z\\-_]{35}",
        "confidence": "HIGH",
    },
    {
        "type": "Stripe Live Key",
        "pattern": r"(?:sk|rk)_live_[0-9a-zA-Z]{24,}",
        "confidence": "HIGH",
    },
    {
        "type": "Slack Token",
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*",
        "confidence": "HIGH",
    },
    {
        "type": "Private Key",
        "pattern": r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----",
        "confidence": "HIGH",
    },
    {
        "type": "JSON Web Token (JWT)",
        "pattern": r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}",
        "confidence": "MEDIUM",
    },
    {
        "type": "Database Connection URL",
        "pattern": r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^:]+:[^@]+@[^/]+",
        "confidence": "HIGH",
    },
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string to detect randomized secret keys."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def mask_secret(text: str, start: int, end: int) -> str:
    """Masks secret text, leaving only the beginning and end visible."""
    val = text[start:end]
    if len(val) <= 8:
        masked = "*" * len(val)
    else:
        prefix_len = min(4, len(val) // 4)
        suffix_len = min(3, len(val) // 4)
        masked = val[:prefix_len] + "*" * (len(val) - prefix_len - suffix_len) + val[-suffix_len:]
    return text[:start] + masked + text[end:]


def detect_secrets(content: str) -> DetectionResult:
    """
    Inspects clipboard content for secrets and credentials.
    Returns DetectionResult with matches and a safely masked version of the text.
    """
    if not content or not content.strip():
        return DetectionResult(is_secret=False, masked_content=content or "")

    matches: List[SecretMatch] = []

    # 1. Regex pattern matching
    for rule in SECRET_PATTERNS:
        for match in re.finditer(rule["pattern"], content, re.IGNORECASE):
            matches.append(
                SecretMatch(
                    secret_type=rule["type"],
                    match_str=match.group(0),
                    confidence=rule["confidence"],
                    start=match.start(),
                    end=match.end(),
                )
            )

    # 2. Entropy check for standalone candidate strings (e.g. passwords, generic hex tokens)
    # If a single word is long (>24 chars) and has very high entropy (> 4.5) without spaces
    words = content.strip().split()
    if len(words) == 1 and len(words[0]) >= 28 and not matches:
        word = words[0]
        entropy = calculate_shannon_entropy(word)
        if entropy >= 4.5:
            matches.append(
                SecretMatch(
                    secret_type="High-Entropy Secret / Password",
                    match_str=word,
                    confidence="MEDIUM",
                    start=0,
                    end=len(word),
                )
            )

    is_secret = len(matches) > 0
    masked_content = content

    if is_secret:
        # Sort matches backwards to replace without altering earlier offsets
        for m in sorted(matches, key=lambda x: x.start, reverse=True):
            masked_content = mask_secret(masked_content, m.start, m.end)

    return DetectionResult(
        is_secret=is_secret,
        matches=matches,
        masked_content=masked_content,
    )
