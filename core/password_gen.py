"""
Password Generator and Health Check module for ShadowVault.
Uses Shannon Entropy + zxcvbn for strength analysis.
"""
from __future__ import annotations
import math
import secrets
import string
from dataclasses import dataclass
from typing import Optional

try:
    import zxcvbn as _zxcvbn
    _HAS_ZXCVBN = True
except ImportError:
    _HAS_ZXCVBN = False

# ── Generator ────────────────────────────────────────────────────

CHARSET_LOWER   = string.ascii_lowercase
CHARSET_UPPER   = string.ascii_uppercase
CHARSET_DIGITS  = string.digits
CHARSET_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"


def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Generate a cryptographically secure random password."""
    charset = ""
    required = []

    if use_lower:
        c = CHARSET_LOWER
        if exclude_ambiguous:
            c = c.replace("l", "").replace("o", "")
        charset += c
        required.append(secrets.choice(c))

    if use_upper:
        c = CHARSET_UPPER
        if exclude_ambiguous:
            c = c.replace("I", "").replace("O", "")
        charset += c
        required.append(secrets.choice(c))

    if use_digits:
        c = CHARSET_DIGITS
        if exclude_ambiguous:
            c = c.replace("0", "").replace("1", "")
        charset += c
        required.append(secrets.choice(c))

    if use_symbols:
        charset += CHARSET_SYMBOLS
        required.append(secrets.choice(CHARSET_SYMBOLS))

    if not charset:
        charset = CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGITS
        required = []

    remaining = length - len(required)
    password_chars = required + [secrets.choice(charset) for _ in range(remaining)]
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


# ── Entropy calculation ───────────────────────────────────────────

def _charset_size(password: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in password):
        size += 26
    if any(c in string.ascii_uppercase for c in password):
        size += 26
    if any(c in string.digits for c in password):
        size += 10
    if any(c in CHARSET_SYMBOLS for c in password):
        size += len(CHARSET_SYMBOLS)
    if any(c not in string.printable for c in password):
        size += 32
    return max(size, 1)


def calc_entropy(password: str) -> float:
    """Shannon entropy in bits: log2(charset_size) * length."""
    if not password:
        return 0.0
    return math.log2(_charset_size(password)) * len(password)


# ── Strength rating ───────────────────────────────────────────────

@dataclass
class StrengthResult:
    score:       int          # 0-4 (zxcvbn scale)
    label:       str          # "Very Weak" … "Very Strong"
    entropy:     float        # bits
    crack_time:  str          # human-readable estimate
    suggestions: list[str]
    color:       str          # hex color for UI

_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
_COLORS = ["#f85149", "#d29922", "#e3b341", "#3fb950", "#58a6ff"]


def check_strength(password: str) -> StrengthResult:
    entropy = calc_entropy(password)

    if _HAS_ZXCVBN:
        result = _zxcvbn.zxcvbn(password)
        score = result["score"]
        crack = result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
        suggestions = result["feedback"]["suggestions"]
        warning = result["feedback"].get("warning", "")
        if warning:
            suggestions = [warning] + suggestions
    else:
        # Fallback: estimate score from entropy
        if entropy < 28:
            score = 0
        elif entropy < 36:
            score = 1
        elif entropy < 50:
            score = 2
        elif entropy < 65:
            score = 3
        else:
            score = 4
        crack = _entropy_to_crack_time(entropy)
        suggestions = _generate_suggestions(password)

    return StrengthResult(
        score=score,
        label=_LABELS[score],
        entropy=entropy,
        crack_time=crack,
        suggestions=suggestions[:3],
        color=_COLORS[score],
    )


def _entropy_to_crack_time(entropy: float) -> str:
    """Rough offline crack time estimate at 10^10 hashes/sec."""
    combos = 2 ** entropy
    seconds = combos / 1e10
    if seconds < 1:         return "instantly"
    if seconds < 60:        return f"{seconds:.0f} seconds"
    if seconds < 3600:      return f"{seconds/60:.0f} minutes"
    if seconds < 86400:     return f"{seconds/3600:.0f} hours"
    if seconds < 2592000:   return f"{seconds/86400:.0f} days"
    if seconds < 31536000:  return f"{seconds/2592000:.0f} months"
    return f"{seconds/31536000:.1f} years"


def _generate_suggestions(password: str) -> list[str]:
    tips = []
    if len(password) < 12:
        tips.append("Use at least 12 characters.")
    if not any(c in string.ascii_uppercase for c in password):
        tips.append("Add uppercase letters.")
    if not any(c in string.digits for c in password):
        tips.append("Add numbers.")
    if not any(c in CHARSET_SYMBOLS for c in password):
        tips.append("Add special characters.")
    return tips


# ── Batch health check ────────────────────────────────────────────

@dataclass
class HealthIssue:
    entry_id:    int
    entry_title: str
    issue_type:  str   # "weak" | "duplicate" | "reused"
    detail:      str


def check_all_health(entries) -> list[HealthIssue]:
    """
    Analyse a list of VaultEntry for weak, duplicate, or reused passwords.
    """
    issues: list[HealthIssue] = []
    password_map: dict[str, list[tuple[int, str]]] = {}

    for e in entries:
        pw = e.password

        # 1. Strength check
        result = check_strength(pw)
        if result.score < 2:
            issues.append(HealthIssue(
                entry_id=e.id,
                entry_title=e.title,
                issue_type="weak",
                detail=f"{result.label} (entropy {result.entropy:.0f} bit)",
            ))

        # 2. Track duplicates
        password_map.setdefault(pw, []).append((e.id, e.title))

    # 3. Flag duplicate passwords
    for pw, occurrences in password_map.items():
        if len(occurrences) > 1:
            titles = ", ".join(t for _, t in occurrences)
            for eid, etitle in occurrences:
                issues.append(HealthIssue(
                    entry_id=eid,
                    entry_title=etitle,
                    issue_type="duplicate",
                    detail=f"Password reused in: {titles}",
                ))

    return issues
