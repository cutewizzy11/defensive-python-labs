"""
Password strength analyzer.

Measures entropy, checks against common passwords, detects patterns,
and provides actionable feedback. No external dependencies required.
"""

from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field
from typing import List

# Top 50 most common passwords (abbreviated list — expand for real use)
COMMON_PASSWORDS = {
    "password", "123456", "password123", "admin", "letmein", "qwerty",
    "abc123", "monkey", "1234567890", "password1", "iloveyou", "sunshine",
    "princess", "welcome", "shadow", "superman", "michael", "football",
    "dragon", "master", "1234", "12345", "123456789", "test", "root",
    "pass", "login", "hello", "charlie", "donald", "password2", "qwerty123",
    "starwars", "123123", "access", "flower", "passw0rd", "baseball",
    "hockey", "solo", "princess1", "jessica", "111111", "000000",
}

KEYBOARD_WALKS = ["qwerty", "asdf", "zxcv", "qwer", "asdfgh", "1234", "abcd"]
LEET_MAP = str.maketrans("@031!5$7", "aoelisg t")


@dataclass
class PasswordReport:
    password: str
    score: int           # 0 (terrible) – 100 (excellent)
    strength: str        # Weak / Fair / Strong / Very Strong
    entropy_bits: float
    issues: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [
            f"Password : {'*' * len(self.password)}",
            f"Strength : {self.strength}  (score {self.score}/100)",
            f"Entropy  : {self.entropy_bits:.1f} bits",
        ]
        if self.issues:
            lines.append("Issues   : " + " | ".join(self.issues))
        if self.suggestions:
            lines.append("Tips     :")
            for tip in self.suggestions:
                lines.append(f"  • {tip}")
        return "\n".join(lines)


def _calculate_entropy(password: str) -> float:
    """Shannon entropy based on character-set size."""
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def analyze(password: str) -> PasswordReport:
    """
    Analyze a password and return a detailed PasswordReport.

    Parameters
    ----------
    password : str
        The password to analyze.

    Returns
    -------
    PasswordReport
        Score, strength label, entropy, issues, and suggestions.

    Examples
    --------
    >>> report = analyze("P@ssw0rd!")
    >>> report.score > 50
    True
    >>> report = analyze("123456")
    >>> report.strength
    'Weak'
    """
    issues: List[str] = []
    suggestions: List[str] = []
    score = 100

    lower = password.lower()
    leet_decoded = lower.translate(LEET_MAP)

    # --- Length checks ---
    length = len(password)
    if length < 8:
        issues.append("Too short (<8)")
        suggestions.append("Use at least 12 characters.")
        score -= 40
    elif length < 12:
        issues.append("Short (<12)")
        suggestions.append("Aim for 16+ characters for better security.")
        score -= 15
    elif length >= 20:
        score += 10  # bonus

    # --- Character variety ---
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    if variety < 3:
        issues.append("Low character variety")
        suggestions.append("Mix uppercase, lowercase, digits, and symbols.")
        score -= 20
    if not has_symbol:
        suggestions.append("Add at least one special character (!@#$%^&*).")

    # --- Common password check ---
    if lower in COMMON_PASSWORDS or leet_decoded in COMMON_PASSWORDS:
        issues.append("Common password")
        suggestions.append("This password appears in breach databases. Choose something unique.")
        score -= 50

    # --- Repeated characters ---
    if re.search(r"(.)\1{2,}", password):
        issues.append("Repeated characters (aaa, 111)")
        suggestions.append("Avoid character repetition.")
        score -= 10

    # --- Keyboard walk detection ---
    for walk in KEYBOARD_WALKS:
        if walk in lower:
            issues.append(f"Keyboard pattern '{walk}'")
            suggestions.append("Avoid keyboard patterns like 'qwerty' or '1234'.")
            score -= 15
            break

    # --- All digits or all alpha ---
    if password.isdigit():
        issues.append("All digits")
        score -= 20
    if password.isalpha():
        issues.append("All letters — no digits/symbols")
        score -= 10

    # --- Entropy ---
    entropy = _calculate_entropy(password)

    score = max(0, min(100, score))

    if score >= 80:
        strength = "Very Strong"
    elif score >= 60:
        strength = "Strong"
    elif score >= 40:
        strength = "Fair"
    else:
        strength = "Weak"

    if not suggestions and score == 100:
        suggestions.append("Excellent password! Consider storing it in a password manager.")

    return PasswordReport(
        password=password,
        score=score,
        strength=strength,
        entropy_bits=entropy,
        issues=issues,
        suggestions=suggestions,
    )


def bulk_analyze(passwords: List[str]) -> List[PasswordReport]:
    """
    Analyze a list of passwords and return sorted reports (weakest first).

    Useful for auditing exported password lists (e.g., from a CSV).

    Examples
    --------
    >>> reports = bulk_analyze(["abc", "C0rrectH0rseBatteryStaple!"])
    >>> reports[0].strength
    'Weak'
    """
    return sorted([analyze(p) for p in passwords], key=lambda r: r.score)
