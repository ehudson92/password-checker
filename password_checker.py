# password_checker.py
"""Simple Password Strength Checker
Usage:
    python password_checker.py
    or
    from password_checker import assess_password; assess_password('P@ssw0rd!')
"""

import math
import re
import sys

# Character class checks
RE_UPPER = re.compile(r"[A-Z]")
RE_LOWER = re.compile(r"[a-z]")
RE_DIGIT = re.compile(r"\d")
RE_SPECIAL = re.compile(r"[^A-Za-z0-9]")

def estimate_entropy(password: str) -> float:
    """
    Estimate Shannon-style entropy based on character set size and length.
    This is a practical approximation: entropy = length * log2(charset_size)
    """
    if not password:
        return 0.0

    charset = 0
    if RE_LOWER.search(password):
        charset += 26
    if RE_UPPER.search(password):
        charset += 26
    if RE_DIGIT.search(password):
        charset += 10
    if RE_SPECIAL.search(password):
        # conservative estimate for printable specials
        charset += 32

    # avoid log(0)
    if charset == 0:
        charset = 1

    entropy = len(password) * math.log2(charset)
    return round(entropy, 2)

def feedback(password: str) -> list:
    """Return actionable feedback list for the password."""
    tips = []
    if len(password) < 12:
        tips.append("Make it at least 12 characters long (longer is better).")
    if not RE_UPPER.search(password):
        tips.append("Add at least one uppercase letter (A-Z).")
    if not RE_LOWER.search(password):
        tips.append("Add at least one lowercase letter (a-z).")
    if not RE_DIGIT.search(password):
        tips.append("Include at least one digit (0-9).")
    if not RE_SPECIAL.search(password):
        tips.append("Include at least one special character (e.g. !@#$%).")
    # discourage common patterns
    common = ["password","1234","admin","qwerty"]
    lower = password.lower()
    if any(c in lower for c in common):
        tips.append("Avoid common words or sequences (e.g. 'password', '1234').")
    return tips

def strength_label(entropy: float) -> str:
    """Map entropy value to a human-friendly label."""
    if entropy < 28:
        return "Very Weak"
    if entropy < 36:
        return "Weak"
    if entropy < 60:
        return "Moderate"
    if entropy < 90:
        return "Strong"
    return "Very Strong"

def assess_password(password: str) -> dict:
    """Return a dictionary with assessment results."""
    ent = estimate_entropy(password)
    label = strength_label(ent)
    fb = feedback(password)
    return {
        "password": password,
        "length": len(password),
        "entropy_bits": ent,
        "strength": label,
        "feedback": fb
    }

def main():
    try:
        pwd = input("Enter password to assess: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return
    if not pwd:
        print("No password entered.")
        return
    result = assess_password(pwd)
    print(f"\nLength: {result['length']}  Entropy: {result['entropy_bits']} bits  Strength: {result['strength']}")
    if result['feedback']:
        print("\nSuggestions:")
        for t in result['feedback']:
            print(" -", t)

if __name__ == "__main__":
    main()
