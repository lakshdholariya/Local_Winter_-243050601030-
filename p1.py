"""Password strength checker.

Checks a password against several security requirements and reports its
strength together with actionable feedback for missing requirements.
"""

import getpass
import re


MIN_LENGTH = 8


def check_password(password: str) -> tuple[int, list[str]]:
    """Return the number of satisfied conditions and missing requirements."""
    checks = {
        f"at least {MIN_LENGTH} characters": len(password) >= MIN_LENGTH,
        "an uppercase letter": bool(re.search(r"[A-Z]", password)),
        "a lowercase letter": bool(re.search(r"[a-z]", password)),
        "a number": bool(re.search(r"\d", password)),
        "a special character": bool(re.search(r"[^A-Za-z0-9]", password)),
    }

    missing = [requirement for requirement, passed in checks.items() if not passed]
    return sum(checks.values()), missing


def strength_category(satisfied_conditions: int) -> str:
    """Classify a password using the number of passed conditions."""
    if satisfied_conditions <= 2:
        return "Very Weak"
    if satisfied_conditions == 3:
        return "Weak"
    if satisfied_conditions == 4:
        return "Medium"
    return "Strong"


def main() -> None:
    password = getpass.getpass("Enter a password to check: ")
    total_conditions = 5
    satisfied, missing = check_password(password)
    category = strength_category(satisfied)

    print(f"\nPassword strength: {category}")
    print(f"Conditions satisfied: {satisfied}/{total_conditions}")

    if missing:
        print("Useful feedback:")
        for requirement in missing:
            print(f"- Add {requirement}.")
    else:
        print("All requirements are satisfied. Avoid reusing this password elsewhere.")


if __name__ == "__main__":
    main()
