#!/usr/bin/env python3
"""
PassSentry - check whether a password has appeared in known data breaches.
Made by Ochena Gamer.

Uses the Have I Been Pwned "Pwned Passwords" range API with k-anonymity:
only the first 5 characters of the password's SHA-1 hash leave your machine.
The password itself is never sent anywhere.

Usage:
    python passsentry.py                  # prompts for a password (hidden input)
    python passsentry.py --file list.txt  # check many passwords, one per line

Exit codes: 0 = not found, 1 = found in breaches, 2 = error.
Standard library only. Python 3.8+.
"""

import argparse
import getpass
import hashlib
import string
import sys
import time
import urllib.error
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/"


def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def fetch_range(prefix: str) -> str:
    """Download all hash suffixes that share this 5-char prefix."""
    req = urllib.request.Request(
        API_URL + prefix,
        headers={
            "User-Agent": "passsentry-cli",
            "Add-Padding": "true",  # pads responses so size doesn't leak info
        },
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode("utf-8")


def count_in_range(body: str, suffix: str) -> int:
    """Return breach count for suffix, or 0 if absent (padding rows are 0)."""
    for line in body.splitlines():
        found_suffix, _, count = line.partition(":")
        if found_suffix.strip() == suffix:
            return int(count.strip() or 0)
    return 0


def breach_count(password: str) -> int:
    digest = sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]
    return count_in_range(fetch_range(prefix), suffix)


def strength_tips(password: str) -> list:
    """Very rough local hints. Being unbreached != being strong."""
    tips = []
    if len(password) < 12:
        tips.append("use at least 12 characters (longer is better)")
    if not any(c in string.ascii_lowercase for c in password) or not any(
        c in string.ascii_uppercase for c in password
    ):
        tips.append("mix upper and lower case")
    if not any(c in string.digits for c in password):
        tips.append("add a digit")
    if not any(c in string.punctuation for c in password):
        tips.append("add a symbol")
    if len(set(password)) < max(4, len(password) // 2):
        tips.append("avoid repeated characters")
    return tips


def report_single(password: str) -> int:
    count = breach_count(password)
    if count:
        print(f"PWNED: this password appears {count:,} times in known breaches.")
        print("Don't use it anywhere. Pick a new one, ideally a long passphrase.")
        code = 1
    else:
        print("Not found in known breach data.")
        code = 0
    tips = strength_tips(password)
    if tips:
        print("Tips: " + "; ".join(tips) + ".")
    return code


def report_file(path: str) -> int:
    worst = 0
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = [ln.rstrip("\r\n") for ln in fh if ln.strip()]
    except OSError as exc:
        print(f"Error: cannot read {path}: {exc}", file=sys.stderr)
        return 2

    for i, pw in enumerate(lines, start=1):
        count = breach_count(pw)
        masked = pw[0] + "*" * (len(pw) - 1) if pw else ""
        if count:
            worst = 1
            print(f"line {i:>4}  {masked:<20} PWNED ({count:,}x)")
        else:
            print(f"line {i:>4}  {masked:<20} ok")
        time.sleep(0.2)  # be polite to the API
    return worst


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check passwords against known data breaches (k-anonymity)."
    )
    parser.add_argument(
        "-f", "--file", help="text file with one password per line"
    )
    args = parser.parse_args()

    try:
        if args.file:
            return report_file(args.file)
        password = getpass.getpass("Password to check (hidden): ")
        if not password:
            print("No password entered.", file=sys.stderr)
            return 2
        return report_single(password)
    except urllib.error.URLError as exc:
        print(f"Network error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print()
        return 2


if __name__ == "__main__":
    sys.exit(main())
