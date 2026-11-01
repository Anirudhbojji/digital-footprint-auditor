"""Password exposure check via the Pwned Passwords k-anonymity API.

Only the first 5 characters of the password's SHA-1 hash ever leave the
machine — the full password and full hash are never transmitted.
This API is free and requires no key.
"""

import hashlib

import requests

RANGE_API_URL = "https://api.pwnedpasswords.com/range"
REQUEST_TIMEOUT = 10


def check_password(password: str) -> int:
    """Return how many times the password appears in known breach corpuses."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    resp = requests.get(
        f"{RANGE_API_URL}/{prefix}",
        headers={"user-agent": "digital-footprint-auditor"},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()

    for line in resp.text.splitlines():
        candidate_suffix, _, count = line.partition(":")
        if candidate_suffix == suffix:
            return int(count)
    return 0
