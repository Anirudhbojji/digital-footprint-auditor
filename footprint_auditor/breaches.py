"""Email breach lookup via the Have I Been Pwned v3 API.

Requires an API key (https://haveibeenpwned.com/API/Key) exported as
HIBP_API_KEY — breach-by-account lookups are a paid HIBP feature.
"""

import os
from dataclasses import dataclass

import requests

HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount"
REQUEST_TIMEOUT = 10


class MissingApiKeyError(Exception):
    """Raised when HIBP_API_KEY is not set in the environment."""


@dataclass
class Breach:
    name: str
    domain: str
    breach_date: str
    data_classes: list[str]


def check_email(email: str) -> list[Breach]:
    """Return breaches involving the given email address."""
    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        raise MissingApiKeyError(
            "Set HIBP_API_KEY to use breach lookups (get a key at https://haveibeenpwned.com/API/Key)"
        )

    resp = requests.get(
        f"{HIBP_API_URL}/{email}",
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": api_key, "user-agent": "digital-footprint-auditor"},
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code == 404:  # not found in any breach
        return []
    resp.raise_for_status()

    return [
        Breach(
            name=b["Name"],
            domain=b.get("Domain", ""),
            breach_date=b.get("BreachDate", "unknown"),
            data_classes=b.get("DataClasses", []),
        )
        for b in resp.json()
    ]
