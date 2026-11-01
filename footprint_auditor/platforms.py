"""Check username presence across public platforms.

Only platforms with reliable found/not-found API semantics are included —
social networks that aggressively block unauthenticated requests (Instagram,
X/Twitter) are intentionally left out to avoid false positives.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

import requests

REQUEST_TIMEOUT = 10
USER_AGENT = "digital-footprint-auditor (self-audit tool)"


@dataclass
class PlatformResult:
    platform: str
    profile_url: str
    found: bool
    error: str | None = None


def _check_http_status(url: str) -> bool:
    resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
    if resp.status_code == 200:
        return True
    if resp.status_code == 404:
        return False
    resp.raise_for_status()
    return False


def _check_gitlab(username: str) -> bool:
    resp = requests.get(
        "https://gitlab.com/api/v4/users",
        params={"username": username},
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )
    resp.raise_for_status()
    return bool(resp.json())


def _check_hackernews(username: str) -> bool:
    resp = requests.get(
        f"https://hacker-news.firebaseio.com/v0/user/{username}.json",
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )
    resp.raise_for_status()
    return resp.json() is not None


def _check_npm(username: str) -> bool:
    # the couchdb user endpoint now requires auth, so detect via maintained packages
    resp = requests.get(
        "https://registry.npmjs.org/-/v1/search",
        params={"text": f"maintainer:{username}", "size": 1},
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )
    resp.raise_for_status()
    return resp.json().get("total", 0) > 0


def _check_keybase(username: str) -> bool:
    resp = requests.get(
        "https://keybase.io/_/api/1.0/user/lookup.json",
        params={"usernames": username},
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )
    resp.raise_for_status()
    them = resp.json().get("them") or []
    return any(them)


# platform name -> (profile URL template, checker)
PLATFORMS = {
    "GitHub": ("https://github.com/{u}", lambda u: _check_http_status(f"https://api.github.com/users/{u}")),
    "GitLab": ("https://gitlab.com/{u}", _check_gitlab),
    "Hacker News": ("https://news.ycombinator.com/user?id={u}", _check_hackernews),
    "Mastodon": ("https://mastodon.social/@{u}", lambda u: _check_http_status(f"https://mastodon.social/api/v1/accounts/lookup?acct={u}")),
    "PyPI": ("https://pypi.org/user/{u}/", lambda u: _check_http_status(f"https://pypi.org/user/{u}/")),
    "npm (maintainer)": ("https://www.npmjs.com/~{u}", _check_npm),
    "Docker Hub": ("https://hub.docker.com/u/{u}", lambda u: _check_http_status(f"https://hub.docker.com/v2/users/{u}/")),
    "Keybase": ("https://keybase.io/{u}", _check_keybase),
    "Dev.to": ("https://dev.to/{u}", lambda u: _check_http_status(f"https://dev.to/api/users/by_username?url={u}")),
}


def check_username(username: str, max_workers: int = 8) -> list[PlatformResult]:
    """Check a username against all platforms concurrently."""
    results: list[PlatformResult] = []

    def run_one(platform: str) -> PlatformResult:
        url_template, checker = PLATFORMS[platform]
        profile_url = url_template.format(u=username)
        try:
            return PlatformResult(platform, profile_url, found=checker(username))
        except requests.RequestException as exc:
            return PlatformResult(platform, profile_url, found=False, error=str(exc))

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(run_one, p) for p in PLATFORMS]
        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda r: r.platform)
