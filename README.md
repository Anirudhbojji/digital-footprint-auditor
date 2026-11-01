# digital-footprint-auditor

A CLI tool to audit **your own** digital footprint — see where your username has public accounts, whether your email appears in known data breaches, and whether a password has been exposed.

Born out of a college lab report on digital footprints and digital wellbeing — this tool automates the manual audit that report described: googling yourself, checking Have I Been Pwned, and reviewing your account sprawl.

## Features

- **Username presence** — checks 9 platforms with reliable APIs (GitHub, GitLab, Hacker News, Mastodon, PyPI, npm, Docker Hub, Keybase, Dev.to), concurrently
- **Email breach lookup** — via the official [Have I Been Pwned](https://haveibeenpwned.com) v3 API
- **Password exposure check** — uses the Pwned Passwords **k-anonymity** API: only the first 5 characters of the SHA-1 hash leave your machine, never the password
- **Markdown report** — one command runs everything and writes a `footprint_report_<username>.md` with findings and remediation steps

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Where does this username have public accounts?
python -m footprint_auditor username yourname

# Has this email been in a breach? (needs a HIBP API key)
export HIBP_API_KEY=...   # https://haveibeenpwned.com/API/Key
python -m footprint_auditor email you@example.com

# Has this password been exposed? (free, password never transmitted)
python -m footprint_auditor password

# Full audit -> markdown report
python -m footprint_auditor report yourname --email you@example.com
```

## Notes

- Instagram, X/Twitter and similar platforms are intentionally excluded — they block unauthenticated lookups, which produces false positives.
- The email breach endpoint is a paid HIBP feature (~$4/mo); the password check is free and keyless.

## Ethics

This tool is for auditing **your own** accounts and identifiers, or those you are explicitly authorized to assess. Checking public username availability is harmless; running breach lookups against other people's emails is not what this is for.
