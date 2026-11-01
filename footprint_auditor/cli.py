"""digital-footprint-auditor CLI.

Audit your own digital footprint: public account presence, email breach
exposure, and password exposure. Intended for auditing accounts you own.
"""

import click

from .breaches import MissingApiKeyError, check_email
from .passwords import check_password
from .platforms import check_username
from .report import build_report, write_report


@click.group()
def cli() -> None:
    """Audit your own digital footprint."""


@cli.command()
@click.argument("username")
def username(username: str) -> None:
    """Check USERNAME presence across public platforms."""
    results = check_username(username)
    for r in results:
        if r.error:
            click.secho(f"  ⚠️  {r.platform:<12} check failed ({r.error})", fg="yellow")
        elif r.found:
            click.secho(f"  ✅ {r.platform:<12} {r.profile_url}", fg="green")
        else:
            click.echo(f"  —  {r.platform}")
    found = sum(1 for r in results if r.found)
    click.echo(f"\nFound on {found}/{len(results)} platforms.")


@cli.command()
@click.argument("email")
def email(email: str) -> None:
    """Check EMAIL against known data breaches (needs HIBP_API_KEY)."""
    try:
        breaches = check_email(email)
    except MissingApiKeyError as exc:
        raise click.ClickException(str(exc)) from exc

    if not breaches:
        click.secho(f"✅ {email} not found in any known breach.", fg="green")
        return
    click.secho(f"🚨 {email} found in {len(breaches)} breach(es):", fg="red")
    for b in breaches:
        click.echo(f"  - {b.name} ({b.breach_date}): {', '.join(b.data_classes)}")


@cli.command()
def password() -> None:
    """Check a password against breach corpuses (k-anonymity, never sent)."""
    pw = click.prompt("Password to check", hide_input=True)
    count = check_password(pw)
    if count:
        click.secho(f"🚨 Seen {count:,} times in breaches — do not use this password.", fg="red")
    else:
        click.secho("✅ Not found in known breach corpuses.", fg="green")


@cli.command()
@click.argument("username")
@click.option("--email", "email_addr", default=None, help="Also run a breach check for this email.")
@click.option("--out-dir", type=click.Path(file_okay=False, writable=True), default=None)
def report(username: str, email_addr: str | None, out_dir: str | None) -> None:
    """Run all checks for USERNAME and write a markdown report."""
    from pathlib import Path

    click.echo(f"Checking {username} across platforms...")
    platform_results = check_username(username)

    breaches = None
    if email_addr:
        try:
            breaches = check_email(email_addr)
        except MissingApiKeyError as exc:
            click.secho(f"Skipping breach check: {exc}", fg="yellow")

    content = build_report(username, platform_results, breaches, email_addr)
    path = write_report(content, username, Path(out_dir) if out_dir else None)
    click.secho(f"Report written to {path}", fg="green")


if __name__ == "__main__":
    cli()
