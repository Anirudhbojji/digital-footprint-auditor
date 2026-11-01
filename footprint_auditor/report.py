"""Markdown footprint report generation."""

from datetime import datetime, timezone
from pathlib import Path

from .breaches import Breach
from .platforms import PlatformResult

REMEDIATION_TIPS = [
    "Review privacy settings on every account found above — limit who can see your information.",
    "Delete or deactivate accounts you no longer use; dormant accounts widen your attack surface.",
    "Use strong, unique passwords per site and a password manager; enable 2FA everywhere.",
    "For any breached account, rotate the password immediately and everywhere it was reused.",
    "Search your name periodically and set up alerts to catch new exposure early.",
    "Limit personal details (address, phone, DOB) shared on public profiles.",
]


def build_report(
    username: str,
    platform_results: list[PlatformResult],
    breaches: list[Breach] | None,
    email: str | None,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    found = [r for r in platform_results if r.found]
    errored = [r for r in platform_results if r.error]

    lines = [
        "# Digital Footprint Report",
        "",
        f"- **Target username:** `{username}`",
        f"- **Generated:** {now}",
        f"- **Platforms found:** {len(found)}/{len(platform_results)}",
        "",
        "## Public account presence",
        "",
        "| Platform | Found | Profile |",
        "|---|---|---|",
    ]
    for r in platform_results:
        status = "✅ yes" if r.found else ("⚠️ check failed" if r.error else "—")
        link = f"<{r.profile_url}>" if r.found else ""
        lines.append(f"| {r.platform} | {status} | {link} |")

    if errored:
        lines += ["", f"> {len(errored)} platform check(s) failed and should be re-run or verified manually."]

    lines += ["", "## Breach exposure", ""]
    if breaches is None:
        lines.append("_Email breach check skipped (no email given or no HIBP API key set)._")
    elif not breaches:
        lines.append(f"✅ `{email}` was **not found** in any known breach.")
    else:
        lines.append(f"🚨 `{email}` appears in **{len(breaches)} breach(es)**:")
        lines += ["", "| Breach | Date | Exposed data |", "|---|---|---|"]
        for b in breaches:
            lines.append(f"| {b.name} ({b.domain}) | {b.breach_date} | {', '.join(b.data_classes)} |")

    lines += ["", "## Recommended actions", ""]
    lines += [f"{i}. {tip}" for i, tip in enumerate(REMEDIATION_TIPS, 1)]
    lines.append("")
    return "\n".join(lines)


def write_report(content: str, username: str, out_dir: Path | None = None) -> Path:
    out_path = (out_dir or Path.cwd()) / f"footprint_report_{username}.md"
    out_path.write_text(content)
    return out_path
