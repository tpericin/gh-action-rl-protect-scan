#!/usr/bin/env python3

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

def relative_date(iso_str):
    if not iso_str:
        return None
    try:
        published = datetime.fromisoformat(iso_str.replace("+0000", "+00:00"))
        delta = datetime.now(timezone.utc) - published
        days = delta.days
        if days < 1:
            return "today"
        if days == 1:
            return "yesterday"
        if days < 7:
            return f"{days} days ago"
        if days < 14:
            return "1 week ago"
        if days < 30:
            return f"{days // 7} weeks ago"
        if days < 60:
            return "1 month ago"
        if days < 365:
            return f"{days // 30} months ago"
        years = days // 365
        return f"{years} year{'s' if years != 1 else ''} ago"
    except (ValueError, TypeError):
        return None


def make_marker(scan_path):
    return f"<!-- rl-protect-scan-result:{scan_path} -->"

SIGNAL_LABELS = {
    "EXISTS": "⚡&nbsp;exploit",
    "MALWARE": "☠️&nbsp;malware",
    "MANDATE": "📋&nbsp;mandate",

}

VALID_LEVELS = {"fail", "warn", "pass"}
VALID_ASSESSMENT_STYLES = {"table", "simplified", "off"}

MAX_VULNS = 5
MAX_PACKAGES = 5

ASSESSMENT_ORDER = ["malware", "tampering", "vulnerabilities", "secrets", "hardening", "licenses", "repository"]
ASSESSMENT_NAMES = {
    "malware": "Malware",
    "tampering": "Tampering",
    "vulnerabilities": "Vulnerabilities",
    "secrets": "Secrets",
    "hardening": "Hardening",
    "licenses": "Licenses",
    "repository": "Repository",
}
STATUS_EMOJI = {"pass": "✅", "warning": "⚠️", "fail": "❌"}


def short_purl(purl):
    purl = purl.split("?")[0]
    return purl.split("/", 1)[1] if "/" in purl else purl


def find_inclusion(target_purl, all_packages):
    reverse_deps = {}
    for p in all_packages:
        for dep in p.get("dependencies", []):
            reverse_deps.setdefault(dep, []).append(p.get("purl", ""))

    all_paths = []
    queue = [[target_purl]]
    while queue:
        path = queue.pop(0)
        parents = reverse_deps.get(path[-1], [])
        if not parents:
            all_paths.append(list(reversed(path)))
        else:
            for parent in parents:
                if parent not in path:
                    queue.append(path + [parent])

    if not all_paths or all_paths == [[target_purl]]:
        return None

    shortest = min(all_paths, key=len)
    chain = "&nbsp;→&nbsp;".join(f"`{short_purl(p)}`" for p in shortest)
    suffix = f" ({len(all_paths)} paths)" if len(all_paths) > 1 else ""
    return f"&nbsp;&nbsp;🔗 {chain}{suffix}"


def meaningful_override(entry):
    override = entry.get("override")
    if override and override.get("to_status") != entry.get("status"):
        return override
    return None


def override_note(entry, show=False):
    if not show:
        return ""
    ov = meaningful_override(entry)
    if not ov:
        return ""
    original = entry.get("status", "").upper()
    author = (ov.get("audit") or {}).get("author", "—")
    return f"<br>*† overridden from {original} by {author}*"


def cvss_dot(score):
    if score >= 9.0:
        return "🔴"
    if score >= 7.0:
        return "🟠"
    if score >= 4.0:
        return "🟡"
    return "🔵"


def api_request(method, path, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def find_existing_comment(token, repo, pr_number, marker):
    page = 1
    while True:
        comments = api_request(
            "GET",
            f"/repos/{repo}/issues/{pr_number}/comments?per_page=100&page={page}",
            token,
        )
        for c in comments:
            if marker in c.get("body", ""):
                return c["id"]
        if len(comments) < 100:
            break
        page += 1
    return None


def post_or_update(token, repo, pr_number, body, marker):
    existing_id = find_existing_comment(token, repo, pr_number, marker)
    if existing_id:
        api_request("PATCH", f"/repos/{repo}/issues/comments/{existing_id}", token, {"body": body})
    else:
        api_request("POST", f"/repos/{repo}/issues/{pr_number}/comments", token, {"body": body})


def classify_package(pkg):
    analysis = pkg.get("analysis", {})
    if analysis.get("recommendation") == "REJECT":
        return "reject"
    for a in analysis.get("assessment", {}).values():
        if a.get("status") in ("warning", "fail"):
            return "warn"
    return "pass"


def vuln_table(vulns, report_url=""):
    if not vulns:
        return ""

    def sort_key(item):
        _, v = item
        score = v.get("cvss", {}).get("baseScore", 0)
        exploits = [f for f in v.get("exploit", []) if f in SIGNAL_LABELS]
        has_signals = len(exploits) > 0
        return (not has_signals, -score, -len(exploits))

    rows = sorted(
        [(cve_id, v) for cve_id, v in vulns.items() if "TRIAGED" not in v.get("exploit", [])],
        key=sort_key,
    )

    counts = {"🔴": 0, "🟠": 0, "🟡": 0, "🔵": 0}
    for _, v in rows:
        counts[cvss_dot(v.get("cvss", {}).get("baseScore", 0))] += 1
    severity_labels = {"🔴": "critical", "🟠": "high", "🟡": "medium", "🔵": "low"}
    summary = "**Vulnerabilities:** " + " · ".join(
        f"{dot} {n} {severity_labels[dot]}"
        for dot, n in counts.items() if n > 0
    )

    lines = [
        summary,
        "",
        "| CVE/GHSA | CVSS | Summary | Signals |",
        "|----------|------|---------|---------|",
    ]
    for cve_id, v in rows[:MAX_VULNS]:
        score = v.get("cvss", {}).get("baseScore", 0)
        summary = v.get("summary", "").replace("|", "\\|")
        dot = cvss_dot(score)
        signals = "<br>".join(SIGNAL_LABELS[f] for f in v.get("exploit", []) if f in SIGNAL_LABELS)
        lines.append(f"| {cve_id} | {dot}&nbsp;{score:.2f} | {summary} | {signals} |")

    remaining = len(rows) - MAX_VULNS
    if remaining > 0:
        suffix = f" — [see full report →]({report_url})" if report_url else ""
        lines.append(f"\n> and {remaining} more vulnerabilities{suffix}")

    return "\n".join(lines)


def malware_block(classifications):
    malicious = list(dict.fromkeys(c.get("result", "") for c in classifications if c.get("status") == "Malicious"))
    suspicious = list(dict.fromkeys(c.get("result", "") for c in classifications if c.get("status") == "Suspicious"))
    if not malicious and not suspicious:
        return ""
    lines = ["> [!CAUTION]", "> **Malware**"]
    for name in malicious:
        lines.append(f"> 🛑 Threat detected: {name}")
    for name in suspicious:
        lines.append(f"> 🔶 Threat detected: {name}")
    return "\n".join(lines)


def assessment_table(assessment, comment_overrides=False):
    if not assessment:
        return ""
    rows = ["| Assessment | Result |", "|---|---|"]
    for key in ASSESSMENT_ORDER:
        a = assessment.get(key, {})
        if not a:
            continue
        status = (a.get("override") or {}).get("to_status") or a.get("status", "pass")
        emoji = STATUS_EMOJI.get(status, "✅")
        label = a.get("label", "")
        rows.append(f"| {ASSESSMENT_NAMES[key]} | {emoji} {label}{override_note(a, comment_overrides)} |")
    return "\n".join(rows)


def simplified_assessment_block(assessment, comment_overrides=False):
    if not assessment:
        return ""
    fails = []
    warnings = []
    for key in ASSESSMENT_ORDER:
        a = assessment.get(key, {})
        if not a:
            continue
        status = (a.get("override") or {}).get("to_status") or a.get("status", "pass")
        label = a.get("label", "")
        note = override_note(a, comment_overrides).replace("<br>", " ")
        if status == "fail":
            fails.append(f"> ❌ {ASSESSMENT_NAMES[key]}: {label}{note}")
        elif status == "warning":
            warnings.append(f"> ⚠️ {ASSESSMENT_NAMES[key]}: {label}{note}")
    if not fails and not warnings:
        return ""
    blocks = []
    if fails:
        blocks.append("\n".join(["> [!CAUTION]", "> **Assessment**"] + fails))
    if warnings:
        blocks.append("\n".join(["> [!WARNING]", "> **Assessment**"] + warnings))
    return "\n\n".join(blocks)


def governance_block(governance):
    blocked = [g for g in governance if g.get("status") == "blocked"]
    if not blocked:
        return ""
    lines = ["> [!CAUTION]", "> **Governance**"]
    for g in blocked:
        lines.append(f"> 🚫 Blocked by governance: {g.get('reason', '')}")
    return "\n".join(lines)


def policy_table(violations, comment_overrides=False, report_url=""):
    if not violations:
        return ""

    def sort_key(item):
        _, v = item
        status = (v.get("override") or {}).get("to_status") or v.get("status", "pass")
        return (0 if status == "fail" else 1, -v.get("violations", 0))

    non_passing = [
        (rule_id, v) for rule_id, v in violations.items()
        if ((v.get("override") or {}).get("to_status") or v.get("status", "pass")) != "pass"
    ]
    sorted_violations = sorted(non_passing, key=sort_key)

    rows = []
    for rule_id, v in sorted_violations[:MAX_VULNS]:
        status = (v.get("override") or {}).get("to_status") or v.get("status", "pass")
        emoji = STATUS_EMOJI.get(status, "")
        description = v.get("description", "")
        count = v.get("violations", 0)
        rows.append(f"| {rule_id} | {emoji} {description}{override_note(v, comment_overrides)} | {count} |")

    if not rows:
        return ""

    fail_count = sum(1 for _, v in sorted_violations if ((v.get("override") or {}).get("to_status") or v.get("status", "pass")) == "fail")
    warn_count = len(sorted_violations) - fail_count
    parts = []
    if fail_count:
        parts.append(f"❌ {fail_count} failed")
    if warn_count:
        parts.append(f"⚠️ {warn_count} warning{'s' if warn_count != 1 else ''}")
    summary = "**Policy violations:** " + " · ".join(parts)

    lines = [summary, "", "| Policy | Description | Count |", "|--------|-------------|-------|"] + rows
    remaining = len(sorted_violations) - MAX_VULNS
    if remaining > 0:
        suffix = f" — [see full report →]({report_url})" if report_url else ""
        lines.append(f"\n> and {remaining} more violations{suffix}")
    return "\n".join(lines)


def summarize_package(pkg, all_packages=None):
    purl = pkg.get("purl", "unknown").split("?")[0]
    analysis = pkg.get("analysis", {})
    assessment = analysis.get("assessment", {})
    finding = ""
    for key in ASSESSMENT_ORDER:
        a = assessment.get(key, {})
        if not a:
            continue
        status = (a.get("override") or {}).get("to_status") or a.get("status", "pass")
        if status in ("fail", "warning"):
            emoji = STATUS_EMOJI.get(status, "")
            label = a.get("label", "")
            finding = f" — {emoji} {ASSESSMENT_NAMES[key]}: {label}"
            break
    lines = [f"> 📦 `{purl}`{finding}"]
    if all_packages:
        inc = find_inclusion(pkg.get("purl", ""), all_packages)
        if inc:
            lines.append(f"> {inc}")
    return "\n".join(lines)


def format_package(pkg, comment_assessment="simplified", comment_vulnerabilities=True, comment_license=False, comment_policy=False, comment_overrides=False, index=None, total=None, inclusion=None):
    analysis = pkg.get("analysis", {})
    purl = pkg.get("purl", "unknown").split("?")[0]
    report_url = analysis.get("report", "")

    status = classify_package(pkg)
    status_label = {"reject": "REJECT", "warn": "WARN", "pass": "PASS"}.get(status, "")
    counter = f" ({index} of {total})" if index is not None and total is not None else ""
    tags = ""
    if pkg.get("removed"):
        tags += " [REMOVED]"
    if pkg.get("quarantined"):
        tags += " [QUARANTINED]"
    parts = [f"#### 📦 **`{purl}`** — {status_label}{counter}{tags}"]
    if inclusion:
        parts.append(inclusion)
    published = relative_date(pkg.get("published"))
    if published:
        parts.append(f"📅 Released {published}")
    if comment_license:
        license_str = pkg.get("license")
        if license_str:
            parts.append(f"⚖️ {license_str}")

    m = malware_block(analysis.get("classifications", []))
    if m:
        parts += ["", m]

    g = governance_block(analysis.get("policy", {}).get("governance", []))
    if g:
        parts += ["", g]

    if comment_assessment == "table":
        a = assessment_table(analysis.get("assessment", {}), comment_overrides)
    elif comment_assessment == "simplified":
        a = simplified_assessment_block(analysis.get("assessment", {}), comment_overrides)
    else:
        a = ""
    if a:
        parts += ["", a]

    if comment_vulnerabilities:
        t = vuln_table(analysis.get("vulnerabilities", {}), report_url)
        if t:
            parts += ["", t]

    if comment_policy:
        p = policy_table(analysis.get("policy", {}).get("violations", {}), comment_overrides, report_url)
        if p:
            parts += ["", p]

    if report_url:
        parts += ["", f"[Full report →]({report_url})"]

    return "\n".join(parts)


def build_comment(scan_status, scan_path, report_data, comment_level, comment_assessment="simplified", comment_vulnerabilities=True, comment_license=False, comment_policy=False, comment_overrides=False, marker=None):
    emoji = "✅" if scan_status == "pass" else "❌"
    label = "PASS" if scan_status == "pass" else "FAIL"

    lines = [marker or make_marker(scan_path), f"## Spectra Assure Community Scan: {emoji} {label}", "", f"**Scanned:** `{scan_path}`"]

    if report_data is None:
        lines += [
            "",
            "> Add the `report:` input to get detailed per-package findings in this comment.",
        ]
        return "\n".join(lines)

    report = report_data.get("analysis", {}).get("report", {})
    packages = report.get("packages", [])
    errors = report.get("errors", [])

    rejected = [p for p in packages if classify_package(p) == "reject"]
    warnings_pkgs = [p for p in packages if classify_package(p) == "warn"]
    passing = [p for p in packages if classify_package(p) == "pass"]

    summary_parts = []
    if rejected:
        summary_parts.append(f"{len(rejected)} rejected")
    if warnings_pkgs:
        summary_parts.append(f"{len(warnings_pkgs)} warning{'s' if len(warnings_pkgs) != 1 else ''}")
    if errors:
        summary_parts.append(f"{len(errors)} scan error{'s' if len(errors) != 1 else ''}")
    summary = f" — {' · '.join(summary_parts)}" if summary_parts else ""
    lines[-1] = lines[-1] + summary

    if rejected:
        lines += ["", "### ❌ Rejected packages"]
        def sort_key(pkg):
            analysis = pkg.get("analysis", {})
            has_malware = any(
                c.get("status") in ("Malicious", "Suspicious")
                for c in analysis.get("classifications", [])
            )
            has_governance = any(
                g.get("status") == "blocked"
                for g in analysis.get("policy", {}).get("governance", [])
            )
            return (not has_malware, not has_governance)
        sorted_rejected = sorted(rejected, key=sort_key)
        for i, pkg in enumerate(sorted_rejected[:MAX_PACKAGES], 1):
            inclusion = find_inclusion(pkg.get("purl", ""), packages)
            lines += ["", format_package(pkg, comment_assessment, comment_vulnerabilities, comment_license, comment_policy, comment_overrides, i, len(sorted_rejected), inclusion), "", "---"]
        if len(sorted_rejected) > MAX_PACKAGES:
            remaining = sorted_rejected[MAX_PACKAGES:]
            block = ["> [!IMPORTANT]", f"> **{len(remaining)} more rejected package{'s' if len(remaining) != 1 else ''}**"]
            block += [summarize_package(p, packages) for p in remaining]
            lines += ["", "\n".join(block)]

    if warnings_pkgs and comment_level in ("warn", "pass"):
        lines += ["", "---", "", "### ⚠️ Scan Warnings", "*Packages with issues that did not meet the rejection threshold.*"]
        def warn_sort_key(pkg):
            vulns = pkg.get("analysis", {}).get("vulnerabilities", {})
            top = max((v.get("cvss", {}).get("baseScore", 0) for v in vulns.values()), default=0)
            return -top
        sorted_warnings = sorted(warnings_pkgs, key=warn_sort_key)
        for i, pkg in enumerate(sorted_warnings[:MAX_PACKAGES], 1):
            inclusion = find_inclusion(pkg.get("purl", ""), packages)
            lines += ["", format_package(pkg, comment_assessment, comment_vulnerabilities, comment_license, comment_policy, comment_overrides, i, len(sorted_warnings), inclusion), "", "---"]
        if len(sorted_warnings) > MAX_PACKAGES:
            remaining = sorted_warnings[MAX_PACKAGES:]
            block = ["> [!IMPORTANT]", f"> **{len(remaining)} more warning{'s' if len(remaining) != 1 else ''}**"]
            block += [summarize_package(p, packages) for p in remaining]
            lines += ["", "\n".join(block)]

    if passing and comment_level == "pass":
        lines += ["", "### ✅ Passing packages", ""]
        for pkg in passing:
            lines.append(f"- `{pkg.get('purl', 'unknown')}`")

    if errors:
        lines += ["", "### ❓ Scan errors", ""]
        for e in errors:
            purl = e.get("purl", "unknown")
            info = e.get("error", {}).get("info", "unknown error")
            lines.append(f"- `{purl}` — {info}")

    return "\n".join(lines)


def main():
    token = os.environ.get("GITHUB_TOKEN", "")
    scan_status = os.environ.get("SCAN_STATUS", "")
    scan_path = os.environ.get("SCAN_PATH", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    repo = os.environ.get("REPO", "")
    report_path = os.environ.get("REPORT", "")
    comment_level = os.environ.get("COMMENT_LEVEL", "fail")
    comment_assessment = os.environ.get("COMMENT_ASSESSMENT", "simplified")
    comment_vulnerabilities = os.environ.get("COMMENT_VULNERABILITIES", "true").lower() == "true"
    comment_license = os.environ.get("COMMENT_LICENSE", "false").lower() == "true"
    comment_policy = os.environ.get("COMMENT_POLICY", "false").lower() == "true"
    comment_overrides = os.environ.get("COMMENT_OVERRIDES", "false").lower() == "true"

    if comment_level not in VALID_LEVELS:
        print(f"WARNING: invalid comment-level '{comment_level}', defaulting to 'fail'", file=sys.stderr)
        comment_level = "fail"

    if comment_assessment not in VALID_ASSESSMENT_STYLES:
        print(f"WARNING: invalid comment-assessment '{comment_assessment}', defaulting to 'table'", file=sys.stderr)
        comment_assessment = "table"

    if not token:
        print("WARNING: github-token not set, skipping PR comment", file=sys.stderr)
        return

    if not pr_number or not repo:
        print("WARNING: missing PR context, skipping PR comment", file=sys.stderr)
        return

    report_data = None
    if report_path:
        try:
            with open(report_path) as f:
                report_data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"WARNING: could not read report file '{report_path}': {e}", file=sys.stderr)

    marker = make_marker(scan_path)
    body = build_comment(scan_status, scan_path, report_data, comment_level, comment_assessment, comment_vulnerabilities, comment_license, comment_policy, comment_overrides, marker)

    try:
        post_or_update(token, repo, pr_number, body, marker)
    except Exception as e:
        print(f"WARNING: could not post PR comment: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
