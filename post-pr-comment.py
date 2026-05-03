#!/usr/bin/env python3

import json
import os
import sys
import urllib.request
import urllib.error

MARKER = "<!-- rl-protect-scan-result -->"

SIGNAL_LABELS = {
    "EXISTS": "⚡ exploit",
    "MALWARE": "☠️ malware",
    "MANDATE": "📋 mandate",
}

VALID_LEVELS = {"fail", "warn", "pass"}
VALID_ASSESSMENT_STYLES = {"table", "simplified", "off"}

MAX_VULNS = 5

ASSESSMENT_ORDER = ["secrets", "licenses", "vulnerabilities", "hardening", "tampering", "malware"]
ASSESSMENT_NAMES = {
    "secrets": "Secrets",
    "licenses": "Licenses",
    "vulnerabilities": "Vulnerabilities",
    "hardening": "Hardening",
    "tampering": "Tampering",
    "malware": "Malware",
}
STATUS_EMOJI = {"pass": "✅", "warning": "⚠️", "fail": "❌"}


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


def find_existing_comment(token, repo, pr_number):
    page = 1
    while True:
        comments = api_request(
            "GET",
            f"/repos/{repo}/issues/{pr_number}/comments?per_page=100&page={page}",
            token,
        )
        for c in comments:
            if MARKER in c.get("body", ""):
                return c["id"]
        if len(comments) < 100:
            break
        page += 1
    return None


def post_or_update(token, repo, pr_number, body):
    existing_id = find_existing_comment(token, repo, pr_number)
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
        signal_count = len([f for f in v.get("exploit", []) if f in SIGNAL_LABELS])
        return (-score, -signal_count)

    rows = sorted(vulns.items(), key=sort_key)
    lines = [
        "| CVE/GHSA | CVSS | Summary | Signals |",
        "|----------|------|---------|---------|",
    ]
    for cve_id, v in rows[:MAX_VULNS]:
        score = v.get("cvss", {}).get("baseScore", 0)
        summary = v.get("summary", "").replace("|", "\\|")
        dot = cvss_dot(score)
        signals = " · ".join(SIGNAL_LABELS[f] for f in v.get("exploit", []) if f in SIGNAL_LABELS)
        lines.append(f"| {cve_id} | {dot} {score:.2f} | {summary} | {signals} |")

    remaining = len(rows) - MAX_VULNS
    if remaining > 0:
        suffix = f" — [see full report →]({report_url})" if report_url else ""
        lines.append(f"\n> and {remaining} more vulnerabilities{suffix}")

    return "\n".join(lines)


def malware_block(classifications):
    malicious = [c for c in classifications if c.get("status") == "Malicious"]
    suspicious = [c for c in classifications if c.get("status") == "Suspicious"]
    if not malicious and not suspicious:
        return ""
    lines = ["> [!CAUTION]"]
    for c in malicious:
        lines.append(f"> 🛑 Malicious file detected: {c.get('result', '')}")
    for c in suspicious:
        lines.append(f"> 🔶 Suspicious file detected: {c.get('result', '')}")
    return "\n".join(lines)


def assessment_table(assessment):
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
        rows.append(f"| {ASSESSMENT_NAMES[key]} | {emoji} {label} |")
    return "\n".join(rows)


def simplified_assessment_block(assessment):
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
        if status == "fail":
            fails.append(f"> ❌ {ASSESSMENT_NAMES[key]}: {label}")
        elif status == "warning":
            warnings.append(f"> ⚠️ {ASSESSMENT_NAMES[key]}: {label}")
    if not fails and not warnings:
        return ""
    level = "CAUTION" if fails else "WARNING"
    return "\n".join([f"> [!{level}]"] + fails + warnings)


def governance_block(governance):
    blocked = [g for g in governance if g.get("status") == "blocked"]
    if not blocked:
        return ""
    lines = ["> [!CAUTION]"]
    for g in blocked:
        lines.append(f"> 🚫 Blocked by governance: {g.get('reason', '')}")
    return "\n".join(lines)


def format_package(pkg, comment_assessment="table"):
    analysis = pkg.get("analysis", {})
    purl = pkg.get("purl", "unknown").split("?")[0]
    report_url = analysis.get("report", "")

    parts = [f"#### `{purl}`"]

    m = malware_block(analysis.get("classifications", []))
    if m:
        parts += ["", m]

    g = governance_block(analysis.get("policy", {}).get("governance", []))
    if g:
        parts += ["", g]

    if comment_assessment == "table":
        a = assessment_table(analysis.get("assessment", {}))
    elif comment_assessment == "simplified":
        a = simplified_assessment_block(analysis.get("assessment", {}))
    else:
        a = ""
    if a:
        parts += ["", a]

    t = vuln_table(analysis.get("vulnerabilities", {}), report_url)
    if t:
        parts += ["", t]

    if report_url:
        parts += ["", f"[Full report →]({report_url})"]

    return "\n".join(parts)


def build_comment(scan_status, scan_path, report_data, comment_level, comment_assessment="table"):
    emoji = "✅" if scan_status == "pass" else "❌"
    label = "PASS" if scan_status == "pass" else "FAIL"

    lines = [MARKER, f"## rl-protect Scan: {emoji} {label}", "", f"**Scanned:** `{scan_path}`"]

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
        for pkg in sorted(rejected, key=sort_key):
            lines += ["", format_package(pkg, comment_assessment), "", "---"]

    if warnings_pkgs and comment_level in ("warn", "pass"):
        lines += ["", "### ⚠️ Warnings"]
        for pkg in warnings_pkgs:
            lines += ["", format_package(pkg, comment_assessment), "", "---"]

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
    comment_assessment = os.environ.get("COMMENT_ASSESSMENT", "table")

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

    body = build_comment(scan_status, scan_path, report_data, comment_level, comment_assessment)

    try:
        post_or_update(token, repo, pr_number, body)
    except Exception as e:
        print(f"WARNING: could not post PR comment: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
