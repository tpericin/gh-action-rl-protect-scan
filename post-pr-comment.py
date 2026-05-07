#!/usr/bin/env python3

import json
import os
import sys
import urllib.request
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone


def _parse_iso(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("+0000", "+00:00").replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def relative_date(iso_str, reference=None):
    if not iso_str:
        return None
    published = _parse_iso(iso_str)
    try:
        delta = (reference or datetime.now(timezone.utc)) - published
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


@dataclass
class ReportConfig:
    level: str = "fail"
    assessment: str = "simplified"
    vulnerabilities: bool = True
    license_info: bool = False
    policy: bool = False
    overrides: bool = False
    show_details: bool = True


TEMPLATES = {
    "concise": ReportConfig(
        assessment="off",
        vulnerabilities=False,
        show_details=False,
    ),
    "expanded": ReportConfig(
        license_info=True,
    ),
    "verbose": ReportConfig(
        level="pass",
        assessment="table",
        policy=True,
        overrides=True,
    ),
}

MAX_VULNS = 5
MAX_PACKAGES = 5

ASSESSMENTS = ["secrets", "licenses", "vulnerabilities", "hardening", "tampering", "malware", "repository"]

# Display priority when multiple categories share the same worst grade.
# Repository is always last — only shown if no other category has a finding.
ASSESSMENT_PRIORITY = ["malware", "tampering", "vulnerabilities", "secrets", "hardening", "licenses", "repository"]
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
STATUS_LABELS = {"reject": "REJECT", "warn": "WARN", "pass": "PASS"}


def get_effective_status(entry):
    return (entry.get("override") or {}).get("to_status") or entry.get("status", "pass")


def short_purl(purl):
    purl = purl.split("?")[0]
    return purl.split("/", 1)[1] if "/" in purl else purl


def build_reverse_deps(all_packages):
    reverse_deps = {}
    for p in all_packages:
        for dep in p.get("dependencies", []):
            reverse_deps.setdefault(dep, []).append(p.get("purl", ""))
    return reverse_deps


def find_inclusion(target_purl, reverse_deps):
    all_paths = []
    queue = deque([[target_purl]])
    while queue:
        path = queue.popleft()
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


def partition_packages(packages):
    rejected, warnings_pkgs, passing = [], [], []
    for p in packages:
        c = classify_package(p)
        if c == "reject":
            rejected.append(p)
        elif c == "warn":
            warnings_pkgs.append(p)
        else:
            passing.append(p)
    return rejected, warnings_pkgs, passing


def sort_key_rejected(pkg):
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


def sort_key_warnings(pkg):
    vulns = pkg.get("analysis", {}).get("vulnerabilities", {})
    top = max((v.get("cvss", {}).get("baseScore", 0) for v in vulns.values()), default=0)
    return -top


def vuln_table(vulns, report_url=""):
    if not vulns:
        return ""

    def sort_key(item):
        _, v = item
        score = v.get("cvss", {}).get("baseScore", 0)
        exploits = [f for f in v.get("exploit", []) if f in SIGNAL_LABELS]
        return (not exploits, -score, -len(exploits))

    rows = sorted(
        [(cve_id, v) for cve_id, v in vulns.items() if "TRIAGED" not in v.get("exploit", [])],
        key=sort_key,
    )

    if not rows:
        return ""

    counts = {"🔴": 0, "🟠": 0, "🟡": 0, "🔵": 0}
    for _, v in rows:
        counts[cvss_dot(v.get("cvss", {}).get("baseScore", 0))] += 1
    severity_labels = {"🔴": "critical", "🟠": "high", "🟡": "medium", "🔵": "low"}
    severity_summary = "**Vulnerabilities:** " + " · ".join(
        f"{dot} {n} {severity_labels[dot]}"
        for dot, n in counts.items() if n > 0
    )

    lines = [severity_summary, "", "| CVE/GHSA | CVSS | Summary | Signals |", "|----------|------|---------|---------|"]
    for cve_id, v in rows[:MAX_VULNS]:
        score = v.get("cvss", {}).get("baseScore", 0)
        cve_summary = v.get("summary", "").replace("|", "\\|")
        dot = cvss_dot(score)
        signals = "<br>".join(SIGNAL_LABELS[f] for f in v.get("exploit", []) if f in SIGNAL_LABELS)
        lines.append(f"| {cve_id} | {dot}&nbsp;{score:.2f} | {cve_summary} | {signals} |")

    remaining = len(rows) - MAX_VULNS
    if remaining > 0:
        suffix = f" — [see full report →]({report_url})" if report_url else ""
        lines.append(f"\n> and {remaining} more vulnerabilities{suffix}")

    return "\n".join(lines)


def _alert_block(level, header, lines):
    return "\n".join([f"> [!{level}]", f"> {header}"] + [f"> {line}" for line in lines])


def malware_block(classifications):
    malicious = list(dict.fromkeys(c.get("result", "") for c in classifications if c.get("status") == "Malicious"))
    suspicious = list(dict.fromkeys(c.get("result", "") for c in classifications if c.get("status") == "Suspicious"))
    if not malicious and not suspicious:
        return ""
    return _alert_block("CAUTION", "**Malware**",
        [f"🛑 Threat detected: {name}" for name in malicious] +
        [f"🔶 Threat detected: {name}" for name in suspicious])


def assessment_table(assessment, comment_overrides=False):
    if not assessment:
        return ""
    rows = ["| Assessment | Result |", "|---|---|"]
    for key in ASSESSMENTS:
        a = assessment.get(key, {})
        if not a:
            continue
        status = get_effective_status(a)
        emoji = STATUS_EMOJI.get(status, "✅")
        label = a.get("label", "")
        rows.append(f"| {ASSESSMENT_NAMES[key]} | {emoji} {label}{override_note(a, comment_overrides)} |")
    return "\n".join(rows)


def simplified_assessment_block(assessment, comment_overrides=False):
    if not assessment:
        return ""
    fails = []
    warnings = []
    for key in ASSESSMENTS:
        a = assessment.get(key, {})
        if not a:
            continue
        status = get_effective_status(a)
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
        blocks.append("\n".join(["> [!CAUTION]", "> **SAFE Assessment**"] + fails))
    if warnings:
        blocks.append("\n".join(["> [!WARNING]", "> **SAFE Assessment**"] + warnings))
    return "\n\n".join(blocks)


def governance_block(governance):
    blocked = [g for g in governance if g.get("status") == "blocked"]
    if not blocked:
        return ""
    return _alert_block("CAUTION", "**Governance**",
        [f"🚫 Blocked by governance: {g.get('reason', '')}" for g in blocked])


def policy_block(violations):
    failing = sorted(
        [(rule_id, v) for rule_id, v in violations.items() if get_effective_status(v) == "fail"],
        key=lambda x: x[0],
    )
    if not failing:
        return ""
    lines = []
    for rule_id, v in failing:
        line = f"❌ {rule_id}"
        if desc := v.get("description", ""):
            line += f" — {desc}"
        lines.append(line)
    return _alert_block("CAUTION", "**Policy violations**", lines)


def policy_table(violations, comment_overrides=False, report_url=""):
    if not violations:
        return ""

    non_passing = [
        (rule_id, v, get_effective_status(v))
        for rule_id, v in violations.items()
        if get_effective_status(v) != "pass"
    ]
    sorted_violations = sorted(non_passing, key=lambda x: (0 if x[2] == "fail" else 1, -x[1].get("violations", 0)))

    if not sorted_violations:
        return ""

    fail_count = sum(1 for _, _, s in sorted_violations if s == "fail")
    warn_count = len(sorted_violations) - fail_count
    parts = []
    if fail_count:
        parts.append(f"❌ {fail_count} failed")
    if warn_count:
        parts.append(f"⚠️ {warn_count} warning{'s' if warn_count != 1 else ''}")
    pol_summary = "**Policy violations:** " + " · ".join(parts)

    rows = []
    for rule_id, v, status in sorted_violations[:MAX_VULNS]:
        emoji = STATUS_EMOJI.get(status, "")
        description = v.get("description", "")
        count = v.get("violations", 0)
        rows.append(f"| {rule_id} | {emoji} {description}{override_note(v, comment_overrides)} | {count} |")

    lines = [pol_summary, "", "| Policy | Description | Count |", "|--------|-------------|-------|"] + rows
    remaining = len(sorted_violations) - MAX_VULNS
    if remaining > 0:
        suffix = f" — [see full report →]({report_url})" if report_url else ""
        lines.append(f"\n> and {remaining} more violations{suffix}")
    return "\n".join(lines)


def deployment_risk_label(pkg):
    analysis = pkg.get("analysis", {})
    for g in analysis.get("policy", {}).get("governance", []):
        if g.get("status") == "blocked":
            return "🚫 Governance block"
    assessment = analysis.get("assessment", {})
    for key in ASSESSMENT_PRIORITY:
        a = assessment.get(key, {})
        if not a:
            continue
        status = get_effective_status(a)
        if status in ("fail", "warning"):
            return f"{STATUS_EMOJI.get(status, '')} {a.get('label', '')}"
    for v in analysis.get("policy", {}).get("violations", {}).values():
        status = get_effective_status(v)
        if status in ("fail", "warning"):
            return f"{STATUS_EMOJI.get(status, '')} Policy violation"
    return "—"


def _summary_row(pkg, status_cell, reverse_deps):
    purl = pkg.get("purl", "unknown").split("?")[0]
    icon = "🔗" if purl in reverse_deps else "📦"
    report_url = pkg.get("analysis", {}).get("report", "")
    purl_cell = f"[`{purl}`]({report_url})" if report_url else f"`{purl}`"
    return f"| {icon} {purl_cell} | {status_cell} | {deployment_risk_label(pkg)} |"


def summary_table(sorted_rejected, sorted_warnings, passing, reverse_deps):
    rows = ["| Package | Status | Assessment |", "|---------|--------|------------|"]
    rows += [_summary_row(pkg, "❌ REJECT", reverse_deps) for pkg in sorted_rejected]
    rows += [_summary_row(pkg, "⚠️ WARN", reverse_deps) for pkg in sorted_warnings]
    if passing:
        n = len(passing)
        rows.append(f"| *{n} package{'s' if n != 1 else ''}* | ✅ PASS | — |")
    return "\n".join(rows)


def summarize_package(pkg, reverse_deps=None):
    purl = pkg.get("purl", "unknown").split("?")[0]
    analysis = pkg.get("analysis", {})
    finding = ""
    for key in ASSESSMENT_PRIORITY:
        a = analysis.get("assessment", {}).get(key, {})
        if not a:
            continue
        status = get_effective_status(a)
        if status in ("fail", "warning"):
            finding = f" — {STATUS_EMOJI.get(status, '')} {ASSESSMENT_NAMES[key]}: {a.get('label', '')}"
            break
    lines = [f"> 📦 `{purl}`{finding}"]
    if reverse_deps is not None:
        inc = find_inclusion(pkg.get("purl", ""), reverse_deps)
        if inc:
            lines.append(f"> {inc}")
    return "\n".join(lines)


def format_package(pkg, config, index=None, total=None, inclusion=None, scan_time=None):
    analysis = pkg.get("analysis", {})
    purl = pkg.get("purl", "unknown").split("?")[0]
    report_url = analysis.get("report", "")

    status = classify_package(pkg)
    counter = f" ({index} of {total})" if index is not None and total is not None else ""
    tags = ""
    if pkg.get("removed"):
        tags += " [REMOVED]"
    if pkg.get("quarantined"):
        tags += " [QUARANTINED]"
    heading = f"#### 📦 **`{purl}`** — {STATUS_LABELS.get(status, '')}{counter}{tags}"
    if inclusion:
        heading += f"<br>{inclusion}"
    parts = [heading]
    published = relative_date(pkg.get("published"), reference=scan_time)
    if published:
        parts.append(f"📅 Released {published}")
    if config.license_info:
        license_str = pkg.get("license")
        if license_str:
            parts.append(f"⚖️ {license_str}")

    m = malware_block(analysis.get("classifications", []))
    if m:
        parts += ["", m]

    g = governance_block(analysis.get("policy", {}).get("governance", []))
    if g:
        parts += ["", g]

    if config.assessment == "table":
        a = assessment_table(analysis.get("assessment", {}), config.overrides)
    elif config.assessment == "simplified":
        a = simplified_assessment_block(analysis.get("assessment", {}), config.overrides)
    else:
        a = ""
    if a:
        parts += ["", a]

    assessment_fail = any(get_effective_status(v) == "fail" for v in analysis.get("assessment", {}).values() if v)
    if not g and not assessment_fail and not config.policy:
        pb = policy_block(analysis.get("policy", {}).get("violations", {}))
        if pb:
            parts += ["", pb]

    if config.vulnerabilities:
        t = vuln_table(analysis.get("vulnerabilities", {}), report_url)
        if t:
            parts += ["", t]

    if config.policy:
        p = policy_table(analysis.get("policy", {}).get("violations", {}), config.overrides, report_url)
        if p:
            parts += ["", p]

    if report_url:
        parts += ["", f"[Full report →]({report_url})"]

    return "\n".join(parts)


def build_comment(scan_status, scan_path, report_data, config, marker=None):
    emoji = "✅" if scan_status == "pass" else "❌"
    label = "PASS" if scan_status == "pass" else "FAIL"

    lines = [marker or make_marker(scan_path), f"## Spectra Assure Community Scan: {emoji} {label}", "", f"**Scanned:** `{scan_path}`"]

    if report_data is None:
        lines += ["", "> Add the `report:` input to get detailed per-package findings in this comment."]
        return "\n".join(lines)

    analysis_meta = report_data.get("analysis", {})
    report = analysis_meta.get("report", {})
    packages = report.get("packages", [])
    errors = report.get("errors", [])
    raw_scan_ts = analysis_meta.get("timestamp")
    scan_time = _parse_iso(raw_scan_ts)

    rejected, warnings_pkgs, passing = partition_packages(packages)
    reverse_deps = build_reverse_deps(packages)

    summary_parts = []
    if rejected:
        summary_parts.append(f"{len(rejected)} rejected")
    if warnings_pkgs:
        summary_parts.append(f"{len(warnings_pkgs)} warning{'s' if len(warnings_pkgs) != 1 else ''}")
    if passing:
        summary_parts.append(f"{len(passing)} passed")
    if errors:
        summary_parts.append(f"{len(errors)} scan error{'s' if len(errors) != 1 else ''}")
    lines[-1] += f" — {' · '.join(summary_parts)}" if summary_parts else ""

    if not config.show_details:
        sorted_rejected = sorted(rejected, key=sort_key_rejected)
        sorted_warnings = sorted(warnings_pkgs, key=sort_key_warnings)
        lines += ["", summary_table(sorted_rejected, sorted_warnings, passing, reverse_deps)]
        return "\n".join(lines)

    if rejected:
        lines += ["", "### ❌ Rejected packages"]
        sorted_rejected = sorted(rejected, key=sort_key_rejected)
        for i, pkg in enumerate(sorted_rejected[:MAX_PACKAGES], 1):
            inclusion = find_inclusion(pkg.get("purl", ""), reverse_deps)
            lines += ["", format_package(pkg, config, i, len(sorted_rejected), inclusion, scan_time=scan_time), "", "---"]
        if len(sorted_rejected) > MAX_PACKAGES:
            remaining = sorted_rejected[MAX_PACKAGES:]
            block = ["> [!IMPORTANT]", f"> **{len(remaining)} more rejected package{'s' if len(remaining) != 1 else ''}**"]
            block += [summarize_package(p, reverse_deps) for p in remaining]
            lines += ["", "\n".join(block)]

    if warnings_pkgs and config.level in ("warn", "pass"):
        lines += ["", "---", "", "### ⚠️ Scan Warnings", "*Packages with issues that did not meet the rejection threshold.*"]
        sorted_warnings = sorted(warnings_pkgs, key=sort_key_warnings)
        for i, pkg in enumerate(sorted_warnings[:MAX_PACKAGES], 1):
            inclusion = find_inclusion(pkg.get("purl", ""), reverse_deps)
            lines += ["", format_package(pkg, config, i, len(sorted_warnings), inclusion, scan_time=scan_time), "", "---"]
        if len(sorted_warnings) > MAX_PACKAGES:
            remaining = sorted_warnings[MAX_PACKAGES:]
            block = ["> [!IMPORTANT]", f"> **{len(remaining)} more warning{'s' if len(remaining) != 1 else ''}**"]
            block += [summarize_package(p, reverse_deps) for p in remaining]
            lines += ["", "\n".join(block)]

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
    comment_template = os.environ.get("COMMENT_TEMPLATE", "")
    comment_level = os.environ.get("COMMENT_LEVEL", "")
    comment_assessment = os.environ.get("COMMENT_ASSESSMENT", "")

    base = TEMPLATES.get(comment_template, ReportConfig())
    config = ReportConfig(
        level=comment_level if comment_level in VALID_LEVELS else base.level,
        assessment=comment_assessment if comment_assessment in VALID_ASSESSMENT_STYLES else base.assessment,
        vulnerabilities=base.vulnerabilities and os.environ.get("COMMENT_VULNERABILITIES", "true").lower() == "true",
        license_info=base.license_info or os.environ.get("COMMENT_LICENSE", "false").lower() == "true",
        policy=base.policy or os.environ.get("COMMENT_POLICY", "false").lower() == "true",
        overrides=base.overrides or os.environ.get("COMMENT_OVERRIDES", "false").lower() == "true",
        show_details=base.show_details,
    )

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
    body = build_comment(scan_status, scan_path, report_data, config, marker)

    try:
        post_or_update(token, repo, pr_number, body, marker)
    except Exception as e:
        print(f"WARNING: could not post PR comment: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
