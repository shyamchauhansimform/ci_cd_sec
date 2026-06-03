#!/usr/bin/env python3
"""
Dependency Vulnerability Scanner
Scans a GitHub repo for package manifests, checks OSV.dev for CVEs,
and posts an Adaptive Card to Microsoft Teams.
"""

import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

# ── Config from env ────────────────────────────────────────────────────────────
GITHUB_TOKEN   = os.environ["GITHUB_TOKEN"]
TEAMS_WEBHOOK  = os.environ["TEAMS_WEBHOOK_URL"]
REPO_OWNER     = os.environ["GITHUB_REPOSITORY"].split("/")[0]
REPO_NAME      = os.environ["GITHUB_REPOSITORY"].split("/")[1]
REPO_BRANCH    = os.environ["GITHUB_REF_NAME"]

# ── Manifest filenames to look for ────────────────────────────────────────────
PACKAGE_FILES = {
    # npm / Node
    "package.json":       "npm",
    "package-lock.json":  "npm",
    "yarn.lock":          "npm",
    "pnpm-lock.yaml":     "npm",
    # Python
    "requirements.txt":   "PyPI",
    "Pipfile":            "PyPI",
    "Pipfile.lock":       "PyPI",
    "pyproject.toml":     "PyPI",
    "setup.py":           "PyPI",
    "setup.cfg":          "PyPI",
    # Ruby
    "Gemfile":            "RubyGems",
    "Gemfile.lock":       "RubyGems",
    # Go
    "go.mod":             "Go",
    "go.sum":             "Go",
    # Rust
    "Cargo.toml":         "crates.io",
    "Cargo.lock":         "crates.io",
    # PHP
    "composer.json":      "Packagist",
    "composer.lock":      "Packagist",
    # Java / Kotlin
    "pom.xml":            "Maven",
    "build.gradle":       "Maven",
    "build.gradle.kts":   "Maven",
}

GITHUB_API = "https://api.github.com"
OSV_API    = "https://api.osv.dev/v1"


# ── HTTP helpers ───────────────────────────────────────────────────────────────
def http_get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def http_post(url, payload, headers=None):
    data = json.dumps(payload).encode()
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def http_get_raw(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


# ── Step 1: List all files in the repo tree ───────────────────────────────────
def list_repo_files():
    print(f"📂 Listing files in {REPO_OWNER}/{REPO_NAME}@{REPO_BRANCH} ...")
    url = f"{GITHUB_API}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{REPO_BRANCH}?recursive=1"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = http_get(url, headers)
    return data.get("tree", [])


# ── Step 2: Filter manifest files ─────────────────────────────────────────────
def filter_manifests(tree):
    found = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        filename = Path(item["path"]).name
        if filename in PACKAGE_FILES:
            found.append({
                "name":      filename,
                "path":      item["path"],
                "ecosystem": PACKAGE_FILES[filename],
                "raw_url":   f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{REPO_BRANCH}/{item['path']}",
            })
    print(f"📄 Found {len(found)} manifest file(s): {[f['path'] for f in found]}")
    return found


# ── Step 3 + 4: Download and parse each manifest ──────────────────────────────
def parse_npm(content):
    pkg = json.loads(content)
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    return [
        {"name": name, "version": ver.lstrip("^~>=< ").split(" ")[0], "ecosystem": "npm"}
        for name, ver in deps.items()
    ]


def parse_requirements_txt(content):
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # handle name==1.2.3, name>=1.2.3, name~=1.2.3
        for sep in ["==", ">=", "<=", "~=", "!="]:
            if sep in line:
                name, ver = line.split(sep, 1)
                packages.append({"name": name.strip(), "version": ver.strip().split(",")[0], "ecosystem": "PyPI"})
                break
        else:
            packages.append({"name": line, "version": "", "ecosystem": "PyPI"})
    return packages


def parse_go_mod(content):
    packages = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require ") or in_require:
            parts = line.replace("require ", "").split()
            if len(parts) >= 2:
                packages.append({"name": parts[0], "version": parts[1].lstrip("v"), "ecosystem": "Go"})
    return packages


def parse_cargo_toml(content):
    packages = []
    in_deps = False
    for line in content.splitlines():
        line = line.strip()
        if line in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
            in_deps = True
            continue
        if line.startswith("[") and line != "[dependencies]":
            in_deps = False
        if in_deps and "=" in line and not line.startswith("#"):
            name, ver_raw = line.split("=", 1)
            ver = ver_raw.strip().strip('"').lstrip("^~>= ")
            if ver:
                packages.append({"name": name.strip(), "version": ver.split(" ")[0], "ecosystem": "crates.io"})
    return packages


def parse_gemfile_lock(content):
    packages = []
    in_specs = False
    for line in content.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            if line.startswith("    ") and not line.startswith("      "):
                # 4-space indent = gem entry
                parts = line.strip().split(" ")
                if len(parts) >= 2:
                    name = parts[0]
                    ver  = parts[1].strip("()")
                    packages.append({"name": name, "version": ver, "ecosystem": "RubyGems"})
            elif line.strip() == "" or (not line.startswith(" ")):
                in_specs = False
    return packages


PARSERS = {
    "package.json":    parse_npm,
    "requirements.txt": parse_requirements_txt,
    "go.mod":          parse_go_mod,
    "Cargo.toml":      parse_cargo_toml,
    "Gemfile.lock":    parse_gemfile_lock,
}


def fetch_and_parse(manifest):
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
    try:
        content = http_get_raw(manifest["raw_url"], headers)
    except Exception as e:
        print(f"  ⚠️  Could not download {manifest['path']}: {e}")
        return []

    parser = PARSERS.get(manifest["name"])
    if not parser:
        print(f"  ⏭️  No parser for {manifest['name']}, skipping")
        return []

    try:
        packages = parser(content)
        print(f"  ✅ Parsed {len(packages)} deps from {manifest['path']}")
        return packages
    except Exception as e:
        print(f"  ⚠️  Parse error in {manifest['path']}: {e}")
        return []


# ── Step 5: Query OSV.dev in batch ────────────────────────────────────────────
def query_osv(packages):
    if not packages:
        return []

    queries = [
        {"version": p["version"], "package": {"name": p["name"], "ecosystem": p["ecosystem"]}}
        for p in packages if p["version"]
    ]

    print(f"\n🔍 Querying OSV.dev for {len(queries)} packages ...")
    response = http_post(f"{OSV_API}/querybatch", {"queries": queries})
    results  = response.get("results", [])

    enriched = []
    for i, result in enumerate(results):
        vulns = result.get("vulns", [])
        if vulns:
            enriched.append({
                "package":    queries[i]["package"]["name"],
                "version":    queries[i]["version"],
                "ecosystem":  queries[i]["package"]["ecosystem"],
                "vuln_count": len(vulns),
                "vulns":      vulns,
            })
    print(f"  ⚠️  {len(enriched)} package(s) have known vulnerabilities")
    return enriched


# ── Step 6+7: Flatten and fetch full CVE details ──────────────────────────────
def fetch_vuln_details(vuln_entry):
    details = []
    for vuln in vuln_entry["vulns"]:
        try:
            v = http_get(f"{OSV_API}/vulns/{vuln['id']}")
        except Exception as e:
            print(f"  ⚠️  Could not fetch {vuln['id']}: {e}")
            continue

        versions  = [e for a in v.get("affected", []) for r in a.get("ranges", []) for e in r.get("events", [])]
        refs      = [r["url"] for r in v.get("references", [])]
        severity  = v.get("database_specific", {}).get("severity") or \
                    (v.get("severity") or [{}])[0].get("type", "UNKNOWN")
        cvss      = (v.get("severity") or [{}])[0].get("score")

        details.append({
            "package":       vuln_entry["package"],
            "version":       vuln_entry["version"],
            "ecosystem":     vuln_entry["ecosystem"],
            "vuln_id":       v["id"],
            "aliases":       v.get("aliases", []),
            "summary":       v.get("summary", ""),
            "severity":      severity,
            "cvss_score":    cvss,
            "cwe_ids":       v.get("database_specific", {}).get("cwe_ids", []),
            "fixed_in":      [e["fixed"] for e in versions if "fixed" in e],
            "fix_available": any("fixed" in e for e in versions),
            "advisory_url":  next((u for u in refs if "github.com/advisories" in u), None),
            "nvd_url":       next((u for u in refs if "nvd.nist.gov" in u), None),
            "web_url":       f"https://osv.dev/vulnerability/{v['id']}",
            "published":     v.get("published", ""),
        })
    return details


# ── Step 8: Build Teams Adaptive Card ─────────────────────────────────────────
SEV_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

def severity_order(s):
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(s, 4)


def build_teams_card(all_vulns, repo):
    if not all_vulns:
        # Clean bill of health card
        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "text": "✅ Dependency Scan — No Vulnerabilities Found",
                         "weight": "Bolder", "size": "Large", "wrap": True},
                        {"type": "TextBlock",
                         "text": f"Repository **{repo}** has no known vulnerable dependencies.",
                         "wrap": True}
                    ]
                }
            }]
        }

    sorted_vulns = sorted(all_vulns, key=lambda v: severity_order(v["severity"]))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in all_vulns:
        counts[v["severity"]] = counts.get(v["severity"], 0) + 1

    # Top 10 findings block
    finding_blocks = []
    for v in sorted_vulns[:10]:
        emoji   = SEV_EMOJI.get(v["severity"], "⚪")
        fix_txt = f"Fix available → `{v['fixed_in'][0]}`" if v["fix_available"] else "⛔ No fix yet"
        cve_aliases = ", ".join(v["aliases"][:2]) if v["aliases"] else ""

        finding_blocks.append({
            "type": "Container",
            "separator": True,
            "items": [
                {"type": "TextBlock",
                 "text": f"{emoji} **{v['package']}** `{v['version']}` — {v['vuln_id']}" +
                         (f" ({cve_aliases})" if cve_aliases else ""),
                 "wrap": True, "weight": "Bolder"},
                {"type": "TextBlock",
                 "text": v["summary"] or "No summary available.",
                 "wrap": True, "size": "Small", "isSubtle": True},
                {"type": "TextBlock", "text": fix_txt, "wrap": True, "size": "Small"},
            ]
        })

    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock",
                     "text": "🔍 Dependency Vulnerability Scan Report",
                     "weight": "Bolder", "size": "Large", "wrap": True},
                    {"type": "FactSet", "facts": [
                        {"title": "Repository",   "value": repo},
                        {"title": "Total CVEs",   "value": str(len(all_vulns))},
                        {"title": "🔴 Critical",  "value": str(counts.get("CRITICAL", 0))},
                        {"title": "🟠 High",      "value": str(counts.get("HIGH", 0))},
                        {"title": "🟡 Medium",    "value": str(counts.get("MEDIUM", 0))},
                        {"title": "🟢 Low",       "value": str(counts.get("LOW", 0))},
                    ]},
                    {"type": "TextBlock", "text": "Top Findings",
                     "weight": "Bolder", "size": "Medium", "separator": True},
                    *finding_blocks,
                ],
                "actions": [
                    {"type": "Action.OpenUrl", "title": "View on OSV.dev",
                     "url": "https://osv.dev"},
                    {"type": "Action.OpenUrl", "title": "View Repository",
                     "url": f"https://github.com/{repo}"},
                ]
            }
        }]
    }
    return card


# ── Step 9: Send to Teams ──────────────────────────────────────────────────────
def send_teams_alert(card):
    print("\n📣 Sending Teams alert ...")
    try:
        data = json.dumps(card).encode()
        req  = urllib.request.Request(
            TEAMS_WEBHOOK, data=data,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"  ✅ Teams responded: {r.status}")
    except urllib.error.HTTPError as e:
        print(f"  ❌ Teams webhook failed: {e.code} {e.read().decode()}")
        sys.exit(1)


# ── Write summary to GitHub Actions step summary ──────────────────────────────
def write_gha_summary(all_vulns, repo):
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return

    lines = [
        f"# 🔍 Dependency Vulnerability Scan — `{repo}`\n",
    ]

    if not all_vulns:
        lines.append("## ✅ No vulnerabilities found!\n")
    else:
        counts = {}
        for v in all_vulns:
            counts[v["severity"]] = counts.get(v["severity"], 0) + 1

        lines += [
            f"**Total CVEs found: {len(all_vulns)}**\n",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {counts.get('CRITICAL', 0)} |",
            f"| 🟠 High     | {counts.get('HIGH', 0)} |",
            f"| 🟡 Medium   | {counts.get('MEDIUM', 0)} |",
            f"| 🟢 Low      | {counts.get('LOW', 0)} |",
            "",
        ]

        # Group findings by severity bucket
        SEVERITY_GROUPS = [
            ("CRITICAL", "🔴 Critical"),
            ("HIGH",     "🟠 High"),
            ("MEDIUM",   "🟡 Medium"),
            ("MODERATE", "🟡 Moderate"),
            ("LOW",      "🟢 Low"),
            ("UNKNOWN",  "⚪ Unknown"),
        ]

        TABLE_HEADER = [
            "| Package | Version | CVE | Fix Available | Description |",
            "|---------|---------|-----|---------------|-------------|",
        ]

        for sev_key, sev_label in SEVERITY_GROUPS:
            group = [v for v in all_vulns if v["severity"].upper() == sev_key]
            if not group:
                continue

            lines += [f"## {sev_label} ({len(group)})\n", *TABLE_HEADER]

            # Collapse multiple CVEs for the same package+version into one row
            from collections import defaultdict
            pkg_map = defaultdict(list)
            for v in group:
                pkg_map[(v["package"], v["version"])].append(v)

            for (pkg, ver) in sorted(pkg_map.keys()):
                entries = pkg_map[(pkg, ver)]

                # Merge CVE links: GHSA-111, GHSA-222
                cves = " ".join(
                    f"[{e['vuln_id']}]({e['web_url']})"
                    for e in entries
                )

                # Best fix = highest version available across all CVEs
                fixes = [e["fixed_in"][0] for e in entries if e["fix_available"]]
                fix   = f"`{max(fixes)}`" if fixes else "—"

                # Join descriptions, truncate each to 80 chars so row stays readable
                descs = []
                for e in entries:
                    d = (e.get("summary") or "No description.").replace("|", "\\|")
                    descs.append((d[:80] + "…") if len(d) > 80 else d)
                desc = " / ".join(descs)

                lines.append(
                    f"| `{pkg}` | `{ver}` | {cves} | {fix} | {desc} |"
                )

            lines.append("")

    with open(summary_file, "w") as f:
        f.write("\n".join(lines))
    print("  📋 GitHub Actions summary written")


# ── Set exit code based on findings ───────────────────────────────────────────
def check_fail_threshold(all_vulns):
    """Exit 1 if any CRITICAL or HIGH vuln found — breaks the CI pipeline."""
    blockers = [v for v in all_vulns if v["severity"] in ("CRITICAL", "HIGH")]
    if blockers:
        print(f"\n❌ {len(blockers)} CRITICAL/HIGH vulnerabilit(ies) found — failing the build.")
        return 1
    return 0


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    repo = f"{REPO_OWNER}/{REPO_NAME}"
    print(f"🚀 Starting vulnerability scan for {repo}\n{'─'*50}")

    # 1. List repo files
    tree = list_repo_files()

    # 2. Filter manifests
    manifests = filter_manifests(tree)
    if not manifests:
        print("⚠️  No package manifest files found. Exiting cleanly.")
        send_teams_alert(build_teams_card([], repo))
        write_gha_summary([], repo)
        return

    # 3+4. Parse each manifest
    all_packages = []
    for m in manifests:
        all_packages.extend(fetch_and_parse(m))

    # Deduplicate by (name, version, ecosystem)
    seen = set()
    deduped = []
    for p in all_packages:
        key = (p["name"], p["version"], p["ecosystem"])
        if key not in seen:
            seen.add(key)
            deduped.append(p)
    print(f"\n📦 Total unique dependencies: {len(deduped)}")

    # 5. Query OSV.dev
    vulnerable_packages = query_osv(deduped)

    # 6+7. Fetch full CVE details
    all_vulns = []
    for pkg in vulnerable_packages:
        print(f"  🔎 Fetching details for {pkg['package']} ({pkg['vuln_count']} CVE(s)) ...")
        all_vulns.extend(fetch_vuln_details(pkg))

    print(f"\n📊 Total enriched CVEs: {len(all_vulns)}")

    # 8+9. Build card and alert Teams
    card = build_teams_card(all_vulns, repo)
    send_teams_alert(card)

    # 10. GHA summary
    write_gha_summary(all_vulns, repo)

    # 11. Fail build on CRITICAL/HIGH
    sys.exit(check_fail_threshold(all_vulns))


if __name__ == "__main__":
    main()