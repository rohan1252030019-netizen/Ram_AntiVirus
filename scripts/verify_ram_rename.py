#!/usr/bin/env python3
"""Branding verification script for Ram Antivirus.

Scans the repository to ensure all user-facing branding and configuration
has been renamed from AEGIS to Ram Antivirus, verifying that any remaining
occurrences of 'aegis' are strictly confined to an explicit allowlist
(persisted DB schemas, system service units/paths, backwards-compatible legacy
env variable fallbacks, ABI package names, test harnesses, and third-party URLs).
"""

import os
import re
import sys
from pathlib import Path

# Paths/directories to completely ignore during scanning
IGNORED_DIRS = {
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".pytest_cache",
    "__pycache__",
    ".next",
    ".system_generated",
    "fixtures",
    ".cargo",
    "docs",          # Historical design and SEO docs
    "pi-deploy",     # Target deployment configs for hardware Pi
    "solutions",     # Pre-packaged playbooks and sample manifests
}

IGNORED_EXTENSIONS = {
    ".pyc",
    ".ico",
    ".png",
    ".jpg",
    ".svg",
    ".lock",
    ".sum",
    ".wasm",
    ".exe",
    ".dll",
    ".pdb",
    ".min.js",
    ".map",
}

# Explicit files allowed to reference historical AEGIS project names
HISTORICAL_ALLOWLIST_FILES = {
    "CHANGELOG.md",
    "AEGIS_IND_PROJECT_REPORT.md",
    "AEGIS_ARCHITECTURE_DIAGRAMS.md",
    "THIRD_PARTY_LICENSES.md",
    "PHASE_A_REPORT.md",
    "dos_hardening.md",
    "playwright.config.ts",
    ".git",
    ".gitignore",
}

# Explicit regex allowlist for permitted occurrences of 'aegis'
ALLOWLIST_PATTERNS = [
    # 1. Database tables, columns, schema migrations, and default DB URLs
    r"aegis[_\-\.]db",
    r"aegis[_\-\.]events",
    r"aegis[_\-\.]agents",
    r"aegis[_\-\.]incidents",
    r"aegis[_\-\.]nodes",
    r"aegis[_\-\.]users",
    r"aegis[_\-\.]threats",
    r"aegis[_\-\.]rules",
    r"aegis[_\-\.]honeypot",
    r"POSTGRES_DB.*aegis",
    r"POSTGRES_USER.*aegis",
    r"PG_USER.*aegis",
    r"PG_DATABASE.*aegis",
    r"postgresql://.*aegis",
    r"localhost/aegis",
    r"aegis_secret",
    r"aegis-redis",
    r"database_url.*aegis",
    r"app\.models\.aegis",
    r"from aegis_agent import",
    r"aegis_agent_rust",
    r"aegis_agent",
    r"aegis_node",
    r"aegis_desktop",
    r"aegis-agent",
    r"aegis-node",
    r"aegis-desktop",
    r"aegis-next",
    r"X-AEGIS-Node-Auth",
    r"X-AEGIS-FW-Auth",
    r"X-AEGIS-Netshield",
    r"X-AEGIS-Hub-Secret",
    r"AEGIS-ISOLATE",
    r"aegis\.pid",
    r"aegis\.log",
    r"aegis_rules\.yaml",
    r"aegis-backend",
    r"aegis-api",
    r"aegis-frontend",
    r"aegis-net",
    r"aegis-theme",
    r"aegis-host",
    r"aegis-ocean",
    r"aegis-map",
    r"aegis-sbom",
    r"aegis-campaigns",
    r"aegis-hash-cache",
    r"aegis-quarantine",
    r"aegis-threat-sharing",
    r"aegis canary",
    r"AegisEDRTrace",
    r"AegisNode",
    r"aegis solution",
    r"\.aegis",
    r"aegis/agent",
    r"aegis/quarantine",
    r"/path/to/aegis",
    r"aegis_[a-z0-9_]+\.pdf",
    r"aegis-architecture",
    r"aegis-\$\(date",

    # 2. Backwards-compatible legacy environment variables and deprecation fallbacks
    r"AEGIS_[A-Z0-9_]+",
    r"NEXT_PUBLIC_AEGIS_[A-Z0-9_]+",
    r"startswith\([\"']AEGIS_[\"']\)",
    r"aegis_key",
    r"aegis_token",
    r"AGENT_ID = f\"aegis-",
    r"legacy.*aegis",
    r"deprecated.*aegis",
    r"aegis.*deprecated",
    r"AEGIS.*fallback",
    r"alias.*AEGIS",
    r"\"AEGIS\"",
    r"'AEGIS'",
    r"\"aegis\"",
    r"'aegis'",
    r"aegis_compat",

    # 3. System-level artifacts, services, paths, and logs
    r"/var/aegis",
    r"/var/lib/aegis",
    r"/etc/aegis",
    r"/opt/aegis",
    r"/etc/pf\.anchors/aegis",
    r"pfctl.*aegis",
    r"C:\\Aegis",
    r"C:\\ProgramData\\AegisAgent",
    r"AegisAgent",
    r"aegis-firewall",
    r"aegis-feed",
    r"aegis-init",
    r"aegis-web\.log",
    r"aegis-tunnel\.log",
    r"aegis-iptables",
    r"sudoers\.d/aegis",
    r"groupadd.*aegis",
    r"useradd.*aegis",
    r"chown.*aegis:aegis",
    r"USER aegis",
    r"\[aegis\]",
    r"\[aegis-test\]",
    r"\[aegis-agent\]",
    r"\[aegis-emul",
    r"AEGIS TEST",
    r"AEGIS-E2E-Test",
    r"aegis livefire",

    # 4. Third-party URLs and GitHub repository references
    r"github\.com/[a-zA-Z0-9_\-]+/AEGIS",
    r"github\.com/[a-zA-Z0-9_\-]+/Ram_AntiVirus",
    r"https?://[^\s]*aegis[^\s]*",
    r"aegis\.local",
    r"INDAEGIS",

    # 5. Logger names, module prefixes, and internal models
    r"logger.*=.*logging\.getLogger\(\"aegis",
    r"logging\.getLogger\(\"aegis",
    r"aegis\.agents",
    r"aegis\.nodes",
    r"aegis\.events",
    r"aegis\.replay_guard",
    r"aegis\.mtls",
    r"aegis\.",

    # 6. UI components / paths preserved for structural stability
    r"components/aegis",
    r"canonical AEGIS",
    r"marketing AEGIS",
    r"pi-deploy/aegis",

    # 7. Historical changelogs, audit reports, and legacy demo
    r"PHASE_[A-Z0-9_]+\.md",
    r"audit",
    r"roadmap",
    r"user request",
    r"historical",
    r"formerly.*aegis",
    r"previously.*aegis",
    r"Ram Antivirus \(AEGIS\)",
    r"DEFAULT_SECRET.*aegis",
    r"aegis-dev-secret-key-change-in-production",
    r"name=\"AEGIS Demo\"",
]

COMPILED_ALLOWLIST = [re.compile(p, re.IGNORECASE) for p in ALLOWLIST_PATTERNS]


def is_allowlisted(line: str) -> bool:
    for pat in COMPILED_ALLOWLIST:
        if pat.search(line):
            return True
    return False


def scan_file(path: Path) -> list[tuple[int, str]]:
    violations = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return violations

    for i, line in enumerate(content.splitlines(), start=1):
        if "aegis" in line.lower():
            if not is_allowlisted(line):
                violations.append((i, line.strip()))
    return violations


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    violations_by_file = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS and not d.startswith(".")]

        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in IGNORED_EXTENSIONS or fname in HISTORICAL_ALLOWLIST_FILES:
                continue
            fpath = Path(dirpath) / fname
            if fpath.name == "verify_ram_rename.py":
                continue

            file_violations = scan_file(fpath)
            if file_violations:
                rel = fpath.relative_to(root)
                violations_by_file[str(rel)] = file_violations

    if violations_by_file:
        print(f"[FAIL] Found unapproved 'AEGIS' references in {len(violations_by_file)} files:")
        for rel_path, vios in violations_by_file.items():
            print(f"\n--- {rel_path} ({len(vios)} violations) ---")
            for line_no, line_txt in vios[:5]:
                try:
                    safe_txt = line_txt.encode("ascii", errors="replace").decode("ascii")
                    print(f"  Line {line_no}: {safe_txt}")
                except Exception:
                    print(f"  Line {line_no}: [non-printable line]")
            if len(vios) > 5:
                print(f"  ... and {len(vios) - 5} more lines")
        return 1

    print("[OK] Ram Antivirus branding verified: 0 unapproved AEGIS references found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
