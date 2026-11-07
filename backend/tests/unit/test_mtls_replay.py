"""Unit tests for Internal CA, mTLS verification, and replay protection."""

import pytest
import time
from app.core.ca import InternalCA
from app.core.replay_guard import ReplayGuard, ReplayProtectionError


@pytest.fixture
def ca():
    instance = InternalCA()
    instance.initialize_ca(common_name="Test Root CA")
    return instance


@pytest.fixture
def replay_guard():
    return ReplayGuard(max_skew_seconds=60.0, nonce_ttl_seconds=300.0)


def test_internal_ca_workflow(ca):
    # 1. Issue client certificate for agent-1
    cert_pem, key_pem, fp = ca.issue_agent_cert(agent_id="agent-001", days_valid=90)
    assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert len(fp) == 64  # SHA-256 hex string

    # 2. Verify valid cert
    is_valid, cn, cert_fp, err = ca.verify_client_cert(cert_pem)
    assert is_valid is True
    assert cn == "agent-001"
    assert cert_fp == fp
    assert err == ""

    # 3. Revoke certificate
    ca.revoke_fingerprint(fp)
    assert ca.is_revoked(fp) is True

    # 4. Revoked cert rejected
    is_valid_revoked, _, _, err_revoked = ca.verify_client_cert(cert_pem)
    assert is_valid_revoked is False
    assert "revoked" in err_revoked.lower()


def test_wrong_ca_rejected(ca):
    # Separate untrusted CA
    rogue_ca = InternalCA()
    rogue_ca.initialize_ca(common_name="Rogue Untrusted CA")
    rogue_cert_pem, _, _ = rogue_ca.issue_agent_cert("agent-001")

    # Verification against trusted CA must fail
    is_valid, _, _, err = ca.verify_client_cert(rogue_cert_pem)
    assert is_valid is False
    assert "not issued by trusted ca" in err.lower() or "verification failed" in err.lower()


def test_replay_guard_valid_message_accepted(replay_guard):
    agent_id = "agent-test-1"
    secret_key = "super-secret-key"
    payload = {"status": "ok", "processes": 42}
    now = time.time()

    sig = replay_guard.compute_signature(
        agent_id=agent_id,
        seq=1,
        nonce="nonce-1",
        timestamp=now,
        payload=payload,
        secret_key=secret_key,
    )

    # Valid message passes
    replay_guard.validate_message(
        agent_id=agent_id,
        seq=1,
        nonce="nonce-1",
        timestamp=now,
        payload=payload,
        signature=sig,
        secret_key=secret_key,
        now=now,
    )


def test_replay_guard_replayed_seq_rejected(replay_guard):
    agent_id = "agent-test-2"
    secret_key = "secret-key-2"
    payload = {"metric": 100}
    now = time.time()

    sig1 = replay_guard.compute_signature(agent_id, 1, "nonce-a", now, payload, secret_key)
    replay_guard.validate_message(agent_id, 1, "nonce-a", now, payload, sig1, secret_key, now=now)

    # Replay with same sequence number (seq=1)
    sig_replay = replay_guard.compute_signature(agent_id, 1, "nonce-b", now + 1, payload, secret_key)
    with pytest.raises(ReplayProtectionError, match="Sequence regression or duplicate sequence"):
        replay_guard.validate_message(agent_id, 1, "nonce-b", now + 1, payload, sig_replay, secret_key, now=now + 1)

    # Sequence regression (seq=0 < 1)
    sig_regression = replay_guard.compute_signature(agent_id, 0, "nonce-c", now + 2, payload, secret_key)
    with pytest.raises(ReplayProtectionError, match="Sequence regression or duplicate sequence"):
        replay_guard.validate_message(agent_id, 0, "nonce-c", now + 2, payload, sig_regression, secret_key, now=now + 2)


def test_replay_guard_replayed_nonce_rejected(replay_guard):
    agent_id = "agent-test-3"
    secret_key = "secret-key-3"
    payload = {"data": "test"}
    now = time.time()

    sig1 = replay_guard.compute_signature(agent_id, 1, "same-nonce", now, payload, secret_key)
    replay_guard.validate_message(agent_id, 1, "same-nonce", now, payload, sig1, secret_key, now=now)

    # Higher sequence number (seq=2) but duplicate nonce
    sig2 = replay_guard.compute_signature(agent_id, 2, "same-nonce", now + 1, payload, secret_key)
    with pytest.raises(ReplayProtectionError, match="Duplicate nonce detected"):
        replay_guard.validate_message(agent_id, 2, "same-nonce", now + 1, payload, sig2, secret_key, now=now + 1)


def test_replay_guard_tampered_payload_rejected(replay_guard):
    agent_id = "agent-test-4"
    secret_key = "secret-key-4"
    original_payload = {"command": "ping"}
    tampered_payload = {"command": "format c:"}
    now = time.time()

    sig = replay_guard.compute_signature(agent_id, 1, "nonce-tamper", now, original_payload, secret_key)

    with pytest.raises(ReplayProtectionError, match="Signature mismatch"):
        replay_guard.validate_message(
            agent_id, 1, "nonce-tamper", now, tampered_payload, sig, secret_key, now=now
        )


def test_replay_guard_old_timestamp_rejected(replay_guard):
    agent_id = "agent-test-5"
    secret_key = "secret-key-5"
    payload = {"event": "login"}
    now = time.time()
    stale_time = now - 120.0  # 2 minutes old, exceeds 60s max skew

    sig = replay_guard.compute_signature(agent_id, 1, "nonce-stale", stale_time, payload, secret_key)

    with pytest.raises(ReplayProtectionError, match="Timestamp outside acceptable skew window"):
        replay_guard.validate_message(
            agent_id, 1, "nonce-stale", stale_time, payload, sig, secret_key, now=now
        )
