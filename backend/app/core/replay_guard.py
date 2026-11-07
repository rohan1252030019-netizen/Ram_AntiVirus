"""Replay attack protection and cryptographic envelope verification for agent telemetry.

Guards against:
- Stale or futuristic messages (configurable timestamp window)
- Sequence regressions / replayed sequence numbers (strictly monotonic per agent)
- Duplicate nonces
- Payload tampering (HMAC-SHA256 signature verification over agent_id:seq:nonce:timestamp:payload)
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Optional

logger = logging.getLogger("aegis.replay_guard")


class ReplayProtectionError(Exception):
    """Raised when an incoming message violates replay protection constraints."""
    pass


def canonical_json(obj: Any) -> str:
    """Format dictionary/object in deterministic canonical JSON."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class ReplayGuard:
    """Per-agent replay protection and payload verification engine."""

    def __init__(self, max_skew_seconds: float = 60.0, nonce_ttl_seconds: float = 300.0):
        self.max_skew_seconds = max_skew_seconds
        self.nonce_ttl_seconds = nonce_ttl_seconds
        # agent_id -> highest sequence number processed
        self._last_seq: dict[str, int] = {}
        # (agent_id, nonce) -> timestamp
        self._seen_nonces: dict[tuple[str, str], float] = {}

    def compute_signature(
        self,
        agent_id: str,
        seq: int,
        nonce: str,
        timestamp: float | int | str,
        payload: Any,
        secret_key: str,
        method: str = "",
        path: str = "",
    ) -> str:
        """Generate canonical HMAC-SHA256 signature."""
        ts_val = self._normalize_timestamp(timestamp)
        payload_str = canonical_json(payload)
        if method or path:
            msg = f"{method.upper()}:{path}:{agent_id}:{seq}:{nonce}:{ts_val:.3f}:{payload_str}"
        else:
            msg = f"{agent_id}:{seq}:{nonce}:{ts_val:.3f}:{payload_str}"
        return hmac.new(
            secret_key.encode("utf-8"),
            msg.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _normalize_timestamp(ts: float | int | str) -> float:
        if isinstance(ts, (int, float)):
            return float(ts)
        if isinstance(ts, str):
            try:
                return float(ts)
            except ValueError:
                from datetime import datetime, timezone
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                return dt.timestamp()
        raise ReplayProtectionError(f"Unsupported timestamp format: {type(ts)}")

    def prune_stale_nonces(self, now: float) -> None:
        """Evict nonces older than TTL."""
        cutoff = now - self.nonce_ttl_seconds
        stale = [k for k, ts in self._seen_nonces.items() if ts < cutoff]
        for k in stale:
            self._seen_nonces.pop(k, None)

    def validate_message(
        self,
        agent_id: str,
        seq: int,
        nonce: str,
        timestamp: float | int | str,
        payload: Any,
        signature: str,
        secret_key: str,
        method: str = "",
        path: str = "",
        now: Optional[float] = None,
    ) -> None:
        """Verify message freshness, sequence ordering, nonce uniqueness, and HMAC signature."""
        current_time = time.time() if now is None else now
        self.prune_stale_nonces(current_time)

        # 1. Timestamp Freshness Check
        ts_float = self._normalize_timestamp(timestamp)
        skew = abs(current_time - ts_float)
        if skew > self.max_skew_seconds:
            raise ReplayProtectionError(
                f"Timestamp outside acceptable skew window: skew={skew:.2f}s > {self.max_skew_seconds}s"
            )

        # 2. Monotonic Sequence Number Check
        last = self._last_seq.get(agent_id)
        if last is not None and seq <= last:
            raise ReplayProtectionError(
                f"Sequence regression or duplicate sequence: received seq={seq} <= last_seen={last}"
            )

        # 3. Nonce Uniqueness Check
        nonce_key = (agent_id, nonce)
        if nonce_key in self._seen_nonces:
            raise ReplayProtectionError(f"Duplicate nonce detected: {nonce} has already been used")

        # 4. Cryptographic HMAC Signature Verification
        # Check signature with (method, path) or without
        sig1 = self.compute_signature(
            agent_id=agent_id,
            seq=seq,
            nonce=nonce,
            timestamp=ts_float,
            payload=payload,
            secret_key=secret_key,
            method=method,
            path=path,
        )
        sig2 = self.compute_signature(
            agent_id=agent_id,
            seq=seq,
            nonce=nonce,
            timestamp=ts_float,
            payload=payload,
            secret_key=secret_key,
            method="",
            path="",
        )
        if not (hmac.compare_digest(sig1, signature) or hmac.compare_digest(sig2, signature)):
            raise ReplayProtectionError("Signature mismatch: payload tampered or unauthorized secret key")

        # Acceptance: commit state
        self._last_seq[agent_id] = seq
        self._seen_nonces[nonce_key] = current_time

    def reset_agent(self, agent_id: str) -> None:
        """Reset sequence tracking for testing or re-enrollment."""
        self._last_seq.pop(agent_id, None)
        keys_to_remove = [k for k in self._seen_nonces if k[0] == agent_id]
        for k in keys_to_remove:
            self._seen_nonces.pop(k, None)


# Default singleton
default_replay_guard = ReplayGuard()


def validate_envelope_or_legacy(
    body: dict,
    secret_key: str,
    agent_id: str,
    method: str = "POST",
    path: str = "",
    guard: Optional[ReplayGuard] = None,
) -> tuple[dict, bool]:
    """Helper to check if a request body is wrapped in a replay protection envelope:
    {seq: int, nonce: str, timestamp: ..., signature: str, payload: dict}
    
    If enveloped: validates against replay guard, returns (payload, True).
    If plain/legacy: checks AEGIS_ALLOW_LEGACY_API_KEY / RAM_ALLOW_LEGACY_API_KEY.
      - If allowed: logs deprecation warning, returns (body, False).
      - If disallowed: raises ReplayProtectionError.
    """
    import os
    rg = guard or default_replay_guard
    has_envelope_fields = "seq" in body and "nonce" in body and "signature" in body and "timestamp" in body

    if has_envelope_fields:
        if "payload" in body and isinstance(body["payload"], (dict, list)):
            payload = body["payload"]
        else:
            payload = {k: v for k, v in body.items() if k not in ("seq", "nonce", "timestamp", "signature")}

        rg.validate_message(
            agent_id=agent_id,
            seq=int(body["seq"]),
            nonce=str(body["nonce"]),
            timestamp=body["timestamp"],
            payload=payload,
            signature=str(body["signature"]),
            secret_key=secret_key,
            method=method,
            path=path,
        )
        return payload, True

    # Legacy request without envelope
    allow_legacy = os.getenv("RAM_ALLOW_LEGACY_API_KEY", os.getenv("AEGIS_ALLOW_LEGACY_API_KEY", "0")) == "1"
    if allow_legacy:
        logger.warning(
            "DEPRECATION: Agent '%s' sent request without replay protection envelope. "
            "Accepted via AEGIS_ALLOW_LEGACY_API_KEY=1. This fallback will be disabled in a future release.",
            agent_id,
        )
        return body, False

    raise ReplayProtectionError(
        "Replay protection envelope required (missing seq, nonce, timestamp, or signature). "
        "Set AEGIS_ALLOW_LEGACY_API_KEY=1 to allow legacy agents."
    )
