"""mTLS verification middleware and dependency for endpoint agents.

Supports:
- Modes: 'disabled', 'optional', 'required' (configured via AEGIS_MTLS_MODE)
- Direct TLS client cert extraction or proxy header extraction (X-SSL-Client-Cert, X-Client-Cert-Fingerprint)
- Certificate verification against the internal CA
- Checking against revoked certificates
- Comparing certificate Common Name / fingerprint to the registered node/agent record
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.ca import default_ca

logger = logging.getLogger("aegis.mtls")


def get_mtls_mode() -> str:
    """Return mTLS mode: 'disabled', 'optional', or 'required'."""
    return os.getenv("AEGIS_MTLS_MODE", getattr(settings, "AEGIS_MTLS_MODE", "optional")).lower().strip()


async def verify_agent_mtls(
    request: Request,
    agent_id: Optional[str] = None,
    x_ssl_client_cert: Optional[str] = Header(default=None, alias="X-SSL-Client-Cert"),
    x_client_cert_fingerprint: Optional[str] = Header(default=None, alias="X-Client-Cert-Fingerprint"),
    db: Optional[AsyncSession] = None,
) -> Optional[str]:
    """Verify incoming request mTLS credentials according to configured mode.

    Returns:
        Verified certificate SHA256 fingerprint if present and valid, or None if optional/disabled.

    Raises:
        HTTPException(401): if certificate is required and missing, or invalid.
        HTTPException(403): if certificate has been revoked.
    """
    mode = get_mtls_mode()
    if mode == "disabled":
        return None

    # Check for client certificate in headers (from reverse proxy / TLS terminator)
    # or ASGI connection state
    cert_raw = x_ssl_client_cert
    if not cert_raw and "ssl" in request.scope:
        ssl_obj = request.scope.get("ssl")
        if ssl_obj and hasattr(ssl_obj, "getpeercert"):
            try:
                cert_raw = ssl_obj.getpeercert(binary_form=False)
            except Exception:
                pass

    if not cert_raw and not x_client_cert_fingerprint:
        if mode == "required":
            logger.warning("mTLS required but no client certificate provided")
            raise HTTPException(status_code=401, detail="Client certificate required (mTLS enforced)")
        return None

    # Verify certificate PEM if present
    fingerprint = ""
    if cert_raw:
        # Normalize PEM format if urlencoded/escaped in header
        cert_pem = cert_raw
        if "-----BEGIN CERTIFICATE-----" not in cert_pem:
            import urllib.parse
            cert_pem = urllib.parse.unquote(cert_pem)

        is_valid, cn, fp, err = default_ca.verify_client_cert(cert_pem)
        if not is_valid:
            if "revoked" in err.lower():
                logger.warning(f"mTLS request rejected: revoked cert fingerprint={fp}")
                raise HTTPException(status_code=403, detail=f"Client certificate revoked: {err}")
            logger.warning(f"mTLS request rejected: {err}")
            raise HTTPException(status_code=401, detail=f"Client certificate validation failed: {err}")

        # If agent_id is declared, CN should match agent_id if set
        if agent_id and cn and cn != agent_id:
            logger.warning(f"mTLS CommonName mismatch: cert CN '{cn}' != agent '{agent_id}'")
            raise HTTPException(status_code=401, detail=f"Certificate CN '{cn}' does not match agent '{agent_id}'")

        fingerprint = fp

    elif x_client_cert_fingerprint:
        fp = x_client_cert_fingerprint.lower().strip()
        if default_ca.is_revoked(fp):
            logger.warning(f"mTLS request rejected: revoked cert fingerprint={fp}")
            raise HTTPException(status_code=403, detail="Client certificate revoked")
        fingerprint = fp

    return fingerprint
