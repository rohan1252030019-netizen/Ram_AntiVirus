import asyncio
import json
import logging
import secrets
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.events import event_bus
from app.models.client import Client
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability
from app.models.scan import Scan

logger = logging.getLogger("aegis.scanner")


def _parse_iso(value) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _scan_row_to_dict(row: Scan) -> dict:
    """Serialize a persisted Scan row into the dict shape the API expects."""
    return {
        "id": row.id,
        "target": row.target,
        "type": row.scan_type,
        "status": row.status,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "client_id": row.client_id,
        "results": row.results or {},
        "assets_found": row.assets_found or 0,
        "error": row.error,
    }


class ScanOrchestrator:
    """Orchestrates discovery and vulnerability scans.

    Scan state is persisted to the ``scans`` table (see app.models.scan.Scan)
    so history survives ``cayde6-api`` restarts. The in-memory ``_active_scans``
    dict is retained as a hot cache for the currently-running scan; reads
    (get_scan / list_scans) query PostgreSQL as the source of truth.
    """

    def __init__(self):
        self._active_scans: dict[str, dict] = {}

    async def persist_scan(self, db: AsyncSession, state: dict) -> None:
        """Upsert the in-memory scan state into the scans table (best-effort)."""
        try:
            row = await db.get(Scan, state["id"])
            if row is None:
                row = Scan(id=state["id"])
                db.add(row)
            row.client_id = state.get("client_id")
            row.target = state.get("target", "")
            row.scan_type = state.get("type", "full")
            row.status = state.get("status", "running")
            row.error = state.get("error")
            row.started_at = _parse_iso(state.get("started_at"))
            row.completed_at = _parse_iso(state.get("completed_at"))
            row.results = state.get("results", {})
            row.assets_found = int(state.get("assets_found", 0) or 0)
            await db.commit()
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to persist scan %s: %s", state.get("id"), exc, exc_info=True)
            try:
                await db.rollback()
            except Exception:  # noqa: BLE001
                pass

    async def _simulate_demo_scan(
        self,
        target: str,
        scan_type: str,
        client: Client,
        db: AsyncSession,
    ) -> dict:
        """Return a fabricated, already-complete scan for the public demo tenant.

        The public demo publishes its admin password, so a real scan would let
        any anonymous visitor run ``nmap -sT`` from this host's IP address and
        consume its CPU. Nothing here spawns a subprocess or opens a socket: the
        discovery payload is derived from the tenant's own seeded inventory, so
        the Surface page keeps demonstrating the workflow without touching the
        host or the network.
        """
        now = datetime.utcnow()
        # Second-precision ids collide if a demo visitor double-clicks; the
        # random suffix keeps every simulated scan a distinct PK row.
        scan_id = f"scan_demo_{now.strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(3)}"

        rows = (
            await db.execute(
                select(Asset).where(Asset.client_id == client.id).limit(25)
            )
        ).scalars().all()

        hosts = [
            {
                "hostname": asset.hostname,
                "ip": asset.ip_address or "",
                "type": asset.asset_type or "web",
                "ports": asset.ports or [],
                "technologies": asset.technologies or [],
            }
            for asset in rows
        ]
        if not hosts:
            hosts = [
                {
                    "hostname": target,
                    "ip": "",
                    "type": "web",
                    "ports": [80, 443],
                    "technologies": [],
                }
            ]

        results: dict = {
            "simulated": True,
            "discovery": {
                "source": "demo-simulation",
                "hosts": hosts,
            },
        }
        if scan_type in ("full", "vuln"):
            results["vulnerabilities"] = {
                "source": "demo-simulation",
                "vulnerabilities": [],
            }

        state = {
            "id": scan_id,
            "target": target,
            "type": scan_type,
            "status": "completed",
            "started_at": now.isoformat(),
            "completed_at": now.isoformat(),
            "client_id": client.id,
            "results": results,
            "assets_found": len(hosts),
        }
        await self.persist_scan(db, state)
        logger.info(
            "Demo tenant scan simulated for %s (%s, %d assets, no subprocess)",
            target,
            scan_type,
            len(hosts),
        )
        return state

    async def launch_scan(
        self,
        target: str,
        scan_type: str,
        client: Client,
        db: AsyncSession,
    ) -> dict:
        """Launch a scan against a target.

        The public demo tenant never reaches a real scan. See
        :meth:`_simulate_demo_scan`.
        """
        from app.core.demo import is_demo_tenant

        if is_demo_tenant(client.id):
            return await self._simulate_demo_scan(target, scan_type, client, db)

        from app.modules.surface.discovery import discovery_engine
        from app.modules.surface.nuclei import nuclei_scanner

        scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{target.replace('.', '_')}"
        self._active_scans[scan_id] = {
            "id": scan_id,
            "target": target,
            "type": scan_type,
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
            "client_id": client.id,
            "results": {},
        }
        # Persist the running record immediately so it survives a restart mid-scan.
        await self.persist_scan(db, self._active_scans[scan_id])

        try:
            # Stage 1: Discovery
            logger.info(f"Starting discovery for {target}")
            discovery_results = await discovery_engine.discover(target)
            self._active_scans[scan_id]["results"]["discovery"] = discovery_results

            # Create assets from discovery
            assets_created = []
            for found in discovery_results.get("hosts", []):
                asset = Asset(
                    client_id=client.id,
                    hostname=found.get("hostname", target),
                    ip_address=found.get("ip", ""),
                    asset_type=found.get("type", "web"),
                    ports=found.get("ports", []),
                    technologies=found.get("technologies", []),
                    status="active",
                    risk_score=0.0,
                    last_scan_at=datetime.utcnow(),
                )
                db.add(asset)
                await db.flush()
                assets_created.append(asset)

            # If no hosts discovered, create one for the target itself
            if not assets_created:
                asset = Asset(
                    client_id=client.id,
                    hostname=target,
                    ip_address="",
                    asset_type="web",
                    ports=[],
                    technologies=[],
                    status="active",
                    risk_score=0.0,
                    last_scan_at=datetime.utcnow(),
                )
                db.add(asset)
                await db.flush()
                assets_created.append(asset)

            # Stage 2: Vulnerability scan
            if scan_type in ("full", "vuln"):
                logger.info(f"Starting vulnerability scan for {target}")
                vuln_results = await nuclei_scanner.scan(target)
                self._active_scans[scan_id]["results"]["vulnerabilities"] = vuln_results

                for vuln_data in vuln_results.get("vulnerabilities", []):
                    vuln = Vulnerability(
                        client_id=client.id,
                        asset_id=assets_created[0].id,
                        title=vuln_data.get("title", "Unknown Vulnerability"),
                        description=vuln_data.get("description", ""),
                        severity=vuln_data.get("severity", "info"),
                        cvss_score=vuln_data.get("cvss_score"),
                        cve_id=vuln_data.get("cve_id"),
                        template_id=vuln_data.get("template_id"),
                        evidence=vuln_data.get("evidence", ""),
                        status="open",
                    )
                    db.add(vuln)

            await db.commit()

            state = self._active_scans[scan_id]
            state["status"] = "completed"
            state["completed_at"] = datetime.utcnow().isoformat()
            state["assets_found"] = len(assets_created)

            # Persist the completed scan (assets already committed above).
            await self.persist_scan(db, state)

            await event_bus.publish("scan_completed", {
                "scan_id": scan_id,
                "target": target,
                "assets_found": len(assets_created),
            })

            # Scan is durably in the `scans` table now (source of truth); drop it
            # from the hot cache so completed scans — each carrying full
            # discovery + nuclei result payloads — don't accumulate in RSS for
            # the life of the process. Reads fall back to the DB.
            return self._active_scans.pop(scan_id, state)

        except Exception as e:
            logger.error(f"Scan failed for {target}: {e}")
            state = self._active_scans[scan_id]
            state["status"] = "failed"
            state["error"] = str(e)
            state["completed_at"] = datetime.utcnow().isoformat()
            # Roll back any partial asset/vuln work, then persist the failure.
            try:
                await db.rollback()
            except Exception:  # noqa: BLE001
                pass
            await self.persist_scan(db, state)
            # Terminal state persisted — evict from the hot cache (see above).
            return self._active_scans.pop(scan_id, state)

    async def get_scan(
        self,
        scan_id: str,
        client_id: Optional[str] = None,
        db: Optional[AsyncSession] = None,
    ) -> Optional[dict]:
        """Fetch a scan by id from the DB (source of truth), falling back to
        the in-memory hot cache when no session is provided."""
        if db is not None:
            row = await db.get(Scan, scan_id)
            if row is None:
                # Fall back to hot cache in case the row hasn't flushed yet.
                cached = self._active_scans.get(scan_id)
                if cached and (not client_id or cached.get("client_id") == client_id):
                    return cached
                return None
            if client_id and row.client_id != client_id:
                return None
            return _scan_row_to_dict(row)

        scan = self._active_scans.get(scan_id)
        if scan and client_id and scan.get("client_id") != client_id:
            return None
        return scan

    async def list_scans(
        self,
        client_id: Optional[str] = None,
        db: Optional[AsyncSession] = None,
        limit: int = 100,
    ) -> list[dict]:
        """List scans from the DB (source of truth), newest first. Falls back
        to the in-memory cache when no session is provided."""
        if db is not None:
            q = select(Scan)
            if client_id:
                q = q.where(Scan.client_id == client_id)
            q = q.order_by(Scan.created_at.desc()).limit(max(1, min(limit, 500)))
            rows = (await db.execute(q)).scalars().all()
            persisted = [_scan_row_to_dict(r) for r in rows]
            persisted_ids = {p["id"] for p in persisted}
            # Merge any in-flight scans not yet flushed to the DB.
            for state in self._active_scans.values():
                if state.get("id") in persisted_ids:
                    continue
                if client_id and state.get("client_id") != client_id:
                    continue
                persisted.append(state)
            return persisted

        if client_id:
            return [s for s in self._active_scans.values() if s.get("client_id") == client_id]
        return list(self._active_scans.values())


scan_orchestrator = ScanOrchestrator()
