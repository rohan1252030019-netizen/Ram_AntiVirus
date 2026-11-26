"""Unit tests for the public-demo identity + read-only sandbox."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from app.config import settings
from app.core import demo
from app.core.demo_sandbox import DemoSandboxMiddleware


PUBLISHED = "test-demo-key-for-unit-tests-only"


@pytest.fixture(autouse=True)
def reset_demo_state():
    """Keep the process-global demo identity isolated per test."""
    demo.configure_demo_identity(None, None, published_key=False)
    yield
    demo.configure_demo_identity(None, None, published_key=False)


def test_read_only_methods_always_allowed():
    assert demo.is_write_allowed_for_demo("/api/v1/response/incidents", "GET")
    assert demo.is_write_allowed_for_demo("/api/v1/settings", "HEAD")
    assert demo.is_write_allowed_for_demo("/api/v1/anything", "OPTIONS")


def test_write_allowlist_is_login_ask_and_simulated_scan():
    assert demo.is_write_allowed_for_demo("/api/v1/auth/login", "POST")
    assert demo.is_write_allowed_for_demo("/api/v1/auth/user/login", "POST")
    assert demo.is_write_allowed_for_demo("/api/v1/ask", "POST")
    assert demo.is_write_allowed_for_demo("/ask", "POST")
    # Allowed only because ScanOrchestrator fabricates the result for the demo
    # tenant before importing nmap/httpx (see test_demo_scan_is_never_executed).
    assert demo.is_write_allowed_for_demo("/api/v1/surface/scan", "POST")
    # A path that merely shares the allowlisted prefix is not allowlisted.
    assert not demo.is_write_allowed_for_demo("/api/v1/ask/../response/incidents", "POST")
    assert not demo.is_write_allowed_for_demo("/api/v1/surface/scan/../harden", "POST")
    assert not demo.is_write_allowed_for_demo("/api/v1/auth/change-password", "POST")


def test_destructive_writes_blocked():
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert not demo.is_write_allowed_for_demo(
            "/api/v1/response/incidents/abc/approve", method
        )
        assert not demo.is_write_allowed_for_demo("/api/v1/edr/kill-process", method)
        assert not demo.is_write_allowed_for_demo("/api/v1/setup/discover", method)


def test_published_key_is_recognised_without_demo_mode(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", False)
    monkeypatch.setattr(settings, "AEGIS_PUBLIC_DEMO_API_KEY", PUBLISHED)
    assert demo.is_public_demo_key(PUBLISHED) is True
    assert demo.is_public_demo_key("not-the-demo-key") is False
    assert demo.is_public_demo_key(None) is False


def test_demo_tenant_requires_an_active_demo_identity(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", False)
    demo.configure_demo_identity("tenant-1", published_key=False)
    # A plain self-host seeds a demo tenant with a random key: no sandbox.
    assert demo.demo_identity_active() is False
    assert demo.is_demo_tenant("tenant-1") is False
    assert demo.is_demo_client("tenant-1") is False

    # The published key (or explicit demo mode) activates the sandbox.
    demo.configure_demo_identity("tenant-1", published_key=True)
    assert demo.demo_identity_active() is True
    assert demo.is_demo_tenant("tenant-1") is True
    assert demo.is_demo_client("tenant-1") is True
    assert demo.is_demo_tenant("tenant-2") is False


def test_responder_guard_ignores_the_http_sandbox_switch(monkeypatch):
    """Even with Ram Antivirus_DEMO_SANDBOX=false, the responder must not act."""
    monkeypatch.setattr(settings, "AEGIS_DEMO_SANDBOX", False)
    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", True)
    demo.configure_demo_identity("tenant-1")

    assert demo.is_demo_client("tenant-1") is False  # HTTP sandbox opted out
    assert demo.is_demo_tenant("tenant-1") is True  # execution still simulated


def test_demo_token_identification(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", True)
    demo.configure_demo_identity("tenant-1", admin_user_id="admin-1")

    assert demo.token_belongs_to_demo({"sub": "admin-1"})
    assert demo.token_belongs_to_demo({"sub": "someone", "type": "user", "client_id": "tenant-1"})
    assert not demo.token_belongs_to_demo({"sub": "someone", "type": "user", "client_id": "tenant-2"})


def _sandboxed_app() -> Starlette:
    async def ok(request):
        return JSONResponse({"ok": True})

    app = Starlette(
        routes=[
            Route("/read", ok, methods=["GET"]),
            Route("/write", ok, methods=["POST"]),
            Route("/api/v1/auth/login", ok, methods=["POST"]),
            Route("/api/v1/ask", ok, methods=["POST"]),
        ]
    )
    app.add_middleware(DemoSandboxMiddleware)
    return app


@pytest.mark.asyncio
async def test_middleware_blocks_demo_writes_but_allows_reads_and_login(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", True)
    monkeypatch.setattr(settings, "AEGIS_DEMO_SANDBOX", True)
    monkeypatch.setattr(settings, "AEGIS_PUBLIC_DEMO_API_KEY", PUBLISHED)
    demo.configure_demo_identity("tenant-1")

    transport = ASGITransport(app=_sandboxed_app())
    headers = {"X-API-Key": PUBLISHED}
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        assert (await http.get("/read", headers=headers)).status_code == 200
        assert (await http.post("/api/v1/auth/login", headers=headers)).status_code == 200
        assert (await http.post("/api/v1/ask", headers=headers)).status_code == 200

        blocked = await http.post("/write", headers=headers)
        assert blocked.status_code == 403
        assert blocked.json()["demo_mode"] is True

        # An unrelated key is not treated as the demo.
        assert (await http.post("/write", headers={"X-API-Key": "other"})).status_code == 200


@pytest.mark.asyncio
async def test_demo_scan_is_never_executed(monkeypatch):
    """A demo scan must be fabricated, never run through nmap/httpx."""
    from types import SimpleNamespace

    from app.services import scanner as scanner_module

    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", True)
    demo.configure_demo_identity("tenant-1", published_key=True)

    simulated: list[tuple] = []

    async def fake_simulate(target, scan_type, client, db):
        simulated.append((target, scan_type, client.id))
        return {
            "id": "scan_demo_test",
            "target": target,
            "type": scan_type,
            "status": "completed",
            "results": {"simulated": True},
            "assets_found": 1,
        }

    # If the real path is taken, discovery would be imported and run. Fail loudly.
    def explode(*_args, **_kwargs):
        raise AssertionError("real discovery ran for the demo tenant")

    monkeypatch.setattr(scanner_module.scan_orchestrator, "_simulate_demo_scan", fake_simulate)
    monkeypatch.setattr(
        scanner_module.ScanOrchestrator, "persist_scan", explode, raising=False
    )

    result = await scanner_module.scan_orchestrator.launch_scan(
        "example.com", "full", SimpleNamespace(id="tenant-1"), None
    )

    assert result["status"] == "completed"
    assert result["results"]["simulated"] is True
    assert simulated == [("example.com", "full", "tenant-1")]


@pytest.mark.asyncio
async def test_non_demo_scan_still_runs_for_a_self_host(monkeypatch):
    """The interception is scoped to the demo tenant, not every scan."""
    from types import SimpleNamespace

    from app.services import scanner as scanner_module

    monkeypatch.setattr(settings, "AEGIS_DEMO_MODE", True)
    demo.configure_demo_identity("tenant-1", published_key=True)

    async def fail_simulate(*_args, **_kwargs):
        raise AssertionError("self-host tenant must not be simulated")

    monkeypatch.setattr(scanner_module.scan_orchestrator, "_simulate_demo_scan", fail_simulate)

    async def fail_discovery(_target):
        raise RuntimeError("stubbed discovery")

    from app.modules.surface import discovery as discovery_module

    monkeypatch.setattr(discovery_module.discovery_engine, "discover", fail_discovery)

    # A non-demo tenant reaches the real path (stubbed here so no network), and
    # the orchestrator records the failure instead of simulating success.
    result = await scanner_module.scan_orchestrator.launch_scan(
        "example.com", "full", SimpleNamespace(id="self-host"), None
    )
    assert result["status"] == "failed"
    assert "stubbed discovery" in (result.get("error") or "")
