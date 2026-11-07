import pytest

from app.core.boot_guard import assert_production_secrets
from app.config import Settings


def test_production_rejects_default_secret():
    with pytest.raises(RuntimeError) as exc_info:
        assert_production_secrets(
            env="production",
            secret_key="aegis-dev-secret-key-change-in-production",
            admin_password="whatever",
        )
    assert "Refusing to start in production mode with default/missing AEGIS_SECRET_KEY" in str(exc_info.value)


def test_production_rejects_default_admin_password():
    with pytest.raises(RuntimeError) as exc_info:
        assert_production_secrets(
            env="production",
            secret_key="a-strong-random-secret",
            admin_password="changeme-on-first-login",
        )
    assert "insecure admin password" in str(exc_info.value)


def test_production_rejects_default_db_password():
    with pytest.raises(RuntimeError) as exc_info:
        assert_production_secrets(
            env="production",
            secret_key="a-strong-random-secret",
            admin_password="a-strong-random-password",
            database_url="postgresql+asyncpg://aegis:aegis_secret@localhost:5432/aegis",
        )
    assert "default/insecure database password in DATABASE_URL" in str(exc_info.value)


def test_staging_rejects_default_secret():
    with pytest.raises(RuntimeError) as exc_info:
        assert_production_secrets(
            env="staging",
            secret_key="aegis-dev-secret-key-change-in-production",
            admin_password="a-strong-random-password",
        )
    assert "Refusing to start in staging mode with default/missing AEGIS_SECRET_KEY" in str(exc_info.value)


def test_production_allows_strong_secrets():
    assert (
        assert_production_secrets(
            env="production",
            secret_key="a-strong-random-secret-at-least-32-bytes-long",
            admin_password="a-strong-random-password",
            database_url="postgresql+asyncpg://aegis:my_super_strong_pass_1234@localhost:5432/aegis",
        )
        is None
    )


def test_dev_allows_default_secret():
    assert (
        assert_production_secrets(
            env="development",
            secret_key="aegis-dev-secret-key-change-in-production",
            admin_password="changeme-on-first-login",
            database_url="postgresql+asyncpg://aegis:aegis_secret@localhost:5432/aegis",
        )
        is None
    )


def test_settings_fails_in_production_with_defaults(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.delenv("AEGIS_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError) as exc_info:
        Settings()
    assert "Refusing to start in production mode" in str(exc_info.value)


def test_settings_succeeds_in_production_with_strong_secrets(monkeypatch):
    monkeypatch.setenv("AEGIS_ENV", "production")
    monkeypatch.setenv("AEGIS_SECRET_KEY", "strong-secret-key-32-chars-long-12345")
    monkeypatch.setenv("AEGIS_ADMIN_PASSWORD", "strong-admin-pass-xyz-1234")
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://aegis:strong_pass_db@localhost:5432/aegis")
    s = Settings()
    assert s.AEGIS_ENV == "production"
