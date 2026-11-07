"""
Boot-time guard against booting Ram Antivirus in non-development environments with default secrets.
"""

from __future__ import annotations

import urllib.parse

# Must match app.config.Settings.AEGIS_SECRET_KEY default exactly.
DEFAULT_SECRET = "aegis-dev-secret-key-change-in-production"

# Must match the default used in app.config.Settings.AEGIS_ADMIN_PASSWORD.
DEFAULT_ADMIN_PASSWORD = "changeme-on-first-login"

# Passwords that are published in documentation/the public demo. They are only
# tolerated when AEGIS_DEMO_MODE is explicitly enabled.
DEMO_ADMIN_PASSWORDS = frozenset({DEFAULT_ADMIN_PASSWORD, "admin123456"})

DEFAULT_DB_PASSWORDS = frozenset({"aegis_secret", "change-me-to-random-string", "password", "postgres", ""})


def assert_production_secrets(
    env: str,
    secret_key: str,
    admin_password: str,
    default_admin_password: str = DEFAULT_ADMIN_PASSWORD,
    demo_mode: bool = False,
    database_url: str = "",
) -> None:
    """
    Raise RuntimeError if running in non-development with default/weak secrets.

    Args:
        env: current AEGIS_ENV value.
        secret_key: current AEGIS_SECRET_KEY value.
        admin_password: the admin password that would be seeded.
        default_admin_password: the known default admin password to compare against.
        demo_mode: when true, the demo admin password is allowed.
        database_url: the database connection string.

    Raises:
        RuntimeError: listing the offending settings.
    """
    if env == "development":
        return

    bad = []
    if not secret_key or secret_key == DEFAULT_SECRET:
        raise RuntimeError(
            f"Refusing to start in {env} mode with default/missing AEGIS_SECRET_KEY. "
            "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
        )

    if database_url:
        try:
            parsed = urllib.parse.urlsplit(database_url)
            if parsed.password and parsed.password in DEFAULT_DB_PASSWORDS:
                bad.append(
                    f"Refusing to start in {env} mode with default/insecure database password in DATABASE_URL. "
                    "Configure a strong password."
                )
        except Exception as e:
            if isinstance(e, RuntimeError):
                raise

    weak_admin = (
        admin_password == default_admin_password
        or admin_password in DEMO_ADMIN_PASSWORDS
    )
    if weak_admin and not demo_mode:
        bad.append(
            f"Refusing to start in {env} mode with insecure admin password. "
            "Set a strong AEGIS_ADMIN_PASSWORD or enable AEGIS_DEMO_MODE=true."
        )

    if bad:
        raise RuntimeError("; ".join(bad))
