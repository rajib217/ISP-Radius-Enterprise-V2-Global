"""Interactive, non-echoing subscriber password provisioning command."""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from uuid import UUID

import psycopg

from isp_radius.aaa.authentication import hash_subscriber_password


def _parse_uuid(value: str, field: str) -> str:
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise argparse.ArgumentTypeError(f"{field} must be a valid UUID") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="isp-radius-set-password",
        description="Set a subscriber's PPP password using an interactive hidden prompt.",
    )
    parser.add_argument("--tenant-id", required=True, type=lambda v: _parse_uuid(v, "tenant-id"))
    parser.add_argument(
        "--subscriber-id",
        required=True,
        type=lambda v: _parse_uuid(v, "subscriber-id"),
    )
    args = parser.parse_args(argv)

    if not sys.stdin.isatty() or not sys.stderr.isatty():
        print(
            "Run this command from an interactive terminal so password input stays hidden.",
            file=sys.stderr,
        )
        return 2

    password = getpass.getpass("New subscriber password (input hidden): ")
    confirmation = getpass.getpass("Confirm password (input hidden): ")
    if password != confirmation:
        print("Password confirmation does not match.", file=sys.stderr)
        return 2
    if len(password) < 8 or len(password) > 1024:
        print("Password must contain 8 to 1024 characters.", file=sys.stderr)
        return 2

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        print("DATABASE_URL is not configured.", file=sys.stderr)
        return 2

    password_hash = hash_subscriber_password(password)
    try:
        with (
            psycopg.connect(database_url, connect_timeout=5) as connection,
            connection.cursor() as cursor,
        ):
                cursor.execute(
                    """
                    SELECT 1
                      FROM subscribers
                     WHERE tenant_id = %s AND id = %s
                     FOR UPDATE
                    """,
                    (args.tenant_id, args.subscriber_id),
                )
                if cursor.fetchone() is None:
                    print("Subscriber was not found in the specified tenant.", file=sys.stderr)
                    return 1
                cursor.execute(
                    """
                    INSERT INTO subscriber_credentials (
                        tenant_id, subscriber_id, password_hash, password_changed_at
                    ) VALUES (%s, %s, %s, now())
                    ON CONFLICT (tenant_id, subscriber_id)
                    DO UPDATE SET
                        password_hash = EXCLUDED.password_hash,
                        password_changed_at = now()
                    """,
                    (args.tenant_id, args.subscriber_id, password_hash),
                )
    except psycopg.Error:
        print("Database operation failed; no password details were logged.", file=sys.stderr)
        return 1

    print("Subscriber password hash updated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
