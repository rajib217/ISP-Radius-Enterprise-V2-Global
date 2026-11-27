"""Tenant-scoped read-only subscriber session monitoring queries."""
from __future__ import annotations

from uuid import UUID

from isp_radius.persistence.accounting_repository import Connection

_DEFAULT_STALE_AFTER_SECONDS = 300
_MAX_PAGE_SIZE = 200
_MAX_OFFSET = 1_000_000
_VALID_STATES = {"online", "stale", "offline"}

_SESSION_SELECT = """
SELECT id, nas_identifier, session_id, username, status,
       started_at, last_event_at, stopped_at,
       input_octets, output_octets, session_seconds, terminate_cause,
       monitor_state, duration_seconds
  FROM (
      SELECT id, nas_identifier, session_id, username, status,
             started_at, last_event_at, stopped_at,
             input_octets, output_octets, session_seconds, terminate_cause,
             CASE
                 WHEN status = 'stopped' THEN 'offline'
                 WHEN last_event_at < now() - (%s * interval '1 second') THEN 'stale'
                 ELSE 'online'
             END AS monitor_state,
             GREATEST(
                 COALESCE(session_seconds, 0),
                 CASE WHEN started_at IS NOT NULL
                      THEN GREATEST(0, floor(extract(epoch FROM
                          (COALESCE(stopped_at, now()) - started_at)))::bigint)
                      ELSE 0 END
             ) AS duration_seconds
        FROM subscriber_sessions
       WHERE tenant_id = %s
  ) AS monitored
 WHERE (%s IS NULL OR monitor_state = %s)
   AND (%s IS NULL OR username ILIKE %s OR session_id ILIKE %s)
   AND (%s IS NULL OR nas_identifier = %s)
 ORDER BY CASE monitor_state WHEN 'online' THEN 0 WHEN 'stale' THEN 1 ELSE 2 END,
          last_event_at DESC, id
 LIMIT %s OFFSET %s
"""

_SESSION_SUMMARY = """
SELECT count(*) AS total_sessions,
       count(*) FILTER (WHERE status = 'active'
           AND last_event_at >= now() - (%s * interval '1 second')) AS online,
       count(*) FILTER (WHERE status = 'active'
           AND last_event_at < now() - (%s * interval '1 second')) AS stale,
       count(*) FILTER (WHERE status = 'stopped') AS offline,
       COALESCE(sum(input_octets), 0) AS input_octets,
       COALESCE(sum(output_octets), 0) AS output_octets
  FROM subscriber_sessions
 WHERE tenant_id = %s
"""


def _validate_tenant(tenant_id: str) -> str:
    try:
        return str(UUID(tenant_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("tenant_id must be a valid UUID") from exc


def _validate_stale_after(stale_after_seconds: int) -> int:
    if type(stale_after_seconds) is not int or not 30 <= stale_after_seconds <= 86400:
        raise ValueError("stale_after_seconds must be an integer between 30 and 86400")
    return stale_after_seconds


def list_subscriber_sessions(
    connection: Connection,
    *,
    tenant_id: str,
    state: str | None = None,
    search: str | None = None,
    nas_identifier: str | None = None,
    stale_after_seconds: int = _DEFAULT_STALE_AFTER_SECONDS,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, object]]:
    """Return a bounded, tenant-scoped session page with derived live state.

    'stale' means the last RADIUS accounting event is older than the configured
    threshold. It is not proof that the subscriber has disconnected.
    """
    normalized_tenant_id = _validate_tenant(tenant_id)
    stale_after_seconds = _validate_stale_after(stale_after_seconds)
    if state is not None and state not in _VALID_STATES:
        raise ValueError("state must be online, stale, offline, or None")
    if type(limit) is not int or not 1 <= limit <= _MAX_PAGE_SIZE:
        raise ValueError(f"limit must be an integer between 1 and {_MAX_PAGE_SIZE}")
    if type(offset) is not int or not 0 <= offset <= _MAX_OFFSET:
        raise ValueError(f"offset must be an integer between 0 and {_MAX_OFFSET}")
    if search is not None and (not isinstance(search, str) or len(search) > 128):
        raise ValueError("search must be a string of at most 128 characters")
    if nas_identifier is not None and (
        not isinstance(nas_identifier, str) or not nas_identifier.strip()
        or len(nas_identifier) > 253
    ):
        raise ValueError("nas_identifier must be a non-empty string of at most 253 characters")

    search_pattern = f"%{search.strip()}%" if search and search.strip() else None
    parameters = (
        stale_after_seconds, normalized_tenant_id, state, state,
        search_pattern, search_pattern, search_pattern,
        nas_identifier, nas_identifier, limit, offset,
    )
    cursor = connection.cursor()
    try:
        cursor.execute(_SESSION_SELECT, parameters)
        rows = cursor.fetchall()
        keys = (
            "id", "nas_identifier", "session_id", "username", "status",
            "started_at", "last_event_at", "stopped_at",
            "input_octets", "output_octets", "session_seconds", "terminate_cause",
            "state", "duration_seconds",
        )
        return [dict(zip(keys, row, strict=True)) for row in rows]
    finally:
        cursor.close()


def get_subscriber_session_summary(
    connection: Connection,
    *,
    tenant_id: str,
    stale_after_seconds: int = _DEFAULT_STALE_AFTER_SECONDS,
) -> dict[str, int]:
    """Return tenant-scoped online/stale/offline counts and cumulative counters."""
    normalized_tenant_id = _validate_tenant(tenant_id)
    stale_after_seconds = _validate_stale_after(stale_after_seconds)
    cursor = connection.cursor()
    try:
        cursor.execute(
            _SESSION_SUMMARY,
            (stale_after_seconds, stale_after_seconds, normalized_tenant_id),
        )
        row = cursor.fetchone()
        if row is None:
            return {
                "total_sessions": 0, "online": 0, "stale": 0, "offline": 0,
                "input_octets": 0, "output_octets": 0,
            }
        keys = (
            "total_sessions", "online", "stale", "offline",
            "input_octets", "output_octets",
        )
        return dict(zip(keys, row, strict=True))
    finally:
        cursor.close()
