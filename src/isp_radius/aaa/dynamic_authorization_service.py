"""Tenant-scoped creation of audited CoA and Disconnect outbox requests."""
from __future__ import annotations

from uuid import uuid4

from isp_radius.aaa.dynamic_authorization import (
    DynamicAuthorizationRequest,
    DynamicAuthorizationType,
)
from isp_radius.adapters.radius_attributes import (
    BandwidthPolicy,
    RadiusProfile,
    get_radius_attribute_adapter,
)
from isp_radius.persistence.accounting_repository import Connection


def enqueue_disconnect(
    connection: Connection,
    *,
    tenant_id: str,
    nas_identifier: str,
    session_id: str,
    username: str,
    idempotency_key: str,
    requested_by: str,
) -> DynamicAuthorizationRequest:
    return _enqueue(
        connection,
        tenant_id=tenant_id,
        nas_identifier=nas_identifier,
        session_id=session_id,
        username=username,
        request_type=DynamicAuthorizationType.DISCONNECT,
        attributes={},
        idempotency_key=idempotency_key,
        requested_by=requested_by,
    )


def enqueue_bandwidth_coa(
    connection: Connection,
    *,
    tenant_id: str,
    nas_identifier: str,
    session_id: str,
    username: str,
    download_bps: int,
    upload_bps: int,
    idempotency_key: str,
    requested_by: str,
) -> DynamicAuthorizationRequest:
    if download_bps <= 0 or upload_bps <= 0:
        raise ValueError("bandwidth values must be positive")
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            SELECT radius_profile
              FROM nas_devices
             WHERE tenant_id = %s AND name = %s AND enabled = TRUE
            """,
            (tenant_id, nas_identifier),
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()
    if len(rows) != 1:
        raise ValueError("NAS is missing, disabled, or ambiguous")
    profile = RadiusProfile(str(rows[0][0]))
    if profile is not RadiusProfile.MIKROTIK:
        raise NotImplementedError(
            "Bandwidth CoA is not enabled for this NAS profile; capability must be verified"
        )
    adapter = get_radius_attribute_adapter(profile)
    attributes = adapter.access_accept_attributes(
        BandwidthPolicy(download_bps=download_bps, upload_bps=upload_bps)
    )
    return _enqueue(
        connection,
        tenant_id=tenant_id,
        nas_identifier=nas_identifier,
        session_id=session_id,
        username=username,
        request_type=DynamicAuthorizationType.COA,
        attributes=attributes,
        idempotency_key=idempotency_key,
        requested_by=requested_by,
    )


def _enqueue(
    connection: Connection,
    *,
    tenant_id: str,
    nas_identifier: str,
    session_id: str,
    username: str,
    request_type: DynamicAuthorizationType,
    attributes: dict[str, str],
    idempotency_key: str,
    requested_by: str,
) -> DynamicAuthorizationRequest:
    request = DynamicAuthorizationRequest(
        id=str(uuid4()),
        tenant_id=tenant_id,
        nas_identifier=nas_identifier,
        session_id=session_id,
        username=username,
        request_type=request_type,
        attributes=attributes,
        idempotency_key=idempotency_key,
        requested_by=requested_by,
    )
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO dynamic_authorization_requests (
                id, tenant_id, nas_identifier, session_id, username,
                request_type, attributes, idempotency_key, requested_by
            )
            SELECT %s, s.tenant_id, s.nas_identifier, s.session_id, s.username,
                   %s, %s::jsonb, %s, %s
              FROM subscriber_sessions AS s
              JOIN nas_devices AS n
                ON n.tenant_id = s.tenant_id
               AND n.name = s.nas_identifier
               AND n.enabled = TRUE
             WHERE s.tenant_id = %s
               AND s.nas_identifier = %s
               AND s.session_id = %s
               AND s.username = %s
               AND s.status = 'active'
            ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
            RETURNING id
            """,
            (
                request.id,
                request.request_type.value,
                request.attributes_json(),
                request.idempotency_key,
                request.requested_by,
                request.tenant_id,
                request.nas_identifier,
                request.session_id,
                request.username,
            ),
        )
        inserted = cursor.fetchone()
        if inserted is None:
            raise ValueError(
                "No active matching session/NAS, or idempotency key was already used"
            )
    finally:
        cursor.close()
    return request
