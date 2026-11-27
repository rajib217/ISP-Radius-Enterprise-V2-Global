"""Private REST endpoint consumed by FreeRADIUS rlm_rest."""
from __future__ import annotations

import os
from collections.abc import Generator

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, Response, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from isp_radius.aaa.authentication import authenticate_subscriber

app = FastAPI(
    title="ISP RADIUS Authentication API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
_basic = HTTPBasic(auto_error=False, realm="ISP-RADIUS")


def _database_connection() -> Generator[psycopg.Connection, None, None]:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise HTTPException(status_code=503, detail="Authentication backend unavailable")
    try:
        with psycopg.connect(database_url, connect_timeout=2) as connection:
            yield connection
    except psycopg.Error as exc:
        raise HTTPException(
            status_code=503, detail="Authentication backend unavailable"
        ) from exc


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def ready(connection: psycopg.Connection = Depends(_database_connection)) -> dict[str, str]:
    connection.execute("SELECT 1")
    return {"status": "ready"}


@app.get("/radius/authenticate", status_code=status.HTTP_204_NO_CONTENT)
def radius_authenticate(
    nas_ip: str = Query(min_length=1, max_length=253),
    credentials: HTTPBasicCredentials | None = Depends(_basic),
    connection: psycopg.Connection = Depends(_database_connection),
) -> Response:
    if credentials is None or not credentials.username or not credentials.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid subscriber credentials",
            headers={"WWW-Authenticate": 'Basic realm="ISP-RADIUS"'},
        )

    subscriber = authenticate_subscriber(
        connection,
        nas_ip=nas_ip,
        username=credentials.username,
        password=credentials.password,
    )
    if subscriber is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid subscriber credentials",
            headers={"WWW-Authenticate": 'Basic realm="ISP-RADIUS"'},
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
