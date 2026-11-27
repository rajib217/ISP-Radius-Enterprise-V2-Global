"""Private REST endpoint consumed by FreeRADIUS rlm_rest."""
from __future__ import annotations

import os
from collections.abc import Generator
from urllib.parse import parse_qs

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status

from isp_radius.aaa.authentication import authenticate_subscriber

app = FastAPI(
    title="ISP RADIUS Authentication API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


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


@app.post("/radius/authenticate", status_code=status.HTTP_204_NO_CONTENT)
async def radius_authenticate(
    request: Request,
    connection: psycopg.Connection = Depends(_database_connection),
) -> Response:
    """Validate one PAP credential request sent over the protected REST channel."""
    raw_body = await request.body()
    if len(raw_body) > 8192:
        raise HTTPException(status_code=413, detail="Request too large")
    try:
        form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
        username = form["username"][0]
        password = form["password"][0]
        nas_ip = form["nas_ip"][0]
        if any(len(form[key]) != 1 for key in ("username", "password", "nas_ip")):
            raise ValueError("duplicate form field")
    except (UnicodeDecodeError, KeyError, IndexError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid authentication request") from None

    subscriber = await run_in_threadpool(
        authenticate_subscriber,
        connection,
        nas_ip=nas_ip,
        username=username,
        password=password,
    )
    if subscriber is None:
        raise HTTPException(status_code=401, detail="Invalid subscriber credentials")

    return Response(status_code=status.HTTP_204_NO_CONTENT)
