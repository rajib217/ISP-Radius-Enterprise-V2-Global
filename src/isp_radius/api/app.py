"""Private REST endpoint consumed by FreeRADIUS rlm_rest."""
from __future__ import annotations

import os
from collections.abc import AsyncIterator, Generator
from contextlib import asynccontextmanager
from urllib.parse import parse_qs

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from psycopg_pool import ConnectionPool, PoolTimeout
from starlette.concurrency import run_in_threadpool

from isp_radius.aaa.authentication import authenticate_subscriber
from isp_radius.aaa.authorization import authorize_subscriber


def _pool_sizes() -> tuple[int, int]:
    """Read bounded pool sizes so environment mistakes cannot exhaust PostgreSQL."""
    try:
        minimum = int(os.environ.get("DB_POOL_MIN_SIZE", "1"))
        maximum = int(os.environ.get("DB_POOL_MAX_SIZE", "10"))
    except ValueError as exc:
        raise RuntimeError("DB_POOL_MIN_SIZE and DB_POOL_MAX_SIZE must be integers") from exc
    if not 1 <= minimum <= maximum <= 100:
        raise RuntimeError("database pool sizes must satisfy 1 <= min <= max <= 100")
    return minimum, maximum


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    database_url = os.environ.get("DATABASE_URL")
    application.state.db_pool = None
    if database_url:
        minimum, maximum = _pool_sizes()
        pool = ConnectionPool(
            conninfo=database_url,
            min_size=minimum,
            max_size=maximum,
            timeout=2,
            open=False,
            name="isp-radius-api",
        )
        pool.open(wait=True, timeout=5)
        application.state.db_pool = pool
    try:
        yield
    finally:
        if application.state.db_pool is not None:
            application.state.db_pool.close()
            application.state.db_pool = None


app = FastAPI(
    title="ISP RADIUS Authentication API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


def _database_connection(request: Request) -> Generator[psycopg.Connection, None, None]:
    pool: ConnectionPool | None = getattr(request.app.state, "db_pool", None)
    if pool is None:
        raise HTTPException(status_code=503, detail="Authentication backend unavailable")
    try:
        with pool.connection(timeout=2) as connection:
            yield connection
    except (psycopg.Error, PoolTimeout) as exc:
        raise HTTPException(
            status_code=503, detail="Authentication backend unavailable"
        ) from exc


_database_dependency = Depends(_database_connection)


@app.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready")
def ready(connection: psycopg.Connection = _database_dependency) -> dict[str, str]:
    connection.execute("SELECT 1")
    return {"status": "ready"}


@app.post("/radius/authenticate", status_code=status.HTTP_204_NO_CONTENT)
async def radius_authenticate(
    request: Request,
    connection: psycopg.Connection = _database_dependency,
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


@app.post("/radius/authorize")
async def radius_authorize(
    request: Request,
    connection: psycopg.Connection = _database_dependency,
) -> dict[str, dict[str, str]]:
    """Return validated Access-Accept reply attributes for an active subscriber."""
    raw_body = await request.body()
    if len(raw_body) > 4096:
        raise HTTPException(status_code=413, detail="Request too large")
    try:
        form = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True, strict_parsing=True)
        username = form["username"][0]
        nas_ip = form["nas_ip"][0]
        if any(len(form[key]) != 1 for key in ("username", "nas_ip")):
            raise ValueError("duplicate form field")
    except (UnicodeDecodeError, KeyError, IndexError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid authorization request") from None

    try:
        authorization = await run_in_threadpool(
            authorize_subscriber,
            connection,
            nas_ip=nas_ip,
            username=username,
        )
    except NotImplementedError as exc:
        raise HTTPException(status_code=503, detail="NAS RADIUS profile is unsupported") from exc
    if authorization is None:
        raise HTTPException(status_code=401, detail="Subscriber authorization rejected")

    return {
        attribute: {"op": ":=", "value": value}
        for attribute, value in authorization.attributes.items()
    }
