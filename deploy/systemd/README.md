# Linux systemd deployment

This is the baseline deployment for the RADIUS dynamic-authorization worker.
Apply PostgreSQL migrations through `0011_dynamic_authorization_worker_leases.sql`
before starting the service.

## Install

The checked-in service unit expects the release at
`/opt/isp-radius/current` and its virtual environment at
`/opt/isp-radius/venv`. Adjust the unit if your release layout differs.

```sh
sudo useradd --system --home /opt/isp-radius --shell /usr/sbin/nologin isp-radius
sudo install -d -o root -g isp-radius -m 0750 /etc/isp-radius
sudo install -o root -g isp-radius -m 0640 deploy/systemd/worker.env.example /etc/isp-radius/worker.env
sudoedit /etc/isp-radius/worker.env
sudo chmod 0640 /etc/isp-radius/worker.env
sudo install -m 0644 deploy/systemd/isp-radius-command-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now isp-radius-command-worker
```

Keep the environment file readable only by root and the service group. Replace
all example credentials. Prefer a secrets manager for DATABASE_URL and NAS
shared secrets. The worker supports secret references such as
`env:RADIUS_NAS_EDGE_01`; the actual secret must be injected at runtime and
must never be committed.

## Verify and operate

```sh
sudo systemctl status isp-radius-command-worker
sudo journalctl -u isp-radius-command-worker -f
curl --fail http://127.0.0.1:9811/health/live
curl --fail http://127.0.0.1:9811/health/ready
curl --fail http://127.0.0.1:9811/metrics
```

Readiness becomes healthy after the first successful worker cycle. Liveness
only confirms the HTTP listener responds. It does not prove that a NAS is
reachable. systemd restarts unexpected process exits. On SIGTERM, the worker
stops between dispatch cycles; an interrupted in-flight lease is recovered
after expiry.

## Prometheus monitoring

Merge `deploy/monitoring/prometheus-worker.yml` into a local Prometheus agent
configuration and load `deploy/monitoring/worker-alerts.yml` as rule files.
The metrics listener binds to `127.0.0.1:9811` without authentication. Never
expose it directly to the public internet. The metrics endpoint reads queue
depth, oldest pending age, in-flight leases, and terminal failures/rejections
from PostgreSQL. Alert thresholds are starter values and must be tuned to
traffic and operational SLOs.

## Production logs

The worker emits structured JSON to stdout/stderr. systemd stores these records
in journald:

```sh
journalctl -u isp-radius-command-worker --since "1 hour ago"
journalctl -u isp-radius-command-worker -p warning
```

Configure persistent journald storage and retention to suit disk capacity and
audit policy. Keep `LOG_LEVEL=INFO` in production. Never log subscriber
passwords, RADIUS shared secrets, database credentials, or full packet payloads.

## Production controls

Use a dedicated least-privilege PostgreSQL role and TLS for remote database
connections. Restrict outbound UDP to approved NAS CoA/Disconnect endpoints
and restrict inbound health access to localhost. Back up PostgreSQL and test
restores. The worker is at-least-once: if a NAS processes a packet but the
worker crashes before recording its ACK, a retry may send a duplicate. Validate
each NAS model and firmware in a lab before production rollout.
