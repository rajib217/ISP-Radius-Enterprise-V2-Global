# Worker deployment

1. Apply migrations through 0011_dynamic_authorization_worker_leases.sql.
2. Create a non-login isp-radius OS account and install the package in /opt/isp-radius/venv.
3. Place the release at /opt/isp-radius/current.
4. Create /etc/isp-radius/worker.env from systemd/worker.env.example. Set owner root:isp-radius and mode 0640. Inject NAS secrets through the host secret manager.
5. Install systemd/isp-radius-command-worker.service in /etc/systemd/system/.
6. Run systemctl daemon-reload && systemctl enable --now isp-radius-command-worker.
7. Verify systemctl status and journalctl -u isp-radius-command-worker.

The service runs as an unprivileged account, restarts on failure, and sends logs to journald. Restrict database and UDP network access at the host firewall. Do not expose worker diagnostics publicly.
