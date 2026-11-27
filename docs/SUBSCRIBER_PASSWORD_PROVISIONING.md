# Subscriber password provisioning

Use the interactive CLI to create or rotate a subscriber's PPP password. The password is read twice with terminal echo disabled, hashed with Argon2id, and written to `subscriber_credentials`. It is never accepted as a command-line argument or written to application logs.

## Usage

Install the project in its virtual environment:

```bash
pip install -e .
export DATABASE_URL='postgresql://...'
isp-radius-set-password \
  --tenant-id 'TENANT-UUID' \
  --subscriber-id 'SUBSCRIBER-UUID'
```

Use a dedicated administrative PostgreSQL role with only the permissions required to lock/read the subscriber row and insert/update that subscriber's credential. Restrict who can run the command and protect the environment containing DATABASE_URL. Prefer a local Unix socket or TLS database connection. Do not put the database URL in shell history.

The command verifies the subscriber belongs to the supplied tenant before writing. A mismatch, missing subscriber, or database failure does not report success. Password input must be 8 to 1024 characters. The database stores only the Argon2id hash.

## Operational controls

- Run this command from a trusted administrator workstation or secured management host.
- Do not pass passwords in shell arguments, environment variables, tickets, chat, or scripts.
- Do not enable shell tracing or terminal/session recording during password entry.
- Ensure terminal, process, database, and central logs do not capture entered passwords.
- Use the normal identity verification and approval process before resetting a customer's credentials.
- Rotate the password through this command, not by editing the hash column manually.

This is a minimal provisioning utility. A production operator portal still needs RBAC, maker-checker approval, immutable audit records, and credential-reset notification workflows.
