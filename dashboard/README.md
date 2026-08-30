# SSHGuard Dashboard MVP

The dashboard is a read-only client of SSHGuard's security event store. It is
deliberately separated from detection, nftables response, and lifecycle
monitoring so other clients—including a future Windows desktop application—can
reuse the same versioned HTTP contract.

## Architecture

```text
SSH journal -> parser -> detector -> SQLite -> read-only API -> clients
                              ^  ^                      |-> React dashboard
                              |  |                      `-> future Windows GUI
                              |  `-- report-only reconciliation snapshot
                              `----- nftables response + read-only inspection
```

The API opens SQLite with both URI `mode=ro` and `PRAGMA query_only = ON`.
There are no POST, PUT, PATCH, or DELETE operations in `/api/v1`.

## API surface

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/health` | Database and schema availability |
| `GET /api/v1/overview` | Current operational metrics |
| `GET /api/v1/incidents` | Paginated and filterable incidents |
| `GET /api/v1/incidents/{incident_id}` | One incident with correlated authentication evidence and linked firewall actions |
| `GET /api/v1/authentication-events` | Paginated SSH authentication history |
| `GET /api/v1/firewall-actions` | nftables response audit trail |
| `GET /api/v1/firewall-reconciliation` | Expected SQLite blocks compared with enforced nftables sets |
| `GET /api/v1/analytics` | Timeline, rankings, and breakdowns |

The reconciliation endpoint is report-only. The privileged security core reads
the two SSHGuard nftables sets using structured JSON output and stores a small
current-state snapshot in SQLite. The unprivileged API never runs `nft`, and no
automatic add/delete repair is performed when drift is found.

If the latest snapshot is older than 30 seconds, the API reports `stale` so a
client does not mistake an old successful comparison for current protection.

Interactive API documentation is available at `/api/docs`.

## Development setup

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dashboard.txt
```

Start the API:

```bash
SSHGUARD_DATABASE_PATH=data/sshguard.db \
uvicorn dashboard.api.app:app --reload --host 127.0.0.1 --port 8000
```

In a second terminal, start Vite:

```bash
cd dashboard/web
npm install
npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173`. Vite proxies `/api` to FastAPI during
development.

## Production build

Build the React client:

```bash
cd dashboard/web
npm ci
npm run build
cd ../..
```

When `dashboard/web/dist` exists, FastAPI serves the React application and the
API from the same origin at `http://127.0.0.1:8000`.

Production must not run from the development checkout. Build the frontend as
the unprivileged developer, then use the repository's production installer to
create a root-owned release under `/opt/sshguard`, migrate persistent state to
`/var/lib/sshguard`, and install both service units:

```bash
sudo bash deploy/install-production.sh /home/mc/sshguard
```

See `deploy/README.md` for the filesystem boundary, backup behavior, and
verification procedure.

Verify it locally:

```bash
curl http://127.0.0.1:8000/api/v1/health
systemctl status sshguard-dashboard-api --no-pager
```

The service binds to loopback by default because incident IP addresses and
usernames are security-sensitive telemetry. Remote access should be added in a
separate deployment step through an authenticated reverse proxy or a trusted
private network, rather than exposing port 8000 directly.

## Verification

Run all core and API tests:

```bash
python -W error::ResourceWarning -m unittest discover -s tests -v
```

Validate the frontend production bundle:

```bash
cd dashboard/web
npm run build
```
