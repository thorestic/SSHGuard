# Production deployment

The Git checkout is a development workspace. Production services must never
execute Python or frontend assets directly from a user-writable home
directory.

The deployment layout is:

```text
/home/mc/sshguard        development checkout
/opt/sshguard/releases   immutable, root-owned releases
/opt/sshguard/current    active release symlink
/var/lib/sshguard        persistent SQLite state
/var/log/sshguard        rotating application logs
/var/backups/sshguard    pre-activation backups
```

## Prepare the source

Commit the intended release and build the React client as the unprivileged
developer:

```bash
cd /home/mc/sshguard/dashboard/web
npm ci
npm run build
cd /home/mc/sshguard
git status --short --branch
```

Tracked files must be clean. The installer copies tracked source from the
exact checked-out commit with `git archive`; it only adds the separately built
React `dist` directory. It does not copy `.git`, the development virtual
environment, `node_modules`, or checkout-local state.

## Install and activate

Run the installer from the repository root:

```bash
sudo bash deploy/install-production.sh /home/mc/sshguard
```

Before migrating SQLite, the installer stops both services so the writer is
not active. It preserves an existing production database, or copies the
legacy checkout database on the first deployment. It also saves the previous
database, log, and unit files under `/var/backups/sshguard/<release-id>`.

The installer creates a fresh virtual environment inside the final release
path, runs the full Python test suite with `ResourceWarning` treated as an
error, installs the units, activates the release, and checks both service
state and API health.

## Verify ownership and runtime paths

```bash
systemctl show sshguard-project.service \
  -p User -p Group -p WorkingDirectory -p ExecStart --no-pager
systemctl show sshguard-dashboard-api.service \
  -p User -p Group -p WorkingDirectory -p ExecStart --no-pager
namei -l /opt/sshguard/current/main.py
stat -c '%U %G %a %n' \
  /var/lib/sshguard/sshguard.db \
  /var/log/sshguard/sshguard.log
curl http://127.0.0.1:8000/api/v1/health
```

Expected security boundary:

- release code and its virtual environment are owned by `root:root` and have
  no group/other write permission;
- the core writes state as `root:mc` with a restrictive umask;
- the dashboard runs as `mc` and opens SQLite in read-only/query-only mode;
- both services have read-only access to `/opt/sshguard` inside their systemd
  sandbox.
