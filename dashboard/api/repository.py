import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator


class DatabaseUnavailable(RuntimeError):
    """Raised when the dashboard cannot read the SSHGuard database."""


class DatabaseChangeMonitor:
    """Track commits made by other SQLite connections without reading rows."""

    def __init__(self, connection: sqlite3.Connection):
        self._connection = connection
        self._data_version = self._read_data_version()

    def _read_data_version(self) -> int:
        return int(
            self._connection.execute(
                "PRAGMA data_version"
            ).fetchone()[0]
        )

    def poll(self) -> bool:
        current_version = self._read_data_version()
        changed = current_version != self._data_version
        self._data_version = current_version
        return changed


class SecurityReadRepository:
    """Read-only query boundary over SSHGuard's SQLite event store."""

    REQUIRED_TABLES = {
        "auth_events",
        "incidents",
        "firewall_actions",
    }

    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        if not self.database_path.is_file():
            raise DatabaseUnavailable(
                f"SSHGuard database not found: {self.database_path}"
            )

        database_uri = f"{self.database_path.resolve().as_uri()}?mode=ro"

        try:
            connection = sqlite3.connect(
                database_uri,
                uri=True,
                timeout=5,
            )
        except sqlite3.Error as error:
            raise DatabaseUnavailable(str(error)) from error

        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 5000")

        try:
            yield connection
        except sqlite3.Error as error:
            raise DatabaseUnavailable(str(error)) from error
        finally:
            connection.close()

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
        return [dict(row) for row in rows]

    def health(self) -> dict[str, str]:
        with self._connection() as connection:
            table_rows = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()

        tables = {row["name"] for row in table_rows}
        missing = self.REQUIRED_TABLES - tables

        if missing:
            raise DatabaseUnavailable(
                "SSHGuard database is missing tables: "
                + ", ".join(sorted(missing))
            )

        return {
            "status": "ok",
            "database": "available",
            "api_version": "v1",
        }

    @contextmanager
    def change_monitor(self) -> Iterator[DatabaseChangeMonitor]:
        """Keep one read-only connection open for SQLite change signals."""

        with self._connection() as connection:
            yield DatabaseChangeMonitor(connection)

    def list_incidents(
        self,
        *,
        limit: int,
        offset: int,
        status: str | None = None,
        source_ip: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        parameters: list[Any] = []

        if status:
            clauses.append("status = ?")
            parameters.append(status)

        if source_ip:
            clauses.append("source_ip LIKE ?")
            parameters.append(f"%{source_ip}%")

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._connection() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) FROM incidents {where}",
                parameters,
            ).fetchone()[0]

            rows = connection.execute(
                f"""
                SELECT
                    id,
                    source_ip,
                    username,
                    attempt_count,
                    first_seen,
                    last_seen,
                    window_seconds,
                    status,
                    response_outcome
                FROM incidents
                {where}
                ORDER BY last_seen DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                [*parameters, limit, offset],
            ).fetchall()

        return self._rows(rows), total

    def list_authentication_events(
        self,
        *,
        limit: int,
        offset: int,
        event_type: str | None = None,
        source_ip: str | None = None,
        username: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        parameters: list[Any] = []

        if event_type:
            clauses.append("event_type = ?")
            parameters.append(event_type)

        if source_ip:
            clauses.append("source_ip LIKE ?")
            parameters.append(f"%{source_ip}%")

        if username:
            clauses.append("username LIKE ?")
            parameters.append(f"%{username}%")

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._connection() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) FROM auth_events {where}",
                parameters,
            ).fetchone()[0]

            rows = connection.execute(
                f"""
                SELECT
                    id,
                    event_type,
                    username,
                    source_ip,
                    source_port,
                    invalid_user,
                    timestamp
                FROM auth_events
                {where}
                ORDER BY timestamp DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                [*parameters, limit, offset],
            ).fetchall()

        items = self._rows(rows)
        for item in items:
            item["invalid_user"] = bool(item["invalid_user"])

        return items, total

    def list_firewall_actions(
        self,
        *,
        limit: int,
        offset: int,
        action: str | None = None,
        source_ip: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        parameters: list[Any] = []

        if action:
            clauses.append("action = ?")
            parameters.append(action)

        if source_ip:
            clauses.append("source_ip LIKE ?")
            parameters.append(f"%{source_ip}%")

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._connection() as connection:
            total = connection.execute(
                f"SELECT COUNT(*) FROM firewall_actions {where}",
                parameters,
            ).fetchone()[0]

            rows = connection.execute(
                f"""
                SELECT
                    id,
                    source_ip,
                    action,
                    timestamp,
                    expires_at,
                    incident_id,
                    related_action_id
                FROM firewall_actions
                {where}
                ORDER BY timestamp DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                [*parameters, limit, offset],
            ).fetchall()

        return self._rows(rows), total

    def overview(self) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        cutoff = self._iso(now - timedelta(hours=24))
        now_iso = self._iso(now)

        with self._connection() as connection:
            metrics = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM incidents) AS incidents_total,
                    (
                        SELECT COUNT(*) FROM incidents
                        WHERE last_seen >= ?
                    ) AS incidents_24h,
                    (
                        SELECT COUNT(*) FROM auth_events
                        WHERE event_type = 'failed_login'
                          AND timestamp >= ?
                    ) AS failed_logins_24h,
                    (
                        SELECT COUNT(*) FROM auth_events
                        WHERE event_type = 'successful_login'
                          AND timestamp >= ?
                    ) AS successful_logins_24h,
                    (
                        SELECT COUNT(DISTINCT source_ip)
                        FROM auth_events
                        WHERE timestamp >= ?
                    ) AS unique_sources_24h,
                    (
                        SELECT COUNT(*)
                        FROM firewall_actions AS block
                        WHERE block.action = 'block'
                          AND block.expires_at > ?
                          AND NOT EXISTS (
                              SELECT 1
                              FROM firewall_actions AS finished
                              WHERE finished.related_action_id = block.id
                                AND finished.action IN (
                                    'expired',
                                    'manual_unblock'
                                )
                          )
                    ) AS active_blocks
                """,
                (cutoff, cutoff, cutoff, cutoff, now_iso),
            ).fetchone()

            recent_rows = connection.execute(
                """
                SELECT
                    id,
                    source_ip,
                    username,
                    attempt_count,
                    first_seen,
                    last_seen,
                    window_seconds,
                    status,
                    response_outcome
                FROM incidents
                ORDER BY last_seen DESC, id DESC
                LIMIT 6
                """
            ).fetchall()

        return {
            "generated_at": now,
            "metrics": dict(metrics),
            "recent_incidents": self._rows(recent_rows),
        }

    def analytics(self, hours: int) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        cutoff = self._iso(now - timedelta(hours=hours))

        with self._connection() as connection:
            auth_timeline = connection.execute(
                """
                SELECT
                    substr(timestamp, 1, 13) || ':00:00+00:00' AS bucket,
                    COUNT(*) AS count
                FROM auth_events
                WHERE timestamp >= ?
                GROUP BY bucket
                ORDER BY bucket
                """,
                (cutoff,),
            ).fetchall()

            incident_timeline = connection.execute(
                """
                SELECT
                    substr(last_seen, 1, 13) || ':00:00+00:00' AS bucket,
                    COUNT(*) AS count
                FROM incidents
                WHERE last_seen >= ?
                GROUP BY bucket
                ORDER BY bucket
                """,
                (cutoff,),
            ).fetchall()

            top_sources = connection.execute(
                """
                SELECT source_ip AS value, COUNT(*) AS count
                FROM auth_events
                WHERE timestamp >= ?
                GROUP BY source_ip
                ORDER BY count DESC, source_ip
                LIMIT 8
                """,
                (cutoff,),
            ).fetchall()

            targeted_users = connection.execute(
                """
                SELECT username AS value, COUNT(*) AS count
                FROM auth_events
                WHERE timestamp >= ?
                  AND event_type = 'failed_login'
                  AND username IS NOT NULL
                GROUP BY username
                ORDER BY count DESC, username
                LIMIT 8
                """,
                (cutoff,),
            ).fetchall()

            statuses = connection.execute(
                """
                SELECT status AS label, COUNT(*) AS count
                FROM incidents
                WHERE last_seen >= ?
                GROUP BY status
                ORDER BY count DESC, status
                """,
                (cutoff,),
            ).fetchall()

            outcomes = connection.execute(
                """
                SELECT
                    COALESCE(response_outcome, 'pending') AS label,
                    COUNT(*) AS count
                FROM incidents
                WHERE last_seen >= ?
                GROUP BY COALESCE(response_outcome, 'pending')
                ORDER BY count DESC, label
                """,
                (cutoff,),
            ).fetchall()

        timeline: dict[str, dict[str, Any]] = {}

        for row in auth_timeline:
            timeline[row["bucket"]] = {
                "bucket": row["bucket"],
                "authentication_events": row["count"],
                "incidents": 0,
            }

        for row in incident_timeline:
            item = timeline.setdefault(
                row["bucket"],
                {
                    "bucket": row["bucket"],
                    "authentication_events": 0,
                    "incidents": 0,
                },
            )
            item["incidents"] = row["count"]

        return {
            "generated_at": now,
            "hours": hours,
            "timeline": [timeline[key] for key in sorted(timeline)],
            "top_sources": self._rows(top_sources),
            "targeted_users": self._rows(targeted_users),
            "incident_statuses": self._rows(statuses),
            "response_outcomes": self._rows(outcomes),
        }

