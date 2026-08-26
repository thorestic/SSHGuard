import os
import sqlite3


class DatabaseManager:
    def __init__(self, database_path="data/sshguard.db"):
        self.database_path = database_path

        database_directory = os.path.dirname(database_path)

        if database_directory:
            os.makedirs(database_directory, exist_ok=True)

        self._create_tables()

    def _connect(self):
        return sqlite3.connect(self.database_path)

    def _create_tables(self):
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    username TEXT,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER,
                    invalid_user INTEGER NOT NULL DEFAULT 0,
                    timestamp TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    username TEXT,
                    attempt_count INTEGER NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    window_seconds INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'detected'
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS firewall_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    action TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    expires_at TEXT
                )
                """
            )

            # Simple database migration:
            # Add new columns if this database was created
            # before these fields existed.
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(firewall_actions)"
                ).fetchall()
            }

            if "incident_id" not in columns:
                connection.execute(
                    """
                    ALTER TABLE firewall_actions
                    ADD COLUMN incident_id INTEGER
                    """
                )

            if "related_action_id" not in columns:
                connection.execute(
                    """
                    ALTER TABLE firewall_actions
                    ADD COLUMN related_action_id INTEGER
                    """
                )

    def save_auth_event(self, event: dict):
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO auth_events (
                    event_type,
                    username,
                    source_ip,
                    source_port,
                    invalid_user,
                    timestamp
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_type"],
                    event.get("username"),
                    event["source_ip"],
                    event.get("source_port"),
                    int(event.get("invalid_user", False)),
                    event["timestamp"],
                ),
            )

    def save_incident(self, incident: dict):
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO incidents (
                    source_ip,
                    username,
                    attempt_count,
                    first_seen,
                    last_seen,
                    window_seconds,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident["source_ip"],
                    incident.get("username"),
                    incident["attempt_count"],
                    incident["first_seen"],
                    incident["last_seen"],
                    incident["window_seconds"],
                    "detected",
                ),
            )

            return cursor.lastrowid

    def save_firewall_action(
        self,
        source_ip: str,
        action: str,
        timestamp: str,
        expires_at: str | None = None,
        incident_id: int | None = None,
        related_action_id: int | None = None,
    ):
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO firewall_actions (
                    source_ip,
                    action,
                    timestamp,
                    expires_at,
                    incident_id,
                    related_action_id
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    source_ip,
                    action,
                    timestamp,
                    expires_at,
                    incident_id,
                    related_action_id,
                ),
            )

            return cursor.lastrowid

    def get_expired_unlogged_blocks(self, current_time: str):
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT
                    block.id,
                    block.incident_id,
                    block.source_ip,
                    block.expires_at
                FROM firewall_actions AS block
                WHERE
                    block.action = 'block'
                    AND block.expires_at IS NOT NULL
                    AND block.expires_at <= ?
                    AND NOT EXISTS (
                        SELECT 1
                        FROM firewall_actions AS expiration
                        WHERE
                            expiration.action = 'expired'
                            AND expiration.related_action_id = block.id
                    )
                ORDER BY block.expires_at
                """,
                (current_time,),
            ).fetchall()

    def update_incident_status(
        self,
        incident_id: int,
        status: str,
    ):
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE incidents
                SET status = ?
                WHERE id = ?
                """,
                (
                    status,
                    incident_id,
                ),
            )
