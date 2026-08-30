import os
import sqlite3
import tempfile
import unittest
from contextlib import closing, contextmanager

from core.database import DatabaseManager


class DatabaseManagerTests(unittest.TestCase):

    def setUp(self):
        """
        Create a completely isolated temporary
        database for every test.

        The real data/sshguard.db is never touched.
        """

        self.temp_directory = tempfile.TemporaryDirectory()

        self.database_path = os.path.join(
            self.temp_directory.name,
            "test_sshguard.db",
        )

        self.database = DatabaseManager(
            database_path=self.database_path
        )

    def tearDown(self):
        """
        Delete the temporary database and directory
        after each test.
        """

        self.temp_directory.cleanup()

    @contextmanager
    def connect(self):
        """
        Open a test database connection and guarantee
        that it is committed or rolled back, then closed.
        """

        connection = sqlite3.connect(
            self.database_path
        )

        try:
            yield connection
            connection.commit()

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def sample_event(self):
        return {
            "event_type": "failed_login",
            "username": "alice",
            "source_ip": "192.0.2.10",
            "source_port": 50000,
            "invalid_user": False,
            "timestamp": (
                "2026-08-27T10:00:00+00:00"
            ),
        }

    def sample_incident(self):
        return {
            "event_type": "brute_force_detected",
            "source_ip": "192.0.2.10",
            "username": "alice",
            "attempt_count": 3,
            "first_seen": (
                "2026-08-27T10:00:00+00:00"
            ),
            "last_seen": (
                "2026-08-27T10:00:10+00:00"
            ),
            "window_seconds": 20,
        }

    def test_database_tables_are_created(self):
        """
        DatabaseManager should automatically create
        all required SSHGuard tables.
        """

        with self.connect() as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    """
                    SELECT name
                    FROM sqlite_master
                    WHERE type = 'table'
                    """
                ).fetchall()
            }

        self.assertIn(
            "auth_events",
            tables,
        )

        self.assertIn(
            "incidents",
            tables,
        )

        self.assertIn(
            "firewall_actions",
            tables,
        )

        self.assertIn(
            "firewall_reconciliation",
            tables,
        )

        self.assertIn(
            "firewall_reconciliation_items",
            tables,
        )

    def test_auth_event_is_persisted(self):
        event = self.sample_event()

        self.database.save_auth_event(
            event
        )

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    event_type,
                    username,
                    source_ip,
                    source_port,
                    invalid_user,
                    timestamp
                FROM auth_events
                """
            ).fetchone()

        self.assertIsNotNone(row)

        self.assertEqual(
            row[0],
            "failed_login",
        )

        self.assertEqual(
            row[1],
            "alice",
        )

        self.assertEqual(
            row[2],
            "192.0.2.10",
        )

        self.assertEqual(
            row[3],
            50000,
        )

        self.assertEqual(
            row[4],
            0,
        )

        self.assertEqual(
            row[5],
            "2026-08-27T10:00:00+00:00",
        )

    def test_invalid_user_boolean_is_stored_as_integer(self):
        event = self.sample_event()

        event["invalid_user"] = True

        self.database.save_auth_event(
            event
        )

        with self.connect() as connection:
            value = connection.execute(
                """
                SELECT invalid_user
                FROM auth_events
                """
            ).fetchone()[0]

        self.assertEqual(
            value,
            1,
        )

    def test_incident_is_created_as_detected(self):
        incident = self.sample_incident()

        incident_id = (
            self.database.save_incident(
                incident
            )
        )

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    source_ip,
                    attempt_count,
                    status,
                    response_outcome
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,),
            ).fetchone()

        self.assertIsNotNone(row)

        self.assertEqual(
            row[0],
            incident_id,
        )

        self.assertEqual(
            row[1],
            "192.0.2.10",
        )

        self.assertEqual(
            row[2],
            3,
        )

        self.assertEqual(
            row[3],
            "detected",
        )

        self.assertIsNone(
            row[4]
        )

    def test_incident_response_can_be_updated(self):
        incident_id = (
            self.database.save_incident(
                self.sample_incident()
            )
        )

        self.database.update_incident_response(
            incident_id=incident_id,
            status="blocked",
            response_outcome="blocked",
        )

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    status,
                    response_outcome
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,),
            ).fetchone()

        self.assertEqual(
            row[0],
            "blocked",
        )

        self.assertEqual(
            row[1],
            "blocked",
        )

    def test_status_update_preserves_response_outcome(self):
        """
        blocked -> resolved must not erase the fact
        that the firewall response was originally
        successful.
        """

        incident_id = (
            self.database.save_incident(
                self.sample_incident()
            )
        )

        self.database.update_incident_response(
            incident_id=incident_id,
            status="blocked",
            response_outcome="blocked",
        )

        self.database.update_incident_status(
            incident_id,
            "resolved",
        )

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    status,
                    response_outcome
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,),
            ).fetchone()

        self.assertEqual(
            row[0],
            "resolved",
        )

        self.assertEqual(
            row[1],
            "blocked",
        )

    def test_firewall_block_action_links_to_incident(self):
        incident_id = (
            self.database.save_incident(
                self.sample_incident()
            )
        )

        block_action_id = (
            self.database.save_firewall_action(
                source_ip="192.0.2.10",
                action="block",
                timestamp=(
                    "2026-08-27T10:00:10+00:00"
                ),
                expires_at=(
                    "2026-08-27T10:01:10+00:00"
                ),
                incident_id=incident_id,
            )
        )

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    id,
                    action,
                    incident_id,
                    related_action_id
                FROM firewall_actions
                WHERE id = ?
                """,
                (block_action_id,),
            ).fetchone()

        self.assertEqual(
            row[0],
            block_action_id,
        )

        self.assertEqual(
            row[1],
            "block",
        )

        self.assertEqual(
            row[2],
            incident_id,
        )

        self.assertIsNone(
            row[3]
        )

    def test_expired_action_can_reference_block_action(self):
        incident_id = (
            self.database.save_incident(
                self.sample_incident()
            )
        )

        block_action_id = (
            self.database.save_firewall_action(
                source_ip="192.0.2.10",
                action="block",
                timestamp=(
                    "2026-08-27T10:00:10+00:00"
                ),
                expires_at=(
                    "2026-08-27T10:01:10+00:00"
                ),
                incident_id=incident_id,
            )
        )

        expired_action_id = (
            self.database.save_firewall_action(
                source_ip="192.0.2.10",
                action="expired",
                timestamp=(
                    "2026-08-27T10:01:10+00:00"
                ),
                incident_id=incident_id,
                related_action_id=block_action_id,
            )
        )

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    action,
                    incident_id,
                    related_action_id
                FROM firewall_actions
                WHERE id = ?
                """,
                (expired_action_id,),
            ).fetchone()

        self.assertEqual(
            row[0],
            "expired",
        )

        self.assertEqual(
            row[1],
            incident_id,
        )

        self.assertEqual(
            row[2],
            block_action_id,
        )

    def test_expired_block_is_returned_for_lifecycle_processing(self):
        incident_id = (
            self.database.save_incident(
                self.sample_incident()
            )
        )

        block_action_id = (
            self.database.save_firewall_action(
                source_ip="192.0.2.10",
                action="block",
                timestamp=(
                    "2026-08-27T10:00:00+00:00"
                ),
                expires_at=(
                    "2026-08-27T10:01:00+00:00"
                ),
                incident_id=incident_id,
            )
        )

        expired = (
            self.database
            .get_expired_unlogged_blocks(
                "2026-08-27T10:02:00+00:00"
            )
        )

        self.assertEqual(
            len(expired),
            1,
        )

        self.assertEqual(
            expired[0][0],
            block_action_id,
        )

        self.assertEqual(
            expired[0][1],
            incident_id,
        )

        self.assertEqual(
            expired[0][2],
            "192.0.2.10",
        )

    def test_unexpired_block_is_not_returned(self):
        incident_id = (
            self.database.save_incident(
                self.sample_incident()
            )
        )

        self.database.save_firewall_action(
            source_ip="192.0.2.10",
            action="block",
            timestamp=(
                "2026-08-27T10:00:00+00:00"
            ),
            expires_at=(
                "2026-08-27T10:10:00+00:00"
            ),
            incident_id=incident_id,
        )

        expired = (
            self.database
            .get_expired_unlogged_blocks(
                "2026-08-27T10:05:00+00:00"
            )
        )

        self.assertEqual(
            expired,
            [],
        )

    def test_already_logged_expiration_is_not_returned_again(self):
        """
        This prevents the lifecycle monitor from
        creating duplicate expired actions every
        two seconds.
        """

        incident_id = (
            self.database.save_incident(
                self.sample_incident()
            )
        )

        block_action_id = (
            self.database.save_firewall_action(
                source_ip="192.0.2.10",
                action="block",
                timestamp=(
                    "2026-08-27T10:00:00+00:00"
                ),
                expires_at=(
                    "2026-08-27T10:01:00+00:00"
                ),
                incident_id=incident_id,
            )
        )

        self.database.save_firewall_action(
            source_ip="192.0.2.10",
            action="expired",
            timestamp=(
                "2026-08-27T10:01:00+00:00"
            ),
            incident_id=incident_id,
            related_action_id=block_action_id,
        )

        expired = (
            self.database
            .get_expired_unlogged_blocks(
                "2026-08-27T10:05:00+00:00"
            )
        )

        self.assertEqual(
            expired,
            [],
        )

    def test_expected_active_blocks_exclude_finished_and_expired_rows(self):
        active_block_id = self.database.save_firewall_action(
            source_ip="192.0.2.10",
            action="block",
            timestamp="2026-08-27T10:00:00+00:00",
            expires_at="2026-08-27T10:10:00+00:00",
        )
        self.database.save_firewall_action(
            source_ip="192.0.2.10",
            action="block",
            timestamp="2026-08-27T10:01:00+00:00",
            expires_at="2026-08-27T10:11:00+00:00",
        )
        finished_block_id = self.database.save_firewall_action(
            source_ip="198.51.100.20",
            action="block",
            timestamp="2026-08-27T10:00:00+00:00",
            expires_at="2026-08-27T10:10:00+00:00",
        )
        self.database.save_firewall_action(
            source_ip="198.51.100.20",
            action="manual_unblock",
            timestamp="2026-08-27T10:02:00+00:00",
            related_action_id=finished_block_id,
        )
        self.database.save_firewall_action(
            source_ip="203.0.113.30",
            action="block",
            timestamp="2026-08-27T09:00:00+00:00",
            expires_at="2026-08-27T09:01:00+00:00",
        )

        expected = self.database.get_expected_active_blocks(
            "2026-08-27T10:05:00+00:00"
        )

        self.assertEqual(expected, ["192.0.2.10"])
        self.assertIsInstance(active_block_id, int)

    def test_reconciliation_replaces_previous_current_state(self):
        self.database.replace_firewall_reconciliation(
            status="drift",
            checked_at="2026-08-27T10:05:00+00:00",
            expected_count=1,
            actual_count=2,
            items=[
                (
                    "198.51.100.20",
                    "unexpected_in_firewall",
                )
            ],
        )

        self.database.replace_firewall_reconciliation(
            status="in_sync",
            checked_at="2026-08-27T10:05:10+00:00",
            expected_count=1,
            actual_count=1,
            items=[],
        )

        with self.connect() as connection:
            summary = connection.execute(
                """
                SELECT
                    status,
                    checked_at,
                    expected_count,
                    actual_count,
                    error_code
                FROM firewall_reconciliation
                WHERE id = 1
                """
            ).fetchone()
            item_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM firewall_reconciliation_items
                """
            ).fetchone()[0]

        self.assertEqual(
            summary,
            (
                "in_sync",
                "2026-08-27T10:05:10+00:00",
                1,
                1,
                None,
            ),
        )
        self.assertEqual(item_count, 0)

    def test_response_skipped_is_persisted(self):
        incident_id = (
            self.database.save_incident(
                self.sample_incident()
            )
        )

        self.database.update_incident_response(
            incident_id=incident_id,
            status="response_skipped",
            response_outcome="whitelisted",
        )

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    status,
                    response_outcome
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,),
            ).fetchone()

        self.assertEqual(
            row,
            (
                "response_skipped",
                "whitelisted",
            ),
        )

    def test_response_failure_is_persisted(self):
        incident_id = (
            self.database.save_incident(
                self.sample_incident()
            )
        )

        self.database.update_incident_response(
            incident_id=incident_id,
            status="response_failed",
            response_outcome="firewall_error",
        )

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    status,
                    response_outcome
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,),
            ).fetchone()

        self.assertEqual(
            row,
            (
                "response_failed",
                "firewall_error",
            ),
        )


class DatabaseMigrationTests(unittest.TestCase):

    def test_legacy_database_is_migrated(self):
        """
        Simulate an older SSHGuard database created
        before response_outcome, incident_id, and
        related_action_id existed.
        """

        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(
                directory,
                "legacy.db",
            )

            with closing(
                sqlite3.connect(database_path)
            ) as connection:
                connection.execute(
                    """
                    CREATE TABLE auth_events (
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
                    CREATE TABLE incidents (
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
                    CREATE TABLE firewall_actions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source_ip TEXT NOT NULL,
                        action TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        expires_at TEXT
                    )
                    """
                )

                connection.commit()

            DatabaseManager(
                database_path=database_path
            )

            with closing(
                sqlite3.connect(database_path)
            ) as connection:
                incident_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(incidents)"
                    ).fetchall()
                }

                firewall_columns = {
                    row[1]
                    for row in connection.execute(
                        """
                        PRAGMA table_info(
                            firewall_actions
                        )
                        """
                    ).fetchall()
                }

            self.assertIn(
                "response_outcome",
                incident_columns,
            )

            self.assertIn(
                "incident_id",
                firewall_columns,
            )

            self.assertIn(
                "related_action_id",
                firewall_columns,
            )


if __name__ == "__main__":
    unittest.main()
