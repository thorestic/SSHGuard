import asyncio
import os
import tempfile
import unittest
from datetime import datetime, timezone

from core.database import DatabaseManager
from dashboard.api.live import security_event_stream
from dashboard.api.repository import SecurityReadRepository


class ConnectedRequest:
    async def is_disconnected(self) -> bool:
        return False


class LiveEventStreamTests(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(
            self.temp_directory.name,
            "live-events.db",
        )
        self.database = DatabaseManager(self.database_path)
        self.repository = SecurityReadRepository(self.database_path)

    def tearDown(self):
        self.temp_directory.cleanup()

    async def test_stream_announces_external_database_change(self):
        stream = security_event_stream(
            ConnectedRequest(),
            self.repository,
            poll_seconds=0.001,
            heartbeat_seconds=30,
        )

        ready_event = await anext(stream)
        self.assertIn("event: ready", ready_event)
        self.assertIn("retry: 1000", ready_event)

        self.database.save_auth_event(
            {
                "event_type": "failed_login",
                "username": "admin",
                "source_ip": "192.0.2.55",
                "source_port": 50022,
                "invalid_user": False,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        update_event = await asyncio.wait_for(
            anext(stream),
            timeout=1,
        )
        self.assertIn("event: security_update", update_event)
        self.assertIn("\"changed_at\"", update_event)

        await stream.aclose()

    async def test_stream_sends_heartbeat_without_database_change(self):
        stream = security_event_stream(
            ConnectedRequest(),
            self.repository,
            poll_seconds=0.001,
            heartbeat_seconds=0,
        )

        await anext(stream)
        heartbeat = await asyncio.wait_for(
            anext(stream),
            timeout=1,
        )

        self.assertTrue(heartbeat.startswith(": keep-alive "))
        await stream.aclose()


if __name__ == "__main__":
    unittest.main()
