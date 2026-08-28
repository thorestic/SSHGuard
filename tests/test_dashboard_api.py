import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from core.database import DatabaseManager
from dashboard.api.app import create_app


class DashboardApiTests(unittest.TestCase):

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(
            self.temp_directory.name,
            "dashboard.db",
        )
        self.database = DatabaseManager(self.database_path)
        self.now = datetime.now(timezone.utc)
        self._seed_database()
        self.client = TestClient(
            create_app(database_path=self.database_path)
        )

    def tearDown(self):
        self.client.close()
        self.temp_directory.cleanup()

    def _seed_database(self):
        failed_at = self.now - timedelta(minutes=10)
        successful_at = self.now - timedelta(minutes=5)

        self.database.save_auth_event(
            {
                "event_type": "failed_login",
                "username": "admin",
                "source_ip": "192.0.2.44",
                "source_port": 51000,
                "invalid_user": True,
                "timestamp": failed_at.isoformat(),
            }
        )
        self.database.save_auth_event(
            {
                "event_type": "successful_login",
                "username": "operator",
                "source_ip": "198.51.100.8",
                "source_port": 51001,
                "invalid_user": False,
                "timestamp": successful_at.isoformat(),
            }
        )

        incident_id = self.database.save_incident(
            {
                "source_ip": "192.0.2.44",
                "username": "admin",
                "attempt_count": 3,
                "first_seen": failed_at.isoformat(),
                "last_seen": failed_at.isoformat(),
                "window_seconds": 20,
            }
        )
        self.database.update_incident_response(
            incident_id=incident_id,
            status="blocked",
            response_outcome="blocked",
        )
        self.database.save_firewall_action(
            source_ip="192.0.2.44",
            action="block",
            timestamp=failed_at.isoformat(),
            expires_at=(self.now + timedelta(minutes=5)).isoformat(),
            incident_id=incident_id,
        )

    def test_health_confirms_database_schema(self):
        response = self.client.get("/api/v1/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["database"], "available")

    def test_overview_returns_security_metrics(self):
        response = self.client.get("/api/v1/overview")

        self.assertEqual(response.status_code, 200)
        metrics = response.json()["metrics"]
        self.assertEqual(metrics["incidents_total"], 1)
        self.assertEqual(metrics["failed_logins_24h"], 1)
        self.assertEqual(metrics["successful_logins_24h"], 1)
        self.assertEqual(metrics["active_blocks"], 1)

    def test_incidents_are_paginated_and_filterable(self):
        response = self.client.get(
            "/api/v1/incidents",
            params={"status": "blocked", "limit": 10},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["pagination"]["total"], 1)
        self.assertEqual(payload["items"][0]["source_ip"], "192.0.2.44")

    def test_authentication_events_preserve_boolean_type(self):
        response = self.client.get(
            "/api/v1/authentication-events",
            params={"event_type": "failed_login"},
        )

        self.assertEqual(response.status_code, 200)
        event = response.json()["items"][0]
        self.assertIs(event["invalid_user"], True)

    def test_firewall_actions_link_to_incidents(self):
        response = self.client.get("/api/v1/firewall-actions")

        self.assertEqual(response.status_code, 200)
        action = response.json()["items"][0]
        self.assertEqual(action["action"], "block")
        self.assertEqual(action["incident_id"], 1)

    def test_analytics_returns_rankings_and_breakdowns(self):
        response = self.client.get(
            "/api/v1/analytics",
            params={"hours": 24},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["top_sources"][0]["value"], "192.0.2.44")
        self.assertEqual(payload["incident_statuses"][0]["label"], "blocked")

    def test_missing_database_returns_service_unavailable(self):
        missing_client = TestClient(
            create_app(
                database_path=os.path.join(
                    self.temp_directory.name,
                    "missing.db",
                )
            )
        )

        response = missing_client.get("/api/v1/health")

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("missing.db", response.text)

    def test_v1_contract_exposes_read_operations_only(self):
        response = self.client.get("/api/openapi.json")

        self.assertEqual(response.status_code, 200)

        for path, operations in response.json()["paths"].items():
            if not path.startswith("/api/v1"):
                continue

            methods = {
                method
                for method in operations
                if method != "parameters"
            }

            self.assertEqual(
                methods,
                {"get"},
                msg=f"{path} must remain read-only",
            )

    def test_built_dashboard_is_served_by_fastapi(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("SSHGuard Security Console", response.text)

    def test_dashboard_brand_image_is_served_as_static_file(self):
        response = self.client.get("/brand/sshguard-mark.png")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "image/png")
        self.assertTrue(response.content.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_unknown_api_path_does_not_return_dashboard_html(self):
        response = self.client.get("/api/v1/not-a-route")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")


if __name__ == "__main__":
    unittest.main()
