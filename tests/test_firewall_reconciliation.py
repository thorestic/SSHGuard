import json
import subprocess
import unittest
from unittest.mock import patch

from core.firewall_reconciliation import (
    FirewallInspectionError,
    FirewallReconciliationMonitor,
    NftablesStateInspector,
)


class FakeDatabase:
    def __init__(self, expected):
        self.expected = expected
        self.snapshot = None

    def get_expected_active_blocks(self, current_time):
        return self.expected

    def replace_firewall_reconciliation(self, **snapshot):
        self.snapshot = snapshot


class FakeInspector:
    def __init__(self, actual=None, error=None):
        self.actual = actual or set()
        self.error = error

    def list_blocked_addresses(self):
        if self.error is not None:
            raise self.error
        return self.actual


class NftablesStateInspectorTests(unittest.TestCase):
    @staticmethod
    def nft_result(set_name, elements):
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps(
                {
                    "nftables": [
                        {"metainfo": {"json_schema_version": 1}},
                        {
                            "set": {
                                "family": "inet",
                                "table": "sshguard",
                                "name": set_name,
                                "elem": elements,
                            }
                        },
                    ]
                }
            ),
            stderr="",
        )

    @patch("core.firewall_reconciliation.subprocess.run")
    def test_reads_ipv4_and_ipv6_sets_from_json(self, run):
        run.side_effect = [
            self.nft_result(
                "blocked_ipv4",
                [
                    {
                        "elem": {
                            "val": "192.0.2.10",
                            "expires": 9000,
                        }
                    }
                ],
            ),
            self.nft_result(
                "blocked_ipv6",
                ["2001:0db8:0:0::10"],
            ),
        ]

        addresses = NftablesStateInspector().list_blocked_addresses()

        self.assertEqual(
            addresses,
            {"192.0.2.10", "2001:db8::10"},
        )
        for call in run.call_args_list:
            self.assertEqual(call.args[0][0:3], ["nft", "-j", "list"])
            self.assertNotIn("shell", call.kwargs)

    @patch("core.firewall_reconciliation.subprocess.run")
    def test_command_failure_is_reported_without_parsing_text(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="permission denied",
        )

        with self.assertRaises(FirewallInspectionError):
            NftablesStateInspector().list_blocked_addresses()

    @patch("core.firewall_reconciliation.subprocess.run")
    def test_malformed_json_is_rejected(self, run):
        run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="not-json",
            stderr="",
        )

        with self.assertRaises(FirewallInspectionError):
            NftablesStateInspector().list_blocked_addresses()

    @patch("core.firewall_reconciliation.subprocess.run")
    def test_missing_nft_binary_is_reported(self, run):
        run.side_effect = FileNotFoundError("nft")

        with self.assertRaises(FirewallInspectionError):
            NftablesStateInspector().list_blocked_addresses()

    @patch("core.firewall_reconciliation.subprocess.run")
    def test_nft_inspection_timeout_is_reported(self, run):
        run.side_effect = subprocess.TimeoutExpired(
            cmd=["nft"],
            timeout=5,
        )

        with self.assertRaises(FirewallInspectionError):
            NftablesStateInspector().list_blocked_addresses()


class FirewallReconciliationMonitorTests(unittest.TestCase):
    def test_in_sync_snapshot_has_no_drift_items(self):
        database = FakeDatabase(["192.0.2.10"])
        monitor = FirewallReconciliationMonitor(
            database=database,
            inspector=FakeInspector({"192.0.2.10"}),
        )

        result = monitor.reconcile_once()

        self.assertEqual(result.status, "in_sync")
        self.assertEqual(result.expected_count, 1)
        self.assertEqual(result.actual_count, 1)
        self.assertEqual(database.snapshot["items"], [])

    def test_drift_classifies_missing_and_unexpected_addresses(self):
        database = FakeDatabase(
            ["192.0.2.10", "2001:db8::10"]
        )
        monitor = FirewallReconciliationMonitor(
            database=database,
            inspector=FakeInspector(
                {"192.0.2.10", "198.51.100.20"}
            ),
        )

        result = monitor.reconcile_once()

        self.assertEqual(result.status, "drift")
        self.assertEqual(
            result.missing_in_firewall,
            ("2001:db8::10",),
        )
        self.assertEqual(
            result.unexpected_in_firewall,
            ("198.51.100.20",),
        )
        self.assertEqual(
            database.snapshot["items"],
            [
                ("2001:db8::10", "missing_in_firewall"),
                ("198.51.100.20", "unexpected_in_firewall"),
            ],
        )

    def test_inspection_failure_is_persisted_as_unavailable(self):
        database = FakeDatabase(["192.0.2.10"])
        monitor = FirewallReconciliationMonitor(
            database=database,
            inspector=FakeInspector(
                error=FirewallInspectionError("failed")
            ),
        )

        result = monitor.reconcile_once()

        self.assertEqual(result.status, "unavailable")
        self.assertIsNone(result.actual_count)
        self.assertEqual(
            result.error_code,
            "nftables_inspection_failed",
        )
        self.assertEqual(database.snapshot["items"], [])

    def test_invalid_database_address_is_persisted_as_unavailable(self):
        database = FakeDatabase(["not-an-ip"])
        monitor = FirewallReconciliationMonitor(
            database=database,
            inspector=FakeInspector(),
        )

        result = monitor.reconcile_once()

        self.assertEqual(result.status, "unavailable")
        self.assertEqual(
            result.error_code,
            "database_state_invalid",
        )
        self.assertEqual(database.snapshot["items"], [])


if __name__ == "__main__":
    unittest.main()
