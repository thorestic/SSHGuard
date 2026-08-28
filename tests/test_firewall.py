import subprocess
import unittest
from unittest.mock import patch

from core.firewall import (
    FirewallManager,
    FirewallResult,
)


class FirewallManagerTests(unittest.TestCase):

    def make_firewall(
        self,
        response_mode="real",
    ):
        return FirewallManager(
            protected_port=22,
            block_duration_seconds=60,
            whitelist_networks=[
                "100.64.0.0/10",
                "127.0.0.0/8",
            ],
            response_mode=response_mode,
        )

    def test_invalid_response_mode_rejected(self):
        with self.assertRaises(ValueError):
            self.make_firewall(
                response_mode="invalid-mode"
            )

    def test_whitelisted_ip_is_detected(self):
        firewall = self.make_firewall()

        self.assertTrue(
            firewall.is_whitelisted(
                "100.71.142.40"
            )
        )

        self.assertTrue(
            firewall.is_whitelisted(
                "127.0.0.1"
            )
        )

    def test_normal_ip_is_not_whitelisted(self):
        firewall = self.make_firewall()

        self.assertFalse(
            firewall.is_whitelisted(
                "192.168.0.11"
            )
        )

    def test_invalid_ip_is_not_whitelisted(self):
        firewall = self.make_firewall()

        self.assertFalse(
            firewall.is_whitelisted(
                "not-an-ip"
            )
        )

    def test_invalid_ip_returns_invalid_ip_result(self):
        firewall = self.make_firewall()

        result = firewall.block_ip(
            "not-an-ip"
        )

        self.assertEqual(
            result,
            FirewallResult.INVALID_IP,
        )

    def test_ipv6_returns_unsupported_result(self):
        firewall = self.make_firewall()

        result = firewall.block_ip(
            "2001:db8::10"
        )

        self.assertEqual(
            result,
            FirewallResult.UNSUPPORTED_IP_VERSION,
        )

    def test_whitelisted_ip_is_not_blocked(self):
        firewall = self.make_firewall()

        result = firewall.block_ip(
            "100.71.142.40"
        )

        self.assertEqual(
            result,
            FirewallResult.WHITELISTED,
        )

    def test_dry_run_does_not_call_nftables(self):
        firewall = self.make_firewall(
            response_mode="dry-run"
        )

        with patch.object(
            firewall,
            "_run_nft",
        ) as mock_run_nft:

            result = firewall.block_ip(
                "192.0.2.10"
            )

        self.assertEqual(
            result,
            FirewallResult.DRY_RUN,
        )

        mock_run_nft.assert_not_called()

    @patch(
        "core.firewall.subprocess.run"
    )
    def test_successful_real_block_returns_blocked(
        self,
        mock_subprocess_run,
    ):
        firewall = self.make_firewall()

        mock_subprocess_run.return_value = (
            subprocess.CompletedProcess(
                args=["nft"],
                returncode=0,
                stdout="",
                stderr="",
            )
        )

        result = firewall.block_ip(
            "192.0.2.10"
        )

        self.assertEqual(
            result,
            FirewallResult.BLOCKED,
        )

        self.assertTrue(
            mock_subprocess_run.called
        )

    @patch(
        "core.firewall.subprocess.run"
    )
    def test_already_blocked_ip_returns_specific_result(
        self,
        mock_subprocess_run,
    ):
        firewall = self.make_firewall()

        mock_subprocess_run.return_value = (
            subprocess.CompletedProcess(
                args=["nft"],
                returncode=1,
                stdout="",
                stderr=(
                    "Error: Could not process rule: "
                    "File exists"
                ),
            )
        )

        result = firewall.block_ip(
            "192.0.2.10"
        )

        self.assertEqual(
            result,
            FirewallResult.ALREADY_BLOCKED,
        )

    @patch(
        "core.firewall.subprocess.run"
    )
    def test_unexpected_nft_error_raises_exception(
        self,
        mock_subprocess_run,
    ):
        firewall = self.make_firewall()

        mock_subprocess_run.return_value = (
            subprocess.CompletedProcess(
                args=["nft"],
                returncode=1,
                stdout="",
                stderr="Permission denied",
            )
        )

        with self.assertRaises(
            RuntimeError
        ):
            firewall.block_ip(
                "192.0.2.10"
            )

    @patch(
        "core.firewall.subprocess.run"
    )
    def test_setup_preserves_existing_table(
        self,
        mock_subprocess_run,
    ):
        firewall = self.make_firewall()

        mock_subprocess_run.return_value = (
            subprocess.CompletedProcess(
                args=["nft"],
                returncode=0,
                stdout=(
                    "table inet sshguard"
                ),
                stderr="",
            )
        )

        firewall.setup()

        self.assertEqual(
            mock_subprocess_run.call_count,
            1,
        )

    def test_dry_run_setup_does_not_touch_nftables(self):
        firewall = self.make_firewall(
            response_mode="dry-run"
        )

        with patch.object(
            firewall,
            "_run_nft",
        ) as mock_run_nft:

            firewall.setup()

        mock_run_nft.assert_not_called()

    @patch(
        "core.firewall.subprocess.run"
    )
    def test_manual_unblock_success(
        self,
        mock_subprocess_run,
    ):
        firewall = self.make_firewall()

        mock_subprocess_run.return_value = (
            subprocess.CompletedProcess(
                args=["nft"],
                returncode=0,
                stdout="",
                stderr="",
            )
        )

        result = firewall.unblock_ip(
            "192.0.2.10"
        )

        self.assertTrue(result)

    @patch(
        "core.firewall.subprocess.run"
    )
    def test_manual_unblock_missing_ip_returns_false(
        self,
        mock_subprocess_run,
    ):
        firewall = self.make_firewall()

        mock_subprocess_run.return_value = (
            subprocess.CompletedProcess(
                args=["nft"],
                returncode=1,
                stdout="",
                stderr="No such file or directory",
            )
        )

        result = firewall.unblock_ip(
            "192.0.2.10"
        )

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
