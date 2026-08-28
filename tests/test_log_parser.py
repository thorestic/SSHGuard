import unittest

from core.log_parser import parse_ssh_message


class SSHLogParserTests(unittest.TestCase):

    def test_parses_failed_password(self):
        message = (
            "Failed password for mc "
            "from 192.168.0.11 "
            "port 51546 ssh2"
        )

        event = parse_ssh_message(message)

        self.assertIsNotNone(event)

        self.assertEqual(
            event["event_type"],
            "failed_login",
        )

        self.assertEqual(
            event["username"],
            "mc",
        )

        self.assertEqual(
            event["source_ip"],
            "192.168.0.11",
        )

        self.assertEqual(
            event["source_port"],
            51546,
        )

        self.assertFalse(
            event["invalid_user"]
        )

    def test_parses_invalid_user_failure(self):
        message = (
            "Failed password for invalid user attacker "
            "from 192.168.0.50 "
            "port 44000 ssh2"
        )

        event = parse_ssh_message(message)

        self.assertIsNotNone(event)

        self.assertEqual(
            event["event_type"],
            "failed_login",
        )

        self.assertEqual(
            event["username"],
            "attacker",
        )

        self.assertEqual(
            event["source_ip"],
            "192.168.0.50",
        )

        self.assertEqual(
            event["source_port"],
            44000,
        )

        self.assertTrue(
            event["invalid_user"]
        )

    def test_parses_successful_password_login(self):
        message = (
            "Accepted password for mc "
            "from 100.71.142.40 "
            "port 53635 ssh2"
        )

        event = parse_ssh_message(message)

        self.assertIsNotNone(event)

        self.assertEqual(
            event["event_type"],
            "successful_login",
        )

        self.assertEqual(
            event["username"],
            "mc",
        )

        self.assertEqual(
            event["source_ip"],
            "100.71.142.40",
        )

        self.assertEqual(
            event["source_port"],
            53635,
        )

        self.assertFalse(
            event["invalid_user"]
        )

    def test_ignores_pam_authentication_failure(self):
        """
        PAM can log authentication failure for the same
        SSH attempt.

        SSHGuard intentionally ignores this message so
        one failed password is not counted twice.
        """

        message = (
            "pam_unix(sshd:auth): authentication failure; "
            "logname= uid=0 euid=0 tty=ssh "
            "ruser= rhost=192.168.0.11 user=mc"
        )

        event = parse_ssh_message(message)

        self.assertIsNone(event)

    def test_ignores_session_open_message(self):
        message = (
            "pam_unix(sshd:session): "
            "session opened for user mc(uid=1000) "
            "by mc(uid=0)"
        )

        event = parse_ssh_message(message)

        self.assertIsNone(event)

    def test_ignores_unrelated_ssh_message(self):
        message = (
            "Connection closed by "
            "192.168.0.11 port 51546"
        )

        event = parse_ssh_message(message)

        self.assertIsNone(event)

    def test_empty_message_returns_none(self):
        event = parse_ssh_message("")

        self.assertIsNone(event)

    def test_parses_ipv6_failed_login(self):
        """
        The parser currently understands IPv6 syntax
        even though the firewall response layer is
        currently IPv4-only.
        """

        message = (
            "Failed password for mc "
            "from 2001:db8::10 "
            "port 55000 ssh2"
        )

        event = parse_ssh_message(message)

        self.assertIsNotNone(event)

        self.assertEqual(
            event["source_ip"],
            "2001:db8::10",
        )

        self.assertEqual(
            event["event_type"],
            "failed_login",
        )


if __name__ == "__main__":
    unittest.main()
