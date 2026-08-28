import unittest

from core.detector import BruteForceDetector


class BruteForceDetectorTests(unittest.TestCase):

    def setUp(self):
        self.detector = BruteForceDetector(
            threshold=3,
            window_seconds=20,
        )

    def make_event(
        self,
        source_ip,
        timestamp,
        username="alice",
        event_type="failed_login",
    ):
        return {
            "event_type": event_type,
            "username": username,
            "source_ip": source_ip,
            "source_port": 50000,
            "timestamp": timestamp,
        }

    def test_detects_at_threshold(self):
        """
        Three failed attempts from the same IP
        inside the configured window should
        generate exactly one incident.
        """

        first = self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:00+00:00",
            )
        )

        second = self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:05+00:00",
            )
        )

        third = self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:10+00:00",
            )
        )

        self.assertIsNone(first)
        self.assertIsNone(second)

        self.assertIsNotNone(third)

        self.assertEqual(
            third["event_type"],
            "brute_force_detected",
        )

        self.assertEqual(
            third["source_ip"],
            "10.0.0.5",
        )

        self.assertEqual(
            third["attempt_count"],
            3,
        )

    def test_does_not_detect_below_threshold(self):
        """
        Two failures should not trigger an incident
        when threshold is three.
        """

        first = self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:00+00:00",
            )
        )

        second = self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:05+00:00",
            )
        )

        self.assertIsNone(first)
        self.assertIsNone(second)

    def test_tracks_ips_independently(self):
        """
        Attempts from different IP addresses
        must not be combined.
        """

        self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:00+00:00",
            )
        )

        self.detector.process_event(
            self.make_event(
                "10.0.0.8",
                "2026-08-27T10:00:02+00:00",
            )
        )

        self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:05+00:00",
            )
        )

        result = self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:10+00:00",
            )
        )

        self.assertIsNotNone(result)

        self.assertEqual(
            result["source_ip"],
            "10.0.0.5",
        )

        self.assertEqual(
            result["attempt_count"],
            3,
        )

    def test_successful_login_is_ignored(self):
        """
        Successful authentication events must not
        increase the brute-force counter.
        """

        self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:00+00:00",
            )
        )

        successful_result = (
            self.detector.process_event(
                self.make_event(
                    "10.0.0.5",
                    "2026-08-27T10:00:03+00:00",
                    event_type="successful_login",
                )
            )
        )

        second_failure = (
            self.detector.process_event(
                self.make_event(
                    "10.0.0.5",
                    "2026-08-27T10:00:05+00:00",
                )
            )
        )

        self.assertIsNone(
            successful_result
        )

        self.assertIsNone(
            second_failure
        )

    def test_old_attempts_leave_sliding_window(self):
        """
        Attempts older than the configured
        20-second window must not count.
        """

        self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:00+00:00",
            )
        )

        self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:05+00:00",
            )
        )

        result = self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:30+00:00",
            )
        )

        self.assertIsNone(result)

        self.assertEqual(
            len(
                self.detector.failed_attempts[
                    "10.0.0.5"
                ]
            ),
            1,
        )

    def test_duplicate_incident_is_suppressed(self):
        """
        Once an incident becomes active,
        further attempts in the same attack
        should not generate duplicate incidents.
        """

        self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:00+00:00",
            )
        )

        self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:05+00:00",
            )
        )

        incident = self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:10+00:00",
            )
        )

        duplicate = self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:12+00:00",
            )
        )

        self.assertIsNotNone(incident)
        self.assertIsNone(duplicate)

    def test_new_incident_after_old_window_expires(self):
        """
        After the previous attack ages out of
        the sliding window, the same IP should
        be able to generate a new incident.
        """

        self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:00+00:00",
            )
        )

        self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:00:05+00:00",
            )
        )

        first_incident = (
            self.detector.process_event(
                self.make_event(
                    "10.0.0.5",
                    "2026-08-27T10:00:10+00:00",
                )
            )
        )

        self.assertIsNotNone(
            first_incident
        )

        # This event occurs after all previous
        # attempts have left the 20-second window.
        reset_event = (
            self.detector.process_event(
                self.make_event(
                    "10.0.0.5",
                    "2026-08-27T10:01:00+00:00",
                )
            )
        )

        self.assertIsNone(
            reset_event
        )

        self.detector.process_event(
            self.make_event(
                "10.0.0.5",
                "2026-08-27T10:01:05+00:00",
            )
        )

        second_incident = (
            self.detector.process_event(
                self.make_event(
                    "10.0.0.5",
                    "2026-08-27T10:01:10+00:00",
                )
            )
        )

        self.assertIsNotNone(
            second_incident
        )

    def test_invalid_threshold_rejected(self):
        with self.assertRaises(ValueError):
            BruteForceDetector(
                threshold=0,
                window_seconds=20,
            )

    def test_invalid_window_rejected(self):
        with self.assertRaises(ValueError):
            BruteForceDetector(
                threshold=3,
                window_seconds=0,
            )


if __name__ == "__main__":
    unittest.main()
