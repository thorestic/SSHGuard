from collections import defaultdict, deque
from datetime import datetime, timedelta


class BruteForceDetector:
    def __init__(self, threshold: int, window_seconds: int):
        if threshold <= 0:
            raise ValueError("threshold must be greater than zero")

        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")

        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

        # Stores recent failed-login timestamps separately for each IP.
        self.failed_attempts = defaultdict(deque)

        # Prevents repeated alerts for the same continuous attack.
        self.active_incidents = set()

    def process_event(self, event: dict):
        """
        Process one normalized SSH event.

        Returns:
            None:
                if the event does not create a new brute-force incident.

            dict:
                if a new brute-force incident is detected.
        """

        # Brute-force counting only uses failed-login events.
        if event.get("event_type") != "failed_login":
            return None

        source_ip = event["source_ip"]

        event_time = datetime.fromisoformat(
            event["timestamp"]
        )

        # Get this IP's own attempt history.
        attempts = self.failed_attempts[source_ip]

        # Add the newest failed attempt.
        attempts.append(event_time)

        # Calculate the beginning of the current sliding window.
        cutoff_time = event_time - self.window

        # Remove attempts that are now too old.
        while attempts and attempts[0] < cutoff_time:
            attempts.popleft()

        attempt_count = len(attempts)

        print(
            f"[DETECTOR] IP={source_ip} "
            f"ATTEMPTS={attempt_count}/{self.threshold}"
        )

        # If the IP has fallen below the threshold,
        # any previous incident can be considered inactive.
        if attempt_count < self.threshold:
            self.active_incidents.discard(source_ip)
            return None

        # The attack has already generated an incident.
        # Avoid creating a new alert for every additional attempt.
        if source_ip in self.active_incidents:
            print(
                f"[DETECTOR] IP={source_ip} "
                "INCIDENT_ALREADY_ACTIVE"
            )
            return None

        # This is the first time the IP has reached
        # the threshold during this attack.
        self.active_incidents.add(source_ip)

        return {
            "event_type": "brute_force_detected",
            "source_ip": source_ip,
            "username": event["username"],
            "attempt_count": attempt_count,
            "first_seen": attempts[0].isoformat(),
            "last_seen": event["timestamp"],
            "window_seconds": int(
                self.window.total_seconds()
            ),
        }
