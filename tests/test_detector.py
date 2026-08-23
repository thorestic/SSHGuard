from core.detector import BruteForceDetector


detector = BruteForceDetector(
    threshold=3,
    window_seconds=20,
)


events = [
    # IP A - failure #1
    {
        "event_type": "failed_login",
        "username": "alice",
        "source_ip": "10.0.0.5",
        "source_port": 50001,
        "timestamp": "2026-08-17T10:00:00+00:00",
    },

    # IP B - failure #1
    {
        "event_type": "failed_login",
        "username": "bob",
        "source_ip": "10.0.0.8",
        "source_port": 51001,
        "timestamp": "2026-08-17T10:00:02+00:00",
    },

    # IP A - failure #2
    {
        "event_type": "failed_login",
        "username": "alice",
        "source_ip": "10.0.0.5",
        "source_port": 50002,
        "timestamp": "2026-08-17T10:00:05+00:00",
    },

    # IP A - successful login
    {
        "event_type": "successful_login",
        "username": "alice",
        "source_ip": "10.0.0.5",
        "source_port": 50002,
        "timestamp": "2026-08-17T10:00:07+00:00",
    },

    # IP B - failure #2
    {
        "event_type": "failed_login",
        "username": "bob",
        "source_ip": "10.0.0.8",
        "source_port": 51002,
        "timestamp": "2026-08-17T10:00:09+00:00",
    },

    # IP A - failure #3 → should trigger detection
    {
        "event_type": "failed_login",
        "username": "alice",
        "source_ip": "10.0.0.5",
        "source_port": 50003,
        "timestamp": "2026-08-17T10:00:12+00:00",
    },
]


for event in events:
    incident = detector.process_event(event)

    if incident:
        print("\n[!!!] BRUTE FORCE DETECTED")
        print(incident)
