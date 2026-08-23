from config import (
    THRESHOLD,
    WINDOW_SECONDS,
    BLOCK_DURATION_SECONDS,
    PROTECTED_SSH_PORT,
    RESPONSE_MODE,
    WHITELIST_NETWORKS,
)

from core.log_parser import stream_ssh_events
from core.detector import BruteForceDetector
from core.firewall import FirewallManager


def display_event(event):
    if event["event_type"] == "failed_login":
        print(
            "[FAILED LOGIN] "
            f"IP={event['source_ip']} "
            f"USER={event['username']} "
            f"PORT={event['source_port']} "
            f"INVALID_USER={event['invalid_user']} "
            f"TIME={event['timestamp']}"
        )

    elif event["event_type"] == "successful_login":
        print(
            "[SUCCESSFUL LOGIN] "
            f"IP={event['source_ip']} "
            f"USER={event['username']} "
            f"PORT={event['source_port']} "
            f"TIME={event['timestamp']}"
        )


def display_incident(incident):
    print("\n======================================")
    print("[!!!] BRUTE FORCE DETECTED")
    print("--------------------------------------")
    print(f"Source IP:   {incident['source_ip']}")
    print(f"Username:    {incident['username']}")
    print(f"Attempts:    {incident['attempt_count']}")
    print(f"First Seen:  {incident['first_seen']}")
    print(f"Last Seen:   {incident['last_seen']}")
    print(
        f"Time Window: "
        f"{incident['window_seconds']} seconds"
    )
    print("======================================")


def main():
    detector = BruteForceDetector(
        threshold=THRESHOLD,
        window_seconds=WINDOW_SECONDS,
    )

    firewall = FirewallManager(
        protected_port=PROTECTED_SSH_PORT,
        block_duration_seconds=BLOCK_DURATION_SECONDS,
        whitelist_networks=WHITELIST_NETWORKS,
        response_mode=RESPONSE_MODE,
    )

    print("======================================")
    print(" SSHGuard")
    print(" Brute-Force Detection")
    print(" & Automatic Blocking System")
    print("======================================")
    print(f"Threshold:       {THRESHOLD}")
    print(f"Time Window:     {WINDOW_SECONDS}s")
    print(f"Block Duration:  {BLOCK_DURATION_SECONDS}s")
    print(f"SSH Port:        {PROTECTED_SSH_PORT}")
    print(f"Response Mode:   {RESPONSE_MODE.upper()}")
    print("======================================\n")

    firewall.setup()

    print("\n[+] SSH event monitoring started")
    print("[+] Waiting for authentication events...\n")

    try:
        for event in stream_ssh_events():

            # Show the normalized authentication event.
            display_event(event)

            # Send the event into the detection engine.
            incident = detector.process_event(event)

            if incident is None:
                continue

            # A new brute-force incident was detected.
            display_incident(incident)

            # Automated response.
            firewall.block_ip(
                incident["source_ip"]
            )

    except KeyboardInterrupt:
        print("\n[+] SSHGuard stopped by administrator")


if __name__ == "__main__":
    main()
