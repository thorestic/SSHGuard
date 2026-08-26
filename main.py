import logging
from datetime import datetime, timedelta, timezone

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
from core.database import DatabaseManager
from core.block_monitor import BlockLifecycleMonitor
from core.logging_config import setup_logging


logger = logging.getLogger(__name__)


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
    # Configure console + file logging before
    # initializing the rest of the application.
    setup_logging()

    logger.info(
        "SSHGuard application starting"
    )

    # Detection engine.
    detector = BruteForceDetector(
        threshold=THRESHOLD,
        window_seconds=WINDOW_SECONDS,
    )

    # Persistent structured storage.
    database = DatabaseManager()

    # Automated firewall response.
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

    # Initialize/preserve SSHGuard's nftables state.
    try:
        firewall.setup()

    except Exception as error:
        logger.exception(
            "Firewall initialization failed: %s",
            error,
        )

        return

    logger.info(
        "Firewall initialized successfully "
        "in %s mode",
        RESPONSE_MODE.upper(),
    )

    # Start lifecycle monitoring only after
    # firewall initialization succeeds.
    block_monitor = BlockLifecycleMonitor(
        database=database,
    )

    block_monitor.start()

    logger.info(
        "Block lifecycle monitor started"
    )

    print("\n[+] SSH event monitoring started")
    print("[+] Waiting for authentication events...\n")

    logger.info(
        "SSH authentication event monitoring started"
    )

    try:
        for event in stream_ssh_events():
            # Display normalized authentication event.
            display_event(event)

            # Persist every relevant SSH authentication event.
            database.save_auth_event(event)

            # Pass event into detection engine.
            incident = detector.process_event(event)

            if incident is None:
                continue

            # A real security incident has been detected.
            display_incident(incident)

            # Save the incident even if the firewall
            # response later fails.
            incident_id = database.save_incident(
                incident
            )

            logger.warning(
                "Brute-force incident #%s detected "
                "from IP %s against user %s "
                "after %s failed attempts",
                incident_id,
                incident["source_ip"],
                incident["username"],
                incident["attempt_count"],
            )

            # Attempt automated firewall response.
            try:
                block_applied = firewall.block_ip(
                    incident["source_ip"]
                )

            except Exception as error:
                # Detection succeeded, but response failed.
                database.update_incident_status(
                    incident_id,
                    "response_failed",
                )

                logger.exception(
                    "Firewall response failed "
                    "for incident #%s from IP %s: %s",
                    incident_id,
                    incident["source_ip"],
                    error,
                )

                continue

            # A firewall action is stored only when
            # a real block was actually applied.
            if (
                block_applied
                and RESPONSE_MODE == "real"
            ):
                blocked_at = datetime.now(
                    timezone.utc
                )

                expires_at = blocked_at + timedelta(
                    seconds=BLOCK_DURATION_SECONDS
                )

                block_action_id = (
                    database.save_firewall_action(
                        source_ip=incident["source_ip"],
                        action="block",
                        timestamp=blocked_at.isoformat(),
                        expires_at=expires_at.isoformat(),
                        incident_id=incident_id,
                    )
                )

                database.update_incident_status(
                    incident_id,
                    "blocked",
                )

                logger.warning(
                    "Firewall block action #%s applied "
                    "to IP %s for incident #%s; "
                    "scheduled expiration at %s",
                    block_action_id,
                    incident["source_ip"],
                    incident_id,
                    expires_at.isoformat(),
                )

                print(
                    "[DATABASE] "
                    f"Block action #{block_action_id} "
                    f"linked to incident #{incident_id}"
                )

            elif RESPONSE_MODE == "dry-run":
                logger.info(
                    "Dry-run firewall response simulated "
                    "for incident #%s from IP %s",
                    incident_id,
                    incident["source_ip"],
                )

            else:
                # block_ip() returned False.
                # This can happen for cases such as
                # whitelisted or already-blocked IPs.
                logger.warning(
                    "No new firewall block was applied "
                    "for incident #%s from IP %s",
                    incident_id,
                    incident["source_ip"],
                )

    except KeyboardInterrupt:
        logger.info(
            "SSHGuard stopped by administrator"
        )

        print(
            "\n[+] SSHGuard stopped by administrator"
        )

    except Exception as error:
        logger.exception(
            "Unhandled error in SSH event loop: %s",
            error,
        )

        raise


if __name__ == "__main__":
    main()
