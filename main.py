import logging
from datetime import (
    datetime,
    timedelta,
    timezone,
)

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
from core.firewall import (
    FirewallManager,
    FirewallResult,
)
from core.database import DatabaseManager
from core.block_monitor import (
    BlockLifecycleMonitor,
)
from core.logging_config import setup_logging
from core.runtime_config import RuntimeSettings


logger = logging.getLogger(__name__)


def display_event(event):
    if event["event_type"] == "failed_login":
        print(
            "[FAILED LOGIN] "
            f"IP={event['source_ip']} "
            f"USER={event['username']} "
            f"PORT={event['source_port']} "
            f"INVALID_USER="
            f"{event['invalid_user']} "
            f"TIME={event['timestamp']}"
        )

    elif (
        event["event_type"]
        == "successful_login"
    ):
        print(
            "[SUCCESSFUL LOGIN] "
            f"IP={event['source_ip']} "
            f"USER={event['username']} "
            f"PORT={event['source_port']} "
            f"TIME={event['timestamp']}"
        )


def display_incident(incident):
    print(
        "\n"
        "======================================"
    )
    print(
        "[!!!] BRUTE FORCE DETECTED"
    )
    print(
        "--------------------------------------"
    )
    print(
        f"Source IP:   "
        f"{incident['source_ip']}"
    )
    print(
        f"Username:    "
        f"{incident['username']}"
    )
    print(
        f"Attempts:    "
        f"{incident['attempt_count']}"
    )
    print(
        f"First Seen:  "
        f"{incident['first_seen']}"
    )
    print(
        f"Last Seen:   "
        f"{incident['last_seen']}"
    )
    print(
        f"Time Window: "
        f"{incident['window_seconds']} "
        "seconds"
    )
    print(
        "======================================"
    )


def main():
    settings = RuntimeSettings.from_environment()

    setup_logging(
        log_path=str(settings.log_path)
    )

    logger.info(
        "SSHGuard application starting"
    )

    detector = BruteForceDetector(
        threshold=THRESHOLD,
        window_seconds=WINDOW_SECONDS,
    )

    database = DatabaseManager(
        database_path=str(
            settings.database_path
        )
    )

    firewall = FirewallManager(
        protected_port=PROTECTED_SSH_PORT,
        block_duration_seconds=(
            BLOCK_DURATION_SECONDS
        ),
        whitelist_networks=(
            WHITELIST_NETWORKS
        ),
        response_mode=RESPONSE_MODE,
    )

    print(
        "======================================"
    )
    print(" SSHGuard")
    print(" Brute-Force Detection")
    print(
        " & Automatic Blocking System"
    )
    print(
        "======================================"
    )
    print(
        f"Threshold:       {THRESHOLD}"
    )
    print(
        f"Time Window:     "
        f"{WINDOW_SECONDS}s"
    )
    print(
        f"Block Duration:  "
        f"{BLOCK_DURATION_SECONDS}s"
    )
    print(
        f"SSH Port:        "
        f"{PROTECTED_SSH_PORT}"
    )
    print(
        f"Response Mode:   "
        f"{RESPONSE_MODE.upper()}"
    )
    print(
        "======================================"
        "\n"
    )

    try:
        firewall.setup()

    except Exception as error:
        logger.exception(
            "Firewall initialization "
            "failed: %s",
            error,
        )

        return

    logger.info(
        "Firewall initialized successfully "
        "in %s mode",
        RESPONSE_MODE.upper(),
    )

    block_monitor = BlockLifecycleMonitor(
        database=database,
    )

    block_monitor.start()

    logger.info(
        "Block lifecycle monitor started"
    )

    print(
        "\n[+] SSH event monitoring started"
    )
    print(
        "[+] Waiting for authentication "
        "events...\n"
    )

    logger.info(
        "SSH authentication event "
        "monitoring started"
    )

    try:
        for event in stream_ssh_events():
            display_event(event)

            database.save_auth_event(
                event
            )

            incident = (
                detector.process_event(
                    event
                )
            )

            if incident is None:
                continue

            display_incident(
                incident
            )

            # Detection is real regardless of whether
            # the response later succeeds, fails,
            # or is intentionally skipped.
            incident_id = (
                database.save_incident(
                    incident
                )
            )

            logger.warning(
                "Brute-force incident #%s "
                "detected from IP %s "
                "against user %s after %s "
                "failed attempts",
                incident_id,
                incident["source_ip"],
                incident["username"],
                incident["attempt_count"],
            )

            try:
                response_result = (
                    firewall.block_ip(
                        incident[
                            "source_ip"
                        ]
                    )
                )

            except Exception as error:
                database.update_incident_response(
                    incident_id=incident_id,
                    status="response_failed",
                    response_outcome=(
                        "firewall_error"
                    ),
                )

                logger.exception(
                    "Firewall response failed "
                    "for incident #%s "
                    "from IP %s: %s",
                    incident_id,
                    incident["source_ip"],
                    error,
                )

                continue

            if (
                response_result
                == FirewallResult.BLOCKED
            ):
                blocked_at = datetime.now(
                    timezone.utc
                )

                expires_at = (
                    blocked_at
                    + timedelta(
                        seconds=(
                            BLOCK_DURATION_SECONDS
                        )
                    )
                )

                block_action_id = (
                    database.save_firewall_action(
                        source_ip=(
                            incident[
                                "source_ip"
                            ]
                        ),
                        action="block",
                        timestamp=(
                            blocked_at
                            .isoformat()
                        ),
                        expires_at=(
                            expires_at
                            .isoformat()
                        ),
                        incident_id=(
                            incident_id
                        ),
                    )
                )

                database.update_incident_response(
                    incident_id=incident_id,
                    status="blocked",
                    response_outcome=(
                        response_result.value
                    ),
                )

                logger.warning(
                    "Firewall block action #%s "
                    "applied to IP %s for "
                    "incident #%s; scheduled "
                    "expiration at %s",
                    block_action_id,
                    incident["source_ip"],
                    incident_id,
                    expires_at.isoformat(),
                )

                print(
                    "[DATABASE] "
                    f"Block action "
                    f"#{block_action_id} "
                    f"linked to incident "
                    f"#{incident_id}"
                )

            elif (
                response_result
                == FirewallResult.DRY_RUN
            ):
                database.update_incident_response(
                    incident_id=incident_id,
                    status="response_skipped",
                    response_outcome=(
                        response_result.value
                    ),
                )

                logger.info(
                    "Firewall response for "
                    "incident #%s from IP %s "
                    "was simulated in dry-run "
                    "mode",
                    incident_id,
                    incident["source_ip"],
                )

            else:
                database.update_incident_response(
                    incident_id=incident_id,
                    status="response_skipped",
                    response_outcome=(
                        response_result.value
                    ),
                )

                logger.warning(
                    "Firewall response skipped "
                    "for incident #%s from IP %s; "
                    "outcome=%s",
                    incident_id,
                    incident["source_ip"],
                    response_result.value,
                )

    except KeyboardInterrupt:
        logger.info(
            "SSHGuard stopped by "
            "administrator"
        )

        print(
            "\n[+] SSHGuard stopped by "
            "administrator"
        )

    except Exception as error:
        logger.exception(
            "Unhandled error in SSH event "
            "loop: %s",
            error,
        )

        raise


if __name__ == "__main__":
    main()
