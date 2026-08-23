import json
import re
import subprocess
from datetime import datetime, timezone


FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for "
    r"(?:(?P<invalid_user>invalid user) )?"
    r"(?P<username>\S+) "
    r"from (?P<source_ip>[0-9a-fA-F:.]+) "
    r"port (?P<source_port>\d+)"
)

ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"Accepted password for "
    r"(?P<username>\S+) "
    r"from (?P<source_ip>[0-9a-fA-F:.]+) "
    r"port (?P<source_port>\d+)"
)


def parse_ssh_message(message: str):
    """
    Convert one raw OpenSSH message into
    a normalized SSH event.
    """

    failed_match = FAILED_PASSWORD_PATTERN.search(message)

    if failed_match:
        return {
            "event_type": "failed_login",
            "username": failed_match.group("username"),
            "source_ip": failed_match.group("source_ip"),
            "source_port": int(
                failed_match.group("source_port")
            ),
            "invalid_user": bool(
                failed_match.group("invalid_user")
            ),
        }

    accepted_match = ACCEPTED_PASSWORD_PATTERN.search(
        message
    )

    if accepted_match:
        return {
            "event_type": "successful_login",
            "username": accepted_match.group("username"),
            "source_ip": accepted_match.group("source_ip"),
            "source_port": int(
                accepted_match.group("source_port")
            ),
            "invalid_user": False,
        }

    return None


def stream_ssh_events():
    """
    Follow new OpenSSH systemd journal events
    and yield normalized SSH events.
    """

    command = [
        "journalctl",
        "-u",
        "ssh",
        "-f",
        "-n",
        "0",
        "-o",
        "json",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    for line in process.stdout:
        try:
            journal_event = json.loads(line)

            message = journal_event.get(
                "MESSAGE",
                "",
            )

            parsed_event = parse_ssh_message(
                message
            )

            if parsed_event is None:
                continue

            timestamp_microseconds = int(
                journal_event.get(
                    "__REALTIME_TIMESTAMP",
                    0,
                )
            )

            timestamp = datetime.fromtimestamp(
                timestamp_microseconds / 1_000_000,
                tz=timezone.utc,
            )

            parsed_event["timestamp"] = (
                timestamp.isoformat()
            )

            yield parsed_event

        except (json.JSONDecodeError, ValueError):
            continue
