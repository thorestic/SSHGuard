import logging
import threading
import time
from datetime import datetime, timezone


logger = logging.getLogger(__name__)


class BlockLifecycleMonitor:
    def __init__(
        self,
        database,
        check_interval_seconds: int = 2,
    ):
        self.database = database
        self.check_interval_seconds = (
            check_interval_seconds
        )

    def _check_expired_blocks(self):
        current_time = datetime.now(
            timezone.utc
        )

        expired_blocks = (
            self.database.get_expired_unlogged_blocks(
                current_time.isoformat()
            )
        )

        for (
            block_action_id,
            incident_id,
            source_ip,
            expires_at,
        ) in expired_blocks:

            # Record when the block was scheduled
            # to expire, not when the monitor happened
            # to notice it.
            expired_action_id = (
                self.database.save_firewall_action(
                    source_ip=source_ip,
                    action="expired",
                    timestamp=expires_at,
                    incident_id=incident_id,
                    related_action_id=block_action_id,
                )
            )

            if incident_id is not None:
                self.database.update_incident_status(
                    incident_id,
                    "resolved",
                )

            logger.info(
                "Firewall block action #%s for IP %s "
                "expired; recorded as action #%s "
                "for incident #%s",
                block_action_id,
                source_ip,
                expired_action_id,
                incident_id,
            )

    def run(self):
        while True:
            try:
                self._check_expired_blocks()

            except Exception as error:
                logger.exception(
                    "Block lifecycle monitor failed: %s",
                    error,
                )

            time.sleep(
                self.check_interval_seconds
            )

    def start(self):
        thread = threading.Thread(
            target=self.run,
            daemon=True,
            name="sshguard-block-monitor",
        )

        thread.start()
