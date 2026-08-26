import logging
import os
import time
from logging.handlers import RotatingFileHandler


def setup_logging(
    log_path="logs/sshguard.log",
):
    log_directory = os.path.dirname(log_path)

    if log_directory:
        os.makedirs(
            log_directory,
            exist_ok=True,
        )

    root_logger = logging.getLogger()

    # Prevent duplicate handlers if setup_logging()
    # is accidentally called more than once.
    if getattr(
        root_logger,
        "_sshguard_configured",
        False,
    ):
        return

    root_logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s "
        "%(levelname)-8s "
        "%(name)s - "
        "%(message)s"
    )

    # Keep timestamps consistent with the rest
    # of SSHGuard, which currently uses UTC.
    formatter.converter = time.gmtime

    console_handler = logging.StreamHandler()

    console_handler.setFormatter(
        formatter
    )

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=2_000_000,
        backupCount=5,
        encoding="utf-8",
    )

    file_handler.setFormatter(
        formatter
    )

    root_logger.addHandler(
        console_handler
    )

    root_logger.addHandler(
        file_handler
    )

    root_logger._sshguard_configured = True
