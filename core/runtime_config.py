import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RuntimeSettings:
    """Filesystem locations used by the security core."""

    database_path: Path
    log_path: Path

    @classmethod
    def from_environment(cls) -> "RuntimeSettings":
        return cls(
            database_path=Path(
                os.getenv(
                    "SSHGUARD_DATABASE_PATH",
                    "data/sshguard.db",
                )
            ),
            log_path=Path(
                os.getenv(
                    "SSHGUARD_LOG_PATH",
                    "logs/sshguard.log",
                )
            ),
        )
