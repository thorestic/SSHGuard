import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DashboardSettings:
    """Runtime settings kept separate from the security-core config."""

    database_path: Path
    web_dist_path: Path
    cors_origins: tuple[str, ...]
    live_poll_seconds: float
    live_heartbeat_seconds: float
    reconciliation_stale_seconds: float

    @classmethod
    def from_environment(cls) -> "DashboardSettings":
        origins = os.getenv(
            "SSHGUARD_DASHBOARD_CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173",
        )

        return cls(
            database_path=Path(
                os.getenv(
                    "SSHGUARD_DATABASE_PATH",
                    "data/sshguard.db",
                )
            ),
            web_dist_path=Path(
                os.getenv(
                    "SSHGUARD_WEB_DIST_PATH",
                    "dashboard/web/dist",
                )
            ),
            cors_origins=tuple(
                origin.strip()
                for origin in origins.split(",")
                if origin.strip()
            ),
            live_poll_seconds=cls._positive_float(
                "SSHGUARD_LIVE_POLL_SECONDS",
                1.0,
            ),
            live_heartbeat_seconds=cls._positive_float(
                "SSHGUARD_LIVE_HEARTBEAT_SECONDS",
                15.0,
            ),
            reconciliation_stale_seconds=cls._positive_float(
                "SSHGUARD_RECONCILIATION_STALE_SECONDS",
                30.0,
            ),
        )

    @staticmethod
    def _positive_float(name: str, default: float) -> float:
        raw_value = os.getenv(name)

        if raw_value is None:
            return default

        try:
            value = float(raw_value)
        except ValueError as error:
            raise ValueError(f"{name} must be a number") from error

        if value <= 0:
            raise ValueError(f"{name} must be greater than zero")

        return value
