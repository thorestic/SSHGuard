import os
import unittest
from pathlib import Path
from unittest.mock import patch

from core.runtime_config import RuntimeSettings


class RuntimeSettingsTests(unittest.TestCase):
    def test_development_paths_remain_the_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            settings = RuntimeSettings.from_environment()

        self.assertEqual(
            settings.database_path,
            Path("data/sshguard.db"),
        )
        self.assertEqual(
            settings.log_path,
            Path("logs/sshguard.log"),
        )

    def test_production_paths_can_be_supplied_by_systemd(self):
        with patch.dict(
            os.environ,
            {
                "SSHGUARD_DATABASE_PATH": (
                    "/var/lib/sshguard/sshguard.db"
                ),
                "SSHGUARD_LOG_PATH": (
                    "/var/log/sshguard/sshguard.log"
                ),
            },
            clear=True,
        ):
            settings = RuntimeSettings.from_environment()

        self.assertEqual(
            settings.database_path,
            Path("/var/lib/sshguard/sshguard.db"),
        )
        self.assertEqual(
            settings.log_path,
            Path("/var/log/sshguard/sshguard.log"),
        )


if __name__ == "__main__":
    unittest.main()
