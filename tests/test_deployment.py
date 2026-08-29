import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_DIRECTORY = REPOSITORY_ROOT / "deploy"


class ProductionDeploymentTests(unittest.TestCase):
    def read_deploy_file(self, name: str) -> str:
        return (DEPLOY_DIRECTORY / name).read_text(
            encoding="utf-8"
        )

    def test_services_never_execute_from_a_user_home(self):
        for service_name in (
            "sshguard-project.service",
            "sshguard-dashboard-api.service",
        ):
            with self.subTest(service=service_name):
                service = self.read_deploy_file(
                    service_name
                )

                self.assertNotIn("/home/", service)
                self.assertIn(
                    "/opt/sshguard/current",
                    service,
                )

    def test_core_state_is_outside_the_code_directory(self):
        service = self.read_deploy_file(
            "sshguard-project.service"
        )

        self.assertIn(
            "SSHGUARD_DATABASE_PATH="
            "/var/lib/sshguard/sshguard.db",
            service,
        )
        self.assertIn(
            "SSHGUARD_LOG_PATH="
            "/var/log/sshguard/sshguard.log",
            service,
        )
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("ProtectHome=true", service)
        self.assertIn("ReadOnlyPaths=/opt/sshguard", service)

    def test_dashboard_keeps_read_only_shared_database_access(self):
        service = self.read_deploy_file(
            "sshguard-dashboard-api.service"
        )

        self.assertIn("User=mc", service)
        self.assertIn("Group=mc", service)
        self.assertIn(
            "SSHGUARD_DATABASE_PATH="
            "/var/lib/sshguard/sshguard.db",
            service,
        )
        self.assertIn(
            "ReadOnlyPaths=/opt/sshguard "
            "/var/lib/sshguard",
            service,
        )

    def test_installer_uses_committed_source_and_preserves_state(self):
        installer = self.read_deploy_file(
            "install-production.sh"
        )

        self.assertIn("dashboard/web/dist/index.html", installer)
        self.assertIn("chown -R root:root", installer)
        self.assertIn("chmod -R go-w", installer)
        self.assertIn(
            'chmod 0755 "${release_dir}"',
            installer,
        )
        self.assertIn(
            'find "${release_dir}/dashboard/web/dist"',
            installer,
        )
        self.assertIn("-type d -exec chmod 0755", installer)
        self.assertIn("-type f -exec chmod 0644", installer)
        self.assertIn("/var/backups/sshguard", installer)
        self.assertIn(
            'archive --format=tar "${revision}"',
            installer,
        )
        self.assertNotIn(
            "archive --format=tar HEAD",
            installer,
        )
        self.assertIn(
            "Built dashboard must not contain symlinks.",
            installer,
        )
        self.assertIn(
            "Copied dashboard must not contain symlinks.",
            installer,
        )
        self.assertIn("stop_service_if_loaded", installer)
        self.assertIn("systemctl enable", installer)

        stop_position = installer.index(
            "stop_service_if_loaded sshguard-dashboard-api.service"
        )
        migration_position = installer.index(
            'legacy_database="${source_dir}/data/sshguard.db"'
        )

        self.assertLess(stop_position, migration_position)

    def test_virtual_environment_is_created_at_final_path(self):
        installer = self.read_deploy_file(
            "install-production.sh"
        )

        move_position = installer.index(
            'mv "${stage_dir}" "${release_dir}"'
        )
        venv_position = installer.index(
            'python3 -m venv "${release_dir}/.venv"'
        )

        self.assertLess(move_position, venv_position)
        self.assertNotIn(
            'python3 -m venv "${stage_dir}/.venv"',
            installer,
        )


if __name__ == "__main__":
    unittest.main()
