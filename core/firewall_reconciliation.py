import json
import logging
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from core.ip_address import parse_source_address


logger = logging.getLogger(__name__)


class FirewallInspectionError(RuntimeError):
    """Raised when the current nftables state cannot be read safely."""


@dataclass(frozen=True)
class FirewallReconciliationResult:
    status: str
    checked_at: str
    expected_count: int
    actual_count: int | None
    missing_in_firewall: tuple[str, ...] = ()
    unexpected_in_firewall: tuple[str, ...] = ()
    error_code: str | None = None


class NftablesStateInspector:
    """Read SSHGuard's nftables sets without changing firewall state."""

    TABLE_NAME = "sshguard"
    BLOCK_SETS = (
        "blocked_ipv4",
        "blocked_ipv6",
    )

    def _read_set(self, set_name: str) -> dict:
        try:
            result = subprocess.run(
                [
                    "nft",
                    "-j",
                    "list",
                    "set",
                    "inet",
                    self.TABLE_NAME,
                    set_name,
                ],
                text=True,
                capture_output=True,
                timeout=5,
            )
        except (
            OSError,
            subprocess.TimeoutExpired,
        ) as error:
            raise FirewallInspectionError(
                "Could not execute nftables inspection"
            ) from error

        if result.returncode != 0:
            raise FirewallInspectionError(
                f"Could not inspect nftables set {set_name}"
            )

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise FirewallInspectionError(
                f"Invalid JSON returned for nftables set {set_name}"
            ) from error

    @staticmethod
    def _element_value(element):
        value = element

        if isinstance(value, dict) and "elem" in value:
            value = value["elem"]

        if isinstance(value, dict) and "val" in value:
            value = value["val"]

        return value

    def _addresses_from_payload(
        self,
        payload: dict,
        set_name: str,
    ) -> set[str]:
        entries = payload.get("nftables")

        if not isinstance(entries, list):
            raise FirewallInspectionError(
                f"Missing nftables data for set {set_name}"
            )

        matching_set = None

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            candidate = entry.get("set")
            if (
                isinstance(candidate, dict)
                and candidate.get("family") == "inet"
                and candidate.get("table") == self.TABLE_NAME
                and candidate.get("name") == set_name
            ):
                matching_set = candidate
                break

        if matching_set is None:
            raise FirewallInspectionError(
                f"Missing nftables set {set_name}"
            )

        elements = matching_set.get("elem", [])
        if not isinstance(elements, list):
            raise FirewallInspectionError(
                f"Invalid nftables elements for set {set_name}"
            )

        addresses: set[str] = set()

        for element in elements:
            value = self._element_value(element)

            if not isinstance(value, str):
                raise FirewallInspectionError(
                    f"Invalid address in nftables set {set_name}"
                )

            try:
                addresses.add(
                    str(parse_source_address(value))
                )
            except ValueError as error:
                raise FirewallInspectionError(
                    f"Invalid address in nftables set {set_name}"
                ) from error

        return addresses

    def list_blocked_addresses(self) -> set[str]:
        addresses: set[str] = set()

        for set_name in self.BLOCK_SETS:
            addresses.update(
                self._addresses_from_payload(
                    self._read_set(set_name),
                    set_name,
                )
            )

        return addresses


class FirewallReconciliationMonitor:
    """Compare expected and enforced blocks, then persist a report only."""

    def __init__(
        self,
        database,
        inspector,
        check_interval_seconds: int = 10,
    ):
        self.database = database
        self.inspector = inspector
        self.check_interval_seconds = check_interval_seconds
        self._last_signature = None

    @staticmethod
    def _canonicalize(addresses) -> set[str]:
        return {
            str(parse_source_address(address))
            for address in addresses
        }

    def _persist(
        self,
        result: FirewallReconciliationResult,
    ):
        items = [
            (source_ip, "missing_in_firewall")
            for source_ip in result.missing_in_firewall
        ]
        items.extend(
            (
                source_ip,
                "unexpected_in_firewall",
            )
            for source_ip in result.unexpected_in_firewall
        )

        self.database.replace_firewall_reconciliation(
            status=result.status,
            checked_at=result.checked_at,
            expected_count=result.expected_count,
            actual_count=result.actual_count,
            items=items,
            error_code=result.error_code,
        )

    def _log_transition(
        self,
        result: FirewallReconciliationResult,
    ):
        signature = (
            result.status,
            result.missing_in_firewall,
            result.unexpected_in_firewall,
            result.error_code,
        )

        if signature == self._last_signature:
            return

        self._last_signature = signature

        if result.status == "in_sync":
            logger.info(
                "Firewall reconciliation is in sync: %s active blocks",
                result.actual_count,
            )
        elif result.status == "drift":
            logger.warning(
                "Firewall reconciliation drift detected: "
                "missing=%s unexpected=%s",
                ",".join(result.missing_in_firewall) or "none",
                ",".join(result.unexpected_in_firewall) or "none",
            )
        else:
            logger.error(
                "Firewall reconciliation unavailable: %s",
                result.error_code,
            )

    def reconcile_once(self) -> FirewallReconciliationResult:
        checked_at = datetime.now(timezone.utc).isoformat()
        stored_expected = (
            self.database.get_expected_active_blocks(
                checked_at
            )
        )

        try:
            expected = self._canonicalize(stored_expected)
        except ValueError:
            result = FirewallReconciliationResult(
                status="unavailable",
                checked_at=checked_at,
                expected_count=len(stored_expected),
                actual_count=None,
                error_code="database_state_invalid",
            )
            self._persist(result)
            self._log_transition(result)
            return result

        try:
            actual = self._canonicalize(
                self.inspector.list_blocked_addresses()
            )
        except FirewallInspectionError:
            result = FirewallReconciliationResult(
                status="unavailable",
                checked_at=checked_at,
                expected_count=len(expected),
                actual_count=None,
                error_code="nftables_inspection_failed",
            )
            self._persist(result)
            self._log_transition(result)
            return result

        missing = tuple(sorted(expected - actual))
        unexpected = tuple(sorted(actual - expected))
        status = "drift" if missing or unexpected else "in_sync"

        result = FirewallReconciliationResult(
            status=status,
            checked_at=checked_at,
            expected_count=len(expected),
            actual_count=len(actual),
            missing_in_firewall=missing,
            unexpected_in_firewall=unexpected,
        )
        self._persist(result)
        self._log_transition(result)
        return result

    def run(self):
        while True:
            try:
                self.reconcile_once()
            except Exception as error:
                logger.exception(
                    "Firewall reconciliation monitor failed: %s",
                    error,
                )

            time.sleep(self.check_interval_seconds)

    def start(self):
        thread = threading.Thread(
            target=self.run,
            daemon=True,
            name="sshguard-firewall-reconciliation",
        )
        thread.start()
