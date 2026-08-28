import ipaddress
import subprocess
from enum import Enum


class FirewallResult(str, Enum):
    BLOCKED = "blocked"
    DRY_RUN = "dry_run"
    WHITELISTED = "whitelisted"
    ALREADY_BLOCKED = "already_blocked"
    INVALID_IP = "invalid_ip"
    UNSUPPORTED_IP_VERSION = "unsupported_ip_version"


class FirewallManager:
    TABLE_NAME = "sshguard"
    BLOCK_SET = "blocked_ipv4"

    def __init__(
        self,
        protected_port: int,
        block_duration_seconds: int,
        whitelist_networks: list[str],
        response_mode: str = "dry-run",
    ):
        self.protected_port = protected_port
        self.block_duration_seconds = (
            block_duration_seconds
        )
        self.response_mode = (
            response_mode.lower()
        )

        if self.response_mode not in {
            "dry-run",
            "real",
        }:
            raise ValueError(
                "response_mode must be "
                "'dry-run' or 'real'"
            )

        self.whitelist_networks = [
            ipaddress.ip_network(network)
            for network in whitelist_networks
        ]

    def _run_nft(
        self,
        arguments: list[str],
        input_text: str | None = None,
        check: bool = True,
    ):
        """
        Execute an nftables command.

        All nftables interaction is isolated inside
        this class so the rest of SSHGuard does not
        need to understand nft command syntax.
        """

        result = subprocess.run(
            ["nft", *arguments],
            input=input_text,
            text=True,
            capture_output=True,
        )

        if (
            check
            and result.returncode != 0
        ):
            raise RuntimeError(
                "nft command failed:\n"
                f"{result.stderr.strip()}"
            )

        return result

    def is_whitelisted(
        self,
        source_ip: str,
    ):
        """
        Check whether the address belongs to one of
        SSHGuard's protected administration networks.
        """

        try:
            address = ipaddress.ip_address(
                source_ip
            )

        except ValueError:
            return False

        return any(
            address in network
            for network in self.whitelist_networks
        )

    def setup(self):
        """
        Create SSHGuard's isolated nftables table.

        Existing SSHGuard runtime state is preserved
        across application restarts.

        Other firewall tables such as UFW, Docker,
        and Tailscale are never flushed.
        """

        if self.response_mode == "dry-run":
            print(
                "[FIREWALL] DRY RUN mode - "
                "nftables will not be modified"
            )
            return

        existing_table = self._run_nft(
            [
                "list",
                "table",
                "inet",
                self.TABLE_NAME,
            ],
            check=False,
        )

        if existing_table.returncode == 0:
            print(
                "[FIREWALL] Existing SSHGuard "
                "nftables table preserved"
            )
            return

        ruleset = f"""
table inet {self.TABLE_NAME} {{

    set {self.BLOCK_SET} {{
        type ipv4_addr
        flags timeout
        timeout {self.block_duration_seconds}s
    }}

    chain input {{
        type filter hook input priority -10; policy accept;

        # Never interfere with local traffic.
        iifname "lo" return

        # Tailscale is our emergency/admin recovery path.
        iifname "tailscale0" return

        # Drop protected SSH traffic from blocked IPv4 sources.
        tcp dport {self.protected_port} ip saddr @{self.BLOCK_SET} drop
    }}
}}
"""

        self._run_nft(
            ["-f", "-"],
            input_text=ruleset,
        )

        print(
            "[FIREWALL] SSHGuard nftables "
            "table initialized"
        )

        print(
            "[FIREWALL] Protected SSH port: "
            f"{self.protected_port}"
        )

        print(
            "[FIREWALL] Automatic block timeout: "
            f"{self.block_duration_seconds}s"
        )

    def block_ip(
        self,
        source_ip: str,
    ):
        """
        Attempt to temporarily block an IPv4 source.

        The return value describes the exact response
        outcome rather than using only True/False.

        Unexpected nftables failures raise an exception.
        """

        try:
            address = ipaddress.ip_address(
                source_ip
            )

        except ValueError:
            print(
                "[FIREWALL] Invalid IP address: "
                f"{source_ip}"
            )

            return FirewallResult.INVALID_IP

        if address.version != 4:
            print(
                "[FIREWALL] Unsupported IP version: "
                f"{source_ip}"
            )

            return (
                FirewallResult
                .UNSUPPORTED_IP_VERSION
            )

        if self.is_whitelisted(source_ip):
            print(
                "[FIREWALL] WHITELISTED - "
                f"will not block {source_ip}"
            )

            return FirewallResult.WHITELISTED

        if self.response_mode == "dry-run":
            print(
                "[DRY RUN] Would block IP: "
                f"{source_ip} for "
                f"{self.block_duration_seconds} "
                "seconds"
            )

            return FirewallResult.DRY_RUN

        command = (
            f"add element inet "
            f"{self.TABLE_NAME} "
            f"{self.BLOCK_SET} "
            f"{{ {source_ip} timeout "
            f"{self.block_duration_seconds}s }}"
        )

        result = self._run_nft(
            ["-f", "-"],
            input_text=command,
            check=False,
        )

        if result.returncode != 0:
            if "File exists" in result.stderr:
                print(
                    "[FIREWALL] IP already blocked: "
                    f"{source_ip}"
                )

                return (
                    FirewallResult
                    .ALREADY_BLOCKED
                )

            raise RuntimeError(
                f"Could not block IP {source_ip}:\n"
                f"{result.stderr.strip()}"
            )

        print(
            f"[FIREWALL] BLOCKED {source_ip} "
            f"for {self.block_duration_seconds} "
            "seconds"
        )

        return FirewallResult.BLOCKED

    def unblock_ip(
        self,
        source_ip: str,
    ):
        """
        Manually remove an IP from the temporary
        block set.

        Normal expiry is handled natively by
        nftables timeouts.
        """

        if self.response_mode == "dry-run":
            print(
                "[DRY RUN] Would manually unblock: "
                f"{source_ip}"
            )

            return True

        command = (
            f"delete element inet "
            f"{self.TABLE_NAME} "
            f"{self.BLOCK_SET} "
            f"{{ {source_ip} }}"
        )

        result = self._run_nft(
            ["-f", "-"],
            input_text=command,
            check=False,
        )

        if result.returncode != 0:
            print(
                "[FIREWALL] IP was not currently "
                f"blocked: {source_ip}"
            )

            return False

        print(
            "[FIREWALL] MANUALLY UNBLOCKED "
            f"{source_ip}"
        )

        return True
