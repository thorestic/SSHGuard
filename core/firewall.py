import ipaddress
import subprocess


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
        self.block_duration_seconds = block_duration_seconds
        self.response_mode = response_mode.lower()

        if self.response_mode not in {"dry-run", "real"}:
            raise ValueError(
                "response_mode must be 'dry-run' or 'real'"
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

        All nftables interaction is kept inside this class
        so the rest of the program does not need to know
        how firewall commands work.
        """

        result = subprocess.run(
            ["nft", *arguments],
            input=input_text,
            text=True,
            capture_output=True,
        )

        if check and result.returncode != 0:
            raise RuntimeError(
                f"nft command failed:\n{result.stderr.strip()}"
            )

        return result

    def is_whitelisted(self, source_ip: str):
        """
        Check whether an IP belongs to one of our
        protected administration networks.
        """

        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return False

        return any(
            address in network
            for network in self.whitelist_networks
        )

    def setup(self):
        """
        Create an isolated nftables table for SSHGuard.

        We do NOT modify or flush UFW, Docker,
        or Tailscale firewall tables.
        """

        if self.response_mode == "dry-run":
            print(
                "[FIREWALL] DRY RUN mode - "
                "nftables will not be modified"
            )
            return

        # Remove only our project's previous table.
        # This does NOT touch UFW/Docker/Tailscale.
        self._run_nft(
            [
                "delete",
                "table",
                "inet",
                self.TABLE_NAME,
            ],
            check=False,
        )

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

        # Drop SSH traffic from IPs in our temporary block set.
        tcp dport {self.protected_port} ip saddr @{self.BLOCK_SET} drop
    }}
}}
"""

        self._run_nft(
            ["-f", "-"],
            input_text=ruleset,
        )

        print(
            "[FIREWALL] SSHGuard nftables table initialized"
        )

        print(
            f"[FIREWALL] Protected SSH port: "
            f"{self.protected_port}"
        )

        print(
            f"[FIREWALL] Automatic block timeout: "
            f"{self.block_duration_seconds}s"
        )

    def block_ip(self, source_ip: str):
        """
        Temporarily block an IPv4 source from accessing
        the protected SSH port.

        The nftables set itself handles automatic expiry.
        """

        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            print(
                f"[FIREWALL] Invalid IP address: {source_ip}"
            )
            return False

        # Current implementation is IPv4 only.
        if address.version != 4:
            print(
                f"[FIREWALL] IPv6 blocking not yet supported: "
                f"{source_ip}"
            )
            return False

        if self.is_whitelisted(source_ip):
            print(
                f"[FIREWALL] WHITELISTED - "
                f"will not block {source_ip}"
            )
            return False

        if self.response_mode == "dry-run":
            print(
                f"[DRY RUN] Would block IP: {source_ip} "
                f"for {self.block_duration_seconds} seconds"
            )
            return True

        command = (
            f"add element inet {self.TABLE_NAME} "
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
            # If it is already blocked, this is not fatal.
            if "File exists" in result.stderr:
                print(
                    f"[FIREWALL] IP already blocked: "
                    f"{source_ip}"
                )
                return False

            raise RuntimeError(
                f"Could not block IP {source_ip}:\n"
                f"{result.stderr.strip()}"
            )

        print(
            f"[FIREWALL] BLOCKED {source_ip} "
            f"for {self.block_duration_seconds} seconds"
        )

        return True

    def unblock_ip(self, source_ip: str):
        """
        Manually remove an IP from the temporary block set.

        Normally nftables automatically removes it after
        the configured timeout.
        """

        if self.response_mode == "dry-run":
            print(
                f"[DRY RUN] Would manually unblock: "
                f"{source_ip}"
            )
            return True

        command = (
            f"delete element inet {self.TABLE_NAME} "
            f"{self.BLOCK_SET} {{ {source_ip} }}"
        )

        result = self._run_nft(
            ["-f", "-"],
            input_text=command,
            check=False,
        )

        if result.returncode != 0:
            print(
                f"[FIREWALL] IP was not currently blocked: "
                f"{source_ip}"
            )
            return False

        print(
            f"[FIREWALL] MANUALLY UNBLOCKED {source_ip}"
        )

        return True
