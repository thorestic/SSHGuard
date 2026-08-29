import ipaddress


def parse_source_address(source_ip: str):
    """
    Validate and canonicalize a network source address.

    Scoped link-local addresses are rejected because an
    ipv6_addr nftables set cannot preserve the interface
    scope safely. IPv4-mapped IPv6 values are returned as
    IPv4 because they represent IPv4 peers.
    """

    address = ipaddress.ip_address(source_ip)

    if isinstance(address, ipaddress.IPv6Address):
        if address.scope_id is not None:
            raise ValueError(
                "scoped IPv6 addresses are unsupported"
            )

        if address.ipv4_mapped is not None:
            return address.ipv4_mapped

    return address
