# ==============================
# SSHGuard Configuration
# ==============================

# Brute-force detection settings
THRESHOLD = 3
WINDOW_SECONDS = 20

# Firewall response settings
BLOCK_DURATION_SECONDS = 60

# SSH service protected by SSHGuard
PROTECTED_SSH_PORT = 22

# Possible values:
# "dry-run" = detect attacks but do not modify firewall
# "real"    = apply real nftables blocking
RESPONSE_MODE = "real"

# Networks that SSHGuard must never block.
# Tailscale is our recovery/admin path.
WHITELIST_NETWORKS = [
    "100.64.0.0/10",
    "127.0.0.0/8",
]
