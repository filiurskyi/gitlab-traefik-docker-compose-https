#!/usr/bin/env bash
# Secure WireGuard client addition script
# This script adds a new WireGuard peer (client) to the server configuration.

# Exit on any error, treat unset variables as errors, and propagate errors through pipes
set -euo pipefail

# Ensure script is run as root (WireGuard config and keys require root access)
if [[ $EUID -ne 0 ]]; then
  echo "Error: This script must be run as root." >&2
  exit 1
fi

# Load user-defined settings from external config file
CONFIG_FILE="/etc/wireguard/wg_config.sh"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Error: Configuration file $CONFIG_FILE not found." >&2
  exit 1
fi
# shellcheck source=/etc/wireguard/wg_config.sh
source "$CONFIG_FILE"

# Verify required configuration variables are set (non-empty)
: "${WG_INTERFACE:?}" "${WG_IPV4_NETWORK:?}" "${WG_IPV6_NETWORK:?}" "${SERVER_ENDPOINT:?}" "${SERVER_PORT:?}"
: "${CLIENT_KEYS_DIR:?}" "${CLIENT_CONFIG_DIR:?}"

generate_wg0_config() {
  local config_path="./${WG_INTERFACE}.conf"
  local private_key_file="${CLIENT_KEYS_DIR}/server_privatekey"

  # Create key directory if missing
  mkdir -p "$CLIENT_KEYS_DIR"
  chmod 700 "$CLIENT_KEYS_DIR"

  # Generate server private key if not exists
  if [[ ! -f "$private_key_file" ]]; then
    echo "[*] Generating server private key..."
    umask 077
    wg genkey > "$private_key_file"
  fi

  SERVER_PRIVATE_KEY=$(<"$private_key_file")

  echo "[*] Creating ${config_path}..."

  {
    echo "[Interface]"
    echo "PrivateKey = ${SERVER_PRIVATE_KEY}"
    echo "Address = ${WG_IPV4_NETWORK%%/*}/24, ${WG_IPV6_NETWORK%%/*}/64"
    echo "ListenPort = ${SERVER_PORT}"
    echo "PostUp = ${NAT_POSTUP}"
    echo "PostDown = ${NAT_POSTDOWN}"
  } > "$config_path"

  chmod 600 "$config_path"

  echo "[*] WireGuard server configuration generated at $config_path"
}

WG_CONFIG_FILE="/etc/wireguard/${WG_INTERFACE}.conf"

# Generate config if it doesn't exist
if [[ ! -f "$WG_CONFIG_FILE" ]]; then
  echo "[*] No WireGuard config found. Generating default one from wg_config.sh..."
  generate_wg0_config
fi

# Check that necessary tools are available
for cmd in wg wg-quick; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "Error: Required command '$cmd' not found. Please install WireGuard tools." >&2; exit 1; }
done
# iptables is needed if NAT is being used (PostUp/PostDown rules)
if [[ -n "${NAT_INTERFACE:-}" ]]; then
  command -v iptables >/dev/null 2>&1 || { echo "Error: iptables not found. Install iptables or adjust NAT settings." >&2; exit 1; }
fi

# Usage function
usage() {
  echo "Usage: $0 <client_name>" >&2
  exit 1
}

# Require exactly one argument: the new client name
if [[ $# -ne 1 ]]; then
  usage
fi
CLIENT_NAME="$1"

# Validate client name (only allow alphanumeric, underscore, and hyphen)
if [[ ! "$CLIENT_NAME" =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "Error: Client name '$CLIENT_NAME' is invalid. Use only letters, numbers, '_' or '-'." >&2
  exit 1
fi

# Define server config file path based on interface name
WG_CONFIG_FILE="/etc/wireguard/${WG_INTERFACE}.conf"
if [[ ! -f "$WG_CONFIG_FILE" ]]; then
  echo "Error: WireGuard config $WG_CONFIG_FILE not found. Ensure the interface is set up." >&2
  exit 1
fi

# Prevent adding a client that already exists
if [[ -d "${CLIENT_KEYS_DIR}/${CLIENT_NAME}" || -f "${CLIENT_CONFIG_DIR}/${CLIENT_NAME}.conf" ]]; then
  echo "Error: Client '${CLIENT_NAME}' already exists." >&2
  exit 1
fi

# Function to determine the next available IPv4 and IPv6 addresses for the new client
find_next_ip() {
    local prefix="10.100.0."
    local used_octets next_octet

    # Ensure the WireGuard config file exists
    if [[ ! -f "$WG_CONFIG_FILE" ]]; then
        echo "Error: Config file '$WG_CONFIG_FILE' not found." >&2
        return 1
    fi

    # Collect all used last-octet values from IPv4 addresses in the config (10.100.0.X/32)
    used_octets=$(grep -oE "${prefix}[0-9]{1,3}/32" "$WG_CONFIG_FILE" | cut -d'/' -f1 | awk -F. '{print $4}')

    # Find the first available X in 2..254 not already used
    for next_octet in {2..254}; do
        if ! grep -qx "$next_octet" <<< "$used_octets"; then
            echo "$next_octet"
            return 0
        fi
    done

    # No available IP found in the subnet
    echo "Error: No available IP addresses in ${prefix}0/24." >&2
    return 1
}

# Determine next IP addresses for the new client
# IPv4 next host (numeric)
NEXT_IPV4_ID=$(find_next_ip "$WG_IPV4_NETWORK")
# Construct the full IPv4 address (assumes /24 or /16 style networks as per above check)
IPv4_PREFIX="${WG_IPV4_NETWORK%%.*}.$(echo "${WG_IPV4_NETWORK#*.}" | cut -d. -f1-2)."  # default prefix building for /16 or /24
# A safer approach: derive prefix by removing the last octet of the base IP
IPv4_PREFIX="$(echo "${WG_IPV4_NETWORK%/*}" | sed 's/\.[0-9]\+$/.'/)"
CLIENT_IPV4="${IPv4_PREFIX}${NEXT_IPV4_ID}"

# Derive corresponding IPv6 address:
# Get the IPv6 prefix (everything before the host portion) and ensure it ends with ':'
BASE_V6_NET="${WG_IPV6_NETWORK%/*}"
if [[ "$BASE_V6_NET" != *:: ]]; then
  # If not in :: shorthand form, append a colon to prepare for host part
  [[ "$BASE_V6_NET" != *: ]] && BASE_V6_NET="${BASE_V6_NET}:"
fi
# Convert the IPv4 host ID to hex for IPv6 (to maintain numeric equivalence)
# e.g., 10 -> "a", 11 -> "b", 16 -> "10", etc.
printf -v HEX_ID "%x" "$NEXT_IPV4_ID"
CLIENT_IPV6="${BASE_V6_NET}${HEX_ID}"

# Generate keys for the new client (private key, public key, and preshared key)
CLIENT_KEY_DIR="${CLIENT_KEYS_DIR}/${CLIENT_NAME}"
mkdir -p "$CLIENT_KEY_DIR"
# Set restrictive permissions for key directory and files (only owner rwx for dir, rw for files)
chmod 700 "$CLIENT_KEY_DIR"

# Use umask to ensure no excessive permissions on created files
umask 077
# Generate WireGuard keys
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(printf "%s" "$CLIENT_PRIVATE_KEY" | wg pubkey)
CLIENT_PSK=$(wg genpsk)
# Save keys to files
echo "$CLIENT_PRIVATE_KEY" > "${CLIENT_KEY_DIR}/privatekey"
echo "$CLIENT_PUBLIC_KEY"  > "${CLIENT_KEY_DIR}/publickey"
echo "$CLIENT_PSK"         > "${CLIENT_KEY_DIR}/psk"

# Obtain the server's public key (needed for client config)
# Try to get it from the running interface, otherwise fall back to config file
SERVER_PUBLIC_KEY=""
if command -v wg >/dev/null 2>&1; then
  SERVER_PUBLIC_KEY=$(wg show "$WG_INTERFACE" public-key 2>/dev/null || true)
fi
if [[ -z "$SERVER_PUBLIC_KEY" ]]; then
  # Extract from config (requires reading server's private key and generating pub)
  SERVER_PRIV_KEY=$(grep -m1 '^PrivateKey' "$WG_CONFIG_FILE" | cut -d'=' -f2 | tr -d ' \t')
  if [[ -n "$SERVER_PRIV_KEY" ]]; then
    SERVER_PUBLIC_KEY=$(printf "%s" "$SERVER_PRIV_KEY" | wg pubkey)
  fi
fi
if [[ -z "$SERVER_PUBLIC_KEY" ]]; then
  echo "Error: Could not determine server public key. Set SERVER_PUBLIC_KEY in config or ensure interface is up." >&2
  exit 1
fi

# Create the WireGuard client configuration file
mkdir -p "$CLIENT_CONFIG_DIR"
CLIENT_CONFIG_PATH="${CLIENT_CONFIG_DIR}/${CLIENT_NAME}.conf"
{
  echo "[Interface]"
  echo "PrivateKey = $CLIENT_PRIVATE_KEY"
  echo "Address = ${CLIENT_IPV4}/32, ${CLIENT_IPV6}/128"
  # If a DNS server is provided or the WireGuard server should act as DNS, you can include a DNS setting:
  echo "DNS = 10.100.0.1"
  echo ""
  echo "[Peer]"
  echo "PublicKey = $SERVER_PUBLIC_KEY"
  echo "PresharedKey = $CLIENT_PSK"
  # Allowed IPs for client side: default to full tunnel or use configured value
  if [[ -n "${CLIENT_ALLOWED_IPS:-}" ]]; then
    echo "AllowedIPs = ${CLIENT_ALLOWED_IPS}"
  else
    echo "AllowedIPs = 0.0.0.0/0, ::/0"
  fi
  echo "Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}"
  # If the client is behind NAT, you may enable a persistent keep-alive to maintain the tunnel:
  # echo "PersistentKeepalive = 25"
} > "$CLIENT_CONFIG_PATH"

chmod 600 "$CLIENT_CONFIG_PATH"

# Update the WireGuard server configuration file with the new peer
{
  echo ""  # ensure a blank line before new peer entry
  echo "[Peer]"
  echo "# ${CLIENT_NAME}"
  echo "PublicKey = $CLIENT_PUBLIC_KEY"
  echo "PresharedKey = $CLIENT_PSK"
  echo "AllowedIPs = ${CLIENT_IPV4}/32, ${CLIENT_IPV6}/128"
} >> "$WG_CONFIG_FILE"

# Apply the updated WireGuard configuration without restarting the interface
# Use wg-quick's "strip" to remove non-WireGuard options, then syncconf to apply changes
wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE")

echo "Successfully added WireGuard peer '$CLIENT_NAME'."
echo "Client configuration file: ${CLIENT_CONFIG_PATH}"
