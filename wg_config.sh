# WireGuard interface name (server)
WG_INTERFACE="wg0"

# VPN network settings (change as needed)
# IPv4 subnet for clients (in CIDR notation) and IPv6 ULA prefix
WG_IPV4_NETWORK="10.100.0.0/24"
WG_IPV6_NETWORK="fd08:4711::/64"

# Server's public endpoint (domain or IP) and listening port
SERVER_ENDPOINT="superbblqvpn.asuscomm.com"   # Replace with your server's domain or IP
SERVER_PORT="51398"                           # WireGuard listening port

# Directories for storing client configurations and keys
CLIENT_CONFIG_DIR="/etc/wireguard/configs"
CLIENT_KEYS_DIR="/etc/wireguard/keys"

# NAT settings for enabling internet access for VPN clients
# External network interface name (the interface that connects to the Internet)
NAT_INTERFACE="enp3s0"

# iptables rules to add when WireGuard interface is up (PostUp) and remove when down (PostDown)
# not working
#NAT_POSTUP="iptables -A FORWARD -i ${WG_INTERFACE} -j ACCEPT; iptables -A FORWARD -o ${WG_INTERFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s ${WG_IPV4_NETWORK} -o ${NAT_INTERFACE} -j MASQUERADE"
#NAT_POSTDOWN="iptables -D FORWARD -i ${WG_INTERFACE} -j ACCEPT; iptables -D FORWARD -o ${WG_INTERFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s ${WG_IPV4_NETWORK} -o ${NAT_INTERFACE} -j MASQUERADE"
NAT_POSTUP="iptables -w -t nat -A POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE; ip6tables -w -t nat -A POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE"
NAT_POSTDOWN="iptables -w -t nat -D POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE; ip6tables -w -t nat -D POSTROUTING -o ${WG_INTERFACE} -j MASQUERADE"


# Allowed IPs for the client configuration (what traffic to route via VPN).
# For full tunnel VPN, use 0.0.0.0/0 and ::/0. For split-tunnel, limit to specific networks.
CLIENT_ALLOWED_IPS="0.0.0.0/0, ::/0"

