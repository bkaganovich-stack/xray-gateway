#!/usr/bin/env bash
# iptables TProxy setup for xray-core transparent proxy
# Called by xray-proxy.service ExecStartPost / ExecStopPost
set -euo pipefail

ACTION="${1:-up}"
TPROXY_PORT=12345
TPROXY_MARK=1
XRAY_MARK=255   # mark on xray's own outbound sockets (set in xray config)

# ── Resolve LAN interface ─────────────────────────────────────────────────────
# Priority 1: network.conf written by install.sh / first-boot.sh
NET_CONF=/opt/xray-proxy/config/network.conf
if [[ -f "$NET_CONF" ]] && grep -q '^LAN_IF=' "$NET_CONF"; then
    # shellcheck source=/dev/null
    source "$NET_CONF"
fi

# Priority 2: environment variable (allows override: LAN_IF=eth0 ./iptables.sh up)
# Priority 3: auto-detect from default route
if [[ -z "${LAN_IF:-}" ]]; then
    LAN_IF=$(ip route show default 2>/dev/null \
             | awk 'NR==1{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); break}}')
fi

[[ -z "${LAN_IF:-}" || "$LAN_IF" == "lo" ]] && \
    { echo "ERROR: cannot resolve LAN interface (set LAN_IF in $NET_CONF)"; exit 1; }

# Detect gateway IP dynamically so rules work on any device
LAN_IP=$(ip -4 addr show "$LAN_IF" | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
[ -n "$LAN_IP" ] || { echo "ERROR: could not detect IP for $LAN_IF"; exit 1; }

flush_rules() {
    iptables -t mangle -D PREROUTING -j XRAY_PREROUTING 2>/dev/null || true
    iptables -t mangle -D OUTPUT     -j XRAY_OUTPUT     2>/dev/null || true
    iptables -t mangle -F XRAY_PREROUTING 2>/dev/null || true
    iptables -t mangle -F XRAY_OUTPUT     2>/dev/null || true
    iptables -t mangle -X XRAY_PREROUTING 2>/dev/null || true
    iptables -t mangle -X XRAY_OUTPUT     2>/dev/null || true
    ip rule  del fwmark $TPROXY_MARK table 100 2>/dev/null || true
    ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
    # DNS redirect cleanup — both old (LAN_IP-specific) and new (any dst) forms
    iptables -t mangle -D XRAY_PREROUTING -p udp --dport 53 -j RETURN 2>/dev/null || true
    iptables -t mangle -D XRAY_PREROUTING -p tcp --dport 53 -j RETURN 2>/dev/null || true
    iptables -t nat -D PREROUTING -p udp --dport 53 -d "$LAN_IP" -j REDIRECT --to-port 5335 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 53 -d "$LAN_IP" -j REDIRECT --to-port 5335 2>/dev/null || true
    iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5335 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5335 2>/dev/null || true
    # FCM bypass cleanup
    iptables -t nat -D POSTROUTING -o "$LAN_IF" -p tcp --dport 5228 -j MASQUERADE 2>/dev/null || true
}

if [ "$ACTION" = "down" ]; then
    flush_rules
    echo "iptables TProxy rules removed"
    exit 0
fi

# ── UP ──────────────────────────────────────────────────────────────────────

# Kernel requirements
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.conf.all.route_localnet=1
sysctl -qw net.ipv4.conf.$LAN_IF.route_localnet=1

# Clean up any stale rules
flush_rules

# IP rule: packets marked with TPROXY_MARK go to local loopback (table 100)
ip rule  add fwmark $TPROXY_MARK table 100 priority 100
ip route add local 0.0.0.0/0 dev lo table 100

# ── PREROUTING: intercept forwarded LAN traffic ────────────────────────────
iptables -t mangle -N XRAY_PREROUTING
iptables -t mangle -A PREROUTING -j XRAY_PREROUTING

# Skip already-marked (xray's own) traffic
iptables -t mangle -A XRAY_PREROUTING -m mark --mark $XRAY_MARK -j RETURN
# Skip multicast / broadcast
iptables -t mangle -A XRAY_PREROUTING -d 224.0.0.0/4   -j RETURN
iptables -t mangle -A XRAY_PREROUTING -d 240.0.0.0/4   -j RETURN
# Skip private/local destinations (private ranges handled by xray routing)
iptables -t mangle -A XRAY_PREROUTING -d 127.0.0.0/8   -j RETURN
iptables -t mangle -A XRAY_PREROUTING -d 10.0.0.0/8    -j RETURN
iptables -t mangle -A XRAY_PREROUTING -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A XRAY_PREROUTING -d 192.168.0.0/16 -j RETURN
# Skip DHCP
iptables -t mangle -A XRAY_PREROUTING -d 255.255.255.255 -j RETURN
# Skip DNS port 53 — handled separately by nat PREROUTING REDIRECT to dnsmasq.
# This intercepts hardcoded resolvers (8.8.8.8, 8.8.4.4, etc.) before TProxy sees them.
iptables -t mangle -A XRAY_PREROUTING -p udp --dport 53 -j RETURN
iptables -t mangle -A XRAY_PREROUTING -p tcp --dport 53 -j RETURN
# Skip Google FCM (Firebase Cloud Messaging) port 5228 — bypass xray entirely.
# FCM is Google Home's persistent backend connection; routing it through xray caused
# the tunnel to act as a middleman and drop the connection every ~2 minutes, causing
# "Connecting to Home" flashes on Google displays. Direct kernel forwarding + NAT is
# much more stable. MASQUERADE below ensures the reply path is symmetric.
iptables -t mangle -A XRAY_PREROUTING -p tcp --dport 5228 -j RETURN
# TPROXY TCP and UDP to xray
iptables -t mangle -A XRAY_PREROUTING -p tcp -j TPROXY \
    --on-port $TPROXY_PORT --tproxy-mark $TPROXY_MARK
iptables -t mangle -A XRAY_PREROUTING -p udp -j TPROXY \
    --on-port $TPROXY_PORT --tproxy-mark $TPROXY_MARK

# ── OUTPUT: intercept locally-generated traffic (from mini PC itself) ──────
iptables -t mangle -N XRAY_OUTPUT
iptables -t mangle -A OUTPUT -j XRAY_OUTPUT

iptables -t mangle -A XRAY_OUTPUT -m mark --mark $XRAY_MARK -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 224.0.0.0/4   -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 240.0.0.0/4   -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 127.0.0.0/8   -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 10.0.0.0/8    -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A XRAY_OUTPUT -d 192.168.0.0/16 -j RETURN
# Mark locally-generated traffic → route via loopback → xray
iptables -t mangle -A XRAY_OUTPUT -p tcp -j MARK --set-mark $TPROXY_MARK
iptables -t mangle -A XRAY_OUTPUT -p udp -j MARK --set-mark $TPROXY_MARK


# ── DNS redirect: перехватываем DNS на ЛЮБОЙ адрес → dnsmasq (порт 5335) ───
# Покрывает: $LAN_IP:53 (из DHCP), 8.8.8.8:53, 8.8.4.4:53 и любые хардкод-резолверы.
# DNS-пакеты пропущены через mangle (RETURN выше), поэтому nat PREROUTING их видит.
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5335
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 5335

# ── FCM bypass NAT: MASQUERADE port 5228 forwarded traffic ──────────────────
# Since port 5228 is skipped by TProxy (RETURN above), packets from LAN devices
# to FCM:5228 are forwarded by the kernel. MASQUERADE rewrites the source IP to
# the gateway's own IP so that return traffic comes back through the gateway,
# allowing conntrack to forward replies back to the originating device.
iptables -t nat -A POSTROUTING -o "$LAN_IF" -p tcp --dport 5228 -j MASQUERADE

echo "iptables TProxy rules installed (port=$TPROXY_PORT, mark=$TPROXY_MARK)"
