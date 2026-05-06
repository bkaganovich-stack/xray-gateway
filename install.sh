#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# xray-gateway — Transparent Proxy Gateway Installer
#
# One-liner (recommended):
#   curl -fsSL https://raw.githubusercontent.com/YOUR_GITHUB/xray-gateway/main/install.sh | sudo bash
#
# Or clone and run:
#   git clone https://github.com/YOUR_GITHUB/xray-gateway
#   cd xray-gateway && sudo bash install.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_URL="https://github.com/YOUR_GITHUB/xray-gateway"
INSTALL_DIR=/opt/xray-proxy
NET_CONF="$INSTALL_DIR/config/network.conf"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step()  { echo -e "\n${YLW}══ $* ══${NC}"; }

[ "$(id -u)" = "0" ] || error "Run as root: sudo bash install.sh"

# ── Bootstrap ─────────────────────────────────────────────────────────────────
# When piped from curl there are no local source files; clone the repo first.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-}")" 2>/dev/null && pwd || true)"
if [[ ! -f "${SCRIPT_DIR}/web/main.py" ]]; then
    step "Downloading xray-gateway"
    command -v git &>/dev/null || { apt-get update -qq && apt-get install -y -qq git; }
    TMP_REPO=$(mktemp -d)
    trap 'rm -rf "$TMP_REPO"' EXIT
    git clone --depth=1 "$REPO_URL" "$TMP_REPO"
    SCRIPT_DIR="$TMP_REPO"
    info "Source ready at $TMP_REPO"
fi

# ── Detect network interface and router IP ────────────────────────────────────
detect_network() {
    local iface router

    # 1. Interface with default route — most reliable
    iface=$(ip route show default 2>/dev/null \
            | awk 'NR==1{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); break}}')

    # 2. Fallback: first physical interface with carrier (link UP)
    if [[ -z "$iface" || "$iface" == "lo" ]]; then
        for p in /sys/class/net/*/carrier; do
            local n; n=$(basename "$(dirname "$p")")
            [[ "$n" == "lo" ]] && continue
            [[ ! -e "/sys/class/net/$n/device" ]] && continue
            [[ "$(cat "$p" 2>/dev/null)" == "1" ]] && { iface=$n; break; }
        done
    fi

    # 3. Last resort: any physical interface
    if [[ -z "$iface" || "$iface" == "lo" ]]; then
        for p in /sys/class/net/*/device; do
            local n; n=$(basename "$(dirname "$p")")
            [[ "$n" != "lo" ]] && { iface=$n; break; }
        done
    fi

    [[ -z "$iface" || "$iface" == "lo" ]] && error "Cannot detect LAN interface"

    router=$(ip route show default 2>/dev/null | awk 'NR==1{print $3}')
    [[ -z "$router" ]] && router="192.168.1.1"

    LAN_IF="$iface"
    ROUTER_IP="$router"
    info "LAN interface : $LAN_IF"
    info "Router IP     : $ROUTER_IP"

    mkdir -p "$INSTALL_DIR/config"
    cat > "$NET_CONF" <<NETEOF
# Auto-detected by install.sh on $(date -u '+%Y-%m-%d %H:%M UTC')
# Edit if wrong, then: systemctl restart xray-proxy
LAN_IF=$LAN_IF
ROUTER_IP=$ROUTER_IP
NETEOF
    info "Saved to $NET_CONF"
}

# ── 1. Stop old services ───────────────────────────────────────────────────────
step "Stopping old services"
for svc in sing-box portal xray-proxy xray-web; do
    systemctl stop    "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
done

# ── 2. Detect network ─────────────────────────────────────────────────────────
step "Detecting network"
detect_network

# ── 3. System packages ────────────────────────────────────────────────────────
step "Installing packages"
apt-get update -qq
apt-get install -y -qq curl python3 python3-pip iptables iproute2 \
    dnsmasq ca-certificates unzip

# ── 4. Python deps ────────────────────────────────────────────────────────────
step "Installing Python dependencies"
pip3 install -q fastapi "uvicorn[standard]" python-multipart

# ── 5. Download xray-core ─────────────────────────────────────────────────────
step "Downloading xray-core"
mkdir -p "$INSTALL_DIR/bin"
case "$(uname -m)" in
    x86_64)  XRAY_ARCH="64" ;;
    aarch64) XRAY_ARCH="arm64-v8a" ;;
    armv7l)  XRAY_ARCH="arm32-v7a" ;;
    *)       error "Unsupported arch: $(uname -m)" ;;
esac

XRAY_API="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
XRAY_TAG=$(curl -sfL "$XRAY_API" | python3 -c "import sys,json;print(json.load(sys.stdin)['tag_name'])")
info "Latest xray-core: $XRAY_TAG"
XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_TAG}/Xray-linux-${XRAY_ARCH}.zip"

TMP_XRAY=$(mktemp -d)
trap 'rm -rf "$TMP_XRAY"' EXIT
curl -sfL --progress-bar -o "$TMP_XRAY/xray.zip" "$XRAY_URL"
cd "$TMP_XRAY" && unzip -q xray.zip
cp xray "$INSTALL_DIR/bin/xray"
chmod +x "$INSTALL_DIR/bin/xray"
"$INSTALL_DIR/bin/xray" version
cd /

# ── 6. Create directory structure ─────────────────────────────────────────────
step "Creating directories"
mkdir -p "$INSTALL_DIR"/{bin,config,scripts,web/static,logs}

# ── 7. Copy application files ─────────────────────────────────────────────────
step "Copying application files"
cp -r "$SCRIPT_DIR/web/."     "$INSTALL_DIR/web/"
cp -r "$SCRIPT_DIR/scripts/." "$INSTALL_DIR/scripts/"
chmod +x "$INSTALL_DIR/scripts/"*.sh

# ── 8. Generate secret key ────────────────────────────────────────────────────
step "Generating secret key"
if [ ! -f "$INSTALL_DIR/.secret" ]; then
    python3 -c "import secrets; print(secrets.token_hex(32))" > "$INSTALL_DIR/.secret"
    chmod 600 "$INSTALL_DIR/.secret"
    info "New secret key generated"
fi

# ── 9. Download geo files ─────────────────────────────────────────────────────
step "Downloading geo files"
bash "$INSTALL_DIR/scripts/update-geo.sh" || warn "Geo download failed — retry with: bash /opt/xray-proxy/scripts/update-geo.sh"

# ── 10. Generate initial xray config ─────────────────────────────────────────
step "Generating initial xray config"
python3 - <<'PYEOF'
import json, sys, pathlib
sys.path.insert(0, '/opt/xray-proxy/web')
from main import build_xray_config, save_settings, DEFAULT_SETTINGS, CFG_DIR, XCFG
pathlib.Path('/opt/xray-proxy/config').mkdir(parents=True, exist_ok=True)
if not pathlib.Path('/opt/xray-proxy/config/settings.json').exists():
    save_settings(dict(DEFAULT_SETTINGS))
XCFG.write_text(json.dumps(build_xray_config(DEFAULT_SETTINGS), indent=2))
print("xray.json written")
PYEOF

# ── 11. Configure dnsmasq ─────────────────────────────────────────────────────
step "Configuring dnsmasq"
LAN_IP=$(ip -4 addr show "$LAN_IF" | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+' | head -1)
[[ -z "$LAN_IP" ]] && warn "No IPv4 yet on $LAN_IF — dnsmasq will bind on first-boot"
info "LAN IP: ${LAN_IP:-<pending>}"

cat > /etc/dnsmasq.d/xray-gateway.conf <<DNSEOF
listen-address=${LAN_IP:-127.0.0.1}
bind-interfaces
port=5335
server=$ROUTER_IP
no-resolv
cache-size=1000
DNSEOF

systemctl enable dnsmasq
systemctl restart dnsmasq

# ── 12. Configure systemd-resolved ────────────────────────────────────────────
step "Configuring systemd-resolved"
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/no-stub.conf <<EOF
[Resolve]
DNSStubListener=no
DNS=9.9.9.9
EOF
systemctl restart systemd-resolved
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf

# ── 13. Enable IP forwarding ──────────────────────────────────────────────────
step "Enabling IP forwarding"
cat > /etc/sysctl.d/90-xray-gateway.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl --system -q

# ── 14. Install systemd services ──────────────────────────────────────────────
step "Installing systemd services"
cp "$SCRIPT_DIR/systemd/xray-proxy.service" /etc/systemd/system/
cp "$SCRIPT_DIR/systemd/xray-web.service"   /etc/systemd/system/
systemctl daemon-reload
systemctl enable xray-proxy xray-web

# ── 15. Weekly geo update cron ────────────────────────────────────────────────
step "Setting up weekly geo update"
echo "0 3 * * 0 root /opt/xray-proxy/scripts/update-geo.sh && systemctl restart xray-proxy" \
    > /etc/cron.d/xray-geo-update

# ── 16. Start services ────────────────────────────────────────────────────────
step "Starting services"
systemctl start xray-web
sleep 2
systemctl start xray-proxy
sleep 2

# ── 17. Status check ──────────────────────────────────────────────────────────
step "Verifying installation"
echo ""
systemctl is-active xray-web   && info "xray-web   ✓ running" || warn "xray-web   ✗ failed"
systemctl is-active xray-proxy && info "xray-proxy ✓ running" || warn "xray-proxy ✗ check: journalctl -u xray-proxy"
systemctl is-active dnsmasq    && info "dnsmasq    ✓ running" || warn "dnsmasq    ✗ failed"

echo ""
echo -e "${GRN}════════════════════════════════════════${NC}"
echo -e "${GRN} Installation complete!${NC}"
echo -e "${GRN}════════════════════════════════════════${NC}"
echo ""
echo " Web UI:  http://${LAN_IP:-<device-ip>}"
echo " Login:   admin / admin"
echo ""
echo " Next steps:"
echo " 1. Open http://${LAN_IP:-<device-ip>} in browser"
echo " 2. Paste your VPN key"
echo " 3. Choose routing profile"
echo " 4. Change the admin password (Settings → Change Password)"
echo " 5. Set this device as Default Gateway + DNS in your router's DHCP settings"
echo ""
