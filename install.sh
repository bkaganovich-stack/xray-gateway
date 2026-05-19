#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# xray-gateway — Transparent Proxy Gateway Installer
#
# One-liner (recommended):
#   curl -fsSL https://raw.githubusercontent.com/bkaganovich-stack/xray-gateway/main/install.sh | sudo bash
#
# Or clone and run:
#   git clone https://github.com/bkaganovich-stack/xray-gateway
#   cd xray-gateway && sudo bash install.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_URL="https://github.com/bkaganovich-stack/xray-gateway"
INSTALL_DIR=/opt/xray-proxy
NET_CONF="$INSTALL_DIR/config/network.conf"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }
step()  { echo -e "\n${YLW}══ $* ══${NC}"; }

[ "$(id -u)" = "0" ] || error "Run as root: sudo bash install.sh"

# ── Package manager detection ─────────────────────────────────────────────────
if   command -v apt-get &>/dev/null; then
    PM=apt
    IPROUTE_PKG=iproute2
    PY_VENV_PKG=python3-venv   # needed on Debian/Ubuntu
elif command -v dnf     &>/dev/null; then
    PM=dnf
    IPROUTE_PKG=iproute
    PY_VENV_PKG=""             # venv ships with python3 on Fedora/RHEL
elif command -v yum     &>/dev/null; then
    PM=yum
    IPROUTE_PKG=iproute
    PY_VENV_PKG=""
else
    error "Unsupported distro — need apt-get, dnf, or yum (Debian/Ubuntu/Fedora/CentOS/RHEL)"
fi
info "Package manager : $PM"

pm_update() {
    case "$PM" in
        apt) apt-get update -qq ;;
        dnf|yum) : ;;   # dnf/yum refresh metadata automatically
    esac
}

pm_install() {
    case "$PM" in
        apt) apt-get install -y -qq "$@" ;;
        dnf) dnf install -y -q  "$@" ;;
        yum) yum install -y -q  "$@" ;;
    esac
}

# ── Bootstrap ─────────────────────────────────────────────────────────────────
# When piped from curl there are no local source files; clone the repo first.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-}")" 2>/dev/null && pwd || true)"
if [[ ! -f "${SCRIPT_DIR}/web/main.py" ]]; then
    step "Downloading xray-gateway"
    command -v git &>/dev/null || { pm_update; pm_install git; }
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
pm_update
pm_install curl python3 python3-pip iptables "$IPROUTE_PKG" \
    dnsmasq ca-certificates unzip ${PY_VENV_PKG:+"$PY_VENV_PKG"}

# On Fedora/RHEL install semanage so we can label port 5335 for dnsmasq (SELinux)
if [[ "$PM" != "apt" ]]; then
    pm_install policycoreutils-python-utils
fi

# ── 4. Python virtualenv + deps ───────────────────────────────────────────────
step "Installing Python dependencies"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q fastapi "uvicorn[standard]" python-multipart
info "Python venv ready at $INSTALL_DIR/venv"

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
"$INSTALL_DIR/venv/bin/python3" - <<'PYEOF'
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

# On SELinux systems (Fedora/RHEL) dnsmasq is only allowed on port 53 by default.
# Label port 5335 as dns_port_t so dnsmasq can bind to it.
if command -v semanage &>/dev/null; then
    semanage port -a -t dns_port_t -p udp 5335 2>/dev/null \
        || semanage port -m -t dns_port_t -p udp 5335 2>/dev/null || true
    semanage port -a -t dns_port_t -p tcp 5335 2>/dev/null \
        || semanage port -m -t dns_port_t -p tcp 5335 2>/dev/null || true
    info "SELinux: port 5335 labeled as dns_port_t"
fi

systemctl enable dnsmasq
systemctl restart dnsmasq

# ── 11b. Open firewall ports (Fedora/RHEL only) ───────────────────────────────
if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null 2>&1; then
    step "Configuring firewalld"
    firewall-cmd --permanent --add-port=80/tcp      # Web UI
    firewall-cmd --permanent --add-port=12345/tcp   # TProxy TCP
    firewall-cmd --permanent --add-port=12345/udp   # TProxy UDP
    firewall-cmd --permanent --add-port=5335/tcp    # dnsmasq
    firewall-cmd --permanent --add-port=5335/udp    # dnsmasq
    firewall-cmd --reload
    info "Firewall: ports 80, 12345, 5335 opened"
fi

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
