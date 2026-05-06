#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# xray-gateway — Uninstaller
#
# One-liner:
#   curl -fsSL https://raw.githubusercontent.com/YOUR_GITHUB/xray-gateway/main/uninstall.sh | sudo bash
#
# Or locally:
#   sudo bash uninstall.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
step()  { echo -e "\n${YLW}══ $* ══${NC}"; }

[ "$(id -u)" = "0" ] || { echo "Run as root: sudo bash uninstall.sh"; exit 1; }

echo ""
echo "════════════════════════════════════════"
echo " xray-gateway — Uninstaller"
echo "════════════════════════════════════════"
echo ""
read -r -p "Remove xray-gateway from this system? [y/N] " CONFIRM
[[ "${CONFIRM,,}" == "y" ]] || { echo "Aborted."; exit 0; }

# ── 1. Stop and disable services ──────────────────────────────────────────────
step "Stopping services"
for svc in xray-proxy xray-web; do
    systemctl stop    "$svc" 2>/dev/null && info "Stopped $svc"    || true
    systemctl disable "$svc" 2>/dev/null && info "Disabled $svc"   || true
done

# ── 2. Remove systemd service files ───────────────────────────────────────────
step "Removing systemd services"
rm -f /etc/systemd/system/xray-proxy.service
rm -f /etc/systemd/system/xray-web.service
systemctl daemon-reload
info "Service files removed"

# ── 3. Remove installation directory ─────────────────────────────────────────
step "Removing /opt/xray-proxy"
rm -rf /opt/xray-proxy
info "Removed /opt/xray-proxy"

# ── 4. Remove dnsmasq config ──────────────────────────────────────────────────
step "Removing dnsmasq config"
rm -f /etc/dnsmasq.d/xray-gateway.conf
rm -f /etc/dnsmasq.d/gateway.conf        # legacy name
systemctl restart dnsmasq 2>/dev/null || true
info "dnsmasq config removed"

# ── 5. Remove sysctl config ────────────────────────────────────────────────────
step "Removing sysctl config"
rm -f /etc/sysctl.d/90-xray-gateway.conf
rm -f /etc/sysctl.d/90-xray-proxy.conf   # legacy name
sysctl --system -q 2>/dev/null || true
info "sysctl config removed"

# ── 6. Remove cron job ────────────────────────────────────────────────────────
step "Removing cron job"
rm -f /etc/cron.d/xray-geo-update
info "Cron job removed"

# ── 7. Restore systemd-resolved ───────────────────────────────────────────────
step "Restoring systemd-resolved"
rm -f /etc/systemd/resolved.conf.d/no-stub.conf
systemctl restart systemd-resolved 2>/dev/null || true
# Restore standard resolv.conf symlink
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true
info "systemd-resolved restored"

echo ""
echo -e "${GRN}════════════════════════════════════════${NC}"
echo -e "${GRN} xray-gateway removed.${NC}"
echo -e "${GRN}════════════════════════════════════════${NC}"
echo ""
echo " Remember to revert your router's DHCP settings:"
echo " Default Gateway and DNS Server → back to your router's own IP"
echo ""
