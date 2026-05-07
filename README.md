# xray-gateway

Transparent proxy gateway based on [Xray-core](https://github.com/XTLS/Xray-core).  
Install on any Linux PC or SBC connected to your router — all LAN devices get routed through your VPN automatically, with no per-device configuration.

## How it works

```
[Internet]
    │
[Router]  ←── one cable ──→  [Mini PC / Gateway]
    │                            (xray TProxy)
    └── Wi-Fi / LAN devices
             │
             └── all traffic transparently routed via VPN or direct
```

The gateway connects via a single Ethernet cable to your router. Your router's DHCP points to the gateway as Default Gateway and DNS. All devices on the network are transparently proxied — no configuration needed on the devices themselves.

## Requirements

- Any Linux PC or SBC (x86_64, arm64, armv7)
- Ubuntu / Debian (or compatible)
- Wired connection to router
- A VPN key: `ss://`, `vless://`, `vmess://` or `trojan://`

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/bkaganovich-stack/xray-gateway/main/install.sh | sudo bash
```

That's it. The script:
1. Auto-detects your network interface and router IP
2. Downloads the latest xray-core binary from GitHub
3. Downloads geo databases
4. Sets up systemd services, dnsmasq, iptables TProxy rules
5. Starts the web management UI on port 80

## After install

Open `http://<gateway-ip>` in your browser:

| Field | Value |
|-------|-------|
| Login | `admin` |
| Password | `admin` |

1. **Paste your VPN key** (Shadowsocks, VLESS, VMess, Trojan)
2. **Choose a routing profile:**

| Profile | Description |
|---------|-------------|
| `all_except_ru` | All traffic via VPN, except specific domains/IPs (direct) |
| `blocked_only` | Only specific sites via VPN, everything else direct |
| `all` | All traffic via VPN |

3. Click **Apply**
4. Go to **Settings → Change Password**

## Configure your router

In your router's DHCP settings:

| Setting | Value |
|---------|-------|
| Default Gateway | Gateway device IP |
| DNS Server | Gateway device IP |

Reconnect devices (or renew DHCP lease) to apply.

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/bkaganovich-stack/xray-gateway/main/uninstall.sh | sudo bash
```

Removes all files, services, and config. Prompts for confirmation first.

## File layout on the gateway

```
/opt/xray-proxy/
├── bin/xray                   # xray-core binary
├── config/
│   ├── xray.json              # generated from settings
│   ├── settings.json          # VPN key, profile, password hash
│   ├── network.conf           # LAN_IF, ROUTER_IP (auto-detected)
│   ├── geoip.dat
│   └── geosite.dat
├── scripts/
│   ├── iptables.sh            # TProxy + DNS redirect rules
│   └── update-geo.sh          # geo database updater
├── web/
│   ├── main.py                # FastAPI backend
│   └── static/index.html      # Web UI
├── logs/
│   └── access.log
└── .secret                    # session signing key (chmod 600)
```

## Troubleshooting

```bash
# Service status
sudo systemctl status xray-proxy xray-web dnsmasq

# xray logs (live)
sudo journalctl -u xray-proxy -f

# Check traffic routing
sudo tail -f /opt/xray-proxy/logs/access.log
# "proxy" = via VPN,  "direct" = bypass

# Test DNS
dig @<gateway-ip> -p 53 google.com +short

# Verify geo databases
sudo bash /opt/xray-proxy/scripts/update-geo.sh
```

## Supported VPN protocols

- **Shadowsocks** — `ss://`
- **VLESS** — `vless://` (including Reality)
- **VMess** — `vmess://`
- **Trojan** — `trojan://`
