#!/usr/bin/env python3
"""Xray Proxy Gateway — Web Management Interface v1.5.0"""

import asyncio, base64, fcntl, hashlib, hmac, io, ipaddress, json, os, pty
import re, shutil, signal, socket, struct, subprocess, tarfile, termios, time
import urllib.parse, urllib.request
import uuid as _uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = "1.5.0"

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, Response, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE      = Path("/opt/xray-proxy")
CFG_DIR   = BASE / "config"
SNAP_DIR  = CFG_DIR / "snapshots"
SCRIPT    = BASE / "scripts"
LOGS      = BASE / "logs"
STATIC    = BASE / "web" / "static"
SETTINGS  = CFG_DIR / "settings.json"
XCFG      = CFG_DIR / "xray.json"
DNS_CONF  = Path("/etc/dnsmasq.d/gateway.conf")

MAX_SNAPSHOTS   = 15
ALERT_LOG_SIZE  = 100   # keep last N alert events in memory

# ── Default settings (v1.5) ────────────────────────────────────────────────────
DEFAULT_SETTINGS: dict = {
    "version":      "1.5.0",
    "auth":         {"username": "admin",
                     "password_hash": hashlib.sha256(b"admin").hexdigest()},
    # VPN: single key kept for migration compatibility; canonical list in vpn_servers
    "vpn_key":      None,       # DEPRECATED — use vpn_servers
    "vpn_servers":  [],         # list of VPNServer dicts
    "active_vpn_id": None,      # id of active server
    "profile":      "all_except_ru",
    "geo_updated":  None,
    "force_aaplimg_vpn": True,
    "custom_rules": {"always_direct": [], "always_vpn": []},
    # Devices: keyed by MAC (or "ip:A.B.C.D" when MAC unavailable)
    # {"aa:bb:cc:dd:ee:ff": {"name":"...", "policy":"inherit", "ips":[]}}
    "devices":      {},
    "device_names": {},         # DEPRECATED — migrated into devices on load
    # DNS config (drives dnsmasq)
    "dns": {
        "upstream":     ["192.168.50.1"],
        "upstream_ru":  [],          # split-DNS: upstream for .ru / local
        "cache_size":   1000,
        "local_records": [],         # [{"hostname":"x.local","ip":"1.2.3.4"}]
    },
    # Alerts
    "alerts": {
        "enabled":      False,
        "webhook_url":  "",
        "events":       ["vpn_down", "config_rollback", "geo_update_failed",
                         "disk_high", "all_vpn_unavailable", "login_failed"],
        "cooldown_min": 30,
    },
}

# ── In-memory alert state ──────────────────────────────────────────────────────
_alert_last_sent: dict[str, float] = {}   # event_type → timestamp
_alert_log:       list[dict]        = []  # recent alert events
_login_fail_count: dict[str, int]   = {}  # ip → consecutive failures
_failover_last:    float            = 0.0 # timestamp of last failover

# ── Settings helpers ───────────────────────────────────────────────────────────
def _migrate_settings(s: dict) -> dict:
    """Upgrade settings from any previous version to current schema."""
    # v1.4 → v1.5: vpn_key → vpn_servers
    if s.get("vpn_key") and not s.get("vpn_servers"):
        srv_id = str(_uuid_mod.uuid4())
        s["vpn_servers"] = [{
            "id": srv_id, "name": "Server 1",
            "key": s["vpn_key"], "enabled": True, "priority": 1,
            "last_status": "unknown", "latency_ms": None, "last_checked": None,
        }]
        s["active_vpn_id"] = srv_id

    # v1.4 → v1.5: device_names → devices
    if s.get("device_names") and not s.get("devices"):
        s["devices"] = {}
        for ip, name in s["device_names"].items():
            key = f"ip:{ip}"
            s["devices"][key] = {"name": name, "policy": "inherit", "ips": [ip]}

    # Fill missing keys from defaults
    for k, v in DEFAULT_SETTINGS.items():
        s.setdefault(k, v)
    if "dns" not in s:
        s["dns"] = dict(DEFAULT_SETTINGS["dns"])
    else:
        for k, v in DEFAULT_SETTINGS["dns"].items():
            s["dns"].setdefault(k, v)
    if "alerts" not in s:
        s["alerts"] = dict(DEFAULT_SETTINGS["alerts"])
    else:
        for k, v in DEFAULT_SETTINGS["alerts"].items():
            s["alerts"].setdefault(k, v)
    s.setdefault("version", VERSION)
    s["custom_rules"].setdefault("always_direct", [])
    s["custom_rules"].setdefault("always_vpn", [])
    return s

def load_settings() -> dict:
    if SETTINGS.exists():
        try:
            s = json.loads(SETTINGS.read_text())
        except Exception:
            s = {}
        return _migrate_settings(s)
    return _migrate_settings(dict(DEFAULT_SETTINGS))

def save_settings(s: dict) -> None:
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS.write_text(json.dumps(s, indent=2))

SECRET = (BASE / ".secret").read_text().strip() if (BASE / ".secret").exists() \
         else "xray-proxy-default-secret"

# ── Auth ───────────────────────────────────────────────────────────────────────
def make_token(user: str) -> str:
    exp = int(time.time()) + 86400
    payload = f"{user}:{exp}"
    sig = hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()

def verify_token(tok: str) -> Optional[str]:
    try:
        decoded = base64.urlsafe_b64decode(tok + "==").decode()
        user, exp, sig = decoded.rsplit(":", 2)
        if int(exp) < int(time.time()):
            return None
        expected = hmac.new(SECRET.encode(), f"{user}:{exp}".encode(), hashlib.sha256).hexdigest()
        return user if hmac.compare_digest(sig, expected) else None
    except Exception:
        return None

def auth_dep(req: Request) -> str:
    tok = req.cookies.get("token") or req.headers.get("X-Token", "")
    user = verify_token(tok)
    if not user:
        raise HTTPException(401, "Unauthorized")
    return user

# ── VPN Key Parsing ────────────────────────────────────────────────────────────
def _b64d(s: str) -> str:
    pad = (4 - len(s) % 4) % 4
    return base64.b64decode(s + "=" * pad).decode()

def parse_key(key: str):
    k = key.strip()
    if k.startswith("ss://"):     return _parse_ss(k)
    if k.startswith("vless://"):  return _parse_vless(k)
    if k.startswith("vmess://"):  return _parse_vmess(k)
    if k.startswith("trojan://"): return _parse_trojan(k)
    raise ValueError(f"Unknown protocol in: {k[:30]}")

def _sockopt():       return {"mark": 255}
def _proxy_sockopt(): return {"mark": 255, "tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15}

def mask_key(key: str) -> str:
    """Return a masked version of a VPN key safe for display."""
    if not key:
        return ""
    try:
        if "@" in key:
            # Show protocol and server only
            at = key.rfind("@")
            host_part = key[at+1:]
            proto = key.split("://")[0] if "://" in key else "??"
            return f"{proto}://***@{host_part}"
        return key[:8] + "***"
    except Exception:
        return "***"

def _parse_ss(uri: str):
    uri = uri[5:]; name = ""
    if "#" in uri:
        uri, name = uri.rsplit("#", 1); name = urllib.parse.unquote(name)
    if "@" not in uri:
        uri = _b64d(uri)
    user, hostport = uri.rsplit("@", 1)
    try:
        user = _b64d(user)
    except Exception:
        pass
    method, password = user.split(":", 1)
    host, port = hostport.rsplit(":", 1)
    ob = {"protocol": "shadowsocks", "tag": "proxy",
          "settings": {"servers": [{"address": host, "port": int(port),
                                    "method": method, "password": password}]},
          "streamSettings": {"network": "tcp", "sockopt": _proxy_sockopt()}}
    return ob, {"name": name or f"{host}:{port}", "server": host,
                "port": int(port), "protocol": "Shadowsocks"}

def _parse_vless(uri: str):
    uri = uri[8:]; name = ""
    if "#" in uri:
        uri, name = uri.rsplit("#", 1); name = urllib.parse.unquote(name)
    uuid, rest = uri.split("@", 1)
    hostport, qs = (rest.split("?", 1) + [""])[:2]
    host, port = hostport.rsplit(":", 1)
    p = dict(urllib.parse.parse_qsl(qs))
    net = p.get("type", "tcp"); sec = p.get("security", "none")
    ss = {"network": net, "sockopt": _proxy_sockopt()}
    if sec == "tls":
        ss["security"] = "tls"
        ss["tlsSettings"] = {"serverName": p.get("sni", host),
                             "allowInsecure": p.get("allowInsecure", "0") == "1"}
    elif sec == "reality":
        ss["security"] = "reality"
        ss["realitySettings"] = {"serverName": p.get("sni", host),
                                  "publicKey": p.get("pbk", ""),
                                  "shortId": p.get("sid", ""),
                                  "fingerprint": p.get("fp", "chrome")}
    if net == "ws":
        ss["wsSettings"] = {"path": p.get("path", "/"), "headers": {"Host": p.get("host", host)}}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": p.get("serviceName", "")}
    ob = {"protocol": "vless", "tag": "proxy",
          "settings": {"vnext": [{"address": host, "port": int(port),
                                   "users": [{"id": uuid, "encryption": "none",
                                              "flow": p.get("flow", "")}]}]},
          "streamSettings": ss}
    return ob, {"name": name or f"{host}:{port}", "server": host,
                "port": int(port), "protocol": "VLESS"}

def _parse_vmess(uri: str):
    d = json.loads(_b64d(uri[8:]))
    host = d.get("add", ""); port = int(d.get("port", 443))
    net = d.get("net", "tcp"); tls_val = d.get("tls", "")
    ss = {"network": net, "sockopt": _proxy_sockopt()}
    if tls_val == "tls":
        ss["security"] = "tls"; ss["tlsSettings"] = {"serverName": d.get("sni", host)}
    if net == "ws":
        ss["wsSettings"] = {"path": d.get("path", "/"), "headers": {"Host": d.get("host", host)}}
    ob = {"protocol": "vmess", "tag": "proxy",
          "settings": {"vnext": [{"address": host, "port": port,
                                   "users": [{"id": d.get("id", ""),
                                              "alterId": int(d.get("aid", 0)),
                                              "security": d.get("scy", "auto")}]}]},
          "streamSettings": ss}
    return ob, {"name": d.get("ps", f"{host}:{port}"), "server": host,
                "port": port, "protocol": "VMess"}

def _parse_trojan(uri: str):
    uri = uri[9:]; name = ""
    if "#" in uri:
        uri, name = uri.rsplit("#", 1); name = urllib.parse.unquote(name)
    password, rest = uri.split("@", 1)
    hostport, qs = (rest.split("?", 1) + [""])[:2]
    host, port = hostport.rsplit(":", 1)
    p = dict(urllib.parse.parse_qsl(qs))
    ob = {"protocol": "trojan", "tag": "proxy",
          "settings": {"servers": [{"address": host, "port": int(port), "password": password}]},
          "streamSettings": {"network": "tcp", "security": "tls",
                             "tlsSettings": {"serverName": p.get("sni", host)},
                             "sockopt": _proxy_sockopt()}}
    return ob, {"name": name or f"{host}:{port}", "server": host,
                "port": int(port), "protocol": "Trojan"}

# ── ARP helpers ────────────────────────────────────────────────────────────────
def get_arp_table() -> list[dict]:
    """Read ARP table; merge IPv4+IPv6 by MAC. Return [{ip, mac, state}...]."""
    try:
        r = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5)
        devices: dict[str, dict] = {}  # mac → {ips:set, mac, state}
        ip_only: dict[str, dict] = {}  # ip → entry (for MAC-less entries)
        seen_ips: set[str] = set()
        for line in r.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) < 2: continue
            ip_str = parts[0]
            try:
                ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if ip_str in seen_ips:
                continue
            seen_ips.add(ip_str)
            mac = state = ""
            for i, p in enumerate(parts):
                if p == "lladdr" and i + 1 < len(parts):
                    mac = parts[i + 1].lower()
                if p in ("REACHABLE", "STALE", "DELAY", "FAILED", "NOARP", "PERMANENT"):
                    state = p
            if state == "FAILED":
                continue
            if mac:
                if mac not in devices:
                    devices[mac] = {"mac": mac, "ips": set(), "state": state}
                devices[mac]["ips"].add(ip_str)
                # prefer REACHABLE state
                if state == "REACHABLE":
                    devices[mac]["state"] = state
            else:
                ip_only[ip_str] = {"mac": "", "ips": {ip_str}, "state": state}
        result = []
        for mac, d in devices.items():
            result.append({"mac": mac, "ips": sorted(d["ips"]), "state": d["state"]})
        for ip, d in ip_only.items():
            result.append({"mac": "", "ips": [ip], "state": d["state"]})
        return result
    except Exception:
        return []

def arp_ip_to_mac() -> dict[str, str]:
    """Return {ip: mac} mapping from current ARP table."""
    m: dict[str, str] = {}
    for entry in get_arp_table():
        if entry["mac"]:
            for ip in entry["ips"]:
                m[ip] = entry["mac"]
    return m

def get_devices_merged(settings: dict) -> list[dict]:
    """Return merged device list: ARP + stored names/policies."""
    stored = settings.get("devices", {})
    arp = get_arp_table()
    result = []
    # Build set of MACs from ARP
    seen_keys: set[str] = set()
    for entry in arp:
        key = entry["mac"] if entry["mac"] else f"ip:{entry['ips'][0]}"
        seen_keys.add(key)
        d = stored.get(key, {})
        result.append({
            "key":    key,
            "mac":    entry["mac"],
            "ips":    entry["ips"],
            "state":  entry["state"],
            "name":   d.get("name", ""),
            "policy": d.get("policy", "inherit"),
        })
    # Add stored devices not in current ARP (offline devices)
    for key, d in stored.items():
        if key not in seen_keys:
            result.append({
                "key":    key,
                "mac":    "" if key.startswith("ip:") else key,
                "ips":    d.get("ips", []),
                "state":  "OFFLINE",
                "name":   d.get("name", ""),
                "policy": d.get("policy", "inherit"),
            })
    return result

# ── Custom Rules Validation ────────────────────────────────────────────────────
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)

def validate_custom_rule(rule: str) -> tuple[bool, str]:
    rule = rule.strip()
    if not rule:    return False, "Empty rule"
    if len(rule) > 512: return False, "Rule too long"
    for prefix in ("domain:", "full:", "keyword:", "regexp:"):
        if rule.startswith(prefix):
            value = rule[len(prefix):]
            if not value: return False, f"Empty value after {prefix}"
            if prefix == "regexp:":
                try:   re.compile(value)
                except re.error as e: return False, f"Invalid regexp: {e}"
            return True, ""
    try:
        ipaddress.ip_network(rule, strict=False); return True, ""
    except ValueError:
        pass
    if _DOMAIN_RE.match(rule): return True, ""
    return False, f"Invalid rule '{rule}'"

def _custom_rule_to_xray(rule: str) -> tuple[str, str]:
    rule = rule.strip()
    for prefix in ("domain:", "full:", "keyword:", "regexp:"):
        if rule.startswith(prefix): return "domain", rule
    try:
        net = ipaddress.ip_network(rule, strict=False); return "ip", str(net)
    except ValueError:
        pass
    return "domain", f"domain:{rule}"

def _rules_to_xray_entry(rules: list[str], outbound: str) -> list[dict]:
    if not rules: return []
    domain_vals, ip_vals = [], []
    for r in rules:
        kind, val = _custom_rule_to_xray(r)
        if kind == "domain": domain_vals.append(val)
        else:                ip_vals.append(val)
    result = []
    if domain_vals: result.append({"type": "field", "domain": domain_vals, "outboundTag": outbound})
    if ip_vals:     result.append({"type": "field", "ip":     ip_vals,     "outboundTag": outbound})
    return result

# ── Device Policy → Xray Rules ─────────────────────────────────────────────────
DEVICE_POLICIES = ("inherit", "blocked_only", "all_except_ru", "all", "always_direct", "always_vpn")

def _device_policy_rules(ips: list[str], policy: str, final: str) -> list[dict]:
    """Generate xray routing rules for a device with a given policy."""
    if policy == "inherit" or not ips: return []
    src = sorted(set(ips))
    if policy == "always_direct":
        return [{"type": "field", "source": src, "network": "tcp,udp", "outboundTag": "direct"}]
    if policy in ("always_vpn", "all"):
        return [{"type": "field", "source": src, "network": "tcp,udp", "outboundTag": final}]
    if policy == "all_except_ru":
        return [
            {"type": "field", "source": src, "ip":     ["geoip:ru"],            "outboundTag": "direct"},
            {"type": "field", "source": src, "domain": ["geosite:category-ru"], "outboundTag": "direct"},
            {"type": "field", "source": src, "network": "tcp,udp",              "outboundTag": final},
        ]
    if policy == "blocked_only":
        return [
            {"type": "field", "source": src, "domain": ["geosite:category-ru-blocked"], "outboundTag": final},
            {"type": "field", "source": src, "ip":     ["geoip:ru"],                    "outboundTag": "direct"},
            {"type": "field", "source": src, "domain": ["geosite:category-ru"],         "outboundTag": "direct"},
            {"type": "field", "source": src, "network": "tcp,udp",                      "outboundTag": "direct"},
        ]
    return []

def _build_device_rules(settings: dict, final: str) -> list[dict]:
    """Build all per-device xray routing rules from stored device policies."""
    rules: list[dict] = []
    stored = settings.get("devices", {})
    # Build MAC→IPs from current ARP for REACHABLE/STALE devices
    arp = get_arp_table()
    arp_by_key: dict[str, list[str]] = {}
    for entry in arp:
        key = entry["mac"] if entry["mac"] else f"ip:{entry['ips'][0]}"
        arp_by_key[key] = entry["ips"]

    for key, d in stored.items():
        policy = d.get("policy", "inherit")
        if policy == "inherit": continue
        # Prefer live ARP IPs; fall back to stored IPs
        ips = arp_by_key.get(key, d.get("ips", []))
        if not ips: continue
        rules.extend(_device_policy_rules(ips, policy, final))
    return rules

# ── Xray Config Builder ────────────────────────────────────────────────────────
def _get_active_vpn_outbound(settings: dict) -> tuple[list, bool, Optional[str]]:
    """Return (outbounds, has_proxy, proxy_server_ip) for active VPN server."""
    servers = settings.get("vpn_servers", [])
    active_id = settings.get("active_vpn_id")
    active = None
    if active_id:
        active = next((s for s in servers if s.get("id") == active_id and s.get("enabled")), None)
    if not active and servers:
        active = next((s for s in sorted(servers, key=lambda x: x.get("priority", 99))
                       if s.get("enabled")), None)
    if active:
        try:
            ob, info = parse_key(active["key"])
            return [ob], True, info.get("server")
        except Exception:
            pass
    # Fallback: legacy vpn_key
    vpn_key = settings.get("vpn_key")
    if vpn_key:
        try:
            ob, info = parse_key(vpn_key)
            return [ob], True, info.get("server")
        except Exception:
            pass
    return [], False, None

def build_xray_config(settings: dict) -> dict:
    profile        = settings.get("profile", "all_except_ru")
    custom         = settings.get("custom_rules", {"always_direct": [], "always_vpn": []})
    force_aaplimg  = settings.get("force_aaplimg_vpn", True)

    vpn_obs, has_proxy, proxy_server_ip = _get_active_vpn_outbound(settings)
    outbounds = vpn_obs + [
        {"protocol": "freedom", "tag": "direct",
         "settings": {"domainStrategy": "UseIP"}, "streamSettings": {"sockopt": _sockopt()}},
        {"protocol": "blackhole", "tag": "block"},
    ]
    final = "proxy" if has_proxy else "direct"

    rules: list[dict] = [
        *([{"type": "field", "ip": [proxy_server_ip], "outboundTag": "direct"}]
          if proxy_server_ip else []),
        {"type": "field", "ip":     ["geoip:private"],   "outboundTag": "direct"},
        {"type": "field", "domain": ["geosite:private"],  "outboundTag": "direct"},
        *_rules_to_xray_entry(custom.get("always_direct", []), "direct"),
        *_rules_to_xray_entry(custom.get("always_vpn", []),    final),
        # Per-device policies (override global profile)
        *_build_device_rules(settings, final),
    ]

    if profile == "blocked_only":
        rules += [
            *([{"type": "field",
                "domain": ["domain:cdn-apple.com", "domain:itunes.apple.com", "domain:aaplimg.com"],
                "outboundTag": final}] if force_aaplimg else []),
            {"type": "field", "ip":     ["geoip:ru"],                   "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:category-ru"],         "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:category-ru-blocked"], "outboundTag": final},
        ]
        default = "direct"
    elif profile == "all_except_ru":
        rules += [
            *([{"type": "field",
                "domain": ["domain:cdn-apple.com", "domain:itunes.apple.com", "domain:aaplimg.com"],
                "outboundTag": final}] if force_aaplimg else []),
            {"type": "field", "ip":     ["geoip:ru"],            "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:category-ru"], "outboundTag": "direct"},
        ]
        default = final
    else:
        default = final

    rules += [
        {"type": "field", "network": "tcp",     "port": "5228", "outboundTag": "direct"},
        {"type": "field", "network": "tcp,udp",                  "outboundTag": default},
    ]

    return {
        "log": {"loglevel": "warning",
                "access": str(LOGS / "access.log"),
                "error":  str(LOGS / "xray.log")},
        "inbounds": [{
            "tag": "tproxy-in", "port": 12345,
            "protocol": "dokodemo-door",
            "settings": {"network": "tcp,udp", "followRedirect": True},
            "sniffing": {"enabled": True,
                         "destOverride": ["http", "tls", "quic"],
                         "routeOnly": True},
            "streamSettings": {"sockopt": {"tproxy": "tproxy", "mark": 255}},
        }],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
        "stats": {},
        "policy": {"system": {"statsInboundUplink": True, "statsInboundDownlink": True}},
    }

# ── DNS Config ─────────────────────────────────────────────────────────────────
def _validate_dns_ip(ip: str) -> bool:
    try: ipaddress.ip_address(ip); return True
    except ValueError: return False

def _validate_hostname(h: str) -> bool:
    return bool(re.match(r'^[a-zA-Z0-9.\-]+$', h) and len(h) <= 253)

def validate_dns_settings(dns: dict) -> list[str]:
    errors = []
    for ip in dns.get("upstream", []):
        if not _validate_dns_ip(ip):
            errors.append(f"Invalid upstream IP: {ip}")
    for ip in dns.get("upstream_ru", []):
        if not _validate_dns_ip(ip):
            errors.append(f"Invalid upstream_ru IP: {ip}")
    cs = dns.get("cache_size", 1000)
    if not isinstance(cs, int) or cs < 0 or cs > 100000:
        errors.append("cache_size must be 0–100000")
    for rec in dns.get("local_records", []):
        if not _validate_hostname(rec.get("hostname", "")):
            errors.append(f"Invalid hostname: {rec.get('hostname')}")
        if not _validate_dns_ip(rec.get("ip", "")):
            errors.append(f"Invalid IP for record: {rec.get('ip')}")
    return errors

def build_dnsmasq_conf(dns: dict) -> str:
    lan_ip = _get_lan_ip() or "127.0.0.1"
    lines = [
        "# Generated by xray-gateway — do not edit manually",
        f"listen-address={lan_ip}",
        "bind-interfaces",
        "port=5335",
        "no-resolv",
        f"cache-size={dns.get('cache_size', 1000)}",
        "",
    ]
    for ip in dns.get("upstream", ["192.168.50.1"]):
        lines.append(f"server={ip}")
    for ip in dns.get("upstream_ru", []):
        lines.append(f"server=/ru/{ip}")
        lines.append(f"server=/local/{ip}")
    for rec in dns.get("local_records", []):
        lines.append(f"address=/{rec['hostname']}/{rec['ip']}")
    return "\n".join(lines) + "\n"

def apply_dns_config(dns: dict) -> tuple[bool, str]:
    """Write dnsmasq config and restart. Returns (ok, error)."""
    try:
        conf = build_dnsmasq_conf(dns)
        DNS_CONF.write_text(conf)
        r = subprocess.run(["systemctl", "restart", "dnsmasq"],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return False, r.stderr[:200]
        return True, ""
    except Exception as e:
        return False, str(e)

def get_dns_status() -> dict:
    """Return current DNS status: active upstream, dnsmasq state."""
    try:
        dns_active = subprocess.run(["systemctl", "is-active", "dnsmasq"],
                                    capture_output=True, text=True).stdout.strip()
        # Test each upstream with a quick ping-level check
        s = load_settings()
        upstreams = s.get("dns", {}).get("upstream", [])
        upstream_status = []
        for ip in upstreams:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                start = time.time()
                sock.connect((ip, 53)); sock.close()
                lat = int((time.time() - start) * 1000)
                upstream_status.append({"ip": ip, "reachable": True, "latency_ms": lat})
            except Exception:
                upstream_status.append({"ip": ip, "reachable": False, "latency_ms": None})
        return {"dnsmasq": dns_active, "upstreams": upstream_status}
    except Exception as e:
        return {"dnsmasq": "unknown", "upstreams": [], "error": str(e)}

# ── Snapshot Management ────────────────────────────────────────────────────────
def _snap_path(snap_id: str) -> Path:
    return SNAP_DIR / f"snap_{snap_id}.json"

def create_snapshot(reason: str, settings: Optional[dict] = None) -> str:
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    snap_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    s = settings or load_settings()
    xray_cfg = {}
    if XCFG.exists():
        try:  xray_cfg = json.loads(XCFG.read_text())
        except Exception: pass
    snap = {"id": snap_id, "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": reason, "settings": s, "xray_config": xray_cfg}
    _snap_path(snap_id).write_text(json.dumps(snap, indent=2))
    _rotate_snapshots(); return snap_id

def _rotate_snapshots() -> None:
    snaps = sorted(SNAP_DIR.glob("snap_*.json"), key=lambda p: p.name)
    for old in snaps[:-MAX_SNAPSHOTS]:
        try: old.unlink()
        except Exception: pass

def list_snapshots() -> list[dict]:
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    result = []
    for p in sorted(SNAP_DIR.glob("snap_*.json"), key=lambda x: x.name, reverse=True):
        try:
            snap = json.loads(p.read_text())
            result.append({"id": snap["id"], "timestamp": snap["timestamp"],
                           "reason": snap.get("reason", ""),
                           "profile": snap.get("settings", {}).get("profile", "?"),
                           "has_vpn": bool(snap.get("settings", {}).get("vpn_key") or
                                          snap.get("settings", {}).get("vpn_servers"))})
        except Exception:
            pass
    return result

def restore_snapshot(snap_id: str) -> tuple[bool, str]:
    p = _snap_path(snap_id)
    if not p.exists(): return False, f"Snapshot {snap_id} not found"
    try:
        snap = json.loads(p.read_text())
    except Exception as e:
        return False, f"Failed to read snapshot: {e}"
    settings = snap.get("settings", {})
    xray_cfg = snap.get("xray_config", {})
    save_settings(settings)
    if xray_cfg: XCFG.write_text(json.dumps(xray_cfg, indent=2))
    r = subprocess.run(["systemctl", "restart", "xray-proxy"], capture_output=True, text=True)
    if r.returncode != 0: return False, f"xray restart failed: {r.stderr[:200]}"
    fire_alert("config_rollback", f"Restored snapshot {snap_id}")
    return True, f"Restored snapshot {snap_id}"

# ── Apply Config (safe, with auto-rollback) ────────────────────────────────────
def apply_config(settings: dict, reason: str = "config_change",
                 _pre_settings: Optional[dict] = None) -> tuple[bool, str]:
    snap_id = create_snapshot(f"pre_{reason}", settings=_pre_settings)
    cfg = build_xray_config(settings)
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    XCFG.write_text(json.dumps(cfg, indent=2))
    subprocess.run(["systemctl", "restart", "xray-proxy"], capture_output=True)
    for _ in range(10):
        time.sleep(0.5)
        r = subprocess.run(["systemctl", "is-active", "xray-proxy"],
                            capture_output=True, text=True)
        if r.stdout.strip() == "active":
            return True, ""
    # Auto-rollback
    ok, msg = restore_snapshot(snap_id)
    rolled = (f"xray failed to start; auto-rollback to {snap_id} "
              f"{'ok' if ok else 'FAILED: '+msg}")
    fire_alert("config_rollback", rolled)
    return False, rolled

# ── Alerts ─────────────────────────────────────────────────────────────────────
def fire_alert(event: str, detail: str = "") -> None:
    """Non-blocking: record event, send webhook if configured and not on cooldown."""
    s = load_settings()
    cfg = s.get("alerts", {})
    now = time.time()
    # Log the event regardless of alert config
    entry = {"ts": datetime.now(timezone.utc).isoformat(), "event": event, "detail": detail}
    _alert_log.append(entry)
    if len(_alert_log) > ALERT_LOG_SIZE: _alert_log.pop(0)

    if not cfg.get("enabled"): return
    if event not in cfg.get("events", []): return
    cooldown = cfg.get("cooldown_min", 30) * 60
    last = _alert_last_sent.get(event, 0)
    if now - last < cooldown: return
    url = cfg.get("webhook_url", "").strip()
    if not url: return
    _alert_last_sent[event] = now
    # Fire-and-forget in background thread to not block caller
    import threading
    def _send():
        try:
            payload = json.dumps({
                "event": event, "detail": detail,
                "timestamp": entry["ts"],
                "gateway": "xray-gateway",
            }).encode()
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={"Content-Type": "application/json",
                         "User-Agent": "xray-gateway-alert/1.5.0"})
            with urllib.request.urlopen(req, timeout=10): pass
        except Exception as exc:
            _alert_log.append({
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": "_alert_send_error",
                "detail": f"{event}: {exc}",
            })
    threading.Thread(target=_send, daemon=True).start()

# ── VPN Health Check ───────────────────────────────────────────────────────────
def _vpn_server_health(srv: dict) -> tuple[bool, Optional[int]]:
    """TCP connect to VPN server:port. Returns (reachable, latency_ms)."""
    try:
        _, info = parse_key(srv["key"])
        host = info["server"]; port = info["port"]
        start = time.time()
        sock = socket.create_connection((host, port), timeout=5)
        sock.close()
        return True, int((time.time() - start) * 1000)
    except Exception:
        return False, None

async def _failover_loop() -> None:
    """Background task: check active VPN, failover if down."""
    global _failover_last
    await asyncio.sleep(30)  # initial delay
    while True:
        try:
            s = load_settings()
            servers = s.get("vpn_servers", [])
            if not servers:
                await asyncio.sleep(60); continue
            active_id = s.get("active_vpn_id")
            active = next((x for x in servers if x.get("id") == active_id), None)
            if not active:
                await asyncio.sleep(60); continue

            ok, lat = await asyncio.get_event_loop().run_in_executor(
                None, _vpn_server_health, active)

            # Update health status
            s2 = load_settings()
            for srv in s2.get("vpn_servers", []):
                if srv.get("id") == active_id:
                    srv["last_status"] = "ok" if ok else "error"
                    srv["latency_ms"]  = lat
                    srv["last_checked"] = datetime.now(timezone.utc).isoformat()
            save_settings(s2)

            if not ok:
                fire_alert("vpn_down", f"Server {active.get('name','?')} unreachable")
                now = time.time()
                if now - _failover_last > 300:   # max one failover per 5 min
                    # Find next available enabled server
                    candidates = [x for x in sorted(servers, key=lambda x: x.get("priority", 99))
                                  if x.get("enabled") and x.get("id") != active_id]
                    for cand in candidates:
                        cok, _ = await asyncio.get_event_loop().run_in_executor(
                            None, _vpn_server_health, cand)
                        if cok:
                            _failover_last = now
                            s3 = load_settings()
                            s3["active_vpn_id"] = cand["id"]
                            save_settings(s3)
                            apply_config(s3, "failover")
                            fire_alert("failover_executed",
                                       f"Switched to {cand.get('name','?')}")
                            break
                    else:
                        fire_alert("all_vpn_unavailable", "No reachable VPN server found")
        except Exception:
            pass
        await asyncio.sleep(120)  # check every 2 minutes

# ── Disk Health Check ──────────────────────────────────────────────────────────
async def _disk_monitor_loop() -> None:
    """Alert when root disk > 90% full."""
    await asyncio.sleep(60)
    while True:
        try:
            du = shutil.disk_usage("/")
            pct = du.used / max(du.total, 1) * 100
            if pct > 90:
                fire_alert("disk_high", f"Root partition {pct:.1f}% full")
        except Exception:
            pass
        await asyncio.sleep(3600)  # check every hour

# ── GeoIP / GeoSite Parsers ────────────────────────────────────────────────────
def _varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while pos < len(data):
        b = data[pos]; pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80): return result, pos
        shift += 7
    return result, pos

def _parse_len_field(data: bytes, pos: int) -> tuple[bytes, int]:
    length, pos = _varint(data, pos)
    return data[pos:pos + length], pos + length

_geoip_ru_nets:    Optional[list] = None
_geoip_ru_mtime:   float          = 0.0
_geosite_ru_data:  Optional[dict] = None
_geosite_ru_mtime: float          = 0.0

def _load_geoip_ru() -> list:
    global _geoip_ru_nets, _geoip_ru_mtime
    geoip_path = CFG_DIR / "geoip.dat"
    try:   mtime = geoip_path.stat().st_mtime
    except Exception: return []
    if _geoip_ru_nets is not None and mtime == _geoip_ru_mtime:
        return _geoip_ru_nets
    networks: list = []
    try:
        data = geoip_path.read_bytes(); pos = 0; n = len(data)
        while pos < n:
            try:
                tag, pos = _varint(data, pos)
                wire = tag & 7; field = tag >> 3
                if wire == 2:
                    entry, pos = _parse_len_field(data, pos)
                    if field != 1: continue
                    cc = None; cidrs_raw = []
                    p = 0; m = len(entry)
                    while p < m:
                        t, p = _varint(entry, p); f, w = t >> 3, t & 7
                        if w == 2:
                            v, p = _parse_len_field(entry, p)
                            if f == 1: cc = v.decode("ascii", errors="replace").strip("\x00 ")
                            elif f == 2:
                                ip_b = plen = None; cp = 0; cm = len(v)
                                while cp < cm:
                                    ct, cp = _varint(v, cp); cf, cw = ct >> 3, ct & 7
                                    if cw == 2:
                                        iv, cp = _parse_len_field(v, cp)
                                        if cf == 1: ip_b = iv
                                    elif cw == 0:
                                        pval, cp = _varint(v, cp)
                                        if cf == 2: plen = pval
                                    else: break
                                if ip_b and plen is not None: cidrs_raw.append((ip_b, plen))
                        elif w == 0: _, p = _varint(entry, p)
                        elif w == 1: p += 8
                        elif w == 5: p += 4
                        else: break
                    if cc and cc.upper() == "RU":
                        for ip_b, plen in cidrs_raw:
                            try:
                                if len(ip_b) == 4:
                                    networks.append(ipaddress.IPv4Network((ip_b, plen), strict=False))
                                elif len(ip_b) == 16:
                                    networks.append(ipaddress.IPv6Network((ip_b, plen), strict=False))
                            except Exception: pass
                elif wire == 0: _, pos = _varint(data, pos)
                elif wire == 1: pos += 8
                elif wire == 5: pos += 4
                else: break
            except Exception: break
    except Exception: pass
    _geoip_ru_nets = networks; _geoip_ru_mtime = mtime
    return networks

def _ip_in_geoip_ru(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _load_geoip_ru())
    except ValueError: return False

def _load_geosite_ru() -> dict:
    global _geosite_ru_data, _geosite_ru_mtime
    geosite_path = CFG_DIR / "geosite.dat"
    try:   mtime = geosite_path.stat().st_mtime
    except Exception: return {"full": set(), "domain": set(), "plain": [], "regex": []}
    if _geosite_ru_data is not None and mtime == _geosite_ru_mtime:
        return _geosite_ru_data
    result: dict = {"full": set(), "domain": set(), "plain": [], "regex": []}
    try:
        data = geosite_path.read_bytes(); pos = 0; n = len(data)
        while pos < n:
            try:
                tag, pos = _varint(data, pos); wire = tag & 7; field = tag >> 3
                if wire == 2:
                    entry, pos = _parse_len_field(data, pos)
                    if field != 1: continue
                    cc = None; domains_raw = []
                    p = 0; m = len(entry)
                    while p < m:
                        t, p = _varint(entry, p); f, w = t >> 3, t & 7
                        if w == 2:
                            v, p = _parse_len_field(entry, p)
                            if f == 1: cc = v.decode("ascii", errors="replace").strip("\x00 ")
                            elif f == 2:
                                dtype = 0; dval = ""; dp = 0; dm = len(v)
                                while dp < dm:
                                    dt, dp = _varint(v, dp); df, dw = dt >> 3, dt & 7
                                    if dw == 0:
                                        dnum, dp = _varint(v, dp)
                                        if df == 1: dtype = dnum
                                    elif dw == 2:
                                        dv, dp = _parse_len_field(v, dp)
                                        if df == 2: dval = dv.decode("utf-8", errors="replace")
                                    else: break
                                if dval: domains_raw.append((dtype, dval.lower()))
                        elif w == 0: _, p = _varint(entry, p)
                        elif w == 1: p += 8
                        elif w == 5: p += 4
                        else: break
                    if cc and cc.upper() == "CATEGORY-RU":
                        for dtype, dval in domains_raw:
                            if dtype == 3:   result["full"].add(dval)
                            elif dtype == 2: result["domain"].add(dval)
                            elif dtype == 0: result["plain"].append(dval)
                            elif dtype == 1:
                                try:   result["regex"].append(re.compile(dval))
                                except Exception: pass
                elif wire == 0: _, pos = _varint(data, pos)
                elif wire == 1: pos += 8
                elif wire == 5: pos += 4
                else: break
            except Exception: break
    except Exception: pass
    _geosite_ru_data = result; _geosite_ru_mtime = mtime
    return result

def _domain_in_geosite_ru(query: str) -> bool:
    q = query.lower().rstrip(".")
    gs = _load_geosite_ru()
    if q in gs["full"]: return True
    for d in gs["domain"]:
        if q == d or q.endswith("." + d): return True
    for k in gs["plain"]:
        if k in q: return True
    for r in gs["regex"]:
        if r.search(q): return True
    return False

# ── Route Tester ──────────────────────────────────────────────────────────────
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
_PRIVATE_DOMAINS   = {"localhost", "local"}
_APPLE_CDN_DOMAINS = {"cdn-apple.com", "itunes.apple.com", "aaplimg.com"}

def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError: return False

def _is_private_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return d in _PRIVATE_DOMAINS or d.endswith(".local") or d.endswith(".localhost")

def _domain_matches_apple_cdn(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == cdn or d.endswith("." + cdn) for cdn in _APPLE_CDN_DOMAINS)

def _custom_matches(rule: str, target_domain: Optional[str], target_ip: Optional[str]) -> bool:
    rule = rule.strip()
    if rule.startswith("domain:"):
        if not target_domain: return False
        d = rule[7:].lower(); q = target_domain.lower()
        return q == d or q.endswith("." + d)
    if rule.startswith("full:"):
        return bool(target_domain) and target_domain.lower() == rule[5:].lower()
    if rule.startswith("keyword:"):
        return bool(target_domain) and rule[8:].lower() in target_domain.lower()
    if rule.startswith("regexp:"):
        target = target_domain or target_ip or ""
        try: return bool(re.search(rule[7:], target))
        except Exception: return False
    if target_ip:
        try:
            net = ipaddress.ip_network(rule, strict=False)
            return ipaddress.ip_address(target_ip) in net
        except ValueError: pass
    if target_domain:
        d = rule.lower(); q = target_domain.lower()
        return q == d or q.endswith("." + d)
    return False

def route_test(target: str, settings: dict) -> dict:
    target = target.strip()
    profile       = settings.get("profile", "all_except_ru")
    custom        = settings.get("custom_rules", {"always_direct": [], "always_vpn": []})
    _, has_vpn, _ = _get_active_vpn_outbound(settings)
    force_aaplimg = settings.get("force_aaplimg_vpn", True)
    final = "proxy" if has_vpn else "direct"

    domain: Optional[str] = None
    ips:    list[str]      = []
    target_type = "unknown"

    try:
        ipaddress.ip_network(target, strict=False)
        target_type = "cidr" if "/" in target else "ip"
        test_ip = str(ipaddress.ip_network(target, strict=False).network_address)
        ips = [test_ip]
    except ValueError:
        target_type = "domain"
        domain = target.lower().rstrip(".")
        if not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
            return {"error": f"Invalid domain or IP: '{target}'", "outbound": None, "matched_rule": None}
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list({r[4][0] for r in info})[:5]
        except socket.gaierror:
            ips = []

    def result(outbound: str, rule: str, note: str = "", rule_source: str = "") -> dict:
        return {"target": target, "target_type": target_type, "domain": domain,
                "resolved_ips": ips, "outbound": outbound,
                "matched_rule": rule, "note": note or rule,
                "rule_source": rule_source, "error": None}

    vpn_server = None
    _, _, vpn_server = _get_active_vpn_outbound(settings)

    if vpn_server and ips and vpn_server in ips:
        return result("direct", "vpn-server-ip", f"VPN server {vpn_server} always direct", "system")
    for ip in ips:
        if _is_private_ip(ip):
            return result("direct", "geoip:private", f"{ip} is private range", "system")
    if domain and _is_private_domain(domain):
        return result("direct", "geosite:private", f"{domain} is private domain", "system")

    for rule in custom.get("always_direct", []):
        if _custom_matches(rule, domain, ips[0] if ips else None):
            return result("direct", f"custom:always_direct ({rule})", rule_source="custom_rule")
    for rule in custom.get("always_vpn", []):
        if _custom_matches(rule, domain, ips[0] if ips else None):
            return result(final, f"custom:always_vpn ({rule})", rule_source="custom_rule")

    # Check device policies for current source (route test is source-agnostic, skip)

    if force_aaplimg and profile in ("blocked_only", "all_except_ru"):
        if domain and _domain_matches_apple_cdn(domain):
            return result(final, "apple-cdn-override", rule_source="system_override")

    if profile == "all":
        return result(final, "catch-all", f"Profile: all traffic via {final}", "global_profile")

    for ip in ips:
        if _ip_in_geoip_ru(ip):
            return result("direct", "geoip:ru", f"{ip} is in geoip:ru", "geoip_database")
    if domain and _domain_in_geosite_ru(domain):
        return result("direct", "geosite:category-ru",
                      f"{domain} is in geosite:category-ru", "geosite_database")

    if profile == "blocked_only":
        return result("direct", "catch-all", "Profile: blocked_only default=direct", "global_profile")

    return result(final, "catch-all",
                  f"not matched by any rule → {final}", "global_profile_fallback")

# ── Connection Explain ─────────────────────────────────────────────────────────
_explain_cache: dict[str, dict] = {}  # key → result

def explain_connection(src_ip: str, dst: str, dst_port: int,
                       proto: str, outbound: str, settings: dict) -> dict:
    cache_key = f"{src_ip}|{dst}|{dst_port}|{proto}"
    if cache_key in _explain_cache:
        return _explain_cache[cache_key]

    # Identify source device
    s_devices = settings.get("devices", {})
    src_mac = arp_ip_to_mac().get(src_ip, "")
    src_key = src_mac if src_mac else f"ip:{src_ip}"
    src_device = s_devices.get(src_key, {})
    src_name = src_device.get("name", "")
    device_policy = src_device.get("policy", "inherit")

    # Determine rule source
    rule_source = "global_profile_fallback"
    matched_rule = outbound
    note = ""

    if device_policy != "inherit":
        rule_source = "device_policy"
        matched_rule = f"device:{device_policy}"
        note = f"Device policy '{device_policy}' overrides global profile"
    elif outbound in ("proxy", "direct"):
        result = route_test(dst, settings)
        rule_source = result.get("rule_source", "")
        matched_rule = result.get("matched_rule", outbound)
        note = result.get("note", "")

    # ASN / country (lightweight: just geoip:ru check)
    country = ""
    try:
        ipaddress.ip_address(dst)
        if _ip_in_geoip_ru(dst): country = "RU"
    except ValueError: pass

    out = {
        "src_ip":       src_ip,
        "src_mac":      src_mac,
        "src_name":     src_name,
        "device_policy": device_policy,
        "dst":          dst,
        "dst_port":     dst_port,
        "proto":        proto,
        "outbound":     outbound,
        "matched_rule": matched_rule,
        "rule_source":  rule_source,
        "note":         note,
        "country":      country,
    }
    _explain_cache[cache_key] = out
    if len(_explain_cache) > 500: # trim oldest
        oldest = next(iter(_explain_cache))
        del _explain_cache[oldest]
    return out

# ── Network helpers ────────────────────────────────────────────────────────────
def _get_lan_if() -> str:
    try:
        conf = (CFG_DIR / "network.conf").read_text()
        for line in conf.splitlines():
            if line.startswith("LAN_IF="):
                iface = line.split("=", 1)[1].strip()
                if iface: return iface
    except Exception: pass
    return "enp1s0"

def _get_lan_ip() -> Optional[str]:
    try:
        r = subprocess.run(["ip", "-4", "addr", "show", _get_lan_if()],
                           capture_output=True, text=True)
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout)
        return m.group(1) if m else None
    except Exception: return None

_prev: dict = {}
def get_speeds() -> dict:
    global _prev
    iface = _get_lan_if(); now = time.time()
    try:
        rx = int(Path(f"/sys/class/net/{iface}/statistics/rx_bytes").read_text())
        tx = int(Path(f"/sys/class/net/{iface}/statistics/tx_bytes").read_text())
    except Exception: return {"rx_bps": 0, "tx_bps": 0}
    p = _prev.get(iface, (now, rx, tx)); dt = max(now - p[0], 0.1)
    _prev[iface] = (now, rx, tx)
    return {"rx_bps": max(0, (rx - p[1]) / dt), "tx_bps": max(0, (tx - p[2]) / dt)}

_prev_cpu_stats: list = []
def _read_cpu_stats() -> list:
    cores = []
    try:
        for line in Path("/proc/stat").read_text().split("\n"):
            if re.match(r"^cpu\d", line):
                parts = line.split(); vals = [int(x) for x in parts[1:8]]
                total = sum(vals); idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
                cores.append((total, idle))
    except Exception: pass
    return cores

def get_system_info() -> dict:
    global _prev_cpu_stats
    curr = _read_cpu_stats(); cpu_pcts = []
    if _prev_cpu_stats and len(_prev_cpu_stats) == len(curr):
        for (ct, ci), (pt, pi) in zip(curr, _prev_cpu_stats):
            dt = ct - pt
            pct = max(0.0, min(100.0, (1 - (ci - pi) / dt) * 100)) if dt > 0 else 0.0
            cpu_pcts.append(round(pct, 1))
    else: cpu_pcts = [0.0] * len(curr)
    _prev_cpu_stats = curr
    mem_total = mem_used = 0
    try:
        m: dict = {}
        for line in Path("/proc/meminfo").read_text().split("\n"):
            if ":" in line:
                k, v = line.split(":", 1); m[k.strip()] = int(v.strip().split()[0]) * 1024
        mem_total = m.get("MemTotal", 0); mem_used = mem_total - m.get("MemAvailable", 0)
    except Exception: pass
    disk_total = disk_used = disk_free = 0
    try:
        du = shutil.disk_usage("/")
        disk_total, disk_used, disk_free = du.total, du.used, du.free
    except Exception: pass
    return {"cpu": cpu_pcts, "mem": {"total": mem_total, "used": mem_used},
            "disk": {"total": disk_total, "used": disk_used, "free": disk_free}}

def get_xray_core_version() -> str:
    if not hasattr(get_xray_core_version, "_cache"):
        try:
            r = subprocess.run([str(BASE / "bin" / "xray"), "version"],
                               capture_output=True, text=True, timeout=5)
            first = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
            m = re.search(r"Xray\s+([\d.]+)", first)
            get_xray_core_version._cache = m.group(1) if m else first[:40] or "?"
        except Exception: get_xray_core_version._cache = "?"
    return get_xray_core_version._cache

def get_xray_state() -> str:
    r = subprocess.run(["systemctl", "is-active", "xray-proxy"], capture_output=True, text=True)
    if r.stdout.strip() != "active":
        fire_alert("vpn_down", "xray-proxy service not active")
        return "stopped"
    s = load_settings()
    return "connected" if (s.get("active_vpn_id") or s.get("vpn_key")) else "no_key"

def parse_access_log_line(line: str) -> Optional[dict]:
    ts_m = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
    ts = ts_m.group(1) if ts_m else ""
    acc_m = re.search(
        r"(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)\s+accepted\s+"
        r"(\w+):(.+):(\d+)\s+\[([^\]]+)\]", line)
    if not acc_m: return None
    src, proto, dst, dport, route_info = acc_m.groups()
    parts = route_info.split(" -> ")
    outbound = parts[-1].strip() if len(parts) > 1 else route_info.strip()
    return {"ts": ts, "src": src, "proto": proto.upper(),
            "dst": dst, "dport": int(dport), "outbound": outbound}

# ── Export / Import helpers ────────────────────────────────────────────────────
def _export_file_list() -> list[tuple[Path, str]]:
    entries: list[tuple[Path, str]] = []
    for rel in ["web/main.py", "web/static/index.html",
                "scripts/iptables.sh", "scripts/update-geo.sh",
                "scripts/first-boot.sh", "install.sh", "SETUP.md",
                "config/settings.json", "config/network.conf"]:
        p = BASE / rel
        if p.exists(): entries.append((p, rel))
    for svc in ("xray-proxy.service", "xray-web.service", "xray-first-boot.service"):
        p = Path("/etc/systemd/system") / svc
        if p.exists(): entries.append((p, f"systemd/{svc}"))
    return entries

def _import_dest(arcname: str) -> Optional[Path]:
    name = arcname.lstrip("./")
    if name.startswith("systemd/") and name.endswith(".service"):
        svc = Path(name).name
        if svc in ("xray-proxy.service", "xray-web.service", "xray-first-boot.service"):
            return Path("/etc/systemd/system") / svc
    allowed = {"web/main.py", "web/static/index.html",
                "scripts/iptables.sh", "scripts/update-geo.sh",
                "scripts/first-boot.sh", "install.sh", "SETUP.md",
                "config/settings.json", "config/network.conf"}
    if name in allowed: return BASE / name
    return None

# ─────────────────────────────────────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(_failover_loop())
    asyncio.create_task(_disk_monitor_loop())

# ── Pydantic Models ────────────────────────────────────────────────────────────
class LoginReq(BaseModel):        username: str; password: str
class KeyReq(BaseModel):          key: str
class ProfileReq(BaseModel):      profile: str
class PwReq(BaseModel):           current: str; new_pw: str
class AaplimgReq(BaseModel):      enabled: bool
class RouteTestReq(BaseModel):    target: str
class CustomRulesReq(BaseModel):
    always_direct: list[str]
    always_vpn:    list[str]
class DeviceNameReq(BaseModel):   name: str
class DevicePolicyReq(BaseModel): policy: str
class VPNServerAddReq(BaseModel): key: str; name: str = ""; priority: int = 99
class VPNServerUpdateReq(BaseModel):
    name:     Optional[str]  = None
    enabled:  Optional[bool] = None
    priority: Optional[int]  = None
class VPNActivateReq(BaseModel):  server_id: str
class DNSSettingsReq(BaseModel):
    upstream:      list[str]
    upstream_ru:   list[str]    = []
    cache_size:    int          = 1000
    local_records: list[dict]   = []
class AlertsConfigReq(BaseModel):
    enabled:      bool
    webhook_url:  str           = ""
    events:       list[str]
    cooldown_min: int           = 30
class ExplainReq(BaseModel):
    src_ip:   str
    dst:      str
    dst_port: int
    proto:    str
    outbound: str

# ── Captive Portal ────────────────────────────────────────────────────────────
@app.get("/generate_204")
@app.head("/generate_204")
async def gen204(): return Response(status_code=204)

@app.get("/hotspot-detect.html")
async def hotspot():
    return HTMLResponse("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")

@app.get("/ncsi.txt")
async def ncsi(): return Response("Microsoft NCSI")

# ── Auth ───────────────────────────────────────────────────────────────────────
@app.post("/api/login")
async def login(req: LoginReq, resp: Response, request: Request):
    s = load_settings()
    src_ip = request.client.host if request.client else "unknown"
    if (req.username != s["auth"]["username"] or
            hashlib.sha256(req.password.encode()).hexdigest() != s["auth"]["password_hash"]):
        _login_fail_count[src_ip] = _login_fail_count.get(src_ip, 0) + 1
        if _login_fail_count[src_ip] >= 5:
            fire_alert("login_failed", f"5+ failed logins from {src_ip}")
        raise HTTPException(401, "Invalid credentials")
    _login_fail_count[src_ip] = 0
    tok = make_token(req.username)
    resp.set_cookie("token", tok, max_age=86400, httponly=True, samesite="lax")
    return {"ok": True, "token": tok}

@app.post("/api/logout")
async def logout(resp: Response):
    resp.delete_cookie("token"); return {"ok": True}

@app.get("/api/auth-check")
async def auth_check(u: str = Depends(auth_dep)):
    return {"ok": True, "user": u}

@app.get("/api/version")
async def get_version(u: str = Depends(auth_dep)):
    return {"version": VERSION, "xray_core": get_xray_core_version()}

# ── Status ─────────────────────────────────────────────────────────────────────
@app.get("/api/status")
async def get_status(u: str = Depends(auth_dep)):
    s = load_settings(); speeds = get_speeds(); state = get_xray_state()
    gw = _get_lan_ip() or "?"
    vpn_meta = None
    # Build VPN meta from active server
    active_id = s.get("active_vpn_id")
    servers   = s.get("vpn_servers", [])
    active    = next((x for x in servers if x.get("id") == active_id), None)
    if active:
        try:
            _, vpn_meta = parse_key(active["key"])
            vpn_meta["masked_key"] = mask_key(active["key"])
            vpn_meta["server_id"]  = active["id"]
            vpn_meta["last_status"] = active.get("last_status", "unknown")
            vpn_meta["latency_ms"]  = active.get("latency_ms")
        except Exception:
            vpn_meta = {"name": active.get("name","?"), "protocol":"?", "server":"?",
                        "port": 0, "last_status": "error"}
    elif s.get("vpn_key"):   # legacy
        try:
            _, vpn_meta = parse_key(s["vpn_key"])
            vpn_meta["masked_key"] = mask_key(s["vpn_key"])
        except Exception:
            vpn_meta = {"name": "Invalid key", "protocol":"?","server":"?","port":0}
    return {"state": state, "gateway_ip": gw, "profile": s.get("profile", "all_except_ru"),
            "vpn": vpn_meta, "geo_updated": s.get("geo_updated"), "speeds": speeds,
            "force_aaplimg_vpn": s.get("force_aaplimg_vpn", True),
            "vpn_server_count": len(servers)}

# ── SSE Streams ────────────────────────────────────────────────────────────────
@app.get("/api/speed-stream")
async def speed_stream(u: str = Depends(auth_dep)):
    async def gen():
        while True:
            yield f"data: {json.dumps(get_speeds())}\n\n"
            await asyncio.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.get("/api/sysinfo")
async def sysinfo_snapshot(u: str = Depends(auth_dep)):
    info = get_system_info(); info["net"] = get_speeds(); return info

@app.get("/api/sysinfo-stream")
async def sysinfo_stream(u: str = Depends(auth_dep)):
    async def gen():
        while True:
            info = get_system_info(); info["net"] = get_speeds()
            yield f"data: {json.dumps(info)}\n\n"
            await asyncio.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── VPN Servers ────────────────────────────────────────────────────────────────
@app.get("/api/vpn-servers")
async def get_vpn_servers(u: str = Depends(auth_dep)):
    s = load_settings()
    servers = s.get("vpn_servers", [])
    # Return masked list
    masked = []
    for srv in servers:
        try:
            _, info = parse_key(srv["key"])
            masked.append({
                "id":           srv["id"],
                "name":         srv.get("name", info.get("name","?")),
                "protocol":     info["protocol"],
                "server":       info["server"],
                "port":         info["port"],
                "enabled":      srv.get("enabled", True),
                "priority":     srv.get("priority", 99),
                "last_status":  srv.get("last_status", "unknown"),
                "latency_ms":   srv.get("latency_ms"),
                "last_checked": srv.get("last_checked"),
                "is_active":    srv["id"] == s.get("active_vpn_id"),
            })
        except Exception:
            masked.append({
                "id": srv.get("id","?"), "name": srv.get("name","?"),
                "protocol":"?", "server":"?", "port":0,
                "enabled": srv.get("enabled", True),
                "priority": srv.get("priority", 99),
                "last_status": "parse_error",
                "latency_ms": None, "last_checked": None,
                "is_active": srv.get("id") == s.get("active_vpn_id"),
            })
    return {"servers": masked, "active_id": s.get("active_vpn_id")}

@app.post("/api/vpn-servers")
async def add_vpn_server(req: VPNServerAddReq, u: str = Depends(auth_dep)):
    try:
        _, info = parse_key(req.key)
    except ValueError as e:
        raise HTTPException(400, str(e))
    s = load_settings(); old_s = dict(s)
    srv_id = str(_uuid_mod.uuid4())
    name = req.name.strip() or info.get("name", f"Server {len(s['vpn_servers'])+1}")
    new_srv = {"id": srv_id, "name": name, "key": req.key.strip(),
               "enabled": True, "priority": req.priority,
               "last_status": "unknown", "latency_ms": None, "last_checked": None}
    s["vpn_servers"].append(new_srv)
    if not s.get("active_vpn_id"):
        s["active_vpn_id"] = srv_id
    save_settings(s)
    ok, err = apply_config(s, "vpn_server_add", _pre_settings=old_s)
    return {"ok": ok, "error": err or None, "server_id": srv_id}

@app.patch("/api/vpn-servers/{server_id}")
async def update_vpn_server(server_id: str, req: VPNServerUpdateReq, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    srv = next((x for x in s.get("vpn_servers", []) if x.get("id") == server_id), None)
    if not srv: raise HTTPException(404, "Server not found")
    if req.name     is not None: srv["name"]     = req.name.strip()[:64]
    if req.enabled  is not None: srv["enabled"]  = req.enabled
    if req.priority is not None: srv["priority"] = max(1, min(99, req.priority))
    save_settings(s)
    ok, err = apply_config(s, "vpn_server_update", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.delete("/api/vpn-servers/{server_id}")
async def delete_vpn_server(server_id: str, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    before = len(s.get("vpn_servers", []))
    s["vpn_servers"] = [x for x in s.get("vpn_servers", []) if x.get("id") != server_id]
    if len(s["vpn_servers"]) == before:
        raise HTTPException(404, "Server not found")
    if s.get("active_vpn_id") == server_id:
        remaining = [x for x in s["vpn_servers"] if x.get("enabled")]
        s["active_vpn_id"] = remaining[0]["id"] if remaining else None
    save_settings(s)
    ok, err = apply_config(s, "vpn_server_delete", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.post("/api/vpn-servers/{server_id}/activate")
async def activate_vpn_server(server_id: str, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    if not any(x.get("id") == server_id for x in s.get("vpn_servers", [])):
        raise HTTPException(404, "Server not found")
    s["active_vpn_id"] = server_id
    save_settings(s)
    ok, err = apply_config(s, "vpn_server_activate", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.post("/api/vpn-servers/{server_id}/check")
async def check_vpn_server(server_id: str, u: str = Depends(auth_dep)):
    s = load_settings()
    srv = next((x for x in s.get("vpn_servers", []) if x.get("id") == server_id), None)
    if not srv: raise HTTPException(404, "Server not found")
    loop = asyncio.get_event_loop()
    ok, lat = await loop.run_in_executor(None, _vpn_server_health, srv)
    # Update status
    s2 = load_settings()
    for x in s2.get("vpn_servers", []):
        if x.get("id") == server_id:
            x["last_status"] = "ok" if ok else "error"
            x["latency_ms"]  = lat
            x["last_checked"] = datetime.now(timezone.utc).isoformat()
    save_settings(s2)
    return {"ok": True, "reachable": ok, "latency_ms": lat}

# Legacy single-key endpoints (kept for backward compat)
@app.post("/api/vpn-key")
async def set_key(req: KeyReq, u: str = Depends(auth_dep)):
    try: _, meta = parse_key(req.key)
    except ValueError as e: raise HTTPException(400, str(e))
    s = load_settings(); old_s = dict(s)
    # Add as new server or update first server
    servers = s.get("vpn_servers", [])
    if servers:
        servers[0]["key"] = req.key.strip()
        if not s.get("active_vpn_id"): s["active_vpn_id"] = servers[0]["id"]
    else:
        srv_id = str(_uuid_mod.uuid4())
        s["vpn_servers"] = [{"id": srv_id, "name": meta.get("name","Server 1"),
                              "key": req.key.strip(), "enabled": True, "priority": 1,
                              "last_status":"unknown","latency_ms":None,"last_checked":None}]
        s["active_vpn_id"] = srv_id
    s["vpn_key"] = req.key.strip()  # keep for compat
    save_settings(s)
    ok, err = apply_config(s, "vpn_key_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None, "vpn": meta}

@app.delete("/api/vpn-key")
async def del_key(u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    s["vpn_key"] = None; s["vpn_servers"] = []; s["active_vpn_id"] = None
    save_settings(s); apply_config(s, "vpn_key_delete", _pre_settings=old_s)
    return {"ok": True}

# ── Profile ────────────────────────────────────────────────────────────────────
@app.post("/api/profile")
async def set_profile(req: ProfileReq, u: str = Depends(auth_dep)):
    if req.profile not in ("blocked_only", "all_except_ru", "all"):
        raise HTTPException(400, "Invalid profile")
    s = load_settings(); old_s = dict(s); s["profile"] = req.profile; save_settings(s)
    ok, err = apply_config(s, "profile_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.post("/api/aaplimg-vpn")
async def set_aaplimg_vpn(req: AaplimgReq, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s); s["force_aaplimg_vpn"] = req.enabled; save_settings(s)
    ok, err = apply_config(s, "aaplimg_toggle", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

# ── Custom Rules ───────────────────────────────────────────────────────────────
@app.get("/api/custom-rules")
async def get_custom_rules(u: str = Depends(auth_dep)):
    return load_settings().get("custom_rules", {"always_direct":[],"always_vpn":[]})

@app.put("/api/custom-rules")
async def set_custom_rules(req: CustomRulesReq, u: str = Depends(auth_dep)):
    errors = []
    for lst, rule in [("always_direct", r) for r in req.always_direct] + \
                     [("always_vpn",    r) for r in req.always_vpn]:
        ok, msg = validate_custom_rule(rule)
        if not ok: errors.append(f"[{lst}] {msg}")
    if errors: raise HTTPException(400, "; ".join(errors))
    s = load_settings(); old_s = dict(s)
    s["custom_rules"] = {"always_direct": req.always_direct, "always_vpn": req.always_vpn}
    save_settings(s)
    ok, err = apply_config(s, "custom_rules_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

# ── Route Test ─────────────────────────────────────────────────────────────────
@app.post("/api/route-test")
async def api_route_test(req: RouteTestReq, u: str = Depends(auth_dep)):
    target = req.target.strip()
    if not target or len(target) > 253: raise HTTPException(400, "invalid target")
    s = load_settings()
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, route_test, target, s)

# ── Devices ────────────────────────────────────────────────────────────────────
@app.get("/api/devices")
async def get_devices(u: str = Depends(auth_dep)):
    s = load_settings()
    return {"devices": get_devices_merged(s)}

@app.post("/api/devices/{key:path}/name")
async def set_device_name(key: str, req: DeviceNameReq, u: str = Depends(auth_dep)):
    s = load_settings()
    s.setdefault("devices", {})
    name = req.name.strip()[:64]
    s["devices"].setdefault(key, {"policy": "inherit", "ips": []})
    if name: s["devices"][key]["name"] = name
    else:    s["devices"][key].pop("name", None)
    save_settings(s)
    return {"ok": True}

@app.post("/api/devices/{key:path}/policy")
async def set_device_policy(key: str, req: DevicePolicyReq, u: str = Depends(auth_dep)):
    if req.policy not in DEVICE_POLICIES:
        raise HTTPException(400, f"Invalid policy. Must be one of: {DEVICE_POLICIES}")
    s = load_settings(); old_s = dict(s)
    s.setdefault("devices", {})
    s["devices"].setdefault(key, {"name": "", "ips": []})
    s["devices"][key]["policy"] = req.policy
    # Update cached IPs from current ARP
    arp = get_arp_table()
    for entry in arp:
        arp_key = entry["mac"] if entry["mac"] else f"ip:{entry['ips'][0]}"
        if arp_key == key:
            s["devices"][key]["ips"] = entry["ips"]
            break
    save_settings(s)
    ok, err = apply_config(s, "device_policy_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

@app.delete("/api/devices/{key:path}")
async def delete_device(key: str, u: str = Depends(auth_dep)):
    s = load_settings(); old_s = dict(s)
    s.get("devices", {}).pop(key, None)
    save_settings(s)
    ok, err = apply_config(s, "device_delete", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

# ── DNS ────────────────────────────────────────────────────────────────────────
@app.get("/api/dns")
async def get_dns(u: str = Depends(auth_dep)):
    s = load_settings()
    return s.get("dns", DEFAULT_SETTINGS["dns"])

@app.put("/api/dns")
async def set_dns(req: DNSSettingsReq, u: str = Depends(auth_dep)):
    dns = {"upstream": req.upstream, "upstream_ru": req.upstream_ru,
           "cache_size": req.cache_size, "local_records": req.local_records}
    errors = validate_dns_settings(dns)
    if errors: raise HTTPException(400, "; ".join(errors))
    s = load_settings()
    s["dns"] = dns; save_settings(s)
    ok, err = apply_dns_config(dns)
    return {"ok": ok, "error": err or None}

@app.get("/api/dns/status")
async def dns_status(u: str = Depends(auth_dep)):
    return get_dns_status()

@app.post("/api/dns/test")
async def dns_test(req: RouteTestReq, u: str = Depends(auth_dep)):
    domain = req.target.strip()
    if not domain or not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
        raise HTTPException(400, "Invalid domain")
    start = time.time()
    try:
        results = socket.getaddrinfo(domain, None)
        ips = list({r[4][0] for r in results})[:10]
        elapsed_ms = int((time.time() - start) * 1000)
        s = load_settings()
        rt = route_test(ips[0] if ips else domain, s)
        return {"domain": domain, "ips": ips, "elapsed_ms": elapsed_ms,
                "route": rt.get("outbound"), "matched_rule": rt.get("matched_rule"),
                "error": None}
    except socket.gaierror as e:
        return {"domain": domain, "ips": [], "elapsed_ms": int((time.time()-start)*1000),
                "route": None, "matched_rule": None, "error": str(e)}

# ── Explain Connection ─────────────────────────────────────────────────────────
@app.post("/api/explain-connection")
async def api_explain(req: ExplainReq, u: str = Depends(auth_dep)):
    s = load_settings()
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, explain_connection,
        req.src_ip, req.dst, req.dst_port, req.proto, req.outbound, s)

# ── Snapshots ──────────────────────────────────────────────────────────────────
@app.get("/api/snapshots")
async def get_snapshots(u: str = Depends(auth_dep)):
    return {"snapshots": list_snapshots()}

@app.post("/api/snapshots/restore/{snap_id}")
async def api_restore_snapshot(snap_id: str, u: str = Depends(auth_dep)):
    if not re.match(r'^\d{8}_\d{6}$', snap_id):
        raise HTTPException(400, "Invalid snapshot id")
    ok, msg = restore_snapshot(snap_id)
    return {"ok": ok, "message": msg}

@app.delete("/api/snapshots/{snap_id}")
async def delete_snapshot(snap_id: str, u: str = Depends(auth_dep)):
    if not re.match(r'^\d{8}_\d{6}$', snap_id):
        raise HTTPException(400, "Invalid snapshot id")
    p = _snap_path(snap_id)
    if not p.exists(): raise HTTPException(404, "Snapshot not found")
    p.unlink(); return {"ok": True}

# ── Alerts ─────────────────────────────────────────────────────────────────────
@app.get("/api/alerts/config")
async def get_alerts_config(u: str = Depends(auth_dep)):
    s = load_settings()
    cfg = dict(s.get("alerts", DEFAULT_SETTINGS["alerts"]))
    # Mask webhook URL
    url = cfg.get("webhook_url","")
    if url:
        cfg["webhook_url_masked"] = url[:20] + "***" if len(url) > 20 else "***"
        cfg["webhook_url"] = ""  # never return full URL
    return cfg

@app.put("/api/alerts/config")
async def set_alerts_config(req: AlertsConfigReq, u: str = Depends(auth_dep)):
    if req.cooldown_min < 1 or req.cooldown_min > 1440:
        raise HTTPException(400, "cooldown_min must be 1–1440")
    valid_events = {"vpn_down","config_rollback","geo_update_failed","disk_high",
                    "all_vpn_unavailable","login_failed","failover_executed","dns_upstream_unhealthy"}
    bad = [e for e in req.events if e not in valid_events]
    if bad: raise HTTPException(400, f"Unknown events: {bad}")
    s = load_settings()
    # Only update webhook_url if non-empty (empty = keep existing)
    existing_url = s.get("alerts", {}).get("webhook_url", "")
    s["alerts"] = {
        "enabled":      req.enabled,
        "webhook_url":  req.webhook_url if req.webhook_url else existing_url,
        "events":       req.events,
        "cooldown_min": req.cooldown_min,
    }
    save_settings(s); return {"ok": True}

@app.post("/api/alerts/test")
async def test_alert(u: str = Depends(auth_dep)):
    s = load_settings()
    url = s.get("alerts", {}).get("webhook_url","")
    if not url: raise HTTPException(400, "No webhook URL configured")
    # Force-send test regardless of cooldown
    old_last = _alert_last_sent.get("_test", 0)
    _alert_last_sent["_test"] = 0
    original_enabled = s["alerts"].get("enabled", False)
    s["alerts"]["enabled"] = True
    s["alerts"]["events"].append("_test") if "_test" not in s["alerts"]["events"] else None
    fire_alert("_test", "Test alert from xray-gateway")
    # Restore
    s["alerts"]["enabled"] = original_enabled
    return {"ok": True, "message": "Test alert sent"}

@app.get("/api/alerts/log")
async def get_alert_log(u: str = Depends(auth_dep)):
    return {"events": list(reversed(_alert_log[-50:]))}

# ── Geo Update ─────────────────────────────────────────────────────────────────
@app.post("/api/geo-update")
async def geo_update(u: str = Depends(auth_dep)):
    global _geoip_ru_nets, _geosite_ru_data
    try:
        r = subprocess.run([str(SCRIPT / "update-geo.sh")],
                           capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            s = load_settings(); s["geo_updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            save_settings(s)
            _geoip_ru_nets = None; _geosite_ru_data = None
            subprocess.run(["systemctl", "restart", "xray-proxy"])
            return {"ok": True, "output": r.stdout[-500:]}
        fire_alert("geo_update_failed", r.stderr[-200:])
        return {"ok": False, "error": r.stderr[-500:]}
    except subprocess.TimeoutExpired:
        fire_alert("geo_update_failed", "Timeout")
        return {"ok": False, "error": "Timeout"}

@app.get("/api/geo-info")
async def geo_info(u: str = Depends(auth_dep)):
    s = load_settings()
    def fsize(p: Path) -> str:
        try:
            b = p.stat().st_size
            return f"{b/1024/1024:.1f} MB" if b > 1024*1024 else f"{b//1024} KB"
        except Exception: return "—"
    return {"geo_updated": s.get("geo_updated"),
            "geoip_size": fsize(CFG_DIR/"geoip.dat"),
            "geosite_size": fsize(CFG_DIR/"geosite.dat")}

# ── Logs ───────────────────────────────────────────────────────────────────────
@app.get("/api/logs")
async def logs_snapshot(n: int = 300, u: str = Depends(auth_dep)):
    r = subprocess.run(["journalctl", "-u", "xray-proxy", "-n", str(min(n,1000)),
                        "--no-pager", "--output=short-iso"], capture_output=True, text=True)
    return {"logs": r.stdout}

@app.get("/api/logs/stream")
async def logs_stream(u: str = Depends(auth_dep)):
    async def gen():
        proc = await asyncio.create_subprocess_exec(
            "journalctl", "-u", "xray-proxy", "-f", "-n", "50",
            "--no-pager", "--output=short-iso",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=25)
                if line: yield f"data: {json.dumps(line.decode().rstrip())}\n\n"
                else: break
        except asyncio.TimeoutError: yield 'data: "--- heartbeat ---"\n\n'
        finally: proc.kill()
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.get("/api/connections")
async def get_connections(n: int = 500, u: str = Depends(auth_dep)):
    log_file = LOGS / "access.log"
    if not log_file.exists(): return {"connections":[],"note":"access.log not found"}
    r = subprocess.run(["tail","-n",str(min(n,2000)),str(log_file)],capture_output=True,text=True)
    conns = [c for line in r.stdout.strip().split("\n")
             if (c := parse_access_log_line(line))]
    return {"connections": list(reversed(conns))}

@app.get("/api/connections/stream")
async def connections_stream(u: str = Depends(auth_dep)):
    log_file = LOGS / "access.log"
    async def gen():
        proc = await asyncio.create_subprocess_exec(
            "tail","-f","-n","0",str(log_file),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=25)
                if line:
                    c = parse_access_log_line(line.decode().rstrip())
                    if c: yield f"data: {json.dumps(c)}\n\n"
                else: break
        except asyncio.TimeoutError: yield "data: null\n\n"
        finally: proc.kill()
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── Config Export / Import ─────────────────────────────────────────────────────
@app.get("/api/settings/export")
async def export_settings(u: str = Depends(auth_dep)):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for fspath, arcname in _export_file_list():
            tar.add(str(fspath), arcname=arcname)
    buf.seek(0)
    ts = datetime.utcnow().strftime("%Y-%m-%d")
    return Response(buf.read(), media_type="application/gzip",
                    headers={"Content-Disposition":f"attachment; filename=xray-proxy-backup-{ts}.tar.gz"})

@app.post("/api/settings/import")
async def import_settings(file: UploadFile = File(...), u: str = Depends(auth_dep)):
    data = await file.read()
    try:
        buf = io.BytesIO(data)
        with tarfile.open(fileobj=buf, mode="r:gz") as _t: pass
    except Exception: raise HTTPException(400, "Invalid tar.gz archive")
    buf.seek(0); restored: list[str] = []
    try:
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            for member in tar.getmembers():
                dest = _import_dest(member.name)
                if dest is None: continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                fobj = tar.extractfile(member)
                if fobj: dest.write_bytes(fobj.read()); restored.append(member.name.lstrip("./"))
    except Exception as e: raise HTTPException(500, f"Extraction failed: {e}")
    old_s = load_settings()
    s = load_settings()
    ok, err = apply_config(s, "settings_import", _pre_settings=old_s)
    if any(r.startswith("systemd/") for r in restored):
        subprocess.run(["systemctl","daemon-reload"],capture_output=True)
    if any(r.startswith("web/") for r in restored):
        subprocess.Popen(["systemctl","restart","xray-web"])
    return {"ok": ok, "restored": restored, "error": err or None}

# ── Password / Factory Reset ───────────────────────────────────────────────────
@app.post("/api/change-password")
async def change_pw(req: PwReq, u: str = Depends(auth_dep)):
    s = load_settings()
    if hashlib.sha256(req.current.encode()).hexdigest() != s["auth"]["password_hash"]:
        raise HTTPException(403, "Wrong current password")
    s["auth"]["password_hash"] = hashlib.sha256(req.new_pw.encode()).hexdigest()
    save_settings(s); return {"ok": True}

@app.post("/api/factory-reset")
async def factory_reset(u: str = Depends(auth_dep)):
    save_settings(dict(DEFAULT_SETTINGS))
    apply_config(DEFAULT_SETTINGS, "factory_reset"); return {"ok": True}

# ── Terminal WebSocket ─────────────────────────────────────────────────────────
@app.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    token = websocket.query_params.get("token","") or websocket.cookies.get("token","")
    if not verify_token(token): await websocket.close(code=4401); return
    await websocket.accept()
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe("bash",["bash","-i"],{**os.environ,"TERM":"xterm-256color",
                                         "HOME":os.environ.get("HOME","/root")})
        os._exit(1)
    loop = asyncio.get_event_loop()
    async def pty_to_ws():
        try:
            while True:
                try:
                    data = await loop.run_in_executor(None, os.read, fd, 4096)
                    if data: await websocket.send_bytes(data)
                    else: break
                except OSError: break
        except Exception: pass
    async def ws_to_pty():
        try:
            while True:
                msg = await websocket.receive()
                if msg["type"] == "websocket.disconnect": break
                raw = msg.get("bytes") or (msg["text"].encode() if msg.get("text") else None)
                if not raw: continue
                try:
                    j = json.loads(raw)
                    if j.get("type") == "resize":
                        cols = max(1, int(j.get("cols",80))); rows = max(1,int(j.get("rows",24)))
                        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH",rows,cols,0,0))
                        continue
                except Exception: pass
                try: os.write(fd, raw)
                except OSError: break
        except Exception: pass
    r_task = asyncio.create_task(pty_to_ws())
    w_task = asyncio.create_task(ws_to_pty())
    try:
        await asyncio.wait([r_task, w_task], return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in [r_task, w_task]: t.cancel()
        for fn in [lambda: os.kill(pid, signal.SIGTERM),
                   lambda: os.waitpid(pid, os.WNOHANG),
                   lambda: os.close(fd)]:
            try: fn()
            except Exception: pass
        try: await websocket.close()
        except Exception: pass

# ── SPA ────────────────────────────────────────────────────────────────────────
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    html_path = STATIC / "index.html"
    if html_path.exists(): return HTMLResponse(html_path.read_text())
    return HTMLResponse("<h1>UI not installed</h1>", 500)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=80, log_level="warning")
