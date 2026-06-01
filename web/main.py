#!/usr/bin/env python3
"""Xray Proxy Gateway — Web Management Interface v1.4.0"""

import asyncio, base64, fcntl, hashlib, hmac, io, ipaddress, json, os, pty
import re, shutil, signal, socket, struct, subprocess, tarfile, termios, time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = "1.4.0"

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, Response, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, field_validator

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE      = Path("/opt/xray-proxy")
CFG_DIR   = BASE / "config"
SNAP_DIR  = CFG_DIR / "snapshots"
SCRIPT    = BASE / "scripts"
LOGS      = BASE / "logs"
STATIC    = BASE / "web" / "static"
SETTINGS  = CFG_DIR / "settings.json"
XCFG      = CFG_DIR / "xray.json"

MAX_SNAPSHOTS = 10  # keep last N snapshots

DEFAULT_SETTINGS: dict = {
    "auth": {"username": "admin",
             "password_hash": hashlib.sha256(b"admin").hexdigest()},
    "vpn_key":    None,
    "profile":    "all_except_ru",
    "geo_updated": None,
    "force_aaplimg_vpn": True,
    # Custom routing overrides: lists of rule strings (see validate_custom_rule)
    "custom_rules": {"always_direct": [], "always_vpn": []},
    # Per-device names: {"192.168.1.x": "My Phone"}
    "device_names": {},
}

# ── Settings helpers ───────────────────────────────────────────────────────────
def load_settings() -> dict:
    if SETTINGS.exists():
        s = json.loads(SETTINGS.read_text())
        for k, v in DEFAULT_SETTINGS.items():
            s.setdefault(k, v)
        # Nested defaults
        if "custom_rules" not in s:
            s["custom_rules"] = {"always_direct": [], "always_vpn": []}
        else:
            s["custom_rules"].setdefault("always_direct", [])
            s["custom_rules"].setdefault("always_vpn", [])
        s.setdefault("device_names", {})
        return s
    return dict(DEFAULT_SETTINGS)

def save_settings(s: dict) -> None:
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS.write_text(json.dumps(s, indent=2))

SECRET = (BASE / ".secret").read_text().strip() if (BASE / ".secret").exists() \
         else "xray-proxy-default-secret"

# ── Auth helpers ───────────────────────────────────────────────────────────────
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

# ── VPN Key Parsing ───────────────────────────────────────────────────────────
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

def _sockopt():        return {"mark": 255}
def _proxy_sockopt():  return {"mark": 255, "tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15}

def _parse_ss(uri: str):
    uri = uri[5:]
    name = ""
    if "#" in uri:
        uri, name = uri.rsplit("#", 1)
        name = urllib.parse.unquote(name)
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
    uri = uri[8:]
    name = ""
    if "#" in uri:
        uri, name = uri.rsplit("#", 1)
        name = urllib.parse.unquote(name)
    uuid, rest = uri.split("@", 1)
    hostport, qs = (rest.split("?", 1) + [""])[:2]
    host, port = hostport.rsplit(":", 1)
    p = dict(urllib.parse.parse_qsl(qs))
    net = p.get("type", "tcp");  sec = p.get("security", "none")
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
    host = d.get("add", "");  port = int(d.get("port", 443))
    net = d.get("net", "tcp");  tls_val = d.get("tls", "")
    ss = {"network": net, "sockopt": _proxy_sockopt()}
    if tls_val == "tls":
        ss["security"] = "tls"
        ss["tlsSettings"] = {"serverName": d.get("sni", host)}
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
    uri = uri[9:]
    name = ""
    if "#" in uri:
        uri, name = uri.rsplit("#", 1)
        name = urllib.parse.unquote(name)
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

# ── Custom Rules Validation ───────────────────────────────────────────────────
# Supported formats:
#   domain:foo.com        — foo.com and all subdomains
#   full:foo.com          — exact domain only
#   keyword:someword      — substring in domain
#   regexp:^.*\.foo\.com$ — regex
#   1.2.3.4               — IPv4 exact
#   1.2.3.0/24            — CIDR
#   2001:db8::/32         — IPv6 CIDR

_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)

def validate_custom_rule(rule: str) -> tuple[bool, str]:
    """Validate a custom rule string. Returns (ok, error_message)."""
    rule = rule.strip()
    if not rule:
        return False, "Empty rule"
    if len(rule) > 512:
        return False, "Rule too long (max 512 chars)"

    for prefix in ("domain:", "full:", "keyword:", "regexp:"):
        if rule.startswith(prefix):
            value = rule[len(prefix):]
            if not value:
                return False, f"Empty value after {prefix}"
            if prefix == "regexp:":
                try:
                    re.compile(value)
                except re.error as e:
                    return False, f"Invalid regexp: {e}"
            return True, ""

    # Try IP / CIDR
    try:
        ipaddress.ip_network(rule, strict=False)
        return True, ""
    except ValueError:
        pass

    # Try bare domain
    if _DOMAIN_RE.match(rule):
        return True, ""

    return False, f"Invalid rule '{rule}': use domain:, full:, keyword:, regexp:, IP, or CIDR"

def _custom_rule_to_xray(rule: str) -> tuple[str, str]:
    """Return ('domain'|'ip', xray_value) for a validated custom rule."""
    rule = rule.strip()
    for prefix in ("domain:", "full:", "keyword:", "regexp:"):
        if rule.startswith(prefix):
            return "domain", rule  # pass through to xray as-is
    # IP or CIDR
    try:
        net = ipaddress.ip_network(rule, strict=False)
        # normalize: use prefix notation
        return "ip", str(net)
    except ValueError:
        pass
    # bare domain → treat as domain:
    return "domain", f"domain:{rule}"

def _rules_to_xray_entry(rules: list[str], outbound: str) -> list[dict]:
    """Convert a list of custom rule strings to xray routing rule entries."""
    if not rules:
        return []
    domain_vals, ip_vals = [], []
    for r in rules:
        kind, val = _custom_rule_to_xray(r)
        if kind == "domain":
            domain_vals.append(val)
        else:
            ip_vals.append(val)
    result = []
    if domain_vals:
        result.append({"type": "field", "domain": domain_vals, "outboundTag": outbound})
    if ip_vals:
        result.append({"type": "field", "ip": ip_vals, "outboundTag": outbound})
    return result

# ── Xray Config Builder ───────────────────────────────────────────────────────
def build_xray_config(settings: dict) -> dict:
    vpn_key = settings.get("vpn_key")
    profile = settings.get("profile", "all_except_ru")
    custom  = settings.get("custom_rules", {"always_direct": [], "always_vpn": []})
    outbounds, has_proxy, proxy_server_ip = [], False, None
    if vpn_key:
        try:
            ob, info = parse_key(vpn_key)
            outbounds.append(ob);  has_proxy = True
            proxy_server_ip = info.get("server")
        except Exception:
            pass
    outbounds += [
        {"protocol": "freedom", "tag": "direct",
         "settings": {"domainStrategy": "UseIP"},
         "streamSettings": {"sockopt": _sockopt()}},
        {"protocol": "blackhole", "tag": "block"},
    ]
    final = "proxy" if has_proxy else "direct"
    force_aaplimg = settings.get("force_aaplimg_vpn", True)

    rules = [
        *([{"type": "field", "ip": [proxy_server_ip], "outboundTag": "direct"}]
          if proxy_server_ip else []),
        {"type": "field", "ip":     ["geoip:private"],   "outboundTag": "direct"},
        {"type": "field", "domain": ["geosite:private"],  "outboundTag": "direct"},
        # Custom overrides — applied BEFORE geo databases
        *_rules_to_xray_entry(custom.get("always_direct", []), "direct"),
        *_rules_to_xray_entry(custom.get("always_vpn", []),    final),
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

    rules.append({"type": "field", "network": "tcp",     "port": "5228", "outboundTag": "direct"})
    rules.append({"type": "field", "network": "tcp,udp",                  "outboundTag": default})

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

# ── Snapshot Management ────────────────────────────────────────────────────────
def _snap_path(snap_id: str) -> Path:
    return SNAP_DIR / f"snap_{snap_id}.json"

def create_snapshot(reason: str, settings: Optional[dict] = None) -> str:
    """Save current config + settings to a snapshot. Returns snapshot id."""
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    snap_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    s = settings or load_settings()
    xray_cfg = {}
    if XCFG.exists():
        try:
            xray_cfg = json.loads(XCFG.read_text())
        except Exception:
            pass
    # Mask VPN key in stored snapshot (keep full key but mark it)
    snap = {
        "id": snap_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "settings": s,
        "xray_config": xray_cfg,
    }
    _snap_path(snap_id).write_text(json.dumps(snap, indent=2))
    _rotate_snapshots()
    return snap_id

def _rotate_snapshots() -> None:
    """Keep only the most recent MAX_SNAPSHOTS snapshots."""
    snaps = sorted(SNAP_DIR.glob("snap_*.json"), key=lambda p: p.name)
    for old in snaps[:-MAX_SNAPSHOTS]:
        try:
            old.unlink()
        except Exception:
            pass

def list_snapshots() -> list[dict]:
    """Return list of snapshot metadata (without full xray_config, mask vpn_key)."""
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    result = []
    for p in sorted(SNAP_DIR.glob("snap_*.json"), key=lambda x: x.name, reverse=True):
        try:
            snap = json.loads(p.read_text())
            result.append({
                "id":        snap["id"],
                "timestamp": snap["timestamp"],
                "reason":    snap.get("reason", ""),
                "profile":   snap.get("settings", {}).get("profile", "?"),
                "has_vpn":   bool(snap.get("settings", {}).get("vpn_key")),
            })
        except Exception:
            pass
    return result

def restore_snapshot(snap_id: str) -> tuple[bool, str]:
    """Restore settings and xray.json from a snapshot. Returns (ok, message)."""
    p = _snap_path(snap_id)
    if not p.exists():
        return False, f"Snapshot {snap_id} not found"
    try:
        snap = json.loads(p.read_text())
    except Exception as e:
        return False, f"Failed to read snapshot: {e}"
    settings = snap.get("settings", {})
    xray_cfg = snap.get("xray_config", {})
    # Restore settings
    save_settings(settings)
    # Restore xray.json directly (bypasses rebuild — restores exact previously-working config)
    if xray_cfg:
        XCFG.write_text(json.dumps(xray_cfg, indent=2))
    # Restart xray
    r = subprocess.run(["systemctl", "restart", "xray-proxy"], capture_output=True, text=True)
    if r.returncode != 0:
        return False, f"xray restart failed: {r.stderr[:200]}"
    return True, f"Restored snapshot {snap_id}"

# ── Safe Config Apply (with snapshot + auto-rollback) ────────────────────────
def apply_config(settings: dict, reason: str = "config_change",
                 _pre_settings: Optional[dict] = None) -> tuple[bool, str]:
    """
    Apply config safely:
      1. Snapshot the PRE-CHANGE state (_pre_settings if given, else current disk state)
      2. Write new xray.json
      3. Restart xray-proxy
      4. Verify it starts within 5 s
      5. If not: auto-restore snapshot + restart
    Returns (success, error_message).

    IMPORTANT: callers should pass _pre_settings=old_s captured BEFORE save_settings(new_s)
    so that the snapshot correctly represents the state prior to the change.
    """
    snap_id = create_snapshot(f"pre_{reason}", settings=_pre_settings)  # snapshot BEFORE change
    cfg = build_xray_config(settings)
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    XCFG.write_text(json.dumps(cfg, indent=2))

    subprocess.run(["systemctl", "restart", "xray-proxy"], capture_output=True)

    # Verify: poll systemctl is-active for up to 5 s
    for _ in range(10):
        time.sleep(0.5)
        r = subprocess.run(["systemctl", "is-active", "xray-proxy"],
                            capture_output=True, text=True)
        if r.stdout.strip() == "active":
            return True, ""

    # Auto-rollback
    ok, msg = restore_snapshot(snap_id)
    rolled = f"xray failed to start; auto-rollback to snapshot {snap_id} {'ok' if ok else 'FAILED: '+msg}"
    return False, rolled

# ── GeoIP / GeoSite Parsers ───────────────────────────────────────────────────
# Minimal protobuf varint reader (no external deps)

def _varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while pos < len(data):
        b = data[pos];  pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    return result, pos

def _parse_len_field(data: bytes, pos: int) -> tuple[bytes, int]:
    """Read a length-delimited field. Returns (content_bytes, new_pos)."""
    length, pos = _varint(data, pos)
    return data[pos:pos + length], pos + length

# Cache objects (lazy loaded)
_geoip_ru_nets: Optional[list] = None
_geoip_ru_mtime: float = 0.0
_geosite_ru_data: Optional[dict] = None
_geosite_ru_mtime: float = 0.0

def _load_geoip_ru() -> list:
    """Parse geoip.dat and return list of IPv4/IPv6 networks for RU. Cached."""
    global _geoip_ru_nets, _geoip_ru_mtime
    geoip_path = CFG_DIR / "geoip.dat"
    try:
        mtime = geoip_path.stat().st_mtime
    except Exception:
        return []
    if _geoip_ru_nets is not None and mtime == _geoip_ru_mtime:
        return _geoip_ru_nets

    networks: list = []
    try:
        data = geoip_path.read_bytes()
        pos = 0
        n = len(data)
        while pos < n:
            try:
                tag, pos = _varint(data, pos)
                wire = tag & 7;  field = tag >> 3
                if wire == 2:
                    entry, pos = _parse_len_field(data, pos)
                    if field != 1:
                        continue
                    # Parse GeoIP entry: field1=country_code, field2=cidr
                    cc = None;  cidrs_raw = []
                    p = 0;  m = len(entry)
                    while p < m:
                        t, p = _varint(entry, p)
                        f, w = t >> 3, t & 7
                        if w == 2:
                            v, p = _parse_len_field(entry, p)
                            if f == 1:
                                cc = v.decode("ascii", errors="replace").strip("\x00 ")
                            elif f == 2:
                                # Parse CIDR: field1=ip_bytes, field2=prefix
                                ip_b = None;  plen = None
                                cp = 0;  cm = len(v)
                                while cp < cm:
                                    ct, cp = _varint(v, cp)
                                    cf, cw = ct >> 3, ct & 7
                                    if cw == 2:
                                        iv, cp = _parse_len_field(v, cp)
                                        if cf == 1:
                                            ip_b = iv
                                    elif cw == 0:
                                        pval, cp = _varint(v, cp)
                                        if cf == 2:
                                            plen = pval
                                    else:
                                        break
                                if ip_b and plen is not None:
                                    cidrs_raw.append((ip_b, plen))
                        elif w == 0:
                            _, p = _varint(entry, p)
                        elif w == 1:
                            p += 8
                        elif w == 5:
                            p += 4
                        else:
                            break
                    if cc and cc.upper() == "RU":
                        for ip_b, plen in cidrs_raw:
                            try:
                                if len(ip_b) == 4:
                                    networks.append(ipaddress.IPv4Network((ip_b, plen), strict=False))
                                elif len(ip_b) == 16:
                                    networks.append(ipaddress.IPv6Network((ip_b, plen), strict=False))
                            except Exception:
                                pass
                elif wire == 0:
                    _, pos = _varint(data, pos)
                elif wire == 1:
                    pos += 8
                elif wire == 5:
                    pos += 4
                else:
                    break
            except Exception:
                break
    except Exception:
        pass

    _geoip_ru_nets = networks
    _geoip_ru_mtime = mtime
    return networks

def _ip_in_geoip_ru(addr: str) -> bool:
    """Check if an IP address is covered by geoip:ru."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    for net in _load_geoip_ru():
        if ip in net:
            return True
    return False

def _load_geosite_ru() -> dict:
    """Parse geosite.dat for CATEGORY-RU entries. Returns {full, domain, plain, regex}. Cached."""
    global _geosite_ru_data, _geosite_ru_mtime
    geosite_path = CFG_DIR / "geosite.dat"
    try:
        mtime = geosite_path.stat().st_mtime
    except Exception:
        return {"full": set(), "domain": set(), "plain": [], "regex": []}
    if _geosite_ru_data is not None and mtime == _geosite_ru_mtime:
        return _geosite_ru_data

    result: dict = {"full": set(), "domain": set(), "plain": [], "regex": []}
    try:
        data = geosite_path.read_bytes()
        pos = 0;  n = len(data)
        while pos < n:
            try:
                tag, pos = _varint(data, pos)
                wire = tag & 7;  field = tag >> 3
                if wire == 2:
                    entry, pos = _parse_len_field(data, pos)
                    if field != 1:
                        continue
                    # Parse GeoSite: field1=country_code, field2=repeated Domain
                    cc = None;  domains_raw = []
                    p = 0;  m = len(entry)
                    while p < m:
                        t, p = _varint(entry, p)
                        f, w = t >> 3, t & 7
                        if w == 2:
                            v, p = _parse_len_field(entry, p)
                            if f == 1:
                                cc = v.decode("ascii", errors="replace").strip("\x00 ")
                            elif f == 2:
                                # Domain: field1=type(varint), field2=value(string)
                                dtype = 0;  dval = ""
                                dp = 0;  dm = len(v)
                                while dp < dm:
                                    dt, dp = _varint(v, dp)
                                    df, dw = dt >> 3, dt & 7
                                    if dw == 0:
                                        dnum, dp = _varint(v, dp)
                                        if df == 1:
                                            dtype = dnum
                                    elif dw == 2:
                                        dv, dp = _parse_len_field(v, dp)
                                        if df == 2:
                                            dval = dv.decode("utf-8", errors="replace")
                                    else:
                                        break
                                if dval:
                                    domains_raw.append((dtype, dval.lower()))
                        elif w == 0:
                            _, p = _varint(entry, p)
                        elif w == 1:
                            p += 8
                        elif w == 5:
                            p += 4
                        else:
                            break
                    if cc and cc.upper() == "CATEGORY-RU":
                        for dtype, dval in domains_raw:
                            if dtype == 3:    result["full"].add(dval)
                            elif dtype == 2:  result["domain"].add(dval)
                            elif dtype == 0:  result["plain"].append(dval)
                            elif dtype == 1:
                                try:
                                    result["regex"].append(re.compile(dval))
                                except Exception:
                                    pass
                elif wire == 0:
                    _, pos = _varint(data, pos)
                elif wire == 1:
                    pos += 8
                elif wire == 5:
                    pos += 4
                else:
                    break
            except Exception:
                break
    except Exception:
        pass

    _geosite_ru_data = result
    _geosite_ru_mtime = mtime
    return result

def _domain_in_geosite_ru(query: str) -> bool:
    """Check if a domain is in geosite:category-ru."""
    q = query.lower().rstrip(".")
    gs = _load_geosite_ru()
    if q in gs["full"]:
        return True
    for d in gs["domain"]:
        if q == d or q.endswith("." + d):
            return True
    for k in gs["plain"]:
        if k in q:
            return True
    for r in gs["regex"]:
        if r.search(q):
            return True
    return False

# ── Route Tester ─────────────────────────────────────────────────────────────
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
_PRIVATE_DOMAINS = {"localhost", "local"}

_APPLE_CDN_DOMAINS = {"cdn-apple.com", "itunes.apple.com", "aaplimg.com"}

def _is_private_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False

def _is_private_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    if d in _PRIVATE_DOMAINS:
        return True
    if d.endswith(".local") or d.endswith(".localhost"):
        return True
    return False

def _domain_matches_apple_cdn(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    for cdn in _APPLE_CDN_DOMAINS:
        if d == cdn or d.endswith("." + cdn):
            return True
    return False

def _custom_matches(rule: str, target_domain: Optional[str], target_ip: Optional[str]) -> bool:
    """Check if a custom rule matches target domain or IP."""
    rule = rule.strip()
    if rule.startswith("domain:"):
        if not target_domain:
            return False
        d = rule[7:].lower()
        q = target_domain.lower()
        return q == d or q.endswith("." + d)
    if rule.startswith("full:"):
        if not target_domain:
            return False
        return target_domain.lower() == rule[5:].lower()
    if rule.startswith("keyword:"):
        if not target_domain:
            return False
        return rule[8:].lower() in target_domain.lower()
    if rule.startswith("regexp:"):
        target = target_domain or target_ip or ""
        try:
            return bool(re.search(rule[7:], target))
        except Exception:
            return False
    # IP or CIDR
    if target_ip:
        try:
            net = ipaddress.ip_network(rule, strict=False)
            return ipaddress.ip_address(target_ip) in net
        except ValueError:
            pass
    # bare domain fallback
    if target_domain:
        d = rule.lower()
        q = target_domain.lower()
        return q == d or q.endswith("." + d)
    return False

def route_test(target: str, settings: dict) -> dict:
    """
    Simulate xray routing for a domain/IP.
    Returns {outbound, matched_rule, note, resolved_ips, target_type, error}.
    """
    target = target.strip()
    profile  = settings.get("profile", "all_except_ru")
    custom   = settings.get("custom_rules", {"always_direct": [], "always_vpn": []})
    has_vpn  = bool(settings.get("vpn_key"))
    force_aaplimg = settings.get("force_aaplimg_vpn", True)
    final    = "proxy" if has_vpn else "direct"

    domain: Optional[str] = None
    ips: list[str] = []
    target_type = "unknown"

    # Detect input type
    try:
        ipaddress.ip_network(target, strict=False)
        # It's an IP or CIDR
        target_type = "cidr" if "/" in target else "ip"
        # For CIDR, test using network address
        test_ip = str(ipaddress.ip_network(target, strict=False).network_address)
        ips = [test_ip]
    except ValueError:
        # Treat as domain
        target_type = "domain"
        domain = target.lower().rstrip(".")
        # Validate domain characters
        if not re.match(r'^[a-zA-Z0-9.\-]+$', domain):
            return {"error": f"Invalid domain or IP: '{target}'",
                    "outbound": None, "matched_rule": None}
        # DNS resolve
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list({r[4][0] for r in info})[:5]
        except socket.gaierror as e:
            # Can't resolve — still continue with domain-only checks
            ips = []

    def result(outbound: str, rule: str, note: str = "") -> dict:
        return {
            "target": target,
            "target_type": target_type,
            "domain": domain,
            "resolved_ips": ips,
            "outbound": outbound,
            "matched_rule": rule,
            "note": note or rule,
            "error": None,
        }

    vpn_server = None
    if settings.get("vpn_key"):
        try:
            _, info = parse_key(settings["vpn_key"])
            vpn_server = info.get("server")
        except Exception:
            pass

    # ── Walk routing rules in order ──────────────────────────────────────────

    # Rule 0: VPN server IP → direct
    if vpn_server and ips and vpn_server in ips:
        return result("direct", "vpn-server-ip", f"VPN server {vpn_server} always direct")

    # Rule 1: geoip:private → direct
    for ip in ips:
        if _is_private_ip(ip):
            return result("direct", "geoip:private", f"{ip} is private range")
    if domain and _is_private_domain(domain):
        return result("direct", "geosite:private", f"{domain} is private domain")

    # Rule 2: Custom always_direct
    for rule in custom.get("always_direct", []):
        if _custom_matches(rule, domain, ips[0] if ips else None):
            return result("direct", f"custom:always_direct ({rule})")

    # Rule 3: Custom always_vpn
    for rule in custom.get("always_vpn", []):
        if _custom_matches(rule, domain, ips[0] if ips else None):
            return result(final, f"custom:always_vpn ({rule})")

    # Rule 4: Apple CDN → proxy (if force_aaplimg_vpn, blocked_only or all_except_ru)
    if force_aaplimg and profile in ("blocked_only", "all_except_ru"):
        if domain and _domain_matches_apple_cdn(domain):
            return result(final, "apple-cdn-override",
                          f"{domain} → Apple CDN force-VPN override")

    if profile == "all":
        return result(final, "catch-all", "Profile: all traffic via VPN")

    # Rule 5: geoip:ru → direct
    for ip in ips:
        if _ip_in_geoip_ru(ip):
            return result("direct", "geoip:ru", f"{ip} is in geoip:ru")

    # Rule 6: geosite:category-ru → direct
    if domain and _domain_in_geosite_ru(domain):
        return result("direct", "geosite:category-ru", f"{domain} is in geosite:category-ru")

    if profile == "blocked_only":
        # blocked_only also checks geosite:category-ru-blocked → final
        # (simplified: skip — requires separate geosite parse)
        return result("direct", "catch-all", "Profile: blocked_only default=direct")

    # Catch-all
    if not ips and domain:
        return result(final, "catch-all",
                      f"{domain} not resolved / not in geo databases → {final}")
    return result(final, "catch-all", f"not matched by any geo rule → {final}")

# ── Network helpers ───────────────────────────────────────────────────────────
def _get_lan_if() -> str:
    try:
        conf = (CFG_DIR / "network.conf").read_text()
        for line in conf.splitlines():
            if line.startswith("LAN_IF="):
                iface = line.split("=", 1)[1].strip()
                if iface:
                    return iface
    except Exception:
        pass
    return "enp1s0"

def get_arp_devices() -> list[dict]:
    """Read ARP table via 'ip neigh show'. Returns list of {ip, mac, state}."""
    try:
        r = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5)
        devices = []
        seen_ips: set[str] = set()
        for line in r.stdout.strip().splitlines():
            # format: IP dev IF lladdr MAC state STATE
            parts = line.split()
            if len(parts) < 2:
                continue
            ip_str = parts[0]
            # validate IP
            try:
                ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if ip_str in seen_ips:
                continue
            seen_ips.add(ip_str)
            mac = ""
            state = ""
            for i, p in enumerate(parts):
                if p == "lladdr" and i + 1 < len(parts):
                    mac = parts[i + 1]
                if p in ("REACHABLE", "STALE", "DELAY", "FAILED", "NOARP", "PERMANENT"):
                    state = p
            if state in ("FAILED", ""):
                continue
            devices.append({"ip": ip_str, "mac": mac, "state": state})
        return devices
    except Exception:
        return []

# ── Speed / CPU / Disk / Mem ──────────────────────────────────────────────────
_prev: dict = {}

def get_speeds() -> dict:
    global _prev
    iface = _get_lan_if();  now = time.time()
    try:
        rx = int(Path(f"/sys/class/net/{iface}/statistics/rx_bytes").read_text())
        tx = int(Path(f"/sys/class/net/{iface}/statistics/tx_bytes").read_text())
    except Exception:
        return {"rx_bps": 0, "tx_bps": 0}
    p = _prev.get(iface, (now, rx, tx));  dt = max(now - p[0], 0.1)
    _prev[iface] = (now, rx, tx)
    return {"rx_bps": max(0, (rx - p[1]) / dt), "tx_bps": max(0, (tx - p[2]) / dt)}

_prev_cpu_stats: list = []

def _read_cpu_stats() -> list:
    cores = []
    try:
        for line in Path("/proc/stat").read_text().split("\n"):
            if re.match(r"^cpu\d", line):
                parts = line.split()
                vals = [int(x) for x in parts[1:8]]
                total = sum(vals);  idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
                cores.append((total, idle))
    except Exception:
        pass
    return cores

def get_system_info() -> dict:
    global _prev_cpu_stats
    curr = _read_cpu_stats();  cpu_pcts = []
    if _prev_cpu_stats and len(_prev_cpu_stats) == len(curr):
        for (ct, ci), (pt, pi) in zip(curr, _prev_cpu_stats):
            dt = ct - pt
            pct = max(0.0, min(100.0, (1 - (ci - pi) / dt) * 100)) if dt > 0 else 0.0
            cpu_pcts.append(round(pct, 1))
    else:
        cpu_pcts = [0.0] * len(curr)
    _prev_cpu_stats = curr
    mem_total = mem_used = 0
    try:
        m: dict = {}
        for line in Path("/proc/meminfo").read_text().split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                m[k.strip()] = int(v.strip().split()[0]) * 1024
        mem_total = m.get("MemTotal", 0);  mem_used = mem_total - m.get("MemAvailable", 0)
    except Exception:
        pass
    disk_total = disk_used = disk_free = 0
    try:
        du = shutil.disk_usage("/")
        disk_total, disk_used, disk_free = du.total, du.used, du.free
    except Exception:
        pass
    return {"cpu": cpu_pcts,
            "mem": {"total": mem_total, "used": mem_used},
            "disk": {"total": disk_total, "used": disk_used, "free": disk_free}}

def get_xray_core_version() -> str:
    if not hasattr(get_xray_core_version, "_cache"):
        try:
            r = subprocess.run([str(BASE / "bin" / "xray"), "version"],
                               capture_output=True, text=True, timeout=5)
            first = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
            m = re.search(r"Xray\s+([\d.]+)", first)
            get_xray_core_version._cache = m.group(1) if m else first[:40] or "?"
        except Exception:
            get_xray_core_version._cache = "?"
    return get_xray_core_version._cache

def get_xray_state() -> str:
    r = subprocess.run(["systemctl", "is-active", "xray-proxy"], capture_output=True, text=True)
    if r.stdout.strip() != "active":
        return "stopped"
    s = load_settings()
    return "connected" if s.get("vpn_key") else "no_key"

# ── Access log parser ─────────────────────────────────────────────────────────
def parse_access_log_line(line: str) -> Optional[dict]:
    ts_m = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
    ts = ts_m.group(1) if ts_m else ""
    acc_m = re.search(
        r"(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)\s+accepted\s+"
        r"(\w+):(.+):(\d+)\s+\[([^\]]+)\]", line)
    if not acc_m:
        return None
    src, proto, dst, dport, route_info = acc_m.groups()
    parts = route_info.split(" -> ")
    outbound = parts[-1].strip() if len(parts) > 1 else route_info.strip()
    return {"ts": ts, "src": src, "proto": proto.upper(),
            "dst": dst, "dport": int(dport), "outbound": outbound}

# ── Config export/import helpers ──────────────────────────────────────────────
def _export_file_list() -> list[tuple[Path, str]]:
    entries: list[tuple[Path, str]] = []
    for rel in ["web/main.py", "web/static/index.html",
                "scripts/iptables.sh", "scripts/update-geo.sh",
                "scripts/first-boot.sh", "install.sh", "SETUP.md",
                "config/settings.json", "config/network.conf"]:
        p = BASE / rel
        if p.exists():
            entries.append((p, rel))
    for svc in ("xray-proxy.service", "xray-web.service", "xray-first-boot.service"):
        p = Path("/etc/systemd/system") / svc
        if p.exists():
            entries.append((p, f"systemd/{svc}"))
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
    if name in allowed:
        return BASE / name
    return None

# ─────────────────────────────────────────────────────────────────────────────
# FastAPI App
# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None)

# ── Pydantic models ───────────────────────────────────────────────────────────
class LoginReq(BaseModel):    username: str; password: str
class KeyReq(BaseModel):      key: str
class ProfileReq(BaseModel):  profile: str
class PwReq(BaseModel):       current: str; new_pw: str
class AaplimgReq(BaseModel):  enabled: bool
class RouteTestReq(BaseModel): target: str
class CustomRulesReq(BaseModel):
    always_direct: list[str]
    always_vpn:    list[str]
class DeviceNameReq(BaseModel): name: str

# ── Captive portal ────────────────────────────────────────────────────────────
@app.get("/generate_204")
@app.head("/generate_204")
async def gen204():                    return Response(status_code=204)

@app.get("/hotspot-detect.html")
async def hotspot():
    return HTMLResponse("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")

@app.get("/ncsi.txt")
async def ncsi():                      return Response("Microsoft NCSI")

# ── Auth ──────────────────────────────────────────────────────────────────────
@app.post("/api/login")
async def login(req: LoginReq, resp: Response):
    s = load_settings()
    if (req.username != s["auth"]["username"] or
            hashlib.sha256(req.password.encode()).hexdigest() != s["auth"]["password_hash"]):
        raise HTTPException(401, "Invalid credentials")
    tok = make_token(req.username)
    resp.set_cookie("token", tok, max_age=86400, httponly=True, samesite="lax")
    return {"ok": True, "token": tok}

@app.post("/api/logout")
async def logout(resp: Response):
    resp.delete_cookie("token");  return {"ok": True}

@app.get("/api/auth-check")
async def auth_check(u: str = Depends(auth_dep)):
    return {"ok": True, "user": u}

@app.get("/api/version")
async def get_version(u: str = Depends(auth_dep)):
    return {"version": VERSION, "xray_core": get_xray_core_version()}

# ── Status ────────────────────────────────────────────────────────────────────
@app.get("/api/status")
async def get_status(u: str = Depends(auth_dep)):
    s = load_settings();  speeds = get_speeds();  state = get_xray_state()
    gw = "?"
    try:
        r = subprocess.run(["ip", "-4", "addr", "show", _get_lan_if()],
                           capture_output=True, text=True)
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout)
        gw = m.group(1) if m else "?"
    except Exception:
        pass
    vpn_meta = None
    if s.get("vpn_key"):
        try:
            _, vpn_meta = parse_key(s["vpn_key"])
        except Exception:
            vpn_meta = {"name": "Invalid key", "protocol": "?", "server": "?", "port": 0}
    return {"state": state, "gateway_ip": gw, "profile": s.get("profile", "all_except_ru"),
            "vpn": vpn_meta, "geo_updated": s.get("geo_updated"), "speeds": speeds,
            "force_aaplimg_vpn": s.get("force_aaplimg_vpn", True)}

# ── SSE streams ───────────────────────────────────────────────────────────────
@app.get("/api/speed-stream")
async def speed_stream(u: str = Depends(auth_dep)):
    async def gen():
        while True:
            yield f"data: {json.dumps(get_speeds())}\n\n"
            await asyncio.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.get("/api/sysinfo")
async def sysinfo_snapshot(u: str = Depends(auth_dep)):
    info = get_system_info();  info["net"] = get_speeds();  return info

@app.get("/api/sysinfo-stream")
async def sysinfo_stream(u: str = Depends(auth_dep)):
    async def gen():
        while True:
            info = get_system_info();  info["net"] = get_speeds()
            yield f"data: {json.dumps(info)}\n\n"
            await asyncio.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── VPN key ───────────────────────────────────────────────────────────────────
@app.post("/api/vpn-key")
async def set_key(req: KeyReq, u: str = Depends(auth_dep)):
    try:
        _, meta = parse_key(req.key)
    except ValueError as e:
        raise HTTPException(400, str(e))
    s = load_settings();  old_s = dict(s)
    s["vpn_key"] = req.key.strip();  save_settings(s)
    ok, err = apply_config(s, "vpn_key_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None, "vpn": meta}

@app.delete("/api/vpn-key")
async def del_key(u: str = Depends(auth_dep)):
    s = load_settings();  old_s = dict(s)
    s["vpn_key"] = None;  save_settings(s)
    apply_config(s, "vpn_key_delete", _pre_settings=old_s);  return {"ok": True}

# ── Profile ───────────────────────────────────────────────────────────────────
@app.post("/api/profile")
async def set_profile(req: ProfileReq, u: str = Depends(auth_dep)):
    if req.profile not in ("blocked_only", "all_except_ru", "all"):
        raise HTTPException(400, "Invalid profile")
    s = load_settings();  old_s = dict(s)
    s["profile"] = req.profile;  save_settings(s)
    ok, err = apply_config(s, "profile_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

# ── Apple CDN override ────────────────────────────────────────────────────────
@app.post("/api/aaplimg-vpn")
async def set_aaplimg_vpn(req: AaplimgReq, u: str = Depends(auth_dep)):
    s = load_settings();  old_s = dict(s)
    s["force_aaplimg_vpn"] = req.enabled;  save_settings(s)
    ok, err = apply_config(s, "aaplimg_toggle", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

# ── Custom Rules ──────────────────────────────────────────────────────────────
@app.get("/api/custom-rules")
async def get_custom_rules(u: str = Depends(auth_dep)):
    s = load_settings()
    return s.get("custom_rules", {"always_direct": [], "always_vpn": []})

@app.put("/api/custom-rules")
async def set_custom_rules(req: CustomRulesReq, u: str = Depends(auth_dep)):
    """Validate and apply custom routing rules."""
    errors = []
    all_rules = [("always_direct", r) for r in req.always_direct] + \
                [("always_vpn",    r) for r in req.always_vpn]
    for list_name, rule in all_rules:
        ok, msg = validate_custom_rule(rule)
        if not ok:
            errors.append(f"[{list_name}] {msg}")
    if errors:
        raise HTTPException(400, "; ".join(errors))
    s = load_settings();  old_s = dict(s)
    s["custom_rules"] = {"always_direct": req.always_direct,
                          "always_vpn":    req.always_vpn}
    save_settings(s)
    ok, err = apply_config(s, "custom_rules_change", _pre_settings=old_s)
    return {"ok": ok, "error": err or None}

# ── Route Tester ──────────────────────────────────────────────────────────────
@app.post("/api/route-test")
async def api_route_test(req: RouteTestReq, u: str = Depends(auth_dep)):
    """
    Test routing decision for a domain or IP.
    Returns outbound (direct/proxy), matched rule, and resolved IPs.
    """
    target = req.target.strip()
    if not target:
        raise HTTPException(400, "target is required")
    if len(target) > 253:
        raise HTTPException(400, "target too long")
    s = load_settings()
    # Run in executor to avoid blocking event loop during DNS + geo DB lookup
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, route_test, target, s)
    return result

# ── Snapshots ─────────────────────────────────────────────────────────────────
@app.get("/api/snapshots")
async def get_snapshots(u: str = Depends(auth_dep)):
    return {"snapshots": list_snapshots()}

@app.post("/api/snapshots/restore/{snap_id}")
async def api_restore_snapshot(snap_id: str, u: str = Depends(auth_dep)):
    # Validate snap_id format (YYYYMMDD_HHMMSS)
    if not re.match(r'^\d{8}_\d{6}$', snap_id):
        raise HTTPException(400, "Invalid snapshot id")
    ok, msg = restore_snapshot(snap_id)
    return {"ok": ok, "message": msg}

@app.delete("/api/snapshots/{snap_id}")
async def delete_snapshot(snap_id: str, u: str = Depends(auth_dep)):
    if not re.match(r'^\d{8}_\d{6}$', snap_id):
        raise HTTPException(400, "Invalid snapshot id")
    p = _snap_path(snap_id)
    if not p.exists():
        raise HTTPException(404, "Snapshot not found")
    p.unlink()
    return {"ok": True}

# ── Devices (ARP table + naming) ──────────────────────────────────────────────
@app.get("/api/devices")
async def get_devices(u: str = Depends(auth_dep)):
    s = load_settings()
    names = s.get("device_names", {})
    devices = get_arp_devices()
    for d in devices:
        d["name"] = names.get(d["ip"], "")
    return {"devices": devices}

@app.post("/api/devices/{ip}/name")
async def set_device_name(ip: str, req: DeviceNameReq, u: str = Depends(auth_dep)):
    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP address")
    name = req.name.strip()[:64]  # max 64 chars
    s = load_settings()
    if not hasattr(s, "get"):
        s = load_settings()
    s.setdefault("device_names", {})
    if name:
        s["device_names"][ip] = name
    else:
        s["device_names"].pop(ip, None)
    save_settings(s)
    return {"ok": True, "ip": ip, "name": name}

# ── Geo update ────────────────────────────────────────────────────────────────
@app.post("/api/geo-update")
async def geo_update(u: str = Depends(auth_dep)):
    global _geoip_ru_nets, _geosite_ru_data  # invalidate caches after update
    try:
        r = subprocess.run([str(SCRIPT / "update-geo.sh")],
                           capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            s = load_settings()
            s["geo_updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            save_settings(s)
            _geoip_ru_nets = None;  _geosite_ru_data = None  # invalidate
            subprocess.run(["systemctl", "restart", "xray-proxy"])
            return {"ok": True, "output": r.stdout[-500:]}
        return {"ok": False, "error": r.stderr[-500:]}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Timeout"}

@app.get("/api/geo-info")
async def geo_info(u: str = Depends(auth_dep)):
    s = load_settings()
    def fsize(p: Path) -> str:
        try:
            b = p.stat().st_size
            return f"{b/1024/1024:.1f} MB" if b > 1024*1024 else f"{b//1024} KB"
        except Exception:
            return "—"
    return {"geo_updated": s.get("geo_updated"),
            "geoip_size":  fsize(CFG_DIR / "geoip.dat"),
            "geosite_size": fsize(CFG_DIR / "geosite.dat")}

# ── System logs ───────────────────────────────────────────────────────────────
@app.get("/api/logs")
async def logs_snapshot(n: int = 300, u: str = Depends(auth_dep)):
    r = subprocess.run(
        ["journalctl", "-u", "xray-proxy", "-n", str(min(n, 1000)),
         "--no-pager", "--output=short-iso"],
        capture_output=True, text=True)
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
                if line:
                    yield f"data: {json.dumps(line.decode().rstrip())}\n\n"
                else:
                    break
        except asyncio.TimeoutError:
            yield 'data: "--- heartbeat ---"\n\n'
        finally:
            proc.kill()
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── Connection log ────────────────────────────────────────────────────────────
@app.get("/api/connections")
async def get_connections(n: int = 500, u: str = Depends(auth_dep)):
    log_file = LOGS / "access.log"
    if not log_file.exists():
        return {"connections": [], "note": "access.log not found"}
    r = subprocess.run(["tail", "-n", str(min(n, 2000)), str(log_file)],
                       capture_output=True, text=True)
    conns = []
    for line in r.stdout.strip().split("\n"):
        c = parse_access_log_line(line)
        if c:
            conns.append(c)
    return {"connections": list(reversed(conns))}

@app.get("/api/connections/stream")
async def connections_stream(u: str = Depends(auth_dep)):
    log_file = LOGS / "access.log"
    async def gen():
        proc = await asyncio.create_subprocess_exec(
            "tail", "-f", "-n", "0", str(log_file),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=25)
                if line:
                    c = parse_access_log_line(line.decode().rstrip())
                    if c:
                        yield f"data: {json.dumps(c)}\n\n"
                else:
                    break
        except asyncio.TimeoutError:
            yield "data: null\n\n"
        finally:
            proc.kill()
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── Config export / import ────────────────────────────────────────────────────
@app.get("/api/settings/export")
async def export_settings(u: str = Depends(auth_dep)):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for fspath, arcname in _export_file_list():
            tar.add(str(fspath), arcname=arcname)
    buf.seek(0)
    ts = datetime.utcnow().strftime("%Y-%m-%d")
    fname = f"xray-proxy-backup-{ts}.tar.gz"
    return Response(buf.read(), media_type="application/gzip",
                    headers={"Content-Disposition": f"attachment; filename={fname}"})

@app.post("/api/settings/import")
async def import_settings(file: UploadFile = File(...), u: str = Depends(auth_dep)):
    data = await file.read()
    try:
        buf = io.BytesIO(data)
        with tarfile.open(fileobj=buf, mode="r:gz") as _t:
            pass
    except Exception:
        raise HTTPException(400, "Invalid tar.gz archive")
    buf.seek(0)
    restored: list[str] = []
    try:
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            for member in tar.getmembers():
                dest = _import_dest(member.name)
                if dest is None:
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                fobj = tar.extractfile(member)
                if fobj:
                    dest.write_bytes(fobj.read())
                    restored.append(member.name.lstrip("./"))
    except Exception as e:
        raise HTTPException(500, f"Extraction failed: {e}")
    old_s = load_settings()  # pre-import settings for snapshot
    s = load_settings()       # reload after file extraction
    ok, err = apply_config(s, "settings_import", _pre_settings=old_s)
    if any(r.startswith("systemd/") for r in restored):
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    if any(r.startswith("web/") for r in restored):
        subprocess.Popen(["systemctl", "restart", "xray-web"])
    return {"ok": ok, "restored": restored, "error": err or None}

# ── Password change ───────────────────────────────────────────────────────────
@app.post("/api/change-password")
async def change_pw(req: PwReq, u: str = Depends(auth_dep)):
    s = load_settings()
    if hashlib.sha256(req.current.encode()).hexdigest() != s["auth"]["password_hash"]:
        raise HTTPException(403, "Wrong current password")
    s["auth"]["password_hash"] = hashlib.sha256(req.new_pw.encode()).hexdigest()
    save_settings(s);  return {"ok": True}

# ── Factory reset ─────────────────────────────────────────────────────────────
@app.post("/api/factory-reset")
async def factory_reset(u: str = Depends(auth_dep)):
    save_settings(dict(DEFAULT_SETTINGS))
    apply_config(DEFAULT_SETTINGS, "factory_reset")
    return {"ok": True}

# ── Terminal WebSocket ────────────────────────────────────────────────────────
@app.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    token = websocket.query_params.get("token", "") or websocket.cookies.get("token", "")
    if not verify_token(token):
        await websocket.close(code=4401);  return
    await websocket.accept()
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe("bash", ["bash", "-i"],
                   {**os.environ, "TERM": "xterm-256color",
                    "HOME": os.environ.get("HOME", "/root")})
        os._exit(1)
    loop = asyncio.get_event_loop()

    async def pty_to_ws():
        try:
            while True:
                try:
                    data = await loop.run_in_executor(None, os.read, fd, 4096)
                    if data:
                        await websocket.send_bytes(data)
                    else:
                        break
                except OSError:
                    break
        except Exception:
            pass

    async def ws_to_pty():
        try:
            while True:
                msg = await websocket.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                raw = msg.get("bytes") or (msg["text"].encode() if msg.get("text") else None)
                if not raw:
                    continue
                try:
                    j = json.loads(raw)
                    if j.get("type") == "resize":
                        cols = max(1, int(j.get("cols", 80)))
                        rows = max(1, int(j.get("rows", 24)))
                        fcntl.ioctl(fd, termios.TIOCSWINSZ,
                                    struct.pack("HHHH", rows, cols, 0, 0))
                        continue
                except Exception:
                    pass
                try:
                    os.write(fd, raw)
                except OSError:
                    break
        except Exception:
            pass

    r_task = asyncio.create_task(pty_to_ws())
    w_task = asyncio.create_task(ws_to_pty())
    try:
        await asyncio.wait([r_task, w_task], return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in [r_task, w_task]:
            t.cancel()
        for fn in [lambda: os.kill(pid, signal.SIGTERM),
                   lambda: os.waitpid(pid, os.WNOHANG),
                   lambda: os.close(fd),
                   lambda: asyncio.ensure_future(websocket.close())]:
            try:
                fn()
            except Exception:
                pass

# ── SPA ───────────────────────────────────────────────────────────────────────
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    html_path = STATIC / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text())
    return HTMLResponse("<h1>UI not installed</h1>", 500)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=80, log_level="warning")
