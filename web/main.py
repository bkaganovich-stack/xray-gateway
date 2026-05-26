#!/usr/bin/env python3
"""Xray Proxy Gateway — Web Management Interface"""

import asyncio, base64, fcntl, hashlib, hmac, io, json, os, pty, re, shutil, signal, struct, subprocess, tarfile, termios, time, urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, Response, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE     = Path("/opt/xray-proxy")
CFG_DIR  = BASE / "config"
SCRIPT   = BASE / "scripts"
LOGS     = BASE / "logs"
STATIC   = BASE / "web" / "static"
SETTINGS = CFG_DIR / "settings.json"
XCFG     = CFG_DIR / "xray.json"

DEFAULT_SETTINGS = {
    "auth": {"username": "admin",
             "password_hash": hashlib.sha256(b"admin").hexdigest()},
    "vpn_key":    None,
    "profile":    "all_except_ru",
    "geo_updated": None,
    # Apple CDN (aaplimg.com) uses Russian-hosted IPs; ISP blocks TLS to Apple
    # domains on those IPs. Force via VPN in all_except_ru / blocked_only profiles.
    "force_aaplimg_vpn": True,
    # Ozon's IP range (AS44386 "LLC Internet Solutions", 185.73.193.x/194.x) is absent from
    # xray's geoip:ru database, so ozon.ru falls through to the catch-all and goes via VPN.
    # Qrator WAF (Ozon anti-fraud) detects the VPN exit IP and shows "Выключите VPN".
    # Force these domains direct so Ozon sees the ISP's Russian IP instead.
    "force_ozon_direct": True,
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def load_settings() -> dict:
    if SETTINGS.exists():
        s = json.loads(SETTINGS.read_text())
        for k, v in DEFAULT_SETTINGS.items():
            s.setdefault(k, v)
        return s
    return dict(DEFAULT_SETTINGS)

def save_settings(s: dict):
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS.write_text(json.dumps(s, indent=2))

SECRET = (BASE / ".secret").read_text().strip() if (BASE / ".secret").exists() \
         else "xray-proxy-default-secret"

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

def _sockopt(): return {"mark": 255}

def _proxy_sockopt():
    """sockopt for the proxy outbound — includes TCP keepalive to prevent
    the Shadowsocks/VLESS tunnel from being killed by the server's idle timeout.
    Without keepalive, the tunnel drops when traffic is quiet (e.g. MacBook asleep),
    causing Google Home and other devices to show 'Connecting to Home'."""
    return {"mark": 255, "tcpKeepAliveIdle": 30, "tcpKeepAliveInterval": 15}

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
    net = p.get("type", "tcp")
    sec = p.get("security", "none")
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
        ss["wsSettings"] = {"path": p.get("path", "/"),
                            "headers": {"Host": p.get("host", host)}}
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
    host = d.get("add", "")
    port = int(d.get("port", 443))
    net = d.get("net", "tcp")
    tls_val = d.get("tls", "")
    ss = {"network": net, "sockopt": _proxy_sockopt()}
    if tls_val == "tls":
        ss["security"] = "tls"
        ss["tlsSettings"] = {"serverName": d.get("sni", host)}
    if net == "ws":
        ss["wsSettings"] = {"path": d.get("path", "/"),
                            "headers": {"Host": d.get("host", host)}}
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
          "settings": {"servers": [{"address": host, "port": int(port),
                                    "password": password}]},
          "streamSettings": {"network": "tcp", "security": "tls",
                             "tlsSettings": {"serverName": p.get("sni", host)},
                             "sockopt": _proxy_sockopt()}}
    return ob, {"name": name or f"{host}:{port}", "server": host,
                "port": int(port), "protocol": "Trojan"}

# ── Xray Config ───────────────────────────────────────────────────────────────
def build_xray_config(settings: dict) -> dict:
    vpn_key = settings.get("vpn_key")
    profile = settings.get("profile", "all_except_ru")
    outbounds = []
    has_proxy = False
    proxy_server_ip = None
    if vpn_key:
        try:
            ob, info = parse_key(vpn_key)
            outbounds.append(ob)
            has_proxy = True
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
    force_ozon   = settings.get("force_ozon_direct", True)
    # Ozon domains to force direct — ozon.ru IPs (AS44386) are absent from geoip:ru database
    OZON_DOMAINS = [
        "domain:ozon.ru",
        "domain:ozonusercontent.com",
        "domain:ozonid.ru",
        "domain:ozone.ru",
        "domain:o3.ru",
    ]
    rules = [
        *([{"type": "field", "ip": [proxy_server_ip], "outboundTag": "direct"}]
          if proxy_server_ip else []),
        # NOTE: captive portal check domains (connectivitycheck.gstatic.com, etc.) are
        # intentionally NOT routed direct here — they fall through to the catch-all (proxy).
        # Routing them direct fails because Google's IPs are blocked by the ISP on the
        # direct path (RKN). Via proxy they return the expected 204 response, so devices
        # correctly detect internet connectivity. Captive portal detection still works:
        # if a real captive portal is present, it intercepts the DNS or TCP before the
        # proxy can respond, and the device sees the redirect.
        {"type": "field", "ip":     ["geoip:private"],      "outboundTag": "direct"},
        {"type": "field", "domain": ["geosite:private"],    "outboundTag": "direct"},
    ]
    if profile == "blocked_only":
        rules += [
            # Apple CDN uses Russian-hosted IPs (INETCOM AS35598, 87.239.27.240).
            # osxapps.itunes.apple.com + updates.cdn-apple.com → CNAME → aaplimg.com → RU IP.
            # xray routes by SNI (not CNAME), so match the original Apple domains.
            # Must be BEFORE geoip:ru so the domain rule wins over the IP rule.
            *([{"type": "field", "domain": ["domain:cdn-apple.com",
                                             "domain:itunes.apple.com",
                                             "domain:aaplimg.com"],
                "outboundTag": final}]
              if force_aaplimg else []),
            # Ozon: IPs (AS44386) absent from geoip:ru — force direct so Ozon WAF
            # (Qrator) sees the ISP's Russian IP, not the VPN exit.
            *([{"type": "field", "domain": OZON_DOMAINS, "outboundTag": "direct"}]
              if force_ozon else []),
            {"type": "field", "ip":     ["geoip:ru"],                   "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:category-ru"],         "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:category-ru-blocked"], "outboundTag": final},
        ]
        default = "direct"
    elif profile == "all_except_ru":
        rules += [
            # Apple CDN uses Russian-hosted IPs (INETCOM AS35598, 87.239.27.240).
            # osxapps.itunes.apple.com + updates.cdn-apple.com → CNAME → aaplimg.com → RU IP.
            # xray routes by SNI (not CNAME), so match the original Apple domains.
            # Must be BEFORE geoip:ru so the domain rule wins over the IP rule.
            *([{"type": "field", "domain": ["domain:cdn-apple.com",
                                             "domain:itunes.apple.com",
                                             "domain:aaplimg.com"],
                "outboundTag": final}]
              if force_aaplimg else []),
            # Ozon: IPs (AS44386) absent from geoip:ru — force direct so Ozon WAF
            # (Qrator) sees the ISP's Russian IP, not the VPN exit.
            *([{"type": "field", "domain": OZON_DOMAINS, "outboundTag": "direct"}]
              if force_ozon else []),
            {"type": "field", "ip":     ["geoip:ru"],            "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:category-ru"], "outboundTag": "direct"},
        ]
        default = final
    else:
        default = final

    # Port 5228 = Google FCM (Firebase Cloud Messaging) — persistent Google Home backend
    # connection. Goes direct to avoid proxy timeouts that cause "Connecting to Home" flashes.
    # FCM is not geo-restricted, works fine without VPN.
    # Note: also handled at iptables level (RETURN before TProxy + MASQUERADE) for full bypass.
    rules.append({"type": "field", "network": "tcp", "port": "5228", "outboundTag": "direct"})
    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": default})
    return {
        "log": {"loglevel": "warning",
                "access": str(LOGS / "access.log"),
                "error":  str(LOGS / "xray.log")},
        "inbounds": [{
            "tag": "tproxy-in", "port": 12345,
            "protocol": "dokodemo-door",
            "settings": {"network": "tcp,udp", "followRedirect": True},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True},
            "streamSettings": {"sockopt": {"tproxy": "tproxy", "mark": 255}},
        }],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
        "stats": {},
        "policy": {"system": {"statsInboundUplink": True, "statsInboundDownlink": True}},
    }

def apply_config(settings: dict):
    cfg = build_xray_config(settings)
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    XCFG.write_text(json.dumps(cfg, indent=2))
    r = subprocess.run(["systemctl", "restart", "xray-proxy"],
                       capture_output=True, text=True)
    return r.returncode == 0, r.stderr

# ── Network interface helper ──────────────────────────────────────────────────
def _get_lan_if() -> str:
    """Read LAN interface name from network.conf; fall back to enp1s0."""
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

# ── Network speed tracking ────────────────────────────────────────────────────
_prev: dict = {}

def get_speeds() -> dict:
    global _prev
    iface = _get_lan_if()
    now = time.time()
    try:
        rx = int(Path(f"/sys/class/net/{iface}/statistics/rx_bytes").read_text())
        tx = int(Path(f"/sys/class/net/{iface}/statistics/tx_bytes").read_text())
    except Exception:
        return {"rx_bps": 0, "tx_bps": 0}
    p = _prev.get(iface, (now, rx, tx))
    dt = max(now - p[0], 0.1)
    _prev[iface] = (now, rx, tx)
    return {"rx_bps": max(0, (rx - p[1]) / dt),
            "tx_bps": max(0, (tx - p[2]) / dt)}

# ── System resource tracking ──────────────────────────────────────────────────
_prev_cpu_stats: list = []

def _read_cpu_stats() -> list:
    """Returns list of (total_ticks, idle_ticks) per CPU core from /proc/stat."""
    cores = []
    try:
        for line in Path("/proc/stat").read_text().split("\n"):
            if re.match(r"^cpu\d", line):
                parts = line.split()
                vals = [int(x) for x in parts[1:8]]  # user nice sys idle iowait irq softirq
                total = sum(vals)
                idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
                cores.append((total, idle))
    except Exception:
        pass
    return cores

def get_system_info() -> dict:
    global _prev_cpu_stats
    # ─ CPU per core ─
    curr = _read_cpu_stats()
    cpu_pcts = []
    if _prev_cpu_stats and len(_prev_cpu_stats) == len(curr):
        for (ct, ci), (pt, pi) in zip(curr, _prev_cpu_stats):
            dt = ct - pt
            pct = max(0.0, min(100.0, (1 - (ci - pi) / dt) * 100)) if dt > 0 else 0.0
            cpu_pcts.append(round(pct, 1))
    else:
        cpu_pcts = [0.0] * len(curr)
    _prev_cpu_stats = curr
    # ─ Memory ─
    mem_total = mem_used = 0
    try:
        m: dict = {}
        for line in Path("/proc/meminfo").read_text().split("\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                m[k.strip()] = int(v.strip().split()[0]) * 1024
        mem_total = m.get("MemTotal", 0)
        mem_used = mem_total - m.get("MemAvailable", 0)
    except Exception:
        pass
    # ─ Disk ─
    disk_total = disk_used = disk_free = 0
    try:
        du = shutil.disk_usage("/")
        disk_total, disk_used, disk_free = du.total, du.used, du.free
    except Exception:
        pass
    return {
        "cpu": cpu_pcts,
        "mem": {"total": mem_total, "used": mem_used},
        "disk": {"total": disk_total, "used": disk_used, "free": disk_free},
    }

# ── Access log parser ─────────────────────────────────────────────────────────
def parse_access_log_line(line: str) -> Optional[dict]:
    """Parse a single xray access.log line into a structured dict."""
    ts_m = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
    ts = ts_m.group(1) if ts_m else ""
    # Match: <src_ip:port> accepted <proto>:<dst_host>:<dst_port> [<inbound> -> <outbound>]
    acc_m = re.search(
        r"(\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?)\s+accepted\s+"
        r"(\w+):(.+):(\d+)\s+\[([^\]]+)\]",
        line,
    )
    if not acc_m:
        return None
    src, proto, dst, dport, route_info = acc_m.groups()
    parts = route_info.split(" -> ")
    outbound = parts[-1].strip() if len(parts) > 1 else route_info.strip()
    return {
        "ts": ts,
        "src": src,
        "proto": proto.upper(),
        "dst": dst,
        "dport": int(dport),
        "outbound": outbound,
    }

def get_xray_state() -> str:
    r = subprocess.run(["systemctl", "is-active", "xray-proxy"],
                       capture_output=True, text=True)
    if r.stdout.strip() != "active":
        return "stopped"
    s = load_settings()
    return "connected" if s.get("vpn_key") else "no_key"

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(docs_url=None, redoc_url=None)

# ─ Models ─────────────────────────────────────────────────────────────────────
class LoginReq(BaseModel):    username: str; password: str
class KeyReq(BaseModel):      key: str
class ProfileReq(BaseModel):  profile: str
class PwReq(BaseModel):       current: str; new_pw: str
class AaplimgReq(BaseModel):  enabled: bool
class OzonReq(BaseModel):     enabled: bool

# ── Captive portal (no auth) ──────────────────────────────────────────────────
@app.get("/generate_204")
@app.head("/generate_204")
async def gen204():
    return Response(status_code=204)

@app.get("/hotspot-detect.html")
async def hotspot():
    return HTMLResponse("<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>")

@app.get("/ncsi.txt")
async def ncsi():
    return Response("Microsoft NCSI")

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
    resp.delete_cookie("token")
    return {"ok": True}

@app.get("/api/auth-check")
async def auth_check(u: str = Depends(auth_dep)):
    return {"ok": True, "user": u}

# ── Status ────────────────────────────────────────────────────────────────────
@app.get("/api/status")
async def get_status(u: str = Depends(auth_dep)):
    s = load_settings()
    speeds = get_speeds()
    state  = get_xray_state()
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
            "force_aaplimg_vpn": s.get("force_aaplimg_vpn", True),
            "force_ozon_direct": s.get("force_ozon_direct", True)}

# ── Speed SSE ─────────────────────────────────────────────────────────────────
@app.get("/api/speed-stream")
async def speed_stream(u: str = Depends(auth_dep)):
    async def gen():
        while True:
            yield f"data: {json.dumps(get_speeds())}\n\n"
            await asyncio.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── System info ───────────────────────────────────────────────────────────────
@app.get("/api/sysinfo")
async def sysinfo_snapshot(u: str = Depends(auth_dep)):
    info = get_system_info()
    info["net"] = get_speeds()
    return info

@app.get("/api/sysinfo-stream")
async def sysinfo_stream(u: str = Depends(auth_dep)):
    async def gen():
        while True:
            info = get_system_info()
            info["net"] = get_speeds()
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
    s = load_settings()
    s["vpn_key"] = req.key.strip()
    save_settings(s)
    ok, err = apply_config(s)
    return {"ok": ok, "error": err or None, "vpn": meta}

@app.delete("/api/vpn-key")
async def del_key(u: str = Depends(auth_dep)):
    s = load_settings()
    s["vpn_key"] = None
    save_settings(s)
    apply_config(s)
    return {"ok": True}

# ── Profile ───────────────────────────────────────────────────────────────────
@app.post("/api/profile")
async def set_profile(req: ProfileReq, u: str = Depends(auth_dep)):
    if req.profile not in ("blocked_only", "all_except_ru", "all"):
        raise HTTPException(400, "Invalid profile")
    s = load_settings()
    s["profile"] = req.profile
    save_settings(s)
    ok, err = apply_config(s)
    return {"ok": ok, "error": err or None}

# ── Apple CDN override ────────────────────────────────────────────────────────
@app.post("/api/aaplimg-vpn")
async def set_aaplimg_vpn(req: AaplimgReq, u: str = Depends(auth_dep)):
    s = load_settings()
    s["force_aaplimg_vpn"] = req.enabled
    save_settings(s)
    ok, err = apply_config(s)
    return {"ok": ok, "error": err or None}

# ── Ozon direct override ──────────────────────────────────────────────────────
@app.post("/api/ozon-direct")
async def set_ozon_direct(req: OzonReq, u: str = Depends(auth_dep)):
    s = load_settings()
    s["force_ozon_direct"] = req.enabled
    save_settings(s)
    ok, err = apply_config(s)
    return {"ok": ok, "error": err or None}

# ── Geo update ────────────────────────────────────────────────────────────────
@app.post("/api/geo-update")
async def geo_update(u: str = Depends(auth_dep)):
    try:
        r = subprocess.run([str(SCRIPT / "update-geo.sh")],
                           capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            s = load_settings()
            s["geo_updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
            save_settings(s)
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
            return f"{b/1024/1024:.1f} MB" if b > 1024 * 1024 else f"{b // 1024} KB"
        except Exception:
            return "—"
    return {
        "geo_updated":  s.get("geo_updated"),
        "geoip_size":   fsize(CFG_DIR / "geoip.dat"),
        "geosite_size": fsize(CFG_DIR / "geosite.dat"),
    }

# ── System logs ───────────────────────────────────────────────────────────────
@app.get("/api/logs")
async def logs_snapshot(n: int = 300, u: str = Depends(auth_dep)):
    r = subprocess.run(
        ["journalctl", "-u", "xray-proxy", "-n", str(n), "--no-pager", "--output=short-iso"],
        capture_output=True, text=True)
    return {"logs": r.stdout}

@app.get("/api/logs/stream")
async def logs_stream(u: str = Depends(auth_dep)):
    async def gen():
        proc = await asyncio.create_subprocess_exec(
            "journalctl", "-u", "xray-proxy", "-f", "-n", "50",
            "--no-pager", "--output=short-iso",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        try:
            while True:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=25)
                if line:
                    yield f"data: {json.dumps(line.decode().rstrip())}\n\n"
                else:
                    break
        except asyncio.TimeoutError:
            yield "data: \"--- heartbeat ---\"\n\n"
        finally:
            proc.kill()
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

# ── Connection log ────────────────────────────────────────────────────────────
@app.get("/api/connections")
async def get_connections(n: int = 200, u: str = Depends(auth_dep)):
    log_file = LOGS / "access.log"
    if not log_file.exists():
        return {"connections": [], "note": "access.log not found"}
    r = subprocess.run(["tail", "-n", str(n), str(log_file)],
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
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
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

# ── Config export/import (tar.gz) ─────────────────────────────────────────────
# Each entry: (filesystem path, archive path inside the .tar.gz)
def _export_file_list() -> list[tuple[Path, str]]:
    """Build list of (absolute_path, archive_name) for all exportable files."""
    entries: list[tuple[Path, str]] = []

    # Files that live under BASE = /opt/xray-proxy
    for rel in [
        "web/main.py",
        "web/static/index.html",
        "scripts/iptables.sh",
        "scripts/update-geo.sh",
        "scripts/first-boot.sh",   # present after autoinstall deploy, absent on legacy
        "install.sh",
        "SETUP.md",
        "config/settings.json",    # VPN key, profile, password hash
        "config/network.conf",     # LAN_IF, ROUTER_IP
    ]:
        p = BASE / rel
        if p.exists():
            entries.append((p, rel))

    # Systemd service files live in /etc/systemd/system/ on a running gateway
    for svc in ("xray-proxy.service", "xray-web.service", "xray-first-boot.service"):
        p = Path("/etc/systemd/system") / svc
        if p.exists():
            entries.append((p, f"systemd/{svc}"))

    return entries

# Paths where imported files should land (archive name → filesystem path)
def _import_dest(arcname: str) -> Path | None:
    """Return absolute destination path for an archive entry, or None if not allowed."""
    name = arcname.lstrip("./")
    if name.startswith("systemd/") and name.endswith(".service"):
        svc = Path(name).name
        if svc in ("xray-proxy.service", "xray-web.service", "xray-first-boot.service"):
            return Path("/etc/systemd/system") / svc
    allowed_base = {
        "web/main.py", "web/static/index.html",
        "scripts/iptables.sh", "scripts/update-geo.sh", "scripts/first-boot.sh",
        "install.sh", "SETUP.md",
        "config/settings.json", "config/network.conf",
    }
    if name in allowed_base:
        return BASE / name
    return None

@app.get("/api/settings/export")
async def export_settings(u: str = Depends(auth_dep)):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for fspath, arcname in _export_file_list():
            tar.add(str(fspath), arcname=arcname)
    buf.seek(0)
    ts = datetime.utcnow().strftime("%Y-%m-%d")
    fname = f"xray-proxy-backup-{ts}.tar.gz"
    return Response(
        buf.read(),
        media_type="application/gzip",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )

@app.post("/api/settings/import")
async def import_settings(file: UploadFile = File(...), u: str = Depends(auth_dep)):
    data = await file.read()
    # ── validate ──
    try:
        buf = io.BytesIO(data)
        with tarfile.open(fileobj=buf, mode="r:gz") as _t:
            pass  # just check it opens
    except Exception:
        raise HTTPException(400, "Invalid tar.gz archive")

    # ── extract allowed files only (strict allowlist, no path traversal) ──
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

    # ── reload settings and apply xray config ──
    s = load_settings()
    ok, err = apply_config(s)

    # ── if systemd services were updated, reload daemon ──
    if any(r.startswith("systemd/") for r in restored):
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

    # ── restart web process to pick up new main.py / index.html ──
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
    save_settings(s)
    return {"ok": True}

# ── Factory reset ─────────────────────────────────────────────────────────────
@app.post("/api/factory-reset")
async def factory_reset(u: str = Depends(auth_dep)):
    save_settings(dict(DEFAULT_SETTINGS))
    apply_config(DEFAULT_SETTINGS)
    return {"ok": True}

# ── Terminal WebSocket ────────────────────────────────────────────────────────
@app.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    """Cockpit-style PTY terminal over WebSocket.
    Auth: Bearer token passed as ?token= query param (cookie not forwarded on WS).
    Protocol:
      client→server: raw bytes (keyboard) OR JSON {"type":"resize","cols":N,"rows":M}
      server→client: raw bytes (terminal output)
    """
    token = websocket.query_params.get("token", "") or websocket.cookies.get("token", "")
    if not verify_token(token):
        await websocket.close(code=4401)
        return
    await websocket.accept()

    # Spawn bash in a PTY
    pid, fd = pty.fork()
    if pid == 0:
        # child process
        os.execvpe("bash", ["bash", "-i"], {
            **os.environ,
            "TERM": "xterm-256color",
            "HOME": os.environ.get("HOME", "/root"),
        })
        os._exit(1)

    loop = asyncio.get_event_loop()

    async def pty_to_ws():
        """Read PTY output, forward to WebSocket."""
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
        """Read WebSocket input, forward to PTY (or handle resize)."""
        try:
            while True:
                msg = await websocket.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                raw = msg.get("bytes") or (
                    msg["text"].encode() if msg.get("text") else None)
                if not raw:
                    continue
                # Resize message?
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
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
        try:
            os.waitpid(pid, os.WNOHANG)
        except Exception:
            pass
        try:
            os.close(fd)
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass

# ── SPA (must be last) ────────────────────────────────────────────────────────
@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    html_path = STATIC / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text())
    return HTMLResponse("<h1>UI not installed</h1>", 500)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=80, log_level="warning")
