"""
Tests for xray-gateway P2 features:
  - device policies (precedence, IPv4/IPv6 merge by MAC)
  - DNS settings validation
  - VPN server masking and multi-server config
  - failover selection logic
  - explain-route logic
  - alert cooldown and event filtering
  - config generation with device rules
  - rollback
Run: python3 -m pytest tests/ -v
"""
import ipaddress
import json
import re
import socket
import sys
import tempfile
import time
import os
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock, call

# ── bootstrap: point BASE to a temp dir ──────────────────────────────────────
_tmp_base = tempfile.mkdtemp(prefix="xray_p2_test_")
sys.path.insert(0, str(Path(__file__).parent.parent / "web"))
import main as m

m.BASE     = Path(_tmp_base)
m.CFG_DIR  = Path(_tmp_base) / "config"
m.SNAP_DIR = Path(_tmp_base) / "config" / "snapshots"
m.SETTINGS = Path(_tmp_base) / "config" / "settings.json"
m.XCFG     = Path(_tmp_base) / "config" / "xray.json"
m.LOGS     = Path(_tmp_base) / "logs"
m.STATIC   = Path(_tmp_base) / "web" / "static"
m.DNS_CONF = Path(_tmp_base) / "etc" / "dnsmasq.d" / "gateway.conf"
m.SECRET   = "test-secret-for-p2"
for d in [m.CFG_DIR, m.SNAP_DIR, m.LOGS, m.STATIC, m.DNS_CONF.parent]:
    d.mkdir(parents=True, exist_ok=True)
Path(_tmp_base, ".secret").write_text("test-secret-for-p2")

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def _srv(id_=None, key="ss://Y2hhY2hhMjA6cGFzc0AxLjIuMy40OjEyMzQ=", enabled=True, priority=1, status="unknown"):
    return {
        "id":           id_ or str(uuid.uuid4()),
        "name":         "Test Server",
        "key":          key,
        "enabled":      enabled,
        "priority":     priority,
        "last_status":  status,
        "latency_ms":   None,
        "last_checked": None,
    }

def _settings(**kwargs):
    s = dict(m.DEFAULT_SETTINGS)
    s["custom_rules"] = {"always_direct": [], "always_vpn": []}
    s["devices"]      = {}
    s["vpn_servers"]  = []
    s["active_vpn_id"] = None
    s["dns"]          = dict(m.DEFAULT_SETTINGS["dns"])
    s["alerts"]       = dict(m.DEFAULT_SETTINGS["alerts"])
    s.update(kwargs)
    return s


# ─────────────────────────────────────────────────────────────────────────────
# Tests: Settings migration
# ─────────────────────────────────────────────────────────────────────────────
class TestMigration:
    def test_vpn_key_migrates_to_vpn_servers(self):
        raw = {"vpn_key": "ss://Y2hhY2hhMjA6cGFzc0AxLjIuMy40OjEyMzQ=",
               "profile": "all_except_ru"}
        s = m._migrate_settings(raw)
        assert len(s["vpn_servers"]) == 1
        assert s["vpn_servers"][0]["key"] == raw["vpn_key"]
        assert s["active_vpn_id"] == s["vpn_servers"][0]["id"]

    def test_device_names_migrate_to_devices(self):
        raw = {"device_names": {"192.168.1.5": "My Phone"}, "profile": "all_except_ru"}
        s = m._migrate_settings(raw)
        assert "devices" in s
        entry = s["devices"].get("ip:192.168.1.5", {})
        assert entry.get("name") == "My Phone"
        assert entry.get("policy") == "inherit"

    def test_migration_idempotent(self):
        raw = {"vpn_servers": [_srv()], "active_vpn_id": "x"}
        s1 = m._migrate_settings(dict(raw))
        s2 = m._migrate_settings(dict(s1))
        assert len(s2["vpn_servers"]) == len(s1["vpn_servers"])

    def test_missing_fields_filled_from_defaults(self):
        s = m._migrate_settings({"profile": "all"})
        assert "dns" in s
        assert "alerts" in s
        assert "devices" in s
        assert "custom_rules" in s


# ─────────────────────────────────────────────────────────────────────────────
# Tests: ARP / device merging
# ─────────────────────────────────────────────────────────────────────────────
class TestARPMerge:
    def _fake_arp(self, entries):
        """Return a mock for get_arp_table."""
        return entries

    def test_mac_based_key(self):
        arp = [{"mac": "aa:bb:cc:dd:ee:ff", "ips": ["192.168.1.5"], "state": "REACHABLE"}]
        with patch.object(m, "get_arp_table", return_value=arp):
            s = _settings(devices={})
            devs = m.get_devices_merged(s)
        assert len(devs) == 1
        assert devs[0]["key"] == "aa:bb:cc:dd:ee:ff"

    def test_ip_fallback_key_when_no_mac(self):
        arp = [{"mac": "", "ips": ["192.168.1.5"], "state": "REACHABLE"}]
        with patch.object(m, "get_arp_table", return_value=arp):
            devs = m.get_devices_merged(_settings())
        assert devs[0]["key"] == "ip:192.168.1.5"

    def test_ipv4_ipv6_merged_by_mac(self):
        """Devices with same MAC but different IPs (v4 + v6) appear as one entry."""
        arp = [{"mac": "aa:bb:cc:dd:ee:ff",
                "ips": ["192.168.1.5", "fe80::1"],
                "state": "REACHABLE"}]
        with patch.object(m, "get_arp_table", return_value=arp):
            devs = m.get_devices_merged(_settings())
        assert len(devs) == 1
        assert "192.168.1.5" in devs[0]["ips"]
        assert "fe80::1" in devs[0]["ips"]

    def test_stored_name_appears(self):
        mac = "aa:bb:cc:dd:ee:ff"
        arp = [{"mac": mac, "ips": ["10.0.0.1"], "state": "REACHABLE"}]
        s   = _settings(devices={mac: {"name": "Living Room TV", "policy": "inherit", "ips": []}})
        with patch.object(m, "get_arp_table", return_value=arp):
            devs = m.get_devices_merged(s)
        assert devs[0]["name"] == "Living Room TV"

    def test_offline_device_included(self):
        """Stored device not in ARP table should appear as OFFLINE."""
        s = _settings(devices={"aa:bb:cc:00:00:01": {"name": "Old PC", "policy": "inherit", "ips": ["10.0.0.2"]}})
        with patch.object(m, "get_arp_table", return_value=[]):
            devs = m.get_devices_merged(s)
        assert len(devs) == 1
        assert devs[0]["state"] == "OFFLINE"


# ─────────────────────────────────────────────────────────────────────────────
# Tests: Device policy → xray rules
# ─────────────────────────────────────────────────────────────────────────────
class TestDevicePolicyRules:
    def test_inherit_produces_no_rules(self):
        rules = m._device_policy_rules(["192.168.1.5"], "inherit", "proxy")
        assert rules == []

    def test_always_direct_single_rule(self):
        rules = m._device_policy_rules(["192.168.1.5"], "always_direct", "proxy")
        assert len(rules) == 1
        assert rules[0]["outboundTag"] == "direct"
        assert rules[0]["source"] == ["192.168.1.5"]
        assert rules[0]["network"] == "tcp,udp"

    def test_always_vpn_single_rule(self):
        rules = m._device_policy_rules(["192.168.1.5"], "always_vpn", "proxy")
        assert len(rules) == 1
        assert rules[0]["outboundTag"] == "proxy"

    def test_all_except_ru_three_rules(self):
        rules = m._device_policy_rules(["192.168.1.5"], "all_except_ru", "proxy")
        assert len(rules) == 3
        outbounds = [r["outboundTag"] for r in rules]
        assert "direct" in outbounds
        assert "proxy"  in outbounds

    def test_blocked_only_four_rules(self):
        rules = m._device_policy_rules(["192.168.1.5"], "blocked_only", "proxy")
        assert len(rules) == 4
        # Last rule is the per-device direct catch-all
        assert rules[-1]["outboundTag"] == "direct"

    def test_multiple_ips_in_source(self):
        ips   = ["192.168.1.5", "192.168.1.6"]
        rules = m._device_policy_rules(ips, "always_vpn", "proxy")
        assert set(rules[0]["source"]) == set(ips)

    def test_empty_ips_returns_no_rules(self):
        rules = m._device_policy_rules([], "always_vpn", "proxy")
        assert rules == []


# ─────────────────────────────────────────────────────────────────────────────
# Tests: Device policy precedence in full xray config
# ─────────────────────────────────────────────────────────────────────────────
class TestDevicePolicyPrecedence:
    def _cfg(self, settings):
        with patch.object(m, "get_arp_table", return_value=[
            {"mac": "aa:bb:cc:dd:ee:ff", "ips": ["192.168.1.10"], "state": "REACHABLE"}
        ]):
            return m.build_xray_config(settings)

    def test_device_always_direct_rule_before_geoip(self):
        mac = "aa:bb:cc:dd:ee:ff"
        s   = _settings(
            profile="all_except_ru",
            devices={mac: {"name": "PC", "policy": "always_direct", "ips": ["192.168.1.10"]}}
        )
        cfg = self._cfg(s)
        rules = cfg["routing"]["rules"]
        dev_idx  = next((i for i, r in enumerate(rules)
                         if r.get("source") and "192.168.1.10" in r.get("source", [])), -1)
        geoip_idx = next((i for i, r in enumerate(rules)
                          if "geoip:ru" in r.get("ip", [])), -1)
        assert dev_idx != -1,  "Device rule not found"
        assert geoip_idx != -1, "geoip:ru rule not found"
        assert dev_idx < geoip_idx, "Device rule must come before geoip:ru"

    def test_inherit_device_not_in_rules(self):
        mac = "aa:bb:cc:dd:ee:ff"
        s   = _settings(
            profile="all_except_ru",
            devices={mac: {"name": "Phone", "policy": "inherit", "ips": ["192.168.1.10"]}}
        )
        cfg = self._cfg(s)
        rules = cfg["routing"]["rules"]
        src_rules = [r for r in rules if r.get("source")]
        assert len(src_rules) == 0, "inherit policy should produce no source rules"

    def test_custom_rules_before_device_rules(self):
        """custom always_direct should appear BEFORE per-device rules."""
        mac = "aa:bb:cc:dd:ee:ff"
        s   = _settings(
            profile="all_except_ru",
            custom_rules={"always_direct": ["domain:bypass.ru"], "always_vpn": []},
            devices={mac: {"name": "TV", "policy": "always_vpn", "ips": ["192.168.1.10"]}}
        )
        cfg = self._cfg(s)
        rules = cfg["routing"]["rules"]
        custom_idx = next((i for i, r in enumerate(rules)
                           if "domain:bypass.ru" in r.get("domain", [])), -1)
        dev_idx    = next((i for i, r in enumerate(rules)
                           if r.get("source")), -1)
        assert custom_idx != -1, "Custom rule not found"
        assert dev_idx    != -1, "Device rule not found"
        assert custom_idx < dev_idx, "Custom rule must precede device rule"


# ─────────────────────────────────────────────────────────────────────────────
# Tests: DNS settings validation
# ─────────────────────────────────────────────────────────────────────────────
class TestDNSValidation:
    def test_valid_ipv4_upstream(self):
        errors = m.validate_dns_settings({"upstream": ["8.8.8.8", "1.1.1.1"],
                                           "upstream_ru": [], "cache_size": 1000,
                                           "local_records": []})
        assert errors == []

    def test_valid_ipv6_upstream(self):
        errors = m.validate_dns_settings({"upstream": ["2001:4860:4860::8888"],
                                           "upstream_ru": [], "cache_size": 1000,
                                           "local_records": []})
        assert errors == []

    def test_invalid_upstream_ip(self):
        errors = m.validate_dns_settings({"upstream": ["not-an-ip"],
                                           "upstream_ru": [], "cache_size": 1000,
                                           "local_records": []})
        assert errors

    def test_invalid_cache_size_negative(self):
        errors = m.validate_dns_settings({"upstream": ["8.8.8.8"],
                                           "upstream_ru": [], "cache_size": -1,
                                           "local_records": []})
        assert errors

    def test_invalid_cache_size_too_large(self):
        errors = m.validate_dns_settings({"upstream": ["8.8.8.8"],
                                           "upstream_ru": [], "cache_size": 200000,
                                           "local_records": []})
        assert errors

    def test_valid_local_record(self):
        errors = m.validate_dns_settings({"upstream": ["8.8.8.8"],
                                           "upstream_ru": [], "cache_size": 1000,
                                           "local_records": [{"hostname": "mydevice.local",
                                                               "ip": "192.168.1.5"}]})
        assert errors == []

    def test_invalid_local_record_hostname(self):
        errors = m.validate_dns_settings({"upstream": ["8.8.8.8"],
                                           "upstream_ru": [], "cache_size": 1000,
                                           "local_records": [{"hostname": "bad host name!",
                                                               "ip": "192.168.1.5"}]})
        assert errors

    def test_invalid_local_record_ip(self):
        errors = m.validate_dns_settings({"upstream": ["8.8.8.8"],
                                           "upstream_ru": [], "cache_size": 1000,
                                           "local_records": [{"hostname": "ok.local",
                                                               "ip": "999.999.999.999"}]})
        assert errors


# ─────────────────────────────────────────────────────────────────────────────
# Tests: DNS config generation
# ─────────────────────────────────────────────────────────────────────────────
class TestDNSConfigGeneration:
    def test_upstream_in_conf(self):
        dns  = {"upstream": ["8.8.8.8", "1.1.1.1"], "upstream_ru": [],
                "cache_size": 500, "local_records": []}
        conf = m.build_dnsmasq_conf(dns)
        assert "server=8.8.8.8" in conf
        assert "server=1.1.1.1" in conf
        assert "cache-size=500" in conf

    def test_split_dns_in_conf(self):
        dns  = {"upstream": ["8.8.8.8"], "upstream_ru": ["192.168.50.1"],
                "cache_size": 1000, "local_records": []}
        conf = m.build_dnsmasq_conf(dns)
        assert "server=/ru/192.168.50.1" in conf
        assert "server=/local/192.168.50.1" in conf

    def test_local_record_in_conf(self):
        dns  = {"upstream": ["8.8.8.8"], "upstream_ru": [], "cache_size": 1000,
                "local_records": [{"hostname": "mydevice.local", "ip": "192.168.1.5"}]}
        conf = m.build_dnsmasq_conf(dns)
        assert "address=/mydevice.local/192.168.1.5" in conf


# ─────────────────────────────────────────────────────────────────────────────
# Tests: VPN server masking
# ─────────────────────────────────────────────────────────────────────────────
class TestVPNMasking:
    def test_mask_ss_key(self):
        # Use standard ss:// format with visible @host:port
        key    = "ss://Y2hhY2hhMjA6cGFzcw==@1.2.3.4:1234"
        masked = m.mask_key(key)
        assert "pass" not in masked.lower()
        assert "1.2.3.4" in masked   # server visible after @
        assert "***" in masked

    def test_mask_empty_key(self):
        assert m.mask_key("") == ""
        assert m.mask_key(None) == ""

    def test_mask_hides_credentials(self):
        key    = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXRwYXNzd29yZEAxMC4wLjAuMTo4Mzg4"
        masked = m.mask_key(key)
        assert "secretpassword" not in masked

    def test_parse_key_returns_server(self):
        key = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzQDEuMi4zLjQ6MTIzNA=="
        ob, info = m.parse_key(key)
        assert info["server"] == "1.2.3.4"
        assert info["port"]   == 1234


# ─────────────────────────────────────────────────────────────────────────────
# Tests: Multi-server config + failover selection
# ─────────────────────────────────────────────────────────────────────────────
class TestMultiServer:
    def test_active_server_used_in_config(self):
        sid1 = str(uuid.uuid4()); sid2 = str(uuid.uuid4())
        s1 = _srv(id_=sid1, key="ss://Y2hhY2hhMjA6czFAMS4xLjEuMToyMjI=", priority=1)
        s2 = _srv(id_=sid2, key="ss://Y2hhY2hhMjA6czJAMi4yLjIuMjoyMjI=", priority=2)
        settings = _settings(vpn_servers=[s1, s2], active_vpn_id=sid2)
        obs, has_proxy, server_ip = m._get_active_vpn_outbound(settings)
        assert has_proxy
        assert server_ip == "2.2.2.2"   # active is sid2

    def test_fallback_to_first_enabled_if_active_missing(self):
        sid1 = str(uuid.uuid4())
        s1   = _srv(id_=sid1, key="ss://Y2hhY2hhMjA6czFAMS4xLjEuMToyMjI=", priority=1)
        settings = _settings(vpn_servers=[s1], active_vpn_id="nonexistent-id")
        obs, has_proxy, server_ip = m._get_active_vpn_outbound(settings)
        assert has_proxy
        assert server_ip == "1.1.1.1"

    def test_disabled_server_skipped_in_fallback(self):
        sid1 = str(uuid.uuid4()); sid2 = str(uuid.uuid4())
        s1   = _srv(id_=sid1, key="ss://Y2hhY2hhMjA6czFAMS4xLjEuMToyMjI=", enabled=False, priority=1)
        s2   = _srv(id_=sid2, key="ss://Y2hhY2hhMjA6czJAMi4yLjIuMjoyMjI=", enabled=True,  priority=2)
        settings = _settings(vpn_servers=[s1, s2], active_vpn_id=None)
        obs, has_proxy, server_ip = m._get_active_vpn_outbound(settings)
        assert has_proxy
        assert server_ip == "2.2.2.2"   # s1 disabled, s2 used

    def test_no_servers_returns_no_proxy(self):
        settings = _settings(vpn_servers=[], active_vpn_id=None, vpn_key=None)
        obs, has_proxy, server_ip = m._get_active_vpn_outbound(settings)
        assert not has_proxy
        assert server_ip is None

    def test_priority_ordering_in_fallback(self):
        sid1 = str(uuid.uuid4()); sid2 = str(uuid.uuid4())
        s_low  = _srv(id_=sid1, key="ss://Y2hhY2hhMjA6czFAMS4xLjEuMToyMjI=", priority=99)
        s_high = _srv(id_=sid2, key="ss://Y2hhY2hhMjA6czJAMi4yLjIuMjoyMjI=", priority=1)
        settings = _settings(vpn_servers=[s_low, s_high], active_vpn_id=None)
        obs, has_proxy, server_ip = m._get_active_vpn_outbound(settings)
        assert server_ip == "2.2.2.2"   # priority=1 wins


# ─────────────────────────────────────────────────────────────────────────────
# Tests: Explain-route logic
# ─────────────────────────────────────────────────────────────────────────────
class TestExplainRoute:
    def _explain(self, src="192.168.1.5", dst="1.2.3.4", dst_port=443,
                 proto="TCP", outbound="proxy", devices=None):
        m._explain_cache.clear()
        s = _settings(devices=devices or {})
        with patch.object(m, "arp_ip_to_mac", return_value={}), \
             patch.object(m, "_ip_in_geoip_ru", return_value=False), \
             patch.object(m, "_domain_in_geosite_ru", return_value=False), \
             patch("socket.getaddrinfo", side_effect=socket.gaierror("no dns")):
            return m.explain_connection(src, dst, dst_port, proto, outbound, s)

    def test_returns_required_fields(self):
        r = self._explain()
        for field in ("src_ip", "src_mac", "src_name", "device_policy",
                      "dst", "dst_port", "proto", "outbound",
                      "matched_rule", "rule_source", "note"):
            assert field in r, f"Missing field: {field}"

    def test_unknown_device_has_inherit_policy(self):
        r = self._explain()
        assert r["device_policy"] == "inherit"

    def test_known_device_name_resolved(self):
        m._explain_cache.clear()
        s = _settings(devices={"aa:bb:cc:00:00:01": {"name": "My PC", "policy": "inherit", "ips": ["192.168.1.5"]}})
        with patch.object(m, "arp_ip_to_mac", return_value={"192.168.1.5": "aa:bb:cc:00:00:01"}), \
             patch.object(m, "_ip_in_geoip_ru", return_value=False), \
             patch.object(m, "_domain_in_geosite_ru", return_value=False), \
             patch("socket.getaddrinfo", side_effect=socket.gaierror("no dns")):
            r = m.explain_connection("192.168.1.5", "1.2.3.4", 443, "TCP", "proxy", s)
        assert r["src_name"] == "My PC"
        assert r["src_mac"]  == "aa:bb:cc:00:00:01"

    def test_device_policy_reflected_in_explanation(self):
        m._explain_cache.clear()
        s = _settings(devices={"aa:bb:cc:00:00:02": {"name": "TV", "policy": "always_direct", "ips": ["10.0.0.5"]}})
        with patch.object(m, "arp_ip_to_mac", return_value={"10.0.0.5": "aa:bb:cc:00:00:02"}):
            r = m.explain_connection("10.0.0.5", "1.2.3.4", 80, "TCP", "direct", s)
        assert r["device_policy"] == "always_direct"

    def test_ru_ip_marked_as_country_ru(self):
        m._explain_cache.clear()
        with patch.object(m, "arp_ip_to_mac", return_value={}), \
             patch.object(m, "_ip_in_geoip_ru", return_value=True), \
             patch.object(m, "_domain_in_geosite_ru", return_value=False), \
             patch("socket.getaddrinfo", side_effect=socket.gaierror("no dns")):
            r = m.explain_connection("192.168.1.1", "185.73.193.68", 443, "TCP", "direct",
                                      _settings())
        assert r["country"] == "RU"

    def test_cache_hit_on_second_call(self):
        m._explain_cache.clear()
        s = _settings()
        call_count = [0]
        orig_arp = m.arp_ip_to_mac
        def counting_arp():
            call_count[0] += 1
            return {}
        with patch.object(m, "arp_ip_to_mac", side_effect=counting_arp), \
             patch.object(m, "_ip_in_geoip_ru", return_value=False), \
             patch.object(m, "_domain_in_geosite_ru", return_value=False), \
             patch("socket.getaddrinfo", side_effect=socket.gaierror("no dns")):
            m.explain_connection("10.0.0.1", "1.2.3.4", 80, "TCP", "proxy", s)
            m.explain_connection("10.0.0.1", "1.2.3.4", 80, "TCP", "proxy", s)
        assert call_count[0] == 1  # second call uses cache


# ─────────────────────────────────────────────────────────────────────────────
# Tests: Alert cooldown and event filtering
# ─────────────────────────────────────────────────────────────────────────────
class TestAlerts:
    def setup_method(self):
        m._alert_last_sent.clear()
        m._alert_log.clear()
        m.CFG_DIR.mkdir(parents=True, exist_ok=True)

    def _settings_with_alerts(self, events, cooldown_min=30, webhook="http://test/hook"):
        s = _settings()
        s["alerts"] = {"enabled": True, "webhook_url": webhook,
                       "events": events, "cooldown_min": cooldown_min}
        m.SETTINGS.write_text(json.dumps(s, indent=2))
        return s

    def test_event_logged_always(self):
        self._settings_with_alerts(events=[])  # no events enabled
        m.fire_alert("vpn_down", "test")
        assert any(e["event"] == "vpn_down" for e in m._alert_log)

    def test_event_not_in_list_skips_webhook(self):
        self._settings_with_alerts(events=["config_rollback"])
        with patch("urllib.request.urlopen") as mock_open:
            m.fire_alert("vpn_down", "should not send")
            import time as _t; _t.sleep(0.1)  # let thread run
        mock_open.assert_not_called()

    def test_cooldown_prevents_second_send(self):
        self._settings_with_alerts(events=["vpn_down"], cooldown_min=60)
        m._alert_last_sent["vpn_down"] = time.time() - 10  # sent 10 sec ago
        with patch("urllib.request.urlopen") as mock_open:
            m.fire_alert("vpn_down", "still cooling down")
            import time as _t; _t.sleep(0.05)
        mock_open.assert_not_called()

    def test_alert_sent_after_cooldown_expires(self):
        self._settings_with_alerts(events=["vpn_down"], cooldown_min=1)
        m._alert_last_sent["vpn_down"] = time.time() - 120  # 2 min ago > 1 min cooldown
        sent = []
        def fake_urlopen(req, timeout=None):
            sent.append(req)
            return MagicMock().__enter__.return_value
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            m.fire_alert("vpn_down", "cooldown expired")
            import time as _t; _t.sleep(0.1)
        assert len(sent) >= 1

    def test_alert_log_respects_max_size(self):
        """fire_alert trims log by 1 each call — verify trim works at all."""
        self._settings_with_alerts(events=[])
        # Fill log to exactly MAX_SIZE
        m._alert_log.clear()
        for i in range(m.ALERT_LOG_SIZE):
            m._alert_log.append({"ts": "x", "event": f"e{i}", "detail": ""})
        assert len(m._alert_log) == m.ALERT_LOG_SIZE
        # One more event: append + trim → still ALERT_LOG_SIZE
        m.fire_alert("overflow_event", "should trim one old entry")
        assert len(m._alert_log) == m.ALERT_LOG_SIZE


# ─────────────────────────────────────────────────────────────────────────────
# Tests: Full xray config generation with device policies
# ─────────────────────────────────────────────────────────────────────────────
class TestXrayConfigWithDevices:
    def _build(self, devices, profile="all_except_ru"):
        arp_entries = []
        for key, d in devices.items():
            if not key.startswith("ip:"):
                arp_entries.append({"mac": key, "ips": d.get("ips", []), "state": "REACHABLE"})
        s = _settings(devices=devices, profile=profile)
        with patch.object(m, "get_arp_table", return_value=arp_entries):
            return m.build_xray_config(s)

    def test_no_devices_gives_no_source_rules(self):
        cfg   = self._build({})
        rules = cfg["routing"]["rules"]
        assert not any(r.get("source") for r in rules)

    def test_always_direct_device_gets_source_rule(self):
        cfg   = self._build({"aa:bb:cc:00:01:01": {"policy": "always_direct", "ips": ["192.168.1.2"]}})
        rules = cfg["routing"]["rules"]
        src   = [r for r in rules if r.get("source")]
        assert len(src) >= 1
        assert src[0]["outboundTag"] == "direct"

    def test_quic_sniffing_preserved(self):
        cfg = self._build({})
        sniff = cfg["inbounds"][0]["sniffing"]
        assert "quic" in sniff["destOverride"]
        assert sniff["routeOnly"] is True


# ─────────────────────────────────────────────────────────────────────────────
# Tests: Snapshot with new settings structure
# ─────────────────────────────────────────────────────────────────────────────
class TestSnapshotV2:
    def setup_method(self):
        m.CFG_DIR.mkdir(parents=True, exist_ok=True)
        m.SNAP_DIR.mkdir(parents=True, exist_ok=True)
        for f in m.SNAP_DIR.glob("snap_*.json"):
            f.unlink()
        m.XCFG.write_text(json.dumps({"test": True}, indent=2))
        s = _settings()
        m.SETTINGS.write_text(json.dumps(s, indent=2))

    def test_snapshot_includes_vpn_servers(self):
        srv_id = str(uuid.uuid4())
        s = _settings(vpn_servers=[_srv(id_=srv_id)])
        m.SETTINGS.write_text(json.dumps(s, indent=2))
        snap_id = m.create_snapshot("test")
        snap    = json.loads(m._snap_path(snap_id).read_text())
        assert len(snap["settings"].get("vpn_servers", [])) == 1

    def test_snapshot_includes_devices(self):
        s = _settings(devices={"aa:bb:cc:00:00:ff": {"name":"TV","policy":"always_direct","ips":[]}})
        m.SETTINGS.write_text(json.dumps(s, indent=2))
        snap_id = m.create_snapshot("devices_test")
        snap    = json.loads(m._snap_path(snap_id).read_text())
        assert "aa:bb:cc:00:00:ff" in snap["settings"].get("devices", {})

    def test_restore_brings_back_device_policies(self):
        s = _settings(devices={"aa:bb:cc:00:00:ff": {"name":"TV","policy":"always_vpn","ips":[]}})
        m.SETTINGS.write_text(json.dumps(s, indent=2))
        snap_id = m.create_snapshot("before_change")
        # Change policy
        s2 = _settings(devices={"aa:bb:cc:00:00:ff": {"name":"TV","policy":"inherit","ips":[]}})
        m.SETTINGS.write_text(json.dumps(s2, indent=2))
        # Restore
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="active\n", stderr="")
            ok, _ = m.restore_snapshot(snap_id)
        assert ok
        restored = json.loads(m.SETTINGS.read_text())
        assert restored["devices"]["aa:bb:cc:00:00:ff"]["policy"] == "always_vpn"
