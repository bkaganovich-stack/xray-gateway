"""
Tests for xray-gateway routing logic, custom rules, snapshots, and config builder.
Run:  python -m pytest tests/ -v
"""
import ipaddress
import json
import socket
import sys
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

# ── Bootstrap: point BASE to a temp dir so we don't need /opt/xray-proxy ────
import importlib

# We need to set up a fake BASE before importing main
_tmp_base = tempfile.mkdtemp(prefix="xray_test_")
os.environ["_TEST_BASE"] = _tmp_base

# Patch the paths before import
import types

# Create necessary dirs/files in temp base
for d in ["config", "config/snapshots", "logs", "web/static", "bin", "scripts"]:
    Path(_tmp_base, d).mkdir(parents=True, exist_ok=True)

# Minimal .secret
Path(_tmp_base, ".secret").write_text("test-secret-key-for-unit-tests")

# Add web/ to path so we can import main
sys.path.insert(0, str(Path(__file__).parent.parent / "web"))

# Patch BASE before importing
import builtins
_real_import = builtins.__import__

# Import main, overriding BASE
import main as m

# Override BASE to temp dir for tests
m.BASE     = Path(_tmp_base)
m.CFG_DIR  = Path(_tmp_base) / "config"
m.SNAP_DIR = Path(_tmp_base) / "config" / "snapshots"
m.SETTINGS = Path(_tmp_base) / "config" / "settings.json"
m.XCFG     = Path(_tmp_base) / "config" / "xray.json"
m.LOGS     = Path(_tmp_base) / "logs"
m.STATIC   = Path(_tmp_base) / "web" / "static"
m.SECRET   = "test-secret-key-for-unit-tests"

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Tests: validate_custom_rule
# ─────────────────────────────────────────────────────────────────────────────
class TestValidateCustomRule:
    def test_domain_prefix_valid(self):
        ok, err = m.validate_custom_rule("domain:example.com")
        assert ok, err

    def test_full_prefix_valid(self):
        ok, err = m.validate_custom_rule("full:example.com")
        assert ok, err

    def test_keyword_prefix_valid(self):
        ok, err = m.validate_custom_rule("keyword:google")
        assert ok, err

    def test_regexp_valid(self):
        ok, err = m.validate_custom_rule(r"regexp:^.*\.google\.com$")
        assert ok, err

    def test_regexp_invalid(self):
        ok, err = m.validate_custom_rule("regexp:[invalid")
        assert not ok
        assert "regexp" in err.lower()

    def test_ipv4_valid(self):
        ok, err = m.validate_custom_rule("1.2.3.4")
        assert ok, err

    def test_cidr_valid(self):
        ok, err = m.validate_custom_rule("192.168.1.0/24")
        assert ok, err

    def test_ipv6_cidr_valid(self):
        ok, err = m.validate_custom_rule("2001:db8::/32")
        assert ok, err

    def test_bare_domain_valid(self):
        ok, err = m.validate_custom_rule("yandex.ru")
        assert ok, err

    def test_empty_invalid(self):
        ok, err = m.validate_custom_rule("")
        assert not ok

    def test_garbage_invalid(self):
        ok, err = m.validate_custom_rule("not a domain!@#$%")
        assert not ok

    def test_domain_empty_value_invalid(self):
        ok, err = m.validate_custom_rule("domain:")
        assert not ok

# ─────────────────────────────────────────────────────────────────────────────
# Tests: _custom_rule_to_xray
# ─────────────────────────────────────────────────────────────────────────────
class TestCustomRuleToXray:
    def test_domain_prefix(self):
        kind, val = m._custom_rule_to_xray("domain:example.com")
        assert kind == "domain"
        assert val == "domain:example.com"

    def test_ip(self):
        kind, val = m._custom_rule_to_xray("1.2.3.4")
        assert kind == "ip"
        assert "1.2.3.4" in val

    def test_cidr(self):
        kind, val = m._custom_rule_to_xray("10.0.0.0/8")
        assert kind == "ip"
        assert "10.0.0.0/8" in val

    def test_bare_domain(self):
        kind, val = m._custom_rule_to_xray("ozon.ru")
        assert kind == "domain"
        assert val == "domain:ozon.ru"

# ─────────────────────────────────────────────────────────────────────────────
# Tests: build_xray_config
# ─────────────────────────────────────────────────────────────────────────────
class TestBuildXrayConfig:
    def _base_settings(self, **kwargs) -> dict:
        s = dict(m.DEFAULT_SETTINGS)
        s.update(kwargs)
        return s

    def test_all_except_ru_has_geoip_rule(self):
        cfg = m.build_xray_config(self._base_settings(profile="all_except_ru"))
        rules = cfg["routing"]["rules"]
        geoip_rules = [r for r in rules if "geoip:ru" in r.get("ip", [])]
        assert geoip_rules, "Should have geoip:ru direct rule"
        assert geoip_rules[0]["outboundTag"] == "direct"

    def test_all_except_ru_catch_all_is_direct_without_vpn(self):
        cfg = m.build_xray_config(self._base_settings(profile="all_except_ru", vpn_key=None))
        last = cfg["routing"]["rules"][-1]
        assert last["outboundTag"] == "direct"

    def test_custom_rules_injected_before_geoip(self):
        settings = self._base_settings(
            profile="all_except_ru",
            custom_rules={"always_direct": ["domain:mysite.ru"], "always_vpn": []}
        )
        cfg = m.build_xray_config(settings)
        rules = cfg["routing"]["rules"]
        # Find index of custom rule and geoip:ru rule
        custom_idx = next((i for i, r in enumerate(rules)
                           if "domain:mysite.ru" in r.get("domain", [])), -1)
        geoip_idx  = next((i for i, r in enumerate(rules)
                           if "geoip:ru" in r.get("ip", [])), -1)
        assert custom_idx != -1, "Custom rule not found in config"
        assert geoip_idx  != -1, "geoip:ru rule not found in config"
        assert custom_idx < geoip_idx, "Custom rule must precede geoip:ru"

    def test_custom_vpn_rules_injected(self):
        settings = self._base_settings(
            profile="all_except_ru",
            custom_rules={"always_direct": [], "always_vpn": ["192.168.5.0/24"]}
        )
        cfg = m.build_xray_config(settings)
        rules = cfg["routing"]["rules"]
        vpn_ip_rules = [r for r in rules
                        if "192.168.5.0/24" in r.get("ip", []) and r.get("outboundTag") in ("proxy", "direct")]
        assert vpn_ip_rules, "Custom VPN IP rule not found"

    def test_blocked_only_profile(self):
        cfg = m.build_xray_config(self._base_settings(profile="blocked_only"))
        rules = cfg["routing"]["rules"]
        blocked_rules = [r for r in rules
                         if "geosite:category-ru-blocked" in r.get("domain", [])]
        assert blocked_rules

    def test_quic_sniffing_enabled(self):
        cfg = m.build_xray_config(self._base_settings())
        sniff = cfg["inbounds"][0]["sniffing"]
        assert "quic" in sniff["destOverride"]

    def test_no_vpn_key_direct_outbound_exists(self):
        cfg = m.build_xray_config(self._base_settings(vpn_key=None))
        tags = [ob["tag"] for ob in cfg["outbounds"]]
        assert "direct" in tags
        assert "proxy" not in tags

# ─────────────────────────────────────────────────────────────────────────────
# Tests: route_test (with mocked geo databases)
# ─────────────────────────────────────────────────────────────────────────────
class TestRouteTester:
    def _settings(self, **kwargs) -> dict:
        s = dict(m.DEFAULT_SETTINGS)
        s["vpn_key"] = None  # no VPN by default → final="direct"
        s.update(kwargs)
        return s

    def test_private_ip_direct(self):
        result = m.route_test("192.168.1.1", self._settings())
        assert result["outbound"] == "direct"
        assert "private" in result["matched_rule"]

    def test_private_ip_127(self):
        result = m.route_test("127.0.0.1", self._settings())
        assert result["outbound"] == "direct"

    def test_private_domain_localhost(self):
        result = m.route_test("localhost", self._settings())
        assert result["outbound"] == "direct"

    def test_custom_always_direct_domain(self):
        settings = self._settings(
            custom_rules={"always_direct": ["domain:mybank.ru"], "always_vpn": []}
        )
        result = m.route_test("mybank.ru", settings)
        assert result["outbound"] == "direct"
        assert "custom" in result["matched_rule"]

    def test_custom_always_direct_cidr(self):
        # Use a non-private IP range so private rule doesn't fire first
        settings = self._settings(
            custom_rules={"always_direct": ["203.0.113.0/24"], "always_vpn": []}
        )
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("no dns")), \
             patch.object(m, "_ip_in_geoip_ru", return_value=False), \
             patch.object(m, "_domain_in_geosite_ru", return_value=False):
            result = m.route_test("203.0.113.5", settings)
        assert result["outbound"] == "direct"
        assert "custom" in result["matched_rule"]

    def test_custom_always_vpn_overrides(self):
        # Even in all_except_ru, a custom_vpn rule sends to proxy/direct(no-vpn)
        settings = self._settings(
            vpn_key=None,  # no VPN, so "final" = "direct"
            custom_rules={"always_direct": [], "always_vpn": ["domain:leak.com"]}
        )
        # With no VPN key, "final"="direct", so custom_vpn still goes "direct"
        result = m.route_test("leak.com", settings)
        assert "custom:always_vpn" in result["matched_rule"]

    def test_apple_cdn_with_force_vpn(self):
        settings = self._settings(
            profile="all_except_ru",
            force_aaplimg_vpn=True,
        )
        result = m.route_test("osxapps.itunes.apple.com", settings)
        assert "apple-cdn" in result["matched_rule"]

    def test_apple_cdn_without_force_vpn(self):
        settings = self._settings(
            profile="all_except_ru",
            force_aaplimg_vpn=False,
        )
        # Should NOT match apple CDN override
        result = m.route_test("osxapps.itunes.apple.com", settings)
        assert "apple-cdn" not in result["matched_rule"]

    def test_geoip_ru_mock(self):
        """Verify that an IP in geoip:ru goes direct."""
        with patch.object(m, "_ip_in_geoip_ru", return_value=True), \
             patch.object(m, "_domain_in_geosite_ru", return_value=False):
            result = m.route_test("1.2.3.4", self._settings())
        assert result["outbound"] == "direct"
        assert "geoip:ru" in result["matched_rule"]

    def test_geosite_ru_mock(self):
        """Verify that a domain in geosite:category-ru goes direct."""
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("no DNS")), \
             patch.object(m, "_ip_in_geoip_ru", return_value=False), \
             patch.object(m, "_domain_in_geosite_ru", return_value=True):
            result = m.route_test("vk.com", self._settings())
        assert result["outbound"] == "direct"
        assert "geosite:category-ru" in result["matched_rule"]

    def test_unknown_domain_catch_all_no_vpn(self):
        """Unknown domain without VPN → default route of profile."""
        settings = self._settings(profile="all_except_ru", vpn_key=None)
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("no DNS")), \
             patch.object(m, "_ip_in_geoip_ru", return_value=False), \
             patch.object(m, "_domain_in_geosite_ru", return_value=False):
            result = m.route_test("unknowndomain.xyz", settings)
        # no VPN → final = "direct" → catch-all for all_except_ru
        assert result["outbound"] == "direct"
        assert "catch-all" in result["matched_rule"]

    def test_profile_all_sends_everything_to_final(self):
        settings = self._settings(profile="all", vpn_key=None)
        result = m.route_test("google.com", settings)
        assert result["matched_rule"] == "catch-all"

    def test_invalid_target(self):
        result = m.route_test("not a domain!#$", self._settings())
        assert result.get("error") is not None

# ─────────────────────────────────────────────────────────────────────────────
# Tests: Snapshot management
# ─────────────────────────────────────────────────────────────────────────────
class TestSnapshots:
    def setup_method(self):
        # Clean snapshots dir before each test
        snap_dir = m.SNAP_DIR
        snap_dir.mkdir(parents=True, exist_ok=True)
        for f in snap_dir.glob("snap_*.json"):
            f.unlink()
        # Write a minimal settings.json and xray.json
        m.CFG_DIR.mkdir(parents=True, exist_ok=True)
        m.SETTINGS.write_text(json.dumps(m.DEFAULT_SETTINGS, indent=2))
        m.XCFG.write_text(json.dumps({"test": "config"}, indent=2))

    def test_create_snapshot_returns_id(self):
        snap_id = m.create_snapshot("test_reason")
        assert re.match(r'^\d{8}_\d{6}$', snap_id)

    def test_create_snapshot_file_exists(self):
        snap_id = m.create_snapshot("test_reason")
        assert m._snap_path(snap_id).exists()

    def test_list_snapshots_empty(self):
        snaps = m.list_snapshots()
        assert isinstance(snaps, list)

    def test_list_snapshots_after_create(self):
        import time as _t
        m.create_snapshot("reason_a")
        _t.sleep(1.05)  # ensure different second → unique snap_id
        m.create_snapshot("reason_b")
        snaps = m.list_snapshots()
        assert len(snaps) == 2
        assert snaps[0]["reason"] == "reason_b"  # most recent first

    def test_snapshot_contains_expected_fields(self):
        snap_id = m.create_snapshot("unit_test")
        snap = json.loads(m._snap_path(snap_id).read_text())
        assert "id" in snap
        assert "timestamp" in snap
        assert "reason" in snap
        assert "settings" in snap
        assert "xray_config" in snap

    def test_rotate_keeps_max_snapshots(self):
        for i in range(m.MAX_SNAPSHOTS + 3):
            m.create_snapshot(f"snap_{i}")
            import time as _t; _t.sleep(0.01)  # ensure unique timestamps
        snaps = m.list_snapshots()
        assert len(snaps) <= m.MAX_SNAPSHOTS

    def test_restore_snapshot_updates_settings(self):
        # Create snapshot of known state
        settings = dict(m.DEFAULT_SETTINGS)
        settings["profile"] = "blocked_only"
        m.SETTINGS.write_text(json.dumps(settings, indent=2))
        snap_id = m.create_snapshot("test_restore")
        # Change settings
        settings["profile"] = "all"
        m.SETTINGS.write_text(json.dumps(settings, indent=2))
        # Restore
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="active\n", stderr="")
            ok, msg = m.restore_snapshot(snap_id)
        assert ok, msg
        restored = json.loads(m.SETTINGS.read_text())
        assert restored["profile"] == "blocked_only"

    def test_restore_nonexistent_snapshot(self):
        ok, msg = m.restore_snapshot("99991231_235959")
        assert not ok
        assert "not found" in msg

    def test_delete_snapshot(self):
        snap_id = m.create_snapshot("delete_me")
        assert m._snap_path(snap_id).exists()
        m._snap_path(snap_id).unlink()
        assert not m._snap_path(snap_id).exists()

# ─────────────────────────────────────────────────────────────────────────────
# Tests: apply_config_safe auto-rollback
# ─────────────────────────────────────────────────────────────────────────────
class TestApplyConfigSafe:
    def setup_method(self):
        m.CFG_DIR.mkdir(parents=True, exist_ok=True)
        m.SNAP_DIR.mkdir(parents=True, exist_ok=True)
        m.SETTINGS.write_text(json.dumps(m.DEFAULT_SETTINGS, indent=2))
        m.XCFG.write_text(json.dumps({"orig": True}, indent=2))
        for f in m.SNAP_DIR.glob("snap_*.json"):
            f.unlink()

    def test_successful_apply(self):
        call_count = [0]
        def fake_run(cmd, **kw):
            r = MagicMock()
            if cmd[0] == "systemctl" and cmd[1] == "is-active":
                r.stdout = "active\n"; r.returncode = 0
            else:
                r.returncode = 0; r.stdout = ""; r.stderr = ""
            call_count[0] += 1
            return r
        with patch("subprocess.run", side_effect=fake_run), \
             patch("time.sleep"):
            ok, err = m.apply_config(m.DEFAULT_SETTINGS, "test")
        assert ok
        assert err == ""

    def test_auto_rollback_on_failure(self):
        """If xray never becomes active, should auto-rollback."""
        m.XCFG.write_text(json.dumps({"original": "config"}, indent=2))

        def fake_run(cmd, **kw):
            r = MagicMock()
            if cmd[0] == "systemctl" and cmd[1] == "is-active":
                r.stdout = "failed\n"; r.returncode = 1
            else:
                r.returncode = 0; r.stdout = "active\n"; r.stderr = ""
            return r

        with patch("subprocess.run", side_effect=fake_run), \
             patch("time.sleep"):
            ok, err = m.apply_config(m.DEFAULT_SETTINGS, "test_rollback")
        assert not ok
        assert "rollback" in err.lower()

# ─────────────────────────────────────────────────────────────────────────────
# Tests: VPN key parsing
# ─────────────────────────────────────────────────────────────────────────────
class TestKeyParsing:
    def test_parse_ss_with_at(self):
        uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@1.2.3.4:1234#Test"
        ob, info = m.parse_key(uri)
        assert ob["protocol"] == "shadowsocks"
        assert info["server"] == "1.2.3.4"
        assert info["port"] == 1234
        assert info["name"] == "Test"

    def test_parse_unknown_protocol(self):
        import pytest
        with pytest.raises(ValueError):
            m.parse_key("https://example.com")

# ─────────────────────────────────────────────────────────────────────────────
# Tests: _varint protobuf helper
# ─────────────────────────────────────────────────────────────────────────────
class TestVarint:
    def test_single_byte(self):
        val, pos = m._varint(b'\x01', 0)
        assert val == 1; assert pos == 1

    def test_multibyte(self):
        # 300 = 0b100101100 → 0xAC 0x02
        val, pos = m._varint(b'\xac\x02', 0)
        assert val == 300; assert pos == 2

    def test_zero(self):
        val, pos = m._varint(b'\x00', 0)
        assert val == 0

import re  # needed for snapshot ID pattern checks
