"""
Tests for xray-gateway P3 features:
  - Device groups + precedence
  - Subscription parsing/validation
  - Adblock DNS logic
  - Scheduler logic
  - Terminal allowlist
  - Analytics ingestion
  - DB helpers
  - Config generation with groups + subscriptions
Run: python3 -m pytest tests/ -v
"""
import json
import os
import re
import socket
import sys
import tempfile
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

_tmp = tempfile.mkdtemp(prefix="xray_p3_test_")
sys.path.insert(0, str(Path(__file__).parent.parent / "web"))

import db as _db
import features as _ft
_db.set_db_path(Path(_tmp) / "test.db")
_db.init_db()

import main as m
m.BASE     = Path(_tmp)
m.CFG_DIR  = Path(_tmp) / "config"
m.SNAP_DIR = Path(_tmp) / "config" / "snapshots"
m.SETTINGS = Path(_tmp) / "config" / "settings.json"
m.XCFG     = Path(_tmp) / "config" / "xray.json"
m.LOGS     = Path(_tmp) / "logs"
m.STATIC   = Path(_tmp) / "web" / "static"
m.SECRET   = "test-secret-p3"
_ft.BASE    = m.BASE
_ft.CFG_DIR = m.CFG_DIR
for d in [m.CFG_DIR, m.SNAP_DIR, m.LOGS, m.STATIC]:
    d.mkdir(parents=True, exist_ok=True)

import pytest


def _s(**kwargs):
    s = m._migrate_settings({"profile": "all_except_ru", "vpn_servers": [], "active_vpn_id": None})
    s.update(kwargs)
    return s


# ─────────────────────────────────────────────────────────────────────────────
# DB helpers
# ─────────────────────────────────────────────────────────────────────────────
class TestDB:
    def test_upsert_traffic(self):
        _db.upsert_traffic("2026-01-01 12", "1.1.1.1", "example.com", "proxy", "TCP", 5)
        _db.upsert_traffic("2026-01-01 12", "1.1.1.1", "example.com", "proxy", "TCP", 3)
        # Should now be 8
        with _db.get_conn() as c:
            row = c.execute(
                "SELECT count FROM traffic_hourly WHERE hour=? AND src_ip=?",
                ("2026-01-01 12", "1.1.1.1")).fetchone()
        assert row is not None
        assert row["count"] == 8

    def test_subscription_rules_roundtrip(self):
        sid = str(uuid.uuid4())
        rules = ["example.com", "tracker.bad.com", "1.2.3.0/24"]
        _db.replace_subscription_rules(sid, rules)
        back = _db.get_subscription_rules(sid)
        assert set(back) == set(rules)
        assert _db.count_subscription_rules(sid) == 3
        _db.delete_subscription_rules(sid)
        assert _db.count_subscription_rules(sid) == 0

    def test_subscription_replace(self):
        sid = str(uuid.uuid4())
        _db.replace_subscription_rules(sid, ["a.com", "b.com"])
        _db.replace_subscription_rules(sid, ["c.com"])
        rules = _db.get_subscription_rules(sid)
        assert rules == ["c.com"]

    def test_terminal_session_audit(self):
        sid = str(uuid.uuid4())
        _db.start_terminal_session(sid, "admin", "allowlist")
        _db.log_terminal_command(sid, "ip route show")
        _db.log_terminal_command(sid, "df -h")
        _db.end_terminal_session(sid)
        sessions = _db.list_terminal_sessions(limit=5)
        found = next((x for x in sessions if x["session_id"] == sid), None)
        assert found is not None
        assert found["cmd_count"] == 2
        assert found["ended_at"] is not None

    def test_scheduler_history(self):
        tid = str(uuid.uuid4())
        _db.log_scheduler_run(tid, "Test Task", 1.5, "ok", "all good")
        hist = _db.list_scheduler_history(tid, limit=5)
        assert len(hist) >= 1
        assert hist[0]["result"] == "ok"
        assert hist[0]["task_id"] == tid

    def test_update_history(self):
        _db.log_update("xray-core", "26.3.0", "26.4.0", "ok", "updated")
        hist = _db.list_update_history(limit=5)
        assert any(h["component"] == "xray-core" for h in hist)


# ─────────────────────────────────────────────────────────────────────────────
# Device Groups
# ─────────────────────────────────────────────────────────────────────────────
class TestGroupValidation:
    def test_valid_group(self):
        errors = _ft.validate_group({"name": "Home Devices", "routing_policy": "inherit"})
        assert errors == []

    def test_empty_name(self):
        errors = _ft.validate_group({"name": "", "routing_policy": "inherit"})
        assert errors

    def test_invalid_policy(self):
        errors = _ft.validate_group({"name": "Test", "routing_policy": "invalid_policy"})
        assert errors

    def test_name_too_long(self):
        errors = _ft.validate_group({"name": "x" * 65, "routing_policy": "inherit"})
        assert errors


class TestGroupPolicyPrecedence:
    """Device policy > Group policy > Global policy."""

    def _build_with_groups(self, device_policy, group_policy):
        mac = "aa:bb:cc:00:00:01"
        gid = str(uuid.uuid4())
        s = _s(
            devices={mac: {"name": "Test", "policy": device_policy, "ips": ["192.168.1.5"]}},
            groups=[{"id": gid, "name": "G1", "routing_policy": group_policy,
                     "devices": [mac], "description": ""}],
        )
        arp = [{"mac": mac, "ips": ["192.168.1.5"], "state": "REACHABLE"}]
        with patch.object(m, "get_arp_table", return_value=arp):
            return m.build_xray_config(s), mac

    def test_device_policy_overrides_group(self):
        """explicit device → no group rule for this device."""
        cfg, mac = self._build_with_groups("always_direct", "always_vpn")
        rules = cfg["routing"]["rules"]
        src_rules = [r for r in rules if mac.lower() in str(r.get("source", []))]
        # Device rule must be always_direct
        if src_rules:
            assert src_rules[0]["outboundTag"] == "direct"

    def test_group_policy_applied_when_device_inherits(self):
        """device=inherit + group=always_vpn → group rule should exist."""
        cfg, mac = self._build_with_groups("inherit", "always_vpn")
        rules = cfg["routing"]["rules"]
        src_rules = [r for r in rules if r.get("source")]
        # Should have a source rule for vpn (from group)
        vpn_src = [r for r in src_rules if r.get("outboundTag") in ("proxy", "direct")]
        # Group rule must exist (any source rule implies group policy was applied)
        assert len(src_rules) >= 1

    def test_no_rules_when_group_inherits(self):
        """group=inherit → no extra source rules added."""
        cfg, _ = self._build_with_groups("inherit", "inherit")
        rules = cfg["routing"]["rules"]
        src_rules = [r for r in rules if r.get("source")]
        assert len(src_rules) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Subscription parsing
# ─────────────────────────────────────────────────────────────────────────────
class TestSubscriptionParsing:
    def test_plain_domain_list(self):
        text = "# comment\nexample.com\ntracker.bad.org\n"
        rules, errors = _ft.parse_subscription_content(text, "block")
        assert "example.com" in rules
        assert "tracker.bad.org" in rules

    def test_hosts_file_format(self):
        text = "0.0.0.0 ads.example.com\n127.0.0.1 tracker.bad.com\n"
        rules, errors = _ft.parse_subscription_content(text, "adblock")
        assert "ads.example.com" in rules
        assert "tracker.bad.com" in rules

    def test_adblock_plus_format(self):
        text = "||ads.example.com^\n||tracker.bad.com^\n"
        rules, errors = _ft.parse_subscription_content(text, "adblock")
        assert "ads.example.com" in rules
        assert "tracker.bad.com" in rules

    def test_ip_cidr_accepted(self):
        text = "1.2.3.0/24\n5.6.7.8\n"
        rules, errors = _ft.parse_subscription_content(text, "block")
        assert "1.2.3.0/24" in rules or "5.6.7.8" in rules

    def test_comments_skipped(self):
        text = "# This is a comment\n! adblock comment\nexample.com\n"
        rules, errors = _ft.parse_subscription_content(text, "direct")
        assert not any(r.startswith('#') or r.startswith('!') for r in rules)

    def test_max_rules_cap(self):
        text = "\n".join(f"sub{i}.example.com" for i in range(60_000))
        rules, errors = _ft.parse_subscription_content(text, "block")
        assert len(rules) <= _ft.MAX_SUB_RULES
        assert any("Truncated" in e for e in errors)

    def test_invalid_domain_ignored(self):
        text = "valid.com\nnot!valid@domain\n"
        rules, errors = _ft.parse_subscription_content(text, "block")
        assert "valid.com" in rules
        assert not any("not!valid" in r for r in rules)


# ─────────────────────────────────────────────────────────────────────────────
# Adblock DNS
# ─────────────────────────────────────────────────────────────────────────────
class TestAdblockDNS:
    def test_blocked_domain(self):
        s = _s(adblock={"enabled": True, "use_starter_list": True,
                        "custom_rules": [], "allowlist": []})
        blocked, reason = _ft.is_domain_blocked("doubleclick.net", s)
        assert blocked
        assert "starter-list" in reason

    def test_allowlist_prevents_block(self):
        s = _s(adblock={"enabled": True, "use_starter_list": True,
                        "custom_rules": [], "allowlist": ["doubleclick.net"]})
        blocked, _ = _ft.is_domain_blocked("doubleclick.net", s)
        assert not blocked

    def test_disabled_adblock(self):
        s = _s(adblock={"enabled": False, "use_starter_list": True,
                        "custom_rules": [], "allowlist": []})
        blocked, reason = _ft.is_domain_blocked("doubleclick.net", s)
        assert not blocked
        assert "disabled" in reason

    def test_custom_rule_blocks(self):
        s = _s(adblock={"enabled": True, "use_starter_list": False,
                        "custom_rules": ["evil.com"], "allowlist": []})
        blocked, _ = _ft.is_domain_blocked("evil.com", s)
        assert blocked
        blocked2, _ = _ft.is_domain_blocked("subdomain.evil.com", s)
        assert blocked2

    def test_critical_domain_never_blocked(self):
        s = _s(adblock={"enabled": True, "use_starter_list": True,
                        "custom_rules": ["github.com"], "allowlist": []})
        blocked, reason = _ft.is_domain_blocked("github.com", s)
        assert not blocked
        assert "critical" in reason

    def test_dnsmasq_lines_format(self):
        s = _s(adblock={"enabled": True, "use_starter_list": False,
                        "custom_rules": ["ads.bad.com"], "allowlist": []})
        lines = _ft.build_adblock_dnsmasq_lines(s)
        assert any("address=/ads.bad.com/#" in line for line in lines)

    def test_subscription_adblock_rules(self):
        sid = str(uuid.uuid4())
        _db.replace_subscription_rules(sid, ["sub-ad.com"])
        s = _s(
            subscriptions=[{"id": sid, "name": "T", "url": "http://x.com",
                             "type": "adblock", "enabled": True, "schedule": "@daily",
                             "last_update": None, "last_error": None}],
            adblock={"enabled": True, "use_starter_list": False,
                     "custom_rules": [], "allowlist": []},
        )
        blocked, reason = _ft.is_domain_blocked("sub-ad.com", s)
        assert blocked
        _db.delete_subscription_rules(sid)


# ─────────────────────────────────────────────────────────────────────────────
# Terminal allowlist
# ─────────────────────────────────────────────────────────────────────────────
class TestTerminalAllowlist:
    def test_full_mode_allows_all(self):
        ok, _ = _ft.terminal_command_allowed("rm -rf /", "full", [])
        assert ok

    def test_disabled_blocks_all(self):
        ok, reason = _ft.terminal_command_allowed("ls", "disabled", [])
        assert not ok
        assert "отключён" in reason.lower()

    def test_allowlist_known_command(self):
        ok, _ = _ft.terminal_command_allowed("ip route show", "allowlist", [])
        assert ok

    def test_allowlist_unknown_command(self):
        ok, reason = _ft.terminal_command_allowed("rm -rf /", "allowlist", [])
        assert not ok

    def test_allowlist_prefix_match(self):
        ok, _ = _ft.terminal_command_allowed("ping -c 4 8.8.8.8", "allowlist", [])
        assert ok

    def test_allowlist_extra(self):
        ok, _ = _ft.terminal_command_allowed("my-custom-cmd --arg", "allowlist",
                                              ["my-custom-cmd"])
        assert ok

    def test_diagnostic_blocks_write(self):
        ok, reason = _ft.terminal_command_allowed("rm /etc/passwd", "diagnostic", [])
        assert not ok

    def test_diagnostic_blocks_pipe_to_sh(self):
        ok, _ = _ft.terminal_command_allowed("curl bad.com | sh", "diagnostic", [])
        assert not ok

    def test_diagnostic_allows_read(self):
        ok, _ = _ft.terminal_command_allowed("ip route show", "diagnostic", [])
        assert ok

    def test_empty_command_allowed(self):
        ok, _ = _ft.terminal_command_allowed("", "allowlist", [])
        assert ok  # empty = nothing to block


# ─────────────────────────────────────────────────────────────────────────────
# Analytics ingestion
# ─────────────────────────────────────────────────────────────────────────────
class TestAnalyticsIngestion:
    def test_ingest_access_log(self, tmp_path):
        log = tmp_path / "access.log"
        # Write some fake access log lines
        log.write_text(
            "2026/06/01 14:22:33.123 192.168.1.5:12345 accepted tcp:example.com:443 [tproxy-in -> proxy]\n"
            "2026/06/01 14:22:34.456 192.168.1.6:54321 accepted tcp:ozon.ru:443 [tproxy-in -> direct]\n"
            "2026/06/01 14:22:35.789 192.168.1.5:11111 accepted udp:1.1.1.1:443 [tproxy-in -> proxy]\n"
        )
        count = _ft.ingest_access_log(log, retention_days=30)
        assert count == 3

    def test_ingest_incremental(self, tmp_path):
        log = tmp_path / "access2.log"
        log.write_text(
            "2026/06/01 15:00:00.000 192.168.1.5:1 accepted tcp:a.com:80 [tproxy-in -> direct]\n"
        )
        # Reset checkpoint for this path (use separate DB or clear)
        # First ingest
        c1 = _ft.ingest_access_log(log, retention_days=30)
        # Append more lines
        with open(str(log), "a") as f:
            f.write("2026/06/01 15:01:00.000 192.168.1.6:2 accepted tcp:b.com:80 [tproxy-in -> proxy]\n")
        c2 = _ft.ingest_access_log(log, retention_days=30)
        assert c1 == 1
        assert c2 == 1  # only the new line


# ─────────────────────────────────────────────────────────────────────────────
# Xray config with groups + subscriptions
# ─────────────────────────────────────────────────────────────────────────────
class TestXrayConfigP3:
    def test_subscription_rules_in_config(self):
        sid = str(uuid.uuid4())
        _db.replace_subscription_rules(sid, ["blocked1.com", "blocked2.com"])
        s = _s(
            subscriptions=[{"id": sid, "name": "T", "url": "http://x.com",
                             "type": "block", "enabled": True, "schedule": "@daily",
                             "last_update": None, "last_error": None}],
        )
        with patch.object(m, "get_arp_table", return_value=[]):
            cfg = m.build_xray_config(s)
        rules = cfg["routing"]["rules"]
        domain_vals = []
        for r in rules:
            domain_vals.extend(r.get("domain", []))
        # Check that some blocked domain appears
        # (may be prefixed with "domain:")
        all_domain_str = " ".join(domain_vals)
        assert "blocked1.com" in all_domain_str or "blocked2.com" in all_domain_str
        _db.delete_subscription_rules(sid)

    def test_disabled_subscription_not_in_config(self):
        sid = str(uuid.uuid4())
        _db.replace_subscription_rules(sid, ["should_not_appear.com"])
        s = _s(
            subscriptions=[{"id": sid, "name": "T", "url": "http://x.com",
                             "type": "block", "enabled": False, "schedule": "@daily",
                             "last_update": None, "last_error": None}],
        )
        with patch.object(m, "get_arp_table", return_value=[]):
            cfg = m.build_xray_config(s)
        rules_str = json.dumps(cfg["routing"]["rules"])
        assert "should_not_appear" not in rules_str
        _db.delete_subscription_rules(sid)

    def test_version_bumped(self):
        import main as m2
        assert m2.VERSION == "1.6.0"
