"""Enrichment: offline GeoIP/ASN (MaxMind GeoLite2), optional AbuseIPDB, optional MalwareBazaar hash lookup.

* GeoLite2 is read from local ``.mmdb`` files only - nothing is sent anywhere.
* AbuseIPDB (off by default) sends one attacker IP per request; a daily budget is enforced.
* MalwareBazaar (off by default) sends **only the SHA-256 hash** of a sample - the file is never uploaded.
* In test mode, documentation-range IPs get deterministic synthetic locations so the map has something to show.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..common.config import Settings
from ..common.netutil import is_public, is_test_net
from .db import DB

log = logging.getLogger("honeynet.enrich")

SIM_PLACES = [
    ("CN", "China", "Beijing", 39.90, 116.40, 4134, "Chinanet"), ("US", "United States", "Ashburn", 39.04, -77.49, 14061, "DigitalOcean"),
    ("RU", "Russia", "Moscow", 55.75, 37.62, 12389, "Rostelecom"), ("BR", "Brazil", "Sao Paulo", -23.55, -46.63, 18881, "Vivo"),
    ("IN", "India", "Mumbai", 19.07, 72.88, 55836, "Reliance Jio"), ("DE", "Germany", "Frankfurt", 50.11, 8.68, 24940, "Hetzner"),
    ("VN", "Vietnam", "Hanoi", 21.03, 105.85, 45899, "VNPT"), ("KR", "South Korea", "Seoul", 37.57, 126.98, 4766, "Korea Telecom"),
    ("NL", "Netherlands", "Amsterdam", 52.37, 4.90, 49981, "WorldStream"), ("ID", "Indonesia", "Jakarta", -6.21, 106.85, 7713, "Telkom"),
    ("IR", "Iran", "Tehran", 35.69, 51.39, 58224, "Iran Telecom"), ("UA", "Ukraine", "Kyiv", 50.45, 30.52, 15895, "Kyivstar"),
    ("TR", "Turkey", "Istanbul", 41.01, 28.98, 9121, "Turk Telekom"), ("EG", "Egypt", "Cairo", 30.04, 31.24, 8452, "TE Data"),
    ("MX", "Mexico", "Mexico City", 19.43, -99.13, 8151, "Uninet"), ("AR", "Argentina", "Buenos Aires", -34.60, -58.38, 7303, "Telecom Argentina"),
    ("ZA", "South Africa", "Johannesburg", -26.20, 28.05, 37457, "Telkom SA"), ("SG", "Singapore", "Singapore", 1.35, 103.82, 16509, "Amazon AWS"),
    ("JP", "Japan", "Tokyo", 35.68, 139.65, 2516, "KDDI"), ("FR", "France", "Paris", 48.86, 2.35, 16276, "OVH"),
    ("GB", "United Kingdom", "London", 51.51, -0.13, 8075, "Microsoft"), ("TW", "Taiwan", "Taipei", 25.03, 121.57, 3462, "HiNet"),
    ("TH", "Thailand", "Bangkok", 13.76, 100.50, 23969, "TOT"), ("PK", "Pakistan", "Karachi", 24.86, 67.01, 17557, "PTCL"),
    ("AU", "Australia", "Sydney", -33.87, 151.21, 1221, "Telstra"), ("CA", "Canada", "Toronto", 43.65, -79.38, 577, "Bell Canada"),
]
DB_NAMES = {
    "city": ("GeoLite2-City.mmdb", "GeoIP2-City.mmdb", "dbip-city-lite.mmdb", "dbip-city.mmdb"),
    "country": ("GeoLite2-Country.mmdb", "GeoIP2-Country.mmdb", "dbip-country-lite.mmdb"),
    "asn": ("GeoLite2-ASN.mmdb", "GeoIP2-ISP.mmdb", "dbip-asn-lite.mmdb"),
}


def sim_geo(ip: str) -> dict[str, Any]:
    h = int.from_bytes(hashlib.sha256(ip.encode()).digest()[:8], "big")
    c, name, city, lat, lon, asn, org = SIM_PLACES[h % len(SIM_PLACES)]
    jitter = ((h >> 8) % 400 - 200) / 100.0
    return {"country": c, "country_name": name, "city": city, "lat": round(lat + jitter / 2, 3), "lon": round(lon + jitter, 3),
            "asn": asn + (h >> 20) % 3, "org": org, "simulated": True}


class GeoResolver:
    def __init__(self, geoip_dir: Path | None, test_mode: bool = False) -> None:
        self.test_mode = test_mode
        self.readers: dict[str, Any] = {}
        self.loaded: list[str] = []
        if geoip_dir and Path(geoip_dir).is_dir():
            try:
                import maxminddb
            except ImportError:
                log.warning("maxminddb not installed; GeoIP disabled")
                return
            for kind, names in DB_NAMES.items():
                for n in names:
                    p = Path(geoip_dir) / n
                    if p.is_file():
                        try:
                            self.readers[kind] = maxminddb.open_database(str(p))
                            self.loaded.append(n)
                            break
                        except Exception as exc:  # noqa: BLE001
                            log.warning("cannot open %s: %s", p, exc)

    @property
    def available(self) -> bool:
        return bool(self.readers) or self.test_mode

    def lookup(self, ip: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if not (is_public(ip) or (self.test_mode and is_test_net(ip))):
            return out
        for kind in ("city", "country"):
            r = self.readers.get(kind)
            if not r or out.get("country"):
                continue
            try:
                rec = r.get(ip) or {}
            except (ValueError, Exception):  # noqa: BLE001
                rec = {}
            c = rec.get("country") or rec.get("registered_country") or {}
            if c.get("iso_code"):
                out["country"] = c["iso_code"]
                out["country_name"] = (c.get("names") or {}).get("en", c["iso_code"])
            if rec.get("city"):
                out["city"] = (rec["city"].get("names") or {}).get("en", "")
            loc = rec.get("location") or {}
            if loc.get("latitude") is not None:
                out["lat"], out["lon"] = float(loc["latitude"]), float(loc["longitude"])
        r = self.readers.get("asn")
        if r:
            try:
                rec = r.get(ip) or {}
            except Exception:  # noqa: BLE001
                rec = {}
            if rec.get("autonomous_system_number"):
                out["asn"] = int(rec["autonomous_system_number"])
                out["org"] = str(rec.get("autonomous_system_organization", ""))[:120]
        if self.test_mode and not out.get("country") and is_test_net(ip):
            out.update(sim_geo(ip))
        return out


# ------------------------------------------------------------------------------ external lookups

HttpFn = Callable[[urllib.request.Request, float], dict]


def _http_json(req: urllib.request.Request, timeout: float = 15.0) -> dict:
    with urllib.request.urlopen(req, timeout=timeout) as resp:      # noqa: S310 - fixed https endpoints below
        return json.loads(resp.read(512 * 1024).decode("utf-8", "replace"))


class ExternalLookups:
    """Background worker for the two optional online services.  Everything is opt-in and budgeted."""

    ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
    BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

    def __init__(self, settings: Settings, db: DB, http: HttpFn | None = None) -> None:
        self.s, self.db = settings, db
        self.http = http or _http_json
        self.q: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=2000)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.abuse_on = bool(settings.abuseipdb_enabled and settings.abuseipdb_key)
        self.bazaar_on = bool(settings.bazaar_enabled and settings.bazaar_key)

    # -- scheduling -------------------------------------------------------------------
    def start(self) -> None:
        if (self.abuse_on or self.bazaar_on) and not self._thread:
            self._thread = threading.Thread(target=self._run, name="external-lookups", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def want_abuse(self, ip: str) -> None:
        if self.abuse_on and is_public(ip):
            self._put(("abuse", ip))

    def want_bazaar(self, sha256: str) -> None:
        if self.bazaar_on:
            self._put(("bazaar", sha256))

    def _put(self, item: tuple[str, str]) -> None:
        try:
            self.q.put_nowait(item)
        except queue.Full:
            pass

    # -- worker -----------------------------------------------------------------------
    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                kind, val = self.q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self.process(kind, val)
            except Exception as exc:  # noqa: BLE001 - lookups are best-effort
                log.warning("%s lookup failed: %s", kind, type(exc).__name__)
            self._stop.wait(1.1)

    def process(self, kind: str, val: str) -> None:
        if kind == "abuse":
            self.abuse_check(val)
        elif kind == "bazaar":
            self.bazaar_lookup(val)

    def _budget_ok(self) -> bool:
        day = time.strftime("%Y-%m-%d", time.gmtime())
        key = f"abuse_used_{day}"
        used = int(self.db.get_meta(key, "0") or 0)
        if used >= self.s.abuseipdb_daily_limit:
            return False
        self.db.set_meta(key, str(used + 1))
        return True

    def abuse_check(self, ip: str) -> int | None:
        row = self.db.one("SELECT abuse_checked FROM ip_info WHERE ip=?", (ip,))
        if row and row["abuse_checked"] and time.time() - row["abuse_checked"] < 7 * 86400:
            return None
        if not self._budget_ok():
            return None
        url = self.ABUSE_URL + "?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        req = urllib.request.Request(url, headers={"Key": self.s.abuseipdb_key, "Accept": "application/json",
                                                   "User-Agent": "honeynet-dashboard"})
        data = self.http(req, 15.0).get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        self.db.execute("UPDATE ip_info SET abuse_score=?, abuse_checked=? WHERE ip=?", (score, time.time(), ip))
        return score

    def bazaar_lookup(self, sha256: str) -> dict | None:
        """Hash-only lookup. Sends the SHA-256 and nothing else; the sample itself never leaves the box."""
        body = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
        req = urllib.request.Request(self.BAZAAR_URL, data=body, method="POST",
                                     headers={"Auth-Key": self.s.bazaar_key, "User-Agent": "honeynet-dashboard"})
        res = self.http(req, 20.0)
        status = res.get("query_status", "error")
        out: dict[str, Any] = {"status": status, "checked": time.time()}
        if status == "ok" and res.get("data"):
            d = res["data"][0]
            out.update({"found": True, "signature": d.get("signature"), "file_type": d.get("file_type"),
                        "tags": (d.get("tags") or [])[:12], "first_seen": d.get("first_seen"),
                        "delivery": d.get("delivery_method"), "link": f"https://bazaar.abuse.ch/sample/{sha256}/",
                        "vendor_hits": len(d.get("vendor_intel") or {})})
        else:
            out["found"] = False
        from ..common.sanitize import sanitize_obj

        out = sanitize_obj(out)
        self.db.execute("UPDATE samples SET bazaar=?, bazaar_checked=? WHERE sha256=?", (json.dumps(out), time.time(), sha256))
        return out


def is_routable(ip: str, test_mode: bool) -> bool:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return is_public(ip) or (test_mode and is_test_net(ip))
