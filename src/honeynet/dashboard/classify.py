"""GreyNoise-style IP classification from observed behaviour (fully offline).

GreyNoise/HoneyDB label internet "noise" as benign scanner / malicious / unknown and tag the
activity.  We derive similar tags from what an IP did on *our* sensors:

    scanner        touched services without ever authenticating or exploiting
    bruteforcer    many credential guesses
    exploiter      triggered exploit rules
    dropper        delivered/fetched files
    interactive    got a shell and typed commands
    web-crawler    only requested common paths / used a known scanner user-agent
    research       matches a known research-scanner organisation or user-agent (benign)
"""

from __future__ import annotations

import json
import re

# Organisations that openly operate internet-wide research scanners (matched against the ASN org name).
RESEARCH_ORGS = re.compile(
    r"shodan|censys|shadowserver|binaryedge|stretchoid|internet[- ]census|rapid7|recyber|onyphe|netsystems research|"
    r"alphastrike|criminalip|leakix|quadmetrics|driftnet|cortex xpanse|palo alto networks.*(?:xpanse|cortex)|"
    r"ipip\.net|bitsight|security ?trails|internet measurement|university.*(?:scan|measure)|project sonar|"
    r"intrinsec|arbor|team cymru|greynoise|projectdiscovery|modat|fofa|zoomeye|netlas", re.I)
RESEARCH_UA = re.compile(r"censys|shodan|zgrab|masscan|nmap scripting|internet-measurement|l9explore|l9tcpid|"
                         r"expanse|binaryedge|netcraft|researchscan|leakix|projectdiscovery|nuclei|go-http-client/1\.1 \(research", re.I)
CRAWLER_UA = re.compile(r"curl/|wget/|python-requests|go-http-client|libwww|zgrab|masscan|nmap|nikto|sqlmap|dirbuster|gobuster|"
                        r"wpscan|httpx|okhttp|java/\d|scrapy|aiohttp|^$", re.I)


def tags_for(stats: dict, ua_flags: set[str] | None = None) -> list[str]:
    tags: set[str] = set(ua_flags or ())
    if stats.get("auth", 0) >= 5:
        tags.add("bruteforcer")
    if stats.get("exploits", 0) > 0:
        tags.add("exploiter")
    if stats.get("files", 0) > 0:
        tags.add("dropper")
    if stats.get("cmds", 0) > 0:
        tags.add("interactive")
    if not (tags & {"bruteforcer", "exploiter", "dropper", "interactive"}) and stats.get("conns", 0) + stats.get("events", 0) > 0:
        tags.add("scanner")
    return sorted(tags)


def classify(stats: dict, tags: list[str], org: str | None) -> str:
    """-> 'malicious' | 'suspicious' | 'benign' | 'scanner' | 'unknown'"""
    if "research" in tags or (org and RESEARCH_ORGS.search(org)):
        if not (set(tags) & {"exploiter", "dropper", "interactive"}):
            return "benign"
    if set(tags) & {"exploiter", "dropper", "interactive"}:
        return "malicious"
    if "bruteforcer" in tags:
        return "malicious" if stats.get("auth", 0) >= 20 else "suspicious"
    if "scanner" in tags or "web-crawler" in tags:
        return "scanner"
    return "unknown"


def ua_flags(user_agent: str) -> set[str]:
    flags: set[str] = set()
    if user_agent:
        if RESEARCH_UA.search(user_agent):
            flags.add("research")
        if CRAWLER_UA.search(user_agent):
            flags.add("web-crawler")
    return flags


def dumps_tags(tags: list[str]) -> str:
    return json.dumps(sorted(set(tags)))
