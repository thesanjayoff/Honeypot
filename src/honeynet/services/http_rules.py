"""Signature rules for the HTTP honeypot (original, regex based).

Each rule says *what* we saw (name / CVE / category) - it is detection only; the
honeypot never executes or forwards anything.  Categories feed the dashboard's
classification ("scanner", "exploit", "bruteforce", ...).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, unquote_plus


@dataclass(frozen=True)
class Rule:
    name: str
    category: str          # traversal | sqli | xss | rce | cmdi | exploit | recon | scanner | webshell | ssrf | info-leak
    pattern: re.Pattern[str]
    cve: str = ""
    where: str = "any"     # uri | body | headers | any
    severity: int = 2      # 1 info, 2 attempt, 3 serious


def R(name, category, pattern, cve="", where="any", severity=2, flags=re.I | re.S) -> Rule:
    return Rule(name, category, re.compile(pattern, flags), cve, where, severity)


RULES: list[Rule] = [
    # ---- generic injection / traversal ------------------------------------------------
    R("path-traversal", "traversal", r"(\.\./|\.\.\\|%2e%2e[/\\%]|%252e%252e|\.\.;/|\.%2e/|%2e\./)"),
    R("lfi-sensitive-file", "traversal", r"(/etc/(passwd|shadow|hosts|group)|/proc/self/(environ|cmdline)|boot\.ini|win\.ini|/windows/system32)", severity=3),
    R("sqli-union", "sqli", r"union(\s|/\*.*?\*/|\+|%20)+(all(\s|\+|%20)+)?select"),
    R("sqli-boolean", "sqli", r"(['\"`)]\s*(or|and)\s*['\"`(]?\s*\w+['\"`)]?\s*(=|like|<|>)|\b(or|and)\s+\d+\s*=\s*\d+)"),
    R("sqli-time-based", "sqli", r"(sleep\s*\(\s*\d+|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)"),
    R("sqli-error-based", "sqli", r"(extractvalue\s*\(|updatexml\s*\(|information_schema|@@version|load_file\s*\(|into\s+outfile)"),
    R("sqli-stacked", "sqli", r";\s*(drop|insert|update|delete|exec|truncate)\s"),
    R("xss-probe", "xss", r"(<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*svg[^>]*on\w+\s*=|<\s*img[^>]+on\w+\s*=)"),
    R("command-injection", "cmdi", r"([;&|`]|\$\(|%3b|%7c|%26)\s*(cat|ls|id|wget|curl|nc|ncat|bash|sh|uname|whoami|ping|busybox|tftp|chmod|rm|python|perl|php)\b"),
    R("shell-download-cradle", "rce", r"(wget|curl|tftp|ftpget)\s+(-\w+\s+)*(https?|ftp)?:?/?/?\S+.*(chmod|\|\s*(ba)?sh|sh\s)", severity=3),
    R("ssrf-metadata", "ssrf", r"(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)", severity=3),
    R("php-cgi-arg-injection", "rce", r"(allow_url_include|auto_prepend_file|php://input)", "CVE-2012-1823", severity=3),
    # ---- named CVEs / well-known exploit paths --------------------------------------
    R("shellshock", "rce", r"\(\)\s*\{\s*[^}]*\}\s*;", "CVE-2014-6271", where="any", severity=3),
    R("log4shell", "rce", r"\$\{\s*(jndi|lower|upper|env|sys|::-|date|ctx)", "CVE-2021-44228", severity=3),
    R("spring4shell", "rce", r"class\.module\.classLoader", "CVE-2022-22965", severity=3),
    R("spring-cloud-function", "rce", r"spring\.cloud\.function\.routing-expression", "CVE-2022-22963", severity=3),
    R("phpunit-eval-stdin", "rce", r"/vendor/phpunit/.*eval-stdin\.php", "CVE-2017-9841", where="uri", severity=3),
    R("apache-path-traversal", "traversal", r"/(cgi-bin|icons)/(\.|%2e){1,2}(%2e|\.)?(/|%2f|%5c)", "CVE-2021-41773", where="uri", severity=3),
    R("thinkphp-rce", "rce", r"(think[\\/]app[\\/]invokefunction|index/\\think|\\think\\)", "CVE-2018-20062", severity=3),
    R("gpon-router-rce", "rce", r"/GponForm/diag_Form", "CVE-2018-10561", where="uri", severity=3),
    R("huawei-hg532-rce", "rce", r"/ctrlt/DeviceUpgrade_1", "CVE-2017-17215", where="uri", severity=3),
    R("realtek-sdk-upnp", "rce", r"/picsdesc\.xml", "CVE-2014-8361", where="uri"),
    R("netgear-setup-cgi", "rce", r"/setup\.cgi\?.*(next_file|syscmd)", "CVE-2016-6277", where="uri", severity=3),
    R("dlink-hnap", "recon", r"/HNAP1", "", where="uri"),
    R("tenda-goform", "rce", r"/goform/(setUsbUnload|SysToolReboot|formSetPortMapping|setMacFilterCfg|SetIpMacBind)", "CVE-2020-10987", where="uri", severity=3),
    R("zyxel-weblogin", "rce", r"/cgi-bin/weblogin\.cgi", "CVE-2020-9054", where="uri", severity=3),
    R("hikvision-webLanguage", "rce", r"/SDK/webLanguage", "CVE-2021-36260", where="uri", severity=3),
    R("tplink-luci-locale", "rce", r"/cgi-bin/luci/;stok=/locale", "CVE-2023-1389", where="uri", severity=3),
    R("draytek-mainfunction", "rce", r"/cgi-bin/mainfunction\.cgi", "CVE-2020-8515", where="uri", severity=3),
    R("citrix-adc-traversal", "traversal", r"/vpn/\.\./vpns/", "CVE-2019-19781", where="uri", severity=3),
    R("fortios-lang-traversal", "traversal", r"/remote/fgt_lang\?lang=/\.\./", "CVE-2018-13379", where="uri", severity=3),
    R("pulse-secure-traversal", "traversal", r"/dana-na/\.\./dana/", "CVE-2019-11510", where="uri", severity=3),
    R("f5-tmui-traversal", "traversal", r"/tmui/login\.jsp/\.\.;/", "CVE-2020-5902", where="uri", severity=3),
    R("confluence-ognl", "rce", r"(\$\{@java\.lang\.Runtime|%24%7B%40java|\$\{\s*\(#a=@)", "CVE-2022-26134", severity=3),
    R("exchange-proxylogon", "rce", r"(/owa/auth/x\.js|/ecp/\w+\.js|autodiscover/autodiscover\.json.*@)", "CVE-2021-26855", where="uri", severity=3),
    R("struts2-ognl", "rce", r"(%\{\(#_=|#cmd=|ognl:|multipart/form-data.*#\w+=)", "CVE-2017-5638", severity=3),
    R("weblogic-console-bypass", "rce", r"/console/css/%252e%252e%252fconsole\.portal", "CVE-2020-14882", where="uri", severity=3),
    R("laravel-ignition", "rce", r"/_ignition/execute-solution", "CVE-2021-3129", where="uri", severity=3),
    R("vcenter-ova-upload", "rce", r"/ui/vropspluginui/rest/services/uploadova", "CVE-2021-21972", where="uri", severity=3),
    R("jenkins-script-console", "recon", r"^/(script|scriptText|securityRealm/user/admin)", "", where="uri"),
    R("docker-api-probe", "recon", r"^/(v1\.\d+/)?(containers|images)/(json|create)", "", where="uri"),
    R("kubernetes-api-probe", "recon", r"^/(api/v1|apis|version)(/|$)", "", where="uri"),
    R("solr-admin-probe", "recon", r"/solr/(admin|\w+/select|\w+/config)", "", where="uri"),
    R("actuator-probe", "recon", r"/actuator(/|$)|/jolokia|/heapdump", "", where="uri"),
    R("tomcat-manager", "bruteforce", r"^/manager/(html|text)", "", where="uri"),
    R("webdav-method-abuse", "recon", r"^(PROPFIND|MKCOL|COPY|MOVE|LOCK)\b", "", where="uri"),
    # ---- information disclosure / recon ---------------------------------------------
    R("dotenv-probe", "info-leak", r"/\.env(\.\w+)?(\?|$)", where="uri"),
    R("git-exposure-probe", "info-leak", r"/\.git/(config|HEAD|index)", where="uri"),
    R("cloud-credentials-probe", "info-leak", r"/\.(aws|ssh|docker)/|id_rsa|credentials\.(json|xml)", where="uri"),
    R("backup-file-probe", "info-leak", r"\.(bak|old|orig|swp|sql|tar\.gz|zip|7z|rar)(\?|$)|/(backup|db|dump|database)\.", where="uri"),
    R("wp-config-probe", "info-leak", r"wp-config\.php(\.|~|$)", where="uri"),
    R("phpinfo-probe", "recon", r"/(phpinfo|info|test)\.php", where="uri"),
    R("wordpress-probe", "recon", r"/(wp-login|wp-admin|xmlrpc|wp-content|wp-includes|wp-json)", where="uri"),
    R("phpmyadmin-probe", "recon", r"/(phpmyadmin|pma|myadmin|mysqladmin|dbadmin)[^/]*(/|$)", where="uri"),
    R("webshell-access", "webshell", r"/(c99|r57|wso|b374k|webshell|shell|cmd|alfa|indoxploit|up|uploader)\.(php\d?|jsp|asp|aspx)", where="uri", severity=3),
    R("admin-panel-probe", "recon", r"^/(admin|administrator|manager|console|login|panel|cpanel|webadmin)(/|\.php|\.html|$)", where="uri"),
    R("scanner-user-agent", "scanner", r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan|acunetix|nessus|openvas|burp|havij|w3af|fimap|jaeles|httpx|feroxbuster)", where="headers"),
]


def _decode_variants(text: str) -> list[str]:
    once = unquote_plus(text)
    twice = unquote(once)
    return list(dict.fromkeys([text, once, twice]))


def match_rules(request_line_uri: str, headers_text: str, body_text: str, method: str = "GET") -> list[dict]:
    """Return a list of matches: {rule, cve, category, severity, snippet}."""
    uri_vars = _decode_variants(request_line_uri)
    body_vars = _decode_variants(body_text[:20000]) if body_text else []
    hdr_vars = _decode_variants(headers_text[:8000])
    targets = {"uri": uri_vars, "body": body_vars, "headers": hdr_vars,
               "any": uri_vars + body_vars + hdr_vars}
    found: dict[str, dict] = {}
    for rule in RULES:
        if rule.name == "webdav-method-abuse":
            if re.match(rule.pattern, method):
                found[rule.name] = _hit(rule, method)
            continue
        for text in targets[rule.where]:
            m = rule.pattern.search(text)
            if m:
                found[rule.name] = _hit(rule, m.group(0))
                break
    return list(found.values())


def _hit(rule: Rule, snippet: str) -> dict:
    return {"rule": rule.name, "cve": rule.cve, "category": rule.category, "severity": rule.severity,
            "snippet": snippet[:200]}


URL_IN_PAYLOAD = re.compile(r"(?:https?|ftp|tftp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,512}", re.I)


def extract_payload_urls(*texts: str) -> list[str]:
    urls: list[str] = []
    for t in texts:
        for variant in _decode_variants(t):
            for m in URL_IN_PAYLOAD.finditer(variant):
                u = m.group(0).rstrip(".,;)'\"")
                if u not in urls:
                    urls.append(u)
    return urls[:10]
