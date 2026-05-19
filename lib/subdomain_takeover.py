#!/usr/bin/env python3
"""
Subdomain takeover / dangling CNAME checks (post-enumeration).

Uses dnspython for CNAME resolution and stdlib HTTP for response fingerprints.
Fingerprint list derived from public takeover signature collections (service suffix + body needle).
"""

from __future__ import annotations

import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

try:
    import dns.exception
    import dns.resolver

    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

# (service, CNAME target suffixes, HTTP body needles — case-insensitive substring match)
TAKEOVER_FINGERPRINTS: Tuple[Tuple[str, Tuple[str, ...], Tuple[str, ...]], ...] = (
    ("GitHub Pages", ("github.io",), ("there isn't a github pages site here", "for root urls (like http://example.com/) you must provide")),
    ("Heroku", ("herokudns.com", "herokuapp.com"), ("no-such-app.html", "herokucdn.com/error-pages/no-such-app")),
    ("AWS S3", ("s3.amazonaws.com", "s3-website"), ("nosuchbucket", "the specified bucket does not exist")),
    ("AWS CloudFront", ("cloudfront.net",), ("error: the request could not be satisfied", "bad request")),
    ("AWS Elastic Beanstalk", ("elasticbeanstalk.com",), ("404 not found")),
    ("AWS API Gateway", ("execute-api.amazonaws.com",), ("invalid api key", "missing authentication token")),
    ("Azure App Service", ("azurewebsites.net", "azure-mobile.net"), ("404 web site not found", "error 404")),
    ("Azure CloudApp", ("cloudapp.net", "cloudapp.azure.com"), ("404 web site not found",)),
    ("Azure Traffic Manager", ("trafficmanager.net",), ("404 web site not found",)),
    ("Azure Blob", ("blob.core.windows.net",), ("the specified account does not exist", "resource not found")),
    ("Google Sites", ("sites.google.com",), ("the requested url was not found on this server",)),
    ("Google Cloud Storage", ("storage.googleapis.com",), ("nosuchbucket", "the specified bucket does not exist")),
    ("Fastly", ("fastly.net",), ("fastly error: unknown domain",)),
    ("Shopify", ("myshopify.com",), ("sorry, this shop is currently unavailable", "only one cname")),
    ("Tumblr", ("domains.tumblr.com",), ("there's nothing here.", "whatever you were looking for doesn't exist")),
    ("WordPress.com", ("wordpress.com",), ("do you want to register",)),
    ("Pantheon", ("pantheonsite.io",), ("404 error unknown site", "the gods are wise")),
    ("Ghost", ("ghost.io",), ("the thing you were looking for is no longer here",)),
    ("Surge.sh", ("surge.sh",), ("project not found",)),
    ("Bitbucket", ("bitbucket.io",), ("repository not found",)),
    ("Vercel", ("vercel.app", "now.sh"), ("the deployment could not be found",)),
    ("Netlify", ("netlify.app", "netlify.com"), ("not found - request id",)),
    ("Webflow", ("proxy.webflow.com", "webflow.io"), ("the page you are looking for doesn't exist",)),
    ("Wix", ("wixsite.com", "wix.com"), ("error connect your domain",)),
    ("Squarespace", ("squarespace.com",), ("no such account",)),
    ("Unbounce", ("unbouncepages.com",), ("the requested unbounce page does not exist",)),
    ("Tilda", ("tilda.ws",), ("please renew your subscription",)),
    ("Strikingly", ("strikinglydns.com", "strikingly.com"), ("page not found",)),
    ("UptimeRobot", ("stats.uptimerobot.com",), ("page not found",)),
    ("Statuspage", ("statuspage.io",), ("you must enable javascript", "status page not found")),
    ("Help Scout", ("helpscoutdocs.com",), ("no settings were found for this company",)),
    ("Freshdesk", ("freshdesk.com",), ("there is no helpdesk here",)),
    ("Zendesk", ("zendesk.com",), ("help center not found",)),
    ("Intercom", ("custom.intercom.help",), ("this page is reserved for artistic dogs",)),
    ("Campaign Monitor", ("createsend.com",), ("try a different domain",)),
    ("Mailchimp", ("mailchimp.com",), ("we can't find that page",)),
    ("SendGrid", ("sendgrid.net",), ("404 page not found",)),
    ("Feedpress", ("redirect.feedpress.me",), ("the feed has not been found",)),
    ("Readme.io", ("readme.io",), ("project doesnt exist", "project not found")),
    ("Cargo", ("cargocollective.com",), ("404 not found",)),
    ("Agile CRM", ("agilecrm.com",), ("sorry, we couldn't find that page",)),
    ("Kajabi", ("endpoint.mykajabi.com", "mykajabi.com"), ("the page you were looking for doesn't exist",)),
    ("LaunchRock", ("launchrock.com",), ("it looks like you may have taken a wrong turn",)),
    ("Mashery", ("mashery.com",), ("unrecognized domain",)),
    ("Ngrok", ("ngrok.io", "ngrok.app"), ("tunnel not found", "ngrok.io not found")),
    ("Pingdom", ("stats.pingdom.com",), ("pingdom could not find this page",)),
    ("Smartling", ("smartling.com",), ("domain is not configured",)),
    ("Statping", ("statping.com",), ("statping.com not found",)),
    ("JetBrains YouTrack", ("myjetbrains.com",), ("is not a registered incloud youtrack",)),
    ("Helprace", ("helprace.com",), ("helprace.com not found",)),
    ("Desk.com", ("desk.com",), ("please try again or try desk.com free",)),
    ("Brightcove", ("brightcove.com",), ("error - can't find account",)),
    ("DigitalOcean", ("ondigitalocean.app", "digitaloceanspaces.com"), ("domain uses do", "project not found")),
    ("Discourse", ("trydiscourse.com",), ("discourse not found",)),
    ("Acquia", ("acquia-test.co", "acquia-sites.com"), ("web site not found",)),
    ("Anima", ("animaapp.io",), ("if you're the owner of this website",)),
)

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_GREEN = "\033[92m"
C_WARN = "\033[93m"
C_FAIL = "\033[91m"
C_DIM = "\033[2m"

DEFAULT_MAX_HOSTS = 200
DEFAULT_HTTP_TIMEOUT = 8.0
DEFAULT_DNS_TIMEOUT = 5.0
BODY_READ_LIMIT = 65536

STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "need_dnspython": "dnspython required: pip install dnspython",
        "takeover_title": "Subdomain takeover (dangling CNAME)",
        "takeover_summary": "Checked {checked} hosts, CNAME on {cname_n}, suspects: {suspects}",
        "takeover_suspect": "  [!] {host} → {cname} ({service}): {detail}",
        "takeover_info": "  [.] {host} → {cname} ({service}): {detail}",
        "takeover_none": "  No dangling CNAME / takeover fingerprints matched.",
        "takeover_empty": "No hostnames to check.",
    },
    "ru": {
        "need_dnspython": "Нужен dnspython: pip install dnspython",
        "takeover_title": "Subdomain takeover (dangling CNAME)",
        "takeover_summary": "Проверено {checked} хостов, CNAME у {cname_n}, подозрений: {suspects}",
        "takeover_suspect": "  [!] {host} → {cname} ({service}): {detail}",
        "takeover_info": "  [.] {host} → {cname} ({service}): {detail}",
        "takeover_none": "  Совпадений с отпечатками takeover не найдено.",
        "takeover_empty": "Нет имён для проверки.",
    },
}


def _t(lang: str, key: str, **kwargs: Any) -> str:
    table = STRINGS.get(lang, STRINGS["en"])
    text = table.get(key, key)
    return text.format(**kwargs) if kwargs else text


def _normalize_hosts(names: List[str]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for raw in names:
        h = raw.strip().lower().rstrip(".")
        if not h or " " in h or h in seen:
            continue
        if not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", h):
            continue
        seen.add(h)
        out.append(h)
    return out


def _match_fingerprint(cname_target: str) -> Optional[Tuple[str, Tuple[str, ...]]]:
    target = cname_target.lower().rstrip(".")
    for service, suffixes, needles in TAKEOVER_FINGERPRINTS:
        for suf in suffixes:
            s = suf.lower()
            if target == s or target.endswith("." + s) or target.endswith(s):
                return service, needles
    return None


def _resolve_cname(fqdn: str, resolver: "dns.resolver.Resolver") -> Optional[str]:
    try:
        ans = resolver.resolve(fqdn, "CNAME")
        return str(ans[0].target).rstrip(".").lower()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return None
    except Exception:
        return None


def _cname_target_missing(cname_target: str, resolver: "dns.resolver.Resolver") -> bool:
    for rtype in ("A", "AAAA"):
        try:
            resolver.resolve(cname_target, rtype)
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception:
            continue
    return True


def _http_body(host: str, *, timeout: float, use_https: bool) -> Tuple[Optional[int], str]:
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}/"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "fnkit-takeover-check/1.0", "Accept": "text/html,*/*"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(BODY_READ_LIMIT)
            return resp.status, raw.decode("utf-8", errors="replace").lower()
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(BODY_READ_LIMIT)
            body = raw.decode("utf-8", errors="replace").lower()
        except Exception:
            body = ""
        return exc.code, body
    except Exception:
        return None, ""


def _probe_http(host: str, *, timeout: float) -> Tuple[Optional[int], str]:
    code, body = _http_body(host, timeout=timeout, use_https=True)
    if body:
        return code, body
    return _http_body(host, timeout=timeout, use_https=False)


def _body_matches(needles: Tuple[str, ...], body: str) -> Optional[str]:
    for needle in needles:
        if needle.lower() in body:
            return needle
    return None


def check_subdomain_takeover(
    hosts: List[str],
    *,
    lang: str = "en",
    max_hosts: int = DEFAULT_MAX_HOSTS,
    dns_timeout: float = DEFAULT_DNS_TIMEOUT,
    http_timeout: float = DEFAULT_HTTP_TIMEOUT,
    sleep_between: float = 0.15,
) -> Dict[str, Any]:
    if not HAS_DNSPYTHON:
        return {"ok": False, "error": _t(lang, "need_dnspython"), "findings": []}

    names = _normalize_hosts(hosts)[:max_hosts]
    if not names:
        return {"ok": True, "checked": 0, "cname_count": 0, "suspect_count": 0, "findings": []}

    resolver = dns.resolver.Resolver()
    resolver.lifetime = dns_timeout

    findings: List[Dict[str, str]] = []
    cname_count = 0

    for host in names:
        cname = _resolve_cname(host, resolver)
        if not cname:
            continue
        cname_count += 1
        matched = _match_fingerprint(cname)
        if not matched:
            continue
        service, needles = matched
        status_code, body = _probe_http(host, timeout=http_timeout)
        hit = _body_matches(needles, body) if body else None
        dangling = _cname_target_missing(cname, resolver)

        if hit:
            findings.append(
                {
                    "host": host,
                    "cname": cname,
                    "service": service,
                    "status": "suspect",
                    "detail": f"HTTP fingerprint: {hit}",
                    "http_status": status_code,
                }
            )
        elif dangling:
            findings.append(
                {
                    "host": host,
                    "cname": cname,
                    "service": service,
                    "status": "suspect",
                    "detail": "CNAME target has no A/AAAA (dangling)",
                    "http_status": status_code,
                }
            )
        else:
            findings.append(
                {
                    "host": host,
                    "cname": cname,
                    "service": service,
                    "status": "info",
                    "detail": f"CNAME to {service}; no fingerprint match (HTTP {status_code or 'n/a'})",
                    "http_status": status_code,
                }
            )
        if sleep_between > 0:
            time.sleep(sleep_between)

    suspects = [f for f in findings if f["status"] == "suspect"]
    return {
        "ok": len(suspects) == 0,
        "checked": len(names),
        "cname_count": cname_count,
        "suspect_count": len(suspects),
        "findings": findings,
        "fingerprint_count": len(TAKEOVER_FINGERPRINTS),
    }


def print_takeover_report(report: Dict[str, Any], *, lang: str = "en") -> None:
    if report.get("error"):
        print(f"{C_FAIL}{report['error']}{C_RESET}")
        return
    print(f"\n{C_BOLD}{_t(lang, 'takeover_title')}{C_RESET}")
    checked = report.get("checked", 0)
    if checked == 0:
        print(_t(lang, "takeover_empty"))
        return
    print(
        _t(
            lang,
            "takeover_summary",
            checked=checked,
            cname_n=report.get("cname_count", 0),
            suspects=report.get("suspect_count", 0),
        )
    )
    suspects = [f for f in report.get("findings", []) if f.get("status") == "suspect"]
    others = [f for f in report.get("findings", []) if f.get("status") != "suspect"]
    if not suspects and not others:
        print(f"{C_GREEN}{_t(lang, 'takeover_none')}{C_RESET}")
        return
    for item in suspects:
        print(
            f"{C_FAIL}{_t(lang, 'takeover_suspect', host=item['host'], cname=item['cname'], service=item['service'], detail=item['detail'])}{C_RESET}"
        )
    for item in others[:25]:
        print(
            f"{C_DIM}{_t(lang, 'takeover_info', host=item['host'], cname=item['cname'], service=item['service'], detail=item['detail'])}{C_RESET}"
        )
    if len(others) > 25:
        print(f"{C_DIM}  … +{len(others) - 25} more CNAME matches (info){C_RESET}")


def load_hosts_file(path: str) -> List[str]:
    from pathlib import Path

    text = Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
    return [line.strip() for line in text.splitlines() if line.strip()]
