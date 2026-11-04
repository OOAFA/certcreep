#!/usr/bin/env python3
"""certcreep — Certificate Transparency name harvester.

Replaces ctfr.py

  * IDN-encodes Cyrillic / CJK apexes before the query
  * Queries crt.sh JSON (apex + %.apex), precert.ru and crt.name by default
  * Scopes names to the apex, keeps wildcard flags, emits A-label + U-label
  * Aggregates first/last seen and issuer set; classifies live / cooling / historical
  * Optional domain list (-iL) for batch apexes
  * Optional A-record resolve (--resolve / --nameserver); off by default so CT queries stay passive to the target

"""
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import random
import socket
import ssl
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

# Neutral client string.
UA = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
    "Gecko/20100101 Firefox/128.0"
)
CRTSH = "https://crt.sh/"
PRECERT = "https://precert.ru/results/ajax"
CRTNAME = "https://crt.name/v1/search"
GOOGLE_CT = "https://transparencyreport.google.com/https/certificates"
TIMEOUT = 45
RETRIES = 3
COOLING_DAYS = 90
DNS_TIMEOUT = 3.0
DNS_WORKERS = 16


@dataclass
class NameHit:
    a_label: str
    u_label: str
    wildcard: bool = False
    first_seen: str = ""
    last_seen: str = ""
    not_after: str = ""
    issuers: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    in_scope: bool = True
    a_records: list[str] = field(default_factory=list)
    dns_status: str = ""

    @property
    def state(self) -> str:
        until = parse_ts(self.not_after)
        if until is None:
            return "unknown"
        now = datetime.now(timezone.utc)
        if until > now:
            return "live"
        if until > now - timedelta(days=COOLING_DAYS):
            return "cooling"
        return "historical"


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d.%m.%Y",
    ):
        try:
            return datetime.strptime(text[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def newer(a: str, b: str) -> str:
    ta, tb = parse_ts(a), parse_ts(b)
    if ta is None:
        return b
    if tb is None:
        return a
    return a if ta >= tb else b


def older(a: str, b: str) -> str:
    ta, tb = parse_ts(a), parse_ts(b)
    if ta is None:
        return b
    if tb is None:
        return a
    return a if ta <= tb else b


def to_ascii_domain(name: str) -> str:
    name = name.strip().lower()
    name = name.replace("https://", "").replace("http://", "").split("/")[0]
    name = name.lstrip("*.")
    name = name.rstrip(".")
    try:
        return name.encode("idna").decode("ascii")
    except Exception:
        return name


def to_unicode_domain(name: str) -> str:
    try:
        return name.encode("ascii").decode("idna")
    except Exception:
        return name


def looks_like_host(part: str) -> bool:
    if not part or "@" in part:
        return False
    if part.startswith("http://") or part.startswith("https://"):
        return False
    if " " in part:
        return False
    if part.replace(".", "").isdigit():
        return False
    return "." in part or part.endswith(".local") or part.endswith(".internal")


def extract_parts(row: dict[str, Any]) -> list[str]:
    blobs: list[str] = []
    for key in ("name_value", "common_name", "cn", "san", "dns_names", "name"):
        val = row.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            blobs.extend(str(x) for x in val)
        else:
            blobs.append(str(val))
    if row.get("cn") and row.get("san") and row["cn"] not in blobs:
        blobs.append(str(row["cn"]))
    parts: list[str] = []
    for blob in blobs:
        for piece in blob.replace(",", "\n").split("\n"):
            piece = piece.strip().lower().rstrip(".")
            if piece:
                parts.append(piece)
    return parts


def in_scope(name: str, apex: str) -> bool:
    if name == apex:
        return True
    if name.endswith("." + apex):
        return True
    u_name, u_apex = to_unicode_domain(name), to_unicode_domain(apex)
    if u_name == u_apex or u_name.endswith("." + u_apex):
        return True
    return False


def request_json(url: str, user_agent: str = UA, no_retry: tuple[int, ...] = ()) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": "application/json,text/plain,*/*",
            "Accept-Language": "en-US,en;q=0.8",
        },
    )
    ctx = ssl.create_default_context()
    last_exc: Exception | None = None
    for attempt in range(1, RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
                raw = resp.read()
            text = raw.decode("utf-8", errors="replace").lstrip()
            if not text or text[0] not in "[{":
                raise ValueError("non-JSON body (likely 502 HTML from the index)")
            return json.loads(text)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as exc:
            last_exc = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code in no_retry:
                raise
            if attempt < RETRIES:
                delay = min(8.0, 1.5 * attempt) + random.uniform(0.2, 1.0)
                print(
                    f"[!] {url.split('?')[0]} attempt {attempt}/{RETRIES} failed: {exc}; sleep {delay:.1f}s",
                    file=sys.stderr,
                )
                time.sleep(delay)
    assert last_exc is not None
    raise last_exc


def crtsh_json(query: str, exclude_expired: bool, dedupe: bool, user_agent: str = UA) -> list[dict[str, Any]]:
    params: dict[str, str] = {"q": query, "output": "json"}
    if exclude_expired:
        params["exclude"] = "expired"
    if dedupe:
        params["deduplicate"] = "Y"
    data = request_json(f"{CRTSH}?{urllib.parse.urlencode(params)}", user_agent)
    return data if isinstance(data, list) else []


def precert_json(query: str, user_agent: str = UA) -> list[dict[str, Any]]:
    params = urllib.parse.urlencode(
        {"query": query, "draw": 1, "start": 0, "length": 1000}
    )
    data = request_json(f"{PRECERT}?{params}", user_agent)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        rows = data.get("data") or data.get("rows") or data.get("results") or []
        return rows if isinstance(rows, list) else []
    return []


def crtname_json(apex: str, user_agent: str = UA) -> list[dict[str, Any]]:
    """crt.name /v1/search: one row per indexed name, (sub, first_seen) only.

    apex must be an eTLD+1. A sub-apex (corp.example.ru) gets HTTP 400 naming
    the eTLD+1; retry once with that and let the in-scope filter narrow it.
    Free tier is 100 requests per IP per day, so 4xx is not retried.
    """
    no_retry = (400, 401, 403, 404, 429)

    def fetch(q: str) -> Any:
        params = urllib.parse.urlencode({"apex": q, "format": "json", "dates": 1})
        return request_json(f"{CRTNAME}?{params}", user_agent, no_retry)

    try:
        data = fetch(apex)
    except urllib.error.HTTPError as exc:
        if exc.code != 400:
            raise
        body = exc.read().decode("utf-8", errors="replace")
        marker = "eTLD+1 is "
        if marker not in body:
            raise ValueError(f"HTTP 400: {body.strip()[:120]}") from exc
        parent = body.split(marker, 1)[1].strip().rstrip(")").split()[0]
        if not parent or parent == apex:
            raise ValueError(f"HTTP 400: {body.strip()[:120]}") from exc
        print(f"[*] crt.name wants the eTLD+1; query apex={parent}", file=sys.stderr)
        data = fetch(parent)
    rows: list[dict[str, Any]] = []
    if not isinstance(data, list):
        return rows
    for item in data:
        if not isinstance(item, dict) or not item.get("sub"):
            continue
        # first_seen is RFC 3339 with a trailing Z; parse_ts wants it bare.
        seen = str(item.get("first_seen") or "").rstrip("Z")
        rows.append({"name_value": str(item["sub"]), "entry_timestamp": seen})
    return rows


def ingest(
    hits: dict[str, NameHit],
    rows: Iterable[dict[str, Any]],
    apex: str,
    source: str,
    keep_siblings: bool,
) -> None:
    for row in rows:
        issued = (
            str(row.get("not_before") or row.get("entry_timestamp") or row.get("issued") or "")
        )
        expires = str(row.get("not_after") or row.get("expires") or row.get("valid_to") or "")
        issuer = str(row.get("issuer_name") or row.get("issuer") or row.get("ca") or "")
        for raw in extract_parts(row):
            wildcard = raw.startswith("*.")
            host = raw[2:] if wildcard else raw
            host = to_ascii_domain(host)
            if not looks_like_host(host) and host != apex:
                continue
            scoped = in_scope(host, apex)
            if not scoped and not keep_siblings:
                continue
            rec = hits.get(host)
            if rec is None:
                rec = NameHit(
                    a_label=host,
                    u_label=to_unicode_domain(host),
                    wildcard=wildcard,
                    first_seen=issued,
                    last_seen=issued,
                    not_after=expires,
                    in_scope=scoped,
                )
                hits[host] = rec
            else:
                rec.wildcard = rec.wildcard or wildcard
                rec.first_seen = older(rec.first_seen, issued)
                rec.last_seen = newer(rec.last_seen, issued)
                rec.not_after = newer(rec.not_after, expires)
                rec.in_scope = rec.in_scope or scoped
            if issuer:
                rec.issuers.add(issuer)
            rec.sources.add(source)


def hint_match(name: str, hints: list[str]) -> list[str]:
    blob = f"{name} {to_unicode_domain(name)}"
    found = []
    for token in hints:
        token = token.strip().lower()
        if token and token in blob:
            found.append(token)
    return found


def load_domains(path: str) -> list[str]:
    """Read apexes from a file (or '-' for stdin). Blank / # lines skipped; order kept, deduped."""
    if path == "-":
        raw = sys.stdin.read().splitlines()
    else:
        try:
            with open(path, encoding="utf-8") as fh:
                raw = fh.read().splitlines()
        except OSError as exc:
            raise SystemExit(f"[!] cannot read {path}: {exc}") from exc
    seen: set[str] = set()
    out: list[str] = []
    for line in raw:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    if not out:
        raise SystemExit(f"[!] no domains in {path}")
    return out


def parse_nameservers(value: str) -> list[str]:
    """Comma-separated IPv4/IPv6 nameserver list for --nameserver."""
    out: list[str] = []
    for part in str(value).split(","):
        token = part.strip()
        if not token:
            raise argparse.ArgumentTypeError(
                f"empty entry in {value!r}; use comma-separated IPv4/IPv6 addresses"
            )
        try:
            out.append(str(ipaddress.ip_address(token)))
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"invalid nameserver {token!r}; need an IPv4 or IPv6 address"
            ) from exc
    if not out:
        raise argparse.ArgumentTypeError("nameserver list is empty")
    return out


def _encode_qname(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    out = bytearray()
    for label in parts:
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError(f"bad DNS label in {name!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _skip_name(buf: bytes, offset: int) -> int:
    while True:
        if offset >= len(buf):
            raise ValueError("truncated DNS name")
        length = buf[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(buf):
                raise ValueError("truncated DNS pointer")
            return offset + 2
        if length == 0:
            return offset + 1
        offset += 1 + length


def _parse_a_answers(buf: bytes) -> tuple[int, list[str]]:
    if len(buf) < 12:
        raise ValueError("short DNS reply")
    rcode = buf[3] & 0x0F
    ancount = struct.unpack("!H", buf[6:8])[0]
    offset = 12
    offset = _skip_name(buf, offset)
    offset += 4  # qtype + qclass
    addrs: list[str] = []
    for _ in range(ancount):
        offset = _skip_name(buf, offset)
        if offset + 10 > len(buf):
            raise ValueError("truncated DNS answer")
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", buf[offset : offset + 10])
        offset += 10
        rdata = buf[offset : offset + rdlen]
        offset += rdlen
        if rtype == 1 and rclass == 1 and rdlen == 4:
            addrs.append(socket.inet_ntoa(rdata))
    return rcode, addrs


def _dns_query_tcp(name: str, nameserver: str, timeout: float) -> tuple[int, list[str]]:
    qid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(name) + struct.pack("!HH", 1, 1)
    packet = header + question
    family = socket.AF_INET6 if ":" in nameserver else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((nameserver, 53))
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        length_raw = sock.recv(2)
        if len(length_raw) < 2:
            raise ValueError("short DNS TCP length")
        (need,) = struct.unpack("!H", length_raw)
        chunks = bytearray()
        while len(chunks) < need:
            piece = sock.recv(need - len(chunks))
            if not piece:
                raise ValueError("short DNS TCP body")
            chunks.extend(piece)
    data = bytes(chunks)
    if len(data) < 12 or struct.unpack("!H", data[:2])[0] != qid:
        raise ValueError("DNS reply id mismatch")
    return _parse_a_answers(data)


def resolve_a_system(name: str, timeout: float = DNS_TIMEOUT) -> tuple[list[str], str]:
    """A records via the system resolver (getaddrinfo, AF_INET only).

    Timeout is enforced with a one-shot worker thread so we never touch the
    process-global socket.setdefaulttimeout (unsafe under the resolve pool).
    """
    def _lookup() -> list[str]:
        infos = socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({info[4][0] for info in infos})

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            addrs = pool.submit(_lookup).result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        return [], "timeout"
    except socket.gaierror as exc:
        msg = str(exc).lower()
        if "name or service not known" in msg or "nodename nor servname" in msg or "not found" in msg:
            return [], "nxdomain"
        if "temporary failure" in msg or "try again" in msg:
            return [], "servfail"
        return [], f"error:{exc}"
    except OSError as exc:
        return [], f"error:{exc}"
    if not addrs:
        return [], "noanswer"
    return addrs, "ok"


def _dns_exchange(name: str, nameserver: str, timeout: float) -> tuple[int, list[str]]:
    """UDP A query; fall back to TCP when the truncation bit is set."""
    qid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _encode_qname(name) + struct.pack("!HH", 1, 1)
    packet = header + question
    family = socket.AF_INET6 if ":" in nameserver else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (nameserver, 53))
        data, _ = sock.recvfrom(4096)
    if len(data) < 12 or struct.unpack("!H", data[:2])[0] != qid:
        raise ValueError("DNS reply id mismatch")
    truncated = bool(data[2] & 0x02)
    if truncated:
        return _dns_query_tcp(name, nameserver, timeout)
    return _parse_a_answers(data)


def _interpret_a_reply(rcode: int, addrs: list[str]) -> tuple[list[str], str] | None:
    """Map rcode/addrs to a final result, or None to try the next nameserver."""
    if rcode == 3:
        return [], "nxdomain"
    if rcode == 2:
        return None  # SERVFAIL — try next NS
    if rcode != 0 and not addrs:
        return None
    if addrs:
        return sorted(set(addrs)), "ok"
    return [], "noanswer"


def resolve_a_custom(
    name: str,
    nameservers: list[str],
    timeout: float = DNS_TIMEOUT,
) -> tuple[list[str], str]:
    """A records via UDP (TCP on truncation or UDP failure) against an ordered NS list."""
    last_status = "error"
    for ns in nameservers:
        try:
            result = _interpret_a_reply(*_dns_exchange(name, ns, timeout))
            if result is None:
                last_status = "servfail"
                continue
            return result
        except TimeoutError:
            last_status = "timeout"
        except (OSError, ValueError, struct.error) as exc:
            last_status = f"error:{exc}"
        # UDP blocked or broken — try TCP against the same NS before moving on.
        try:
            result = _interpret_a_reply(*_dns_query_tcp(name, ns, timeout))
            if result is None:
                last_status = "servfail"
                continue
            return result
        except TimeoutError:
            last_status = "timeout"
        except (OSError, ValueError, struct.error) as exc:
            last_status = f"error:{exc}"
    return [], last_status


def resolve_hits(
    hits: list[NameHit],
    nameservers: list[str] | None,
    workers: int = DNS_WORKERS,
    timeout: float = DNS_TIMEOUT,
) -> None:
    """Fill a_records / dns_status on each hit. Wildcards are skipped (no lookup)."""
    targets = [h for h in hits if not h.wildcard]
    for h in hits:
        if h.wildcard:
            h.dns_status = "skipped:wildcard"
            h.a_records = []

    def one(h: NameHit) -> tuple[NameHit, list[str], str]:
        if nameservers:
            addrs, status = resolve_a_custom(h.a_label, nameservers, timeout)
        else:
            addrs, status = resolve_a_system(h.a_label, timeout)
        return h, addrs, status

    if not targets:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as pool:
        for h, addrs, status in pool.map(one, targets):
            h.a_records = addrs
            h.dns_status = status


SOURCES = ("crtsh", "precert", "crtname")


def parse_sources(value: str) -> tuple[str, ...]:
    """--source value: one index, a comma list (crtsh,precert), or all.

    Case-insensitive, whitespace-trimmed, duplicates collapsed. "all" anywhere
    in the list means every index. Query order is always crtsh, precert,
    crtname regardless of the order given.
    """
    valid = ", ".join((*SOURCES, "all"))
    picked: set[str] = set()
    for part in str(value).split(","):
        name = part.strip().lower()
        if not name:
            raise argparse.ArgumentTypeError(
                f"empty entry in {value!r}; use a comma-separated list of: {valid}"
            )
        if name == "all":
            picked.update(SOURCES)
        elif name in SOURCES:
            picked.add(name)
        else:
            raise argparse.ArgumentTypeError(f"unknown source {name!r}; choose from: {valid}")
    return tuple(s for s in SOURCES if s in picked)


def harvest_one(
    apex_raw: str,
    sources: tuple[str, ...],
    *,
    exclude_expired: bool,
    dedupe_certs: bool,
    siblings: bool,
    user_agent: str,
    no_jitter: bool,
    limit: int,
    hints: list[str],
    raw: bool,
    do_resolve: bool,
    nameservers: list[str] | None,
) -> tuple[list[NameHit], list[NameHit], int]:
    """Query indexes for one apex. Returns (scoped_shown, siblings, status).

    status: 0 = at least one index returned rows, 2 = every index failed.
    """
    apex = to_ascii_domain(apex_raw)
    u_apex = to_unicode_domain(apex)
    print(f"[*] apex {apex}" + (f" ({u_apex})" if u_apex != apex else ""), file=sys.stderr)

    crt_rows: list[dict[str, Any]] = []
    precert_rows: list[dict[str, Any]] = []
    crtname_rows: list[dict[str, Any]] = []
    sources_planned = list(sources)

    for i, src in enumerate(sources_planned):
        if i and not no_jitter:
            delay = random.uniform(1.0, 3.0)
            print(f"[*] jitter {delay:.1f}s before {src}", file=sys.stderr)
            time.sleep(delay)
        try:
            if src == "crtsh":
                print(f"[*] query crt.sh  q={apex} and q=%.{apex}", file=sys.stderr)
                seen_ids: set[Any] = set()
                for q in (apex, f"%.{apex}"):
                    batch = crtsh_json(q, exclude_expired, dedupe_certs, user_agent)
                    for row in batch:
                        rid = row.get("id") or row.get("min_cert_id") or id(row)
                        if rid in seen_ids:
                            continue
                        seen_ids.add(rid)
                        crt_rows.append(row)
            elif src == "precert":
                print(f"[*] query precert.ru  q={apex}", file=sys.stderr)
                precert_rows = precert_json(apex, user_agent)
            else:
                print(f"[*] query crt.name  apex={apex}", file=sys.stderr)
                crtname_rows = crtname_json(apex, user_agent)
        except urllib.error.HTTPError as exc:
            print(f"[!] {src} HTTP {exc.code}", file=sys.stderr)
        except Exception as exc:
            print(f"[!] {src} failed: {exc}", file=sys.stderr)

    hits: dict[str, NameHit] = {}
    ingest(hits, crt_rows, apex, "crtsh", siblings)
    ingest(hits, precert_rows, apex, "precert", siblings)
    ingest(hits, crtname_rows, apex, "crtname", siblings)

    scoped = [h for h in hits.values() if h.in_scope]
    sibling_hits = [h for h in hits.values() if not h.in_scope]
    scoped.sort(
        key=lambda h: (
            parse_ts(h.last_seen) or datetime.min.replace(tzinfo=timezone.utc),
            h.a_label,
        ),
        reverse=True,
    )

    print(
        f"[+] {len(crt_rows)} crt.sh rows, {len(precert_rows)} precert.ru rows, "
        f"{len(crtname_rows)} crt.name rows, "
        f"{len(scoped)} in-scope names, {len(sibling_hits)} sibling SANs",
        file=sys.stderr,
    )
    by_state: dict[str, int] = {}
    for h in scoped:
        by_state[h.state] = by_state.get(h.state, 0) + 1
    if by_state:
        print(
            "[+] states  " + ", ".join(f"{k}={v}" for k, v in sorted(by_state.items())),
            file=sys.stderr,
        )

    if not crt_rows and not precert_rows and not crtname_rows:
        print(f"[!] Google CT: {GOOGLE_CT}", file=sys.stderr)
        print("[!] Fallbacks: https://precert.ru  (RU Yandex/VK/Mintsifry logs)", file=sys.stderr)
        print("[!]            https://crt.sh/?q=" + urllib.parse.quote(apex), file=sys.stderr)
        print("[!]            https://crt.name/v1/search?apex=" + urllib.parse.quote(apex), file=sys.stderr)
        return [], sibling_hits, 2

    shown = scoped[:limit]
    flagged = []
    for h in shown:
        marks = hint_match(h.a_label, hints)
        if marks:
            flagged.append((h, marks))
    if flagged:
        print("[+] hinted names:", file=sys.stderr)
        for h, marks in flagged[:25]:
            label = h.a_label if h.u_label == h.a_label else f"{h.a_label} ({h.u_label})"
            wild = " *." if h.wildcard else "    "
            print(f"    {wild}{label}  [{h.state}]  {','.join(marks)}", file=sys.stderr)

    if do_resolve:
        print(f"[*] resolve A records for {len(shown)} names", file=sys.stderr)
        resolve_hits(shown, nameservers)
        if siblings:
            resolve_hits(sibling_hits, nameservers)
        ok = sum(1 for h in shown if h.dns_status == "ok")
        print(
            f"[+] resolve  ok={ok}  "
            + ", ".join(
                f"{k}={v}"
                for k, v in sorted(
                    {
                        s: sum(1 for h in shown if h.dns_status == s)
                        for s in {h.dns_status for h in shown}
                        if s != "ok"
                    }.items()
                )
            ),
            file=sys.stderr,
        )

    if raw:
        for row in crt_rows[:25]:
            print(
                f"    {row.get('not_before', '')}  "
                f"{str(row.get('issuer_name', ''))[:60]}  "
                f"{str(row.get('name_value', ''))[:80]}",
                file=sys.stderr,
            )
    return shown, sibling_hits, 0


def hit_to_json(h: NameHit, hints: list[str], include_dns: bool, apex: str | None = None) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "name": h.a_label,
        "unicode": h.u_label,
        "wildcard": h.wildcard,
        "state": h.state,
        "first_seen": h.first_seen,
        "last_seen": h.last_seen,
        "not_after": h.not_after,
        "issuers": sorted(h.issuers),
        "sources": sorted(h.sources),
        "hints": hint_match(h.a_label, hints),
    }
    if apex is not None:
        rec["apex"] = apex
    if include_dns:
        rec["a_records"] = list(h.a_records)
        rec["dns_status"] = h.dns_status
    return rec


def format_text_line(h: NameHit, include_dns: bool, multi: bool, apex: str) -> str:
    name = h.a_label
    if h.wildcard:
        name = "*." + name
    if multi:
        name = f"{apex}\t{name}"
    if include_dns:
        if h.dns_status == "ok" and h.a_records:
            name = f"{name}\t{','.join(h.a_records)}"
        else:
            name = f"{name}\t[{h.dns_status or 'unresolved'}]"
    return name


def csv_fieldnames(include_dns: bool) -> list[str]:
    fields = [
        "apex",
        "name",
        "unicode",
        "wildcard",
        "state",
        "first_seen",
        "last_seen",
        "not_after",
        "issuers",
        "sources",
        "hints",
    ]
    if include_dns:
        fields.extend(["a_records", "dns_status"])
    return fields


def hit_to_csv_row(
    h: NameHit,
    hints: list[str],
    include_dns: bool,
    apex: str,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "apex": apex,
        "name": h.a_label,
        "unicode": h.u_label,
        "wildcard": "1" if h.wildcard else "0",
        "state": h.state,
        "first_seen": h.first_seen,
        "last_seen": h.last_seen,
        "not_after": h.not_after,
        "issuers": ";".join(sorted(h.issuers)),
        "sources": ";".join(sorted(h.sources)),
        "hints": ";".join(hint_match(h.a_label, hints)),
    }
    if include_dns:
        row["a_records"] = ";".join(h.a_records)
        row["dns_status"] = h.dns_status
    return row


class LiveOutput:
    """Stream results as each apex finishes.

    Text/CSV: append rows and flush (works with tail -f). JSON: keep the array
    format and rewrite the whole file atomically after each apex so the file
    is always valid JSON. JSON without -o is still emitted once at close.
    """

    def __init__(self, path: str | None, kind: str, include_dns: bool = False) -> None:
        if kind not in ("text", "json", "csv"):
            raise ValueError(f"unknown output kind {kind!r}")
        self.path = path
        self.kind = kind
        self.include_dns = include_dns
        self.payload: list[Any] = []
        self.records = 0
        self._fields = csv_fieldnames(include_dns)
        if kind == "json":
            if path:
                self._atomic_write("[]\n")
            return
        if path:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                if kind == "csv":
                    csv.DictWriter(fh, fieldnames=self._fields).writeheader()
                    fh.flush()
                    os.fsync(fh.fileno())
        elif kind == "csv":
            csv.DictWriter(sys.stdout, fieldnames=self._fields, lineterminator="\n").writeheader()
            sys.stdout.flush()

    def _append_text(self, block: str) -> None:
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(block)
                fh.flush()
                os.fsync(fh.fileno())
        else:
            sys.stdout.write(block)
            sys.stdout.flush()

    def add_text(self, lines: list[str]) -> None:
        if not lines:
            return
        block = "\n".join(lines) + "\n"
        self.records += len(lines)
        self._append_text(block)
        if self.path:
            print(f"[+] wrote {self.records} lines -> {self.path}", file=sys.stderr)

    def add_csv(self, rows: list[dict[str, Any]]) -> None:
        if not rows:
            return
        if self.path:
            with open(self.path, "a", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(fh, fieldnames=self._fields, extrasaction="ignore")
                for row in rows:
                    writer.writerow(row)
                fh.flush()
                os.fsync(fh.fileno())
        else:
            writer = csv.DictWriter(
                sys.stdout, fieldnames=self._fields, extrasaction="ignore", lineterminator="\n"
            )
            for row in rows:
                writer.writerow(row)
            sys.stdout.flush()
        self.records += len(rows)
        if self.path:
            print(f"[+] wrote {self.records} CSV rows -> {self.path}", file=sys.stderr)

    def add_json(self, records: list[Any]) -> None:
        if not records:
            if self.path:
                self._atomic_write(json.dumps(self.payload, ensure_ascii=False, indent=2) + "\n")
            return
        self.payload.extend(records)
        self.records = len(self.payload)
        body = json.dumps(self.payload, ensure_ascii=False, indent=2) + "\n"
        if self.path:
            self._atomic_write(body)
            print(f"[+] wrote {self.records} JSON records -> {self.path}", file=sys.stderr)

    def _atomic_write(self, body: str) -> None:
        assert self.path
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        fd, tmp = tempfile.mkstemp(prefix=".certcreep-", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def close(self) -> None:
        if self.kind == "json" and not self.path:
            sys.stdout.write(json.dumps(self.payload, ensure_ascii=False, indent=2) + "\n")
            sys.stdout.flush()


def main() -> int:
    p = argparse.ArgumentParser(
        description="CT name harvest via crt.sh + precert.ru + crt.name (IDN-aware, scoped)"
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("-d", "--domain", help="Apex or IDN (yandex.ru, яндекс.рф, baidu.com)")
    target.add_argument(
        "-iL",
        "--input-file",
        metavar="FILE",
        help="File of apexes, one per line (# and blanks skipped); '-' reads stdin",
    )
    p.add_argument(
        "-o",
        "--output",
        help="Write results live as each apex finishes (text/CSV append+flush; "
        "JSON rewritten atomically after each apex). Use tail -f on text/CSV files",
    )
    p.add_argument("--limit", type=int, default=200, help="Max names to print per apex (after last-seen sort)")
    p.add_argument(
        "--source",
        type=parse_sources,
        default="all",
        metavar="SOURCES",
        help="Index or comma-separated indexes to query: crtsh, precert, crtname, "
        "or all (default) = crt.sh + precert.ru + crt.name. "
        "Example: crtsh,precert. Jitter between indexes when more than one",
    )
    p.add_argument("--exclude-expired", action="store_true", help="crt.sh exclude=expired")
    p.add_argument("--dedupe-certs", action="store_true", help="crt.sh deduplicate=Y")
    p.add_argument("--siblings", action="store_true", help="Also keep out-of-scope SANs from the same certs")
    fmt = p.add_mutually_exclusive_group()
    fmt.add_argument(
        "--json",
        action="store_true",
        help="JSON records instead of a name list. With -o the file is a JSON array "
        "rewritten after each apex (always valid). Without -o, one array is printed at the end",
    )
    fmt.add_argument(
        "--csv",
        action="store_true",
        help="CSV records with a header row (stdlib csv). Columns match JSON fields; "
        "multi-value fields use ';'. Appended and flushed after each apex "
        "(tail -f friendly). Mutually exclusive with --json",
    )
    p.add_argument("--raw", action="store_true", help="Dump a few raw crt.sh rows to stderr")
    p.add_argument(
        "--hints",
        default="",
        help="Comma-separated tokens to flag on stderr (empty to disable)",
    )
    p.add_argument("--user-agent", default=UA, help="User-Agent header for all requests")
    p.add_argument("--no-jitter", action="store_true", help="Do not sleep between backends or between apexes")
    p.add_argument(
        "--resolve",
        action="store_true",
        help="Resolve A records for discovered names (system resolver unless --nameserver)",
    )
    p.add_argument(
        "--nameserver",
        type=parse_nameservers,
        metavar="IPS",
        help="Comma-separated IPv4/IPv6 nameservers for --resolve "
        "(implies --resolve). Tried in order on failure. Example: 77.88.8.8,9.9.9.9",
    )
    args = p.parse_args()

    if args.nameserver and not args.resolve:
        args.resolve = True

    if args.json:
        kind = "json"
    elif args.csv:
        kind = "csv"
    else:
        kind = "text"

    hints = [h.strip() for h in args.hints.split(",") if h.strip()] if args.hints else []
    if args.input_file is not None:
        domains = load_domains(args.input_file)
    else:
        domains = [args.domain]

    multi = len(domains) > 1
    nameservers = args.nameserver
    out = LiveOutput(args.output, kind, include_dns=args.resolve)
    any_ok = False
    any_fail = False

    try:
        for di, domain in enumerate(domains):
            if di and not args.no_jitter:
                delay = random.uniform(1.0, 3.0)
                print(f"[*] jitter {delay:.1f}s before next apex", file=sys.stderr)
                time.sleep(delay)
            try:
                shown, siblings, status = harvest_one(
                    domain,
                    args.source,
                    exclude_expired=args.exclude_expired,
                    dedupe_certs=args.dedupe_certs,
                    siblings=args.siblings,
                    user_agent=args.user_agent,
                    no_jitter=args.no_jitter,
                    limit=args.limit,
                    hints=hints,
                    raw=args.raw,
                    do_resolve=args.resolve,
                    nameservers=nameservers,
                )
            except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
                print(f"[!] apex {domain} aborted: {exc}", file=sys.stderr)
                any_fail = True
                continue
            apex = to_ascii_domain(domain)
            if status == 0:
                any_ok = True
            else:
                any_fail = True
            # Emit only after this apex's sources (+ optional resolve) finished.
            # Per-apex ingest already dedupes names; each apex is written once.
            if kind == "json":
                batch: list[Any] = [
                    hit_to_json(h, hints, args.resolve, apex if multi else None) for h in shown
                ]
                if args.siblings and siblings:
                    sib_block: dict[str, Any] = {
                        "_siblings": [
                            {
                                "name": s.a_label,
                                "unicode": s.u_label,
                                "wildcard": s.wildcard,
                                **(
                                    {
                                        "a_records": list(s.a_records),
                                        "dns_status": s.dns_status,
                                    }
                                    if args.resolve
                                    else {}
                                ),
                            }
                            for s in siblings
                        ]
                    }
                    if multi:
                        sib_block["apex"] = apex
                    batch.append(sib_block)
                out.add_json(batch)
            elif kind == "csv":
                out.add_csv(
                    [hit_to_csv_row(h, hints, args.resolve, apex) for h in shown]
                )
            else:
                out.add_text(
                    [format_text_line(h, args.resolve, multi, apex) for h in shown]
                )
    except KeyboardInterrupt:
        print("[!] interrupted; keeping results written so far", file=sys.stderr)
        any_fail = True
    finally:
        out.close()

    if any_ok and not any_fail:
        return 0
    if any_ok and any_fail:
        return 1
    return 2



if __name__ == "__main__":
    raise SystemExit(main())
