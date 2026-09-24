#!/usr/bin/env python3
"""certcreep — Certificate Transparency name harvester.

Replaces ctfr.py

  * IDN-encodes Cyrillic / CJK apexes before the query
  * Queries crt.sh JSON (apex + %.apex) and optionally precert.ru
  * Scopes names to the apex, keeps wildcard flags, emits A-label + U-label
  * Aggregates first/last seen and issuer set; classifies live / cooling / historical
  * Never resolves or connects to discovered hosts (read-only public logs)

"""
from __future__ import annotations

import argparse
import json
import random
import ssl
import sys
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
GOOGLE_CT = "https://transparencyreport.google.com/https/certificates"
TIMEOUT = 45
RETRIES = 3
COOLING_DAYS = 90


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


def request_json(url: str, user_agent: str = UA) -> Any:
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


def main() -> int:
    p = argparse.ArgumentParser(
        description="CT name harvest via crt.sh + precert.ru (IDN-aware, scoped)"
    )
    p.add_argument("-d", "--domain", required=True, help="Apex or IDN (yandex.ru, яндекс.рф, baidu.com)")
    p.add_argument("-o", "--output", help="Write unique in-scope A-labels, one per line")
    p.add_argument("--limit", type=int, default=200, help="Max names to print (after last-seen sort)")
    p.add_argument(
        "--source",
        choices=("crtsh", "precert", "both"),
        default="both",
        help="Which index to query (default both, with jitter)",
    )
    p.add_argument("--exclude-expired", action="store_true", help="crt.sh exclude=expired")
    p.add_argument("--dedupe-certs", action="store_true", help="crt.sh deduplicate=Y")
    p.add_argument("--siblings", action="store_true", help="Also keep out-of-scope SANs from the same certs")
    p.add_argument("--json", action="store_true", help="JSON records instead of a name list")
    p.add_argument("--raw", action="store_true", help="Dump a few raw crt.sh rows to stderr")
    p.add_argument(
        "--hints",
        default="",
        help="Comma-separated tokens to flag on stderr (empty to disable)",
    )
    p.add_argument("--user-agent", default=UA, help="User-Agent header for all requests")
    p.add_argument("--no-jitter", action="store_true", help="Do not sleep between backends")
    args = p.parse_args()

    apex = to_ascii_domain(args.domain)
    u_apex = to_unicode_domain(apex)
    hints = [h.strip() for h in args.hints.split(",") if h.strip()] if args.hints else []

    print(f"[*] apex {apex}" + (f" ({u_apex})" if u_apex != apex else ""), file=sys.stderr)

    crt_rows: list[dict[str, Any]] = []
    precert_rows: list[dict[str, Any]] = []
    sources_planned = []
    if args.source in ("crtsh", "both"):
        sources_planned.append("crtsh")
    if args.source in ("precert", "both"):
        sources_planned.append("precert")

    for i, src in enumerate(sources_planned):
        if i and not args.no_jitter:
            delay = random.uniform(1.0, 3.0)
            print(f"[*] jitter {delay:.1f}s before {src}", file=sys.stderr)
            time.sleep(delay)
        try:
            if src == "crtsh":
                print(f"[*] query crt.sh  q={apex} and q=%.{apex}", file=sys.stderr)
                seen_ids: set[Any] = set()
                for q in (apex, f"%.{apex}"):
                    batch = crtsh_json(q, args.exclude_expired, args.dedupe_certs, args.user_agent)
                    for row in batch:
                        rid = row.get("id") or row.get("min_cert_id") or id(row)
                        if rid in seen_ids:
                            continue
                        seen_ids.add(rid)
                        crt_rows.append(row)
            else:
                print(f"[*] query precert.ru  q={apex}", file=sys.stderr)
                precert_rows = precert_json(apex, args.user_agent)
        except urllib.error.HTTPError as exc:
            print(f"[!] {src} HTTP {exc.code}", file=sys.stderr)
        except Exception as exc:
            print(f"[!] {src} failed: {exc}", file=sys.stderr)

    hits: dict[str, NameHit] = {}
    ingest(hits, crt_rows, apex, "crtsh", args.siblings)
    ingest(hits, precert_rows, apex, "precert", args.siblings)

    scoped = [h for h in hits.values() if h.in_scope]
    siblings = [h for h in hits.values() if not h.in_scope]
    scoped.sort(key=lambda h: (parse_ts(h.last_seen) or datetime.min.replace(tzinfo=timezone.utc), h.a_label), reverse=True)

    print(
        f"[+] {len(crt_rows)} crt.sh rows, {len(precert_rows)} precert.ru rows, "
        f"{len(scoped)} in-scope names, {len(siblings)} sibling SANs",
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

    if not crt_rows and not precert_rows:
        print(f"[!] Google CT: {GOOGLE_CT}", file=sys.stderr)
        print("[!] Fallbacks: https://precert.ru  (RU Yandex/VK/Mintsifry logs)", file=sys.stderr)
        print("[!]            https://crt.sh/?q=" + urllib.parse.quote(apex), file=sys.stderr)
        return 2

    shown = scoped[: args.limit]
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

    if args.json:
        payload = []
        for h in shown:
            payload.append(
                {
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
            )
        if args.siblings:
            payload.append(
                {
                    "_siblings": [
                        {"name": s.a_label, "unicode": s.u_label, "wildcard": s.wildcard}
                        for s in siblings
                    ]
                }
            )
        text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    else:
        lines = []
        for h in shown:
            name = h.a_label
            if h.wildcard:
                name = "*." + name
            lines.append(name)
        text = "\n".join(lines) + ("\n" if lines else "")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"[+] wrote {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)

    if args.raw:
        for row in crt_rows[:25]:
            print(
                f"    {row.get('not_before', '')}  "
                f"{str(row.get('issuer_name', ''))[:60]}  "
                f"{str(row.get('name_value', ''))[:80]}",
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
