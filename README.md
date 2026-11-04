# certcreep

**Certificate Transparency Harvester** 

Reads public CT indexes by default. It does not connect to a discovered host for HTTP/TLS.
Optional `--resolve` looks up A records (active DNS) against the system resolver or `--nameserver`.

Why this exists:

- `ctfr.py` (UnaPibaGeek) talks only to crt.sh, has no IDN handling, and dies when crt.sh is slow or blocked from RF.
- Chrome-trusted logs miss RU national CAs. Those land in Yandex Agate / VK NCA / Минцифры and are searchable via precert.ru.
- A raw name dump from `%.yandex.ru` is not a target list. certcreep scopes, aggregates, and classifies.

---

## Features

- IDN in (`яндекс.рф`, CJK) → punycode query; U-label kept on the record
- crt.sh JSON: apex **and** `%.apex` (the wildcard query alone misses the corporate apex)
- Optional precert.ru AJAX (RU logs). Isolated behind `--source` so a scrape break does not fail the lab
- crt.name subdomain index (`/v1/search`, free, no token, 100 requests per IP per day). On by default (`--source all`); to leave it out, list the other indexes (`--source crtsh,precert`). Names merge into the same per-name records, tagged `crtname`
- In-scope filter (name == apex or ends with `.apex`); `--siblings` keeps out-of-scope SANs separately
- Wildcard marker preserved (`*.corp.example.ru` stays a wildcard, not a fake host)
- Per-name rollup: first seen, last seen, latest `not_after`, issuer set, source set
- State: `live` / `cooling` (expired &lt; 90 days) / `historical`
- Sort by last-seen, not alphabetically, before `--limit`
- Neutral browser UA
- Jitter between backends and between apexes in a file; 3 attempts on 502 / HTML-as-JSON
- Batch apexes from a file (`-iL` / `--input-file`, or `-` for stdin); `-d` and `-iL` are mutually exclusive
- Optional A-record resolve (`--resolve`) with a stdlib DNS client; `--nameserver` picks the resolvers (implies `--resolve`)
- Live `-o` writing as each apex finishes (text/CSV append+flush; JSON atomic rewrite); optional `--csv` output
- Stdlib only (`python3`), no pip

`--json` is the record format. Default stdout is still one name per line so it pipes into the rest of S4.

---

## Install

```bash
cd certcreep
chmod +x certcreep.py
python3 certcreep.py -h
```

---

## Quick start

```bash
# Public RU / CN practice — logs only, do not connect
python3 certcreep.py -d yandex.ru -o ct-yandex.txt
python3 certcreep.py -d яндекс.рф --limit 80
python3 certcreep.py -d baidu.com --exclude-expired --json -o ct-baidu.json

# RU national logs only (Yandex Agate / VK NCA / Минцифры via precert.ru)
python3 certcreep.py -d example.ru --source precert

# Chrome-log world only
python3 certcreep.py -d example.com --source crtsh --dedupe-certs --exclude-expired

# crt.name index only (eTLD+1 apex; a sub-apex is retried at its eTLD+1 and scoped back down)
python3 certcreep.py -d example.com --source crtname

# Default is every index (--source all): crt.sh + precert.ru + crt.name, merged and deduplicated per name
python3 certcreep.py -d example.com --json -o ct-example.json

# Comma-separated subset: crt.sh + precert.ru, merged, no crt.name
python3 certcreep.py -d example.ru --source crtsh,precert

# Keep partner / CDN SANs that shared a cert with the apex
python3 certcreep.py -d vk.com --siblings --limit 80

# Several apexes from a file (one per line; # and blanks skipped). Text lines are apex\tname
python3 certcreep.py -iL domains.txt --source crtsh --limit 40 -o ct-batch.txt
printf 'sqlite.org\nexample.com\n' | python3 certcreep.py -iL - --source crtname --limit 5

# Resolve A records (system resolver). Wildcards are skipped.
python3 certcreep.py -d sqlite.org --source crtname --limit 20 --resolve --json -o ct-resolve.json

# Same, but ask Yandex DNS then Quad9 (tried in order on failure). Implies --resolve.
python3 certcreep.py -d sqlite.org --source crtname --limit 20 --nameserver 77.88.8.8,9.9.9.9
```

Stderr is the operator view (counts, states, hinted names, resolve summary). Stdout / `-o` is the list.
With `-iL` and more than one apex, text lines are `apex\tname` (plus `\tIPs` when resolving); JSON records carry an `apex` field.

### Live output

Results are written **as each apex finishes** (after its CT queries and optional `--resolve`), not once at the end:

- **Text** (`-o` or stdout): lines are appended and flushed. `tail -f outfile.txt` shows names appear between apexes.
- **CSV** (`--csv`, with or without `-o`): header row first, then one row per name appended and flushed after each apex (`tail -f` friendly). Columns: `apex`, `name`, `unicode`, `wildcard`, `state`, `first_seen`, `last_seen`, `not_after`, `issuers`, `sources`, `hints`, plus `a_records` / `dns_status` when `--resolve`. Multi-value fields are joined with `;`. `--csv` and `--json` are mutually exclusive.
- **JSON + `-o`**: the file stays a single JSON array. After each apex the whole array is rewritten via a temp file + `os.replace`, so the file is always valid JSON (including `[]` before the first apex). A crash or Ctrl-C leaves the last successful rewrite.
- **JSON without `-o`**: one array is printed to stdout when the run ends (pipes still get valid JSON).
- Within an apex, names are still merged/deduped across sources before anything is written; each apex is emitted once.

If every queried index fails:

1. Browser: `https://crt.sh/?q=<apex>` via LibreWolf with the S3 `rus` / `chn` profile
2. `https://precert.ru`
3. `https://crt.name/v1/search?apex=<apex>`
4. `https://transparencyreport.google.com/https/certificates`

### crt.name notes

- Endpoint: `GET https://crt.name/v1/search?apex=<eTLD+1>&format=json&dates=1` → `[{"sub": "...", "first_seen": "...Z"}, ...]`.
- The index stores only `(apex, subdomain, first-seen)`: no issuer, no `not_after`. Names seen only by crt.name have `first_seen` / `last_seen` set to the crt.name first-seen date and state `unknown`; names also seen on crt.sh keep crt.sh issuers and expiry.
- `apex` must be an eTLD+1. If `-d` is a sub-apex (`corp.example.ru`), crt.name answers 400 with the eTLD+1; certcreep re-queries that apex once and the in-scope filter keeps only `corp.example.ru` names.
- Free tier: 100 requests per IP per day, no token. 4xx (including 429) is not retried so the budget is not burned on retries.
- Queried by default (`--source all`). To skip it, list the indexes you do want: `--source crtsh,precert` (merged as usual), or a single `--source crtsh` / `--source precert`.
- A crt.name failure is logged on stderr and does not affect the other indexes.

---

## Flags

| Flag | Default | Point |
|------|---------|--------|
| `-d / --domain` | one of `-d` / `-iL` required | Apex or IDN |
| `-iL / --input-file` | one of `-d` / `-iL` required | File of apexes (one per line; `#` and blanks skipped; deduped). `-` reads stdin. Mutually exclusive with `-d` |
| `-o / --output` | stdout | Live write: text/CSV append+flush after each apex; JSON array rewritten atomically after each apex |
| `--limit` | 200 | Applied **after** last-seen sort, **per apex** |
| `--source` | `all` | `crtsh` \| `precert` \| `crtname` \| `all` (crt.sh + precert.ru + crt.name), or a comma-separated list such as `crtsh,precert`. Case-insensitive; spaces and duplicates ignored; `all` anywhere in the list means every index. Unknown or empty entries are an error. Query order is always crt.sh → precert.ru → crt.name |
| `--exclude-expired` | off | crt.sh `exclude=expired` — current surface, not naming history |
| `--dedupe-certs` | off | crt.sh `deduplicate=Y` |
| `--siblings` | off | Keep out-of-scope SANs |
| `--json` | off | Records with unicode, state, issuers, sources, hints (and `a_records` / `dns_status` with `--resolve`). With `-o`, rewritten after each apex; without `-o`, one array at exit. Mutually exclusive with `--csv` |
| `--csv` | off | CSV with header; columns match JSON fields (`apex` always present; multi-values joined with `;`). Append+flush after each apex. Mutually exclusive with `--json` |
| `--raw` | off | First 25 raw crt.sh rows on stderr |
| `--hints` | built-in list | Empty string disables |
| `--user-agent` | Firefox/Linux | User-Agent header for all requests |
| `--no-jitter` | off | Back-to-back backends and apexes (don't) |
| `--resolve` | off | Look up A records for each printed name (thread pool, 3 s timeout). Wildcards get `dns_status=skipped:wildcard`. Text lines append `\tIP,IP` or `\t[status]`; JSON adds `a_records` and `dns_status` |
| `--nameserver` | system resolver | Comma-separated IPv4/IPv6 addresses used as DNS servers for `--resolve` (implies `--resolve`). Tried in order on timeout/error. Empty or non-IP entries are an argparse error. Example: `77.88.8.8,9.9.9.9` |

---

## Query OPSEC

Passive to the **target** is not passive to the **index**. crt.sh (Sectigo), precert.ru, and crt.name store the query string against the source IP.

1. **User-Agent.** Old wrapper sent `IPTnWIT-ct-search/1.0 (class lab; +training)`. That is a course banner on 30 identical clients. certcreep sends a current Firefox/Linux UA. Do not put the course, the lab company, or “training” back in the header.
2. **Source IP.** Until the shared Proton NL/CH/SG gateways ship, the request is the hypervisor NAT or the student’s hotel IP. After they ship, 30 Kalis still look like one Proton `/32`. That is acceptable for class; it is not invisibility. Check `ifconfig.co` before Lab 4. If it shows the Proxmox country, stop.
3. **Query content is the collection event.** `q=%.superdrones.aero` is interest in that string. Practice queries on `yandex.ru` / `baidu.com` are camouflage-by-volume and expected. Real `supercam.aero` / staff domains stay forbidden. Organization search (`O=…`) is more identifying than a domain wildcard — it is not in this client.
4. **Three backends, separate operators.** crt.sh ≈ Chrome-log world. precert.ru ≈ Yandex Agate + VK NCA + Минцифры. crt.name ≈ a CT-derived subdomain index run by Defendio (EU). Pick `--source` on purpose. Default `all` (crt.sh + precert.ru + crt.name) waits 1–3 s between each; a comma list (`crtsh,precert`) sends the query only to the listed indexes, with the same jitter; a single `--source` sends it to that index only.
5. **Burst.** Thirty Kalis hitting `yandex.ru` in the same second look like abuse and 502 the index. Stagger. A portal cache of the practice JSON (same pattern as `/research` for BDU) is the right next range change; it is not in this folder.
6. **TLS persona.** Stock CPython `urllib`.
7. **What this client will not do.** No CertSpotter + Shodan CTL + Censys (more copies of the query). crt.name is in the default `all`; to keep the query off it, use `--source crtsh,precert` (or a single index). No live HTTP/TLS to discovered hosts. No Google Transparency Report scrape (browser fallback only).
8. **`--resolve` is active.** A CT harvest alone never talks to the target. `--resolve` (or `--nameserver`) sends an A query for every printed name to the chosen resolvers. That is visible to those resolvers and, when they recurse, to the target's authoritative servers. Prefer resolvers you control or trust for the jurisdiction; the default system resolver is whatever the host's `/etc/resolv.conf` points at. Wildcards are not queried. Jitter between apexes still applies; DNS lookups for one apex are concurrent (bounded thread pool).

---

## Exit status

| Code | Meaning |
|------|---------|
| 0 | Every apex got rows from at least one index |
| 1 | Mixed: some apexes succeeded, at least one failed (batch `-iL` runs) |
| 2 | Every apex failed (or the only apex failed); fallback URLs printed on stderr |

