# certcreep

**Certificate Transparency Harvester** 

Reads public CT indexes only. It never resolves a name and never connects to a host it printed.

Why this exists:

- `ctfr.py` (UnaPibaGeek) talks only to crt.sh, has no IDN handling, and dies when crt.sh is slow or blocked from RF.
- Chrome-trusted logs miss RU national CAs. Those land in Yandex Agate / VK NCA / Минцифры and are searchable via precert.ru.
- A raw name dump from `%.yandex.ru` is not a target list. certcreep scopes, aggregates, and classifies.

---

## Features

- IDN in (`яндекс.рф`, CJK) → punycode query; U-label kept on the record
- crt.sh JSON: apex **and** `%.apex` (the wildcard query alone misses the corporate apex)
- Optional precert.ru AJAX (RU logs). Isolated behind `--source` so a scrape break does not fail the lab
- In-scope filter (name == apex or ends with `.apex`); `--siblings` keeps out-of-scope SANs separately
- Wildcard marker preserved (`*.corp.example.ru` stays a wildcard, not a fake host)
- Per-name rollup: first seen, last seen, latest `not_after`, issuer set, source set
- State: `live` / `cooling` (expired &lt; 90 days) / `historical`
- Sort by last-seen, not alphabetically, before `--limit`
- Neutral browser UA
- Jitter between backends; 3 attempts on 502 / HTML-as-JSON
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

# Keep partner / CDN SANs that shared a cert with the apex
python3 certcreep.py -d vk.com --siblings --limit 80
```

Stderr is the operator view (counts, states, hinted names). Stdout / `-o` is the list.

If both indexes fail:

1. Browser: `https://crt.sh/?q=<apex>` via LibreWolf with the S3 `rus` / `chn` profile
2. `https://precert.ru`
3. `https://transparencyreport.google.com/https/certificates`

---

## Flags

| Flag | Default | Point |
|------|---------|--------|
| `-d / --domain` | required | Apex or IDN |
| `-o / --output` | stdout | Write the list / JSON |
| `--limit` | 200 | Applied **after** last-seen sort |
| `--source` | `both` | `crtsh` \| `precert` \| `both` |
| `--exclude-expired` | off | crt.sh `exclude=expired` — current surface, not naming history |
| `--dedupe-certs` | off | crt.sh `deduplicate=Y` |
| `--siblings` | off | Keep out-of-scope SANs |
| `--json` | off | Records with unicode, state, issuers, sources, hints |
| `--raw` | off | First 25 raw crt.sh rows on stderr |
| `--hints` | built-in list | Empty string disables |
| `--no-jitter` | off | Back-to-back backends (don't) |

---

## Query OPSEC

Passive to the **target** is not passive to the **index**. crt.sh (Sectigo) and precert.ru store the query string against the source IP.

1. **User-Agent.** Old wrapper sent `IPTnWIT-ct-search/1.0 (class lab; +training)`. That is a course banner on 30 identical clients. certcreep sends a current Firefox/Linux UA. Do not put the course, the lab company, or “training” back in the header.
2. **Source IP.** Until the shared Proton NL/CH/SG gateways ship, the request is the hypervisor NAT or the student’s hotel IP. After they ship, 30 Kalis still look like one Proton `/32`. That is acceptable for class; it is not invisibility. Check `ifconfig.co` before Lab 4. If it shows the Proxmox country, stop.
3. **Query content is the collection event.** `q=%.superdrones.aero` is interest in that string. Practice queries on `yandex.ru` / `baidu.com` are camouflage-by-volume and expected. Real `supercam.aero` / staff domains stay forbidden. Organization search (`O=…`) is more identifying than a domain wildcard — it is not in this client.
4. **Two backends, two jurisdictions.** crt.sh ≈ Chrome-log world. precert.ru ≈ Yandex Agate + VK NCA + Минцифры. Pick `--source` on purpose. Default `both` waits 1–3 s between them.
5. **Burst.** Thirty Kalis hitting `yandex.ru` in the same second look like abuse and 502 the index. Stagger. A portal cache of the practice JSON (same pattern as `/research` for BDU) is the right next range change; it is not in this folder.
6. **TLS persona.** Stock CPython `urllib`.
7. **What this client will not do.** No CertSpotter + crt.name + Shodan CTL + Censys by default (more copies of the query). No live DNS. No Google Transparency Report scrape (browser fallback only).

---

## Exit status

| Code | Meaning |
|------|---------|
| 0 | At least one index returned rows |
| 2 | Both indexes failed; fallback URLs printed on stderr |

