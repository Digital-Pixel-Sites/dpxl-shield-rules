# DPXL Shield — Threat Feed

Public, signed threat-intelligence feed for the **DPXL Shield** WordPress security plugin
by [Digital Pixel](https://digitalpixel.com.br/).

DPXL Shield's protection is **not paywalled**. Its WAF rules are open source and published
here in the open — no 30-day delay, no black box. The plugin pulls updates from this feed
on a daily schedule, so sites get current rules without waiting for a plugin release.

> This repository contains **data only** (JSON). It never contains executable code, and the
> plugin never executes anything it downloads — artifacts are parsed as data and validated
> before use.

## What's here

| Path | Purpose |
|---|---|
| `dist/manifest.json` | Versioned index: feed version, artifact URLs, SHA-256 of each artifact, and an Ed25519 signature over the manifest. |
| `dist/waf-rules.json` | Web Application Firewall rules (regex patterns, targets, action, severity). |
| `dist/signatures.json` | Malware/webshell signatures used by the scanner. |

> `dist/` is a skeleton for now — artifacts are published as the feed pipeline lands.

## How the plugin consumes it

1. A daily cron job (with jitter) fetches `manifest.json` via the free
   [jsDelivr](https://www.jsdelivr.com/) CDN:
   `https://cdn.jsdelivr.net/gh/Digital-Pixel-Sites/dpxl-shield-rules@main/dist/manifest.json`
2. It verifies the manifest's **Ed25519 signature** against a public key embedded in the plugin.
3. It applies the feed only if `feed_version` is **newer** than what's installed (anti-rollback).
4. It downloads each artifact and verifies its **SHA-256** against the signed manifest.
5. It writes the artifacts atomically to disk, with a one-level rollback on failure.

The plugin's built-in rules and signatures remain the **immutable floor** — this feed only
*adds* coverage, it never disables built-in protection. So even a compromised feed cannot
weaken a site's baseline defense.

## Security

- **Signing.** Every release is signed with an Ed25519 private key that **never leaves the
  build environment** and is **never committed to this repository**. The corresponding public
  key ships inside the plugin.
- **Integrity.** The manifest carries the SHA-256 of every artifact, so signing the manifest
  transitively protects the artifacts.
- **Reporting.** Suspected tampering or a security issue with the feed:
  security@digitalpixel.com.br.

## Versioning

`feed_version` is a monotonic, lexicographically comparable string: `YYYY.MM.DD[.n]`
(e.g. `2026.07.26`, `2026.07.26.2`). Consumers must reject any feed whose version is not
strictly greater than the one already installed.

## Contributing

Issues and rule proposals are welcome. A good rule submission includes: the attack it
detects, a regex with its targets (GET/POST/COOKIE/BODY/HEADER), an expected-match sample,
and a false-positive check against common page-builder / REST traffic. Rules are reviewed
before release — nothing is auto-published to sites.

## Attribution & license

This repository is licensed **GPL-2.0-or-later** (see [LICENSE](LICENSE)), matching the plugin.

Rule and signature content is curated and adapted from open sources, including:

- [OWASP Core Rule Set](https://coreruleset.org/) — Apache-2.0
- [php-malware-finder](https://github.com/nbs-system/php-malware-finder) — GPL

The GeoLite2 Country database distributed via this feed's releases includes
GeoLite2 data created by MaxMind, available from
[https://www.maxmind.com](https://www.maxmind.com), used under the GeoLite2 End
User License Agreement.

Trademarks and product names belong to their respective owners. "Wordfence" is a trademark of
Defiant, Inc.; it is referenced only for comparison and this project is not affiliated with it.
