# Top 10 Attack Surface Exposures - Presentation Guide

## Overview

This guide covers the **Top 10 Attack Surface Exposures (2026)** track. Unlike the
OWASP Web and LLM lists — which catalogue *application vulnerability classes* — this
track is about *exposures*: services, panels, and protocols that should never have
been reachable from the public internet in the first place.

The data comes from an analysis of ~3,000 real-world attack surfaces, reported by
The Hacker News in ["The Top 10 Attack Surface Exposures in 2026"](https://thehackernews.com/2026/06/the-top-10-attack-surface-exposures-in.html)
(underlying figures: Intruder's 2026 Attack Surface Management Index).

**One-line framing for the audience:** *"The OWASP lists tell you how attackers break
in. This list is about the doors you left open."*

## Pre-Presentation Checklist

This track is **100% static frontend content** — there is no backend, no live target,
and no exploitation. That makes it the lowest-risk track to demo.

- [ ] Frontend running (`npm start` in `frontend/`, or `docker-compose up`)
- [ ] Page loads at `http://localhost:3000/asm`
- [ ] Projector/screen share ready; browser zoom set so cards are legible
- [ ] (Optional) Pre-expand the first card or two if you prefer to scroll-and-talk

## How This Track Works (read before presenting)

Everything lives on a **single page** (`/asm`) — there are no per-exposure sub-pages.
The page has three parts:

1. **Stats strip** — the headline numbers, plus the source link.
2. **The ten cards** (AS01 → AS10) — each is one "slide".
3. **Presentation Flow footer** — a one-paragraph recap and a link back home.

Each card shows, at a glance: the rank, the exposure name, a **% of surfaces** chip, a
**port/service** chip, a one-line description, and three example bullets. Every card
also has a collapsible **"Talk-through details"** disclosure. Expand it to reveal:

- a longer **summary**,
- **🔎 What an attacker sees** — simulated recon scan output + the attacker's next move,
- **💥 Impact** bullets,
- **🛡️ How to fix it** — concrete fixes with config/command snippets,
- **🏆 Best practices**.

**Recommended technique:** keep the details collapsed and expand each card live as you
reach it — the recon-scan reveal ("here's literally what the scanner sees") is the hook
for each exposure. Read the title + stat + port, ask the room "what's the risk?", then
expand to confirm with the scan, impact, and fix.

## Presentation Flow (~25-35 minutes, scales to fit)

### Introduction (5 minutes)

1. **Open** at the home page (`/`) and click the **Attack Surface Top 10 (2026)** card.
2. **Lead with the stats strip** — these land hard with any audience:
   - **60%** had at least one HTTP panel exposed
   - **49%** exposed a risky port or service
   - **42%** had a database reachable directly from the internet
   - **30%** exposed files or information that shouldn't be
3. **Set the frame:** these aren't subtle code bugs — they're things switched on and
   left facing the internet. Attackers don't break in so much as walk in; automated
   scanners sweep the whole internet for exactly these every day.

### Core Walk-Through (~2-3 min per exposure)

Walk AS01 → AS10. For each: state the **stat + port**, expand **Talk-through details**,
show the **recon scan**, then land the **impact** and the **one-line fix**.

#### AS01 - MySQL Database Exposed (26% · 3306/tcp)
- **What the scan shows:** port 3306 open, MySQL bound to `0.0.0.0`, no TLS required.
- **Why it matters:** no exploit needed — point a credential-stuffing tool at root and
  try common passwords. One guess = full read/write to every schema; a top driver of
  mass-ransomware campaigns.
- **The fix in one line:** bind to localhost, firewall 3306 to the app subnet, strong
  unique creds, TLS + least privilege.

#### AS02 - Postgres Database Exposed (16% · 5432/tcp)
- **What the scan shows:** `listen_addresses = '*'`, and `psql` connecting with **no
  password at all** thanks to `pg_hba.conf` `trust` auth.
- **Why it matters:** instant superuser; dump or drop the whole cluster; `COPY`/extensions
  can read host files or run code in some setups.
- **The fix in one line:** `listen_addresses = 'localhost'`, never `trust` for remote
  hosts (use `scram-sha-256`), firewall the port, TLS + scoped roles.

#### AS03 - API Documentation Exposed (15% · HTTP/HTTPS)
- **What the scan shows:** a public `swagger.json` listing `/api/admin/users`,
  `/api/internal/debug`, `/api/payments/refund`.
- **Why it matters:** it hands the attacker a complete, documented map of every endpoint,
  parameter, and auth scheme — including internal/admin routes. GraphQL introspection
  leaks the full schema the same way.
- **The fix in one line:** disable docs/introspection in prod, authenticate any exposed
  docs, and enforce authz on every route at the gateway (no security by obscurity).

#### AS04 - WordPress Admin Panel Exposed (15% · HTTP/HTTPS)
- **What the scan shows:** `wpscan` finds `/wp-login.php`, XML-RPC enabled, users
  `admin`/`editor`, and a plugin with a known CVE.
- **Why it matters:** relentless credential guessing plus the enormous plugin/theme CVE
  surface → admin takeover, webshell/RCE, defacement, and a pivot off the web host.
- **The fix in one line:** restrict `/wp-admin` to VPN/known IPs, disable `xmlrpc.php`,
  enforce MFA + rate limiting, and patch/prune plugins aggressively.

#### AS05 - Remote Desktop (RDP) Exposed (11% · 3389/tcp)
- **What the scan shows:** RDP open and leaking `FILESRV01.corp.local` / domain `CORP`,
  with **NLA not enforced**.
- **Why it matters:** one of the most common ransomware entry points — password-spray the
  leaked hostname, or fire a pre-auth exploit like BlueKeep. A single guess = an
  interactive desktop inside the network, then AD compromise.
- **The fix in one line:** never expose RDP (VPN / RD Gateway only), enforce NLA + MFA,
  account lockout, patch and restrict source IPs.

#### AS06 - SNMP Service Exposed (9% · 161/udp)
- **What the scan shows:** `snmpwalk -c public` returns device model, hostname
  `core-sw-01`, interfaces, and internal IP tables.
- **Why it matters:** the default `public` string leaks a full internal network map; a
  writable `private` string lets attackers reconfigure devices; open SNMP is also a DDoS
  amplifier.
- **The fix in one line:** keep 161/udp off the internet, use SNMPv3 (auth+priv), remove
  default community strings, restrict to monitoring hosts, read-only.

#### AS07 - phpMyAdmin Panel Exposed (8% · HTTP/HTTPS)
- **What the scan shows:** `/phpmyadmin/` returns 200, the README leaks version 4.9.7,
  and the login form is ready for brute-force.
- **Why it matters:** the same prize as an exposed database (AS01) but through a friendly
  browser UI — full DB control, and SQL-to-file RCE in some configurations.
- **The fix in one line:** don't expose it (VPN/allowlist), put proxy auth + MFA in front,
  remove it if unused, patch and use strong DB credentials.

#### AS08 - UPnP Service Exposed (8% · 1900/udp)
- **What the scan shows:** an SSDP `M-SEARCH` reveals a `rootDesc.xml` with a
  `WANIPConnection` control URL.
- **Why it matters:** a protocol meant for trusted LANs, on the WAN side — attackers
  rewrite NAT/port-forward rules to expose internal hosts, enumerate the network, and
  abuse the device for SSDP reflection DDoS.
- **The fix in one line:** disable UPnP on the WAN, drop inbound 1900/udp, segment IoT,
  and patch device firmware.

#### AS09 - NTP Service Exposed (7% · 123/udp)
- **What the scan shows:** `ntpdc monlist` returns a list of recent clients (internal
  IPs) — a tiny request producing a large reply.
- **Why it matters:** a powerful reflection/amplification DDoS weapon that also leaks
  internal client addresses; leads to IP blocklisting and bandwidth costs.
- **The fix in one line:** disable `monlist` (modern ntpd/chrony), default-deny status
  queries, firewall 123/udp to real time servers, deploy BCP38 anti-spoofing.

#### AS10 - RPC Portmapper Exposed (7% · 111/tcp+udp)
- **What the scan shows:** `rpcinfo -p` enumerates `portmapper`, `nfs` (2049), `mountd`,
  and `status` — a map of internal RPC services.
- **Why it matters:** a roadmap to world-readable NFS exports and other legacy services,
  and itself a DDoS amplification vector.
- **The fix in one line:** block port 111, disable `rpcbind` where unused, lock down NFS
  exports (`root_squash`, specific hosts), modernise to NFSv4 + Kerberos.

### Optional grouping (if you're short on time)

Rather than ten separate beats, cluster them:

- **Exposed databases** — AS01 (MySQL), AS02 (Postgres), AS07 (phpMyAdmin gateway)
- **Management panels / HTTP surfaces** — AS03 (API docs), AS04 (WordPress)
- **Remote access** — AS05 (RDP)
- **Legacy UDP services that also amplify DDoS** — AS06 (SNMP), AS08 (UPnP), AS09 (NTP),
  AS10 (RPC)

### Conclusion (5 minutes)

1. **The key takeaway:** patching matters, but **attack-surface reduction** — turning off
   and firewalling what never needed to be public — prevents whole classes of attack
   *before a single exploit is written.*
2. **Three recurring patterns:**
   - Defaults left on (community strings, `trust` auth, blank/weak passwords).
   - Management interfaces facing the whole internet instead of a VPN/allowlist.
   - Legacy protocols (SNMP/UPnP/NTP/RPC) that double as DDoS amplifiers.
3. **Next steps for the audience:**
   - Continuously scan *your own* IP ranges for these exposures.
   - Default-deny at the perimeter; put admin behind VPN/ZTNA.
   - Treat attack-surface management as an ongoing process, not a one-time audit.

## Presentation Tips

- The recon-scan blocks are the emotional hook — "this is what an attacker sees about
  *you*, today, with no effort." Pause on them.
- Tie each exposure to a real headline (ransomware via RDP/MySQL, NTP/SSDP DDoS events).
- You don't need network isolation for this track — there are no live targets — but keep
  the standard "educational purposes only" framing consistent with the other tracks.

## Resources

- [The Top 10 Attack Surface Exposures in 2026 — The Hacker News](https://thehackernews.com/2026/06/the-top-10-attack-surface-exposures-in.html)
- [OWASP Attack Surface Analysis Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html)
- [Shodan](https://www.shodan.io/) / [Censys](https://censys.io/) — see your own external footprint
