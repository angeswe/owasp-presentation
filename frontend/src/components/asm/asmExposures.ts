// Data for the "Top 10 Attack Surface Exposures (2026)" track.
//
// Source: analysis of ~3,000 real-world attack surfaces, summarised by
// The Hacker News, "The Top 10 Attack Surface Exposures in 2026".
// Unlike the OWASP Web/LLM Top 10 (application-level vulnerability classes),
// these are *exposures* — services and panels that should never have been
// reachable from the public internet in the first place.

export interface ExposureFix {
  title: string;
  detail: string;
  code: string;
}

export interface ExposureBestPractice {
  term: string;
  text: string;
}

export interface Exposure {
  id: string; // route segment, e.g. "as01"
  rank: number; // 1-10
  shortId: string; // "AS01"
  title: string;
  navTitle: string; // compact label for the nav bar
  port: string; // typical port/service
  stat: string; // share of analysed attack surfaces affected
  cardDescription: string; // one-line summary for the home grid
  summary: string; // longer paragraph for the detail page
  examples: string[]; // bullet list for the home grid + nav context
  scan: string[]; // simulated "what an attacker sees" recon output
  attackerNext: string; // what the attacker does with that recon
  impact: string[]; // business / security impact bullets
  fixes: ExposureFix[]; // remediation grid
  bestPractices: ExposureBestPractice[];
}

// Overall stats the article opened with — shown on the home page.
export const surfaceStats = {
  analysed: "3,000 attack surfaces analysed",
  source: {
    label: "The Hacker News — “The Top 10 Attack Surface Exposures in 2026”",
    url: "https://thehackernews.com/2026/06/the-top-10-attack-surface-exposures-in.html",
  },
  highlights: [
    { value: "60%", label: "had at least one HTTP panel exposed" },
    { value: "49%", label: "exposed a risky port or service" },
    { value: "42%", label: "had a database reachable from the internet" },
    { value: "30%", label: "exposed files or information that shouldn't be" },
  ],
};

export const exposures: Exposure[] = [
  {
    id: "as01",
    rank: 1,
    shortId: "AS01",
    title: "MySQL Database Exposed",
    navTitle: "AS01 - MySQL Exposed",
    port: "3306/tcp",
    stat: "26%",
    cardDescription:
      "Internet-facing MySQL on port 3306 — a routine target for credential brute-force and ransomware crews.",
    summary:
      "A MySQL server bound to all interfaces and reachable from the internet lets anyone attempt to connect. Attackers run automated credential brute-force and known-CVE checks; a weak, default, or blank root password gives full read/write access to every database. This is one of the most exploited exposures on the internet and has fuelled mass ransomware campaigns against hundreds of thousands of databases.",
    examples: [
      "Root brute-force on weak passwords",
      "Bulk exfiltration of customer data",
      "Databases dumped and held for ransom",
    ],
    scan: [
      "$ nmap -sV -p 3306 203.0.113.10",
      "PORT     STATE SERVICE VERSION",
      "3306/tcp open  mysql   MySQL 5.7.38",
      "| mysql-info:",
      "|   Protocol: 10",
      "|   Server bound to 0.0.0.0 (all interfaces)",
      "|_  Auth: native password, no TLS required",
    ],
    attackerNext:
      "From here an attacker simply points a credential-stuffing tool at the login and tries common root passwords — no exploit required, just an open door.",
    impact: [
      "Full read/write access to every schema once a single credential is guessed",
      "Bulk exfiltration of customer records and PII",
      "Databases wiped and replaced with a ransom note",
      "A foothold for pivoting deeper into the internal network",
    ],
    fixes: [
      {
        title: "1. Bind to localhost",
        detail: "Never expose the database engine to the public internet.",
        code: "bind-address = 127.0.0.1",
      },
      {
        title: "2. Firewall / private subnet",
        detail: "Allow 3306 only from your application servers.",
        code: "SG: allow 3306 from app-subnet only",
      },
      {
        title: "3. Strong, unique credentials",
        detail: "Eliminate default, blank, and reused passwords.",
        code: "ALTER USER 'root'@'%' ...; use a secrets manager",
      },
      {
        title: "4. TLS + least privilege",
        detail: "Encrypt connections and scope app users tightly.",
        code: "REQUIRE SSL; GRANT only needed privileges",
      },
    ],
    bestPractices: [
      { term: "Network segmentation", text: "Databases live in a private subnet, never a public one." },
      { term: "Attack-surface monitoring", text: "Continuously scan your own ranges for an open 3306." },
      { term: "Least privilege", text: "App accounts get only the schemas and operations they need." },
      { term: "Patch management", text: "Keep the engine current to close known CVEs." },
    ],
  },
  {
    id: "as02",
    rank: 2,
    shortId: "AS02",
    title: "Postgres Database Exposed",
    navTitle: "AS02 - Postgres Exposed",
    port: "5432/tcp",
    stat: "16%",
    cardDescription:
      "PostgreSQL listening on 5432 across all interfaces — the same direct-access risk as exposed MySQL.",
    summary:
      "PostgreSQL listening on 5432 across all interfaces presents the same risk as an exposed MySQL instance: direct login attempts and weak-password brute force. Worse, a misconfigured pg_hba.conf with `trust` authentication accepts connections with no password at all, handing an attacker the superuser account instantly.",
    examples: [
      "`trust` auth requiring no password",
      "Brute-force of the postgres superuser",
      "Direct dump of every database",
    ],
    scan: [
      "$ nmap -sV -p 5432 203.0.113.11",
      "PORT     STATE SERVICE    VERSION",
      "5432/tcp open  postgresql PostgreSQL DB 14.2",
      "|_pgsql: listen_addresses = '*'",
      "$ psql -h 203.0.113.11 -U postgres",
      "psql: connected (no password — pg_hba 'trust')",
    ],
    attackerNext:
      "With `trust` auth the attacker is already a superuser; otherwise they brute-force the postgres role and dump every database.",
    impact: [
      "Superuser access with a single weak or absent password",
      "Exfiltration of every database on the cluster",
      "Destructive DROP/ransom of business data",
      "Use of COPY/extensions to read host files or run code in some setups",
    ],
    fixes: [
      {
        title: "1. Bind to localhost",
        detail: "Only listen on interfaces that actually need it.",
        code: "listen_addresses = 'localhost'",
      },
      {
        title: "2. Fix pg_hba.conf",
        detail: "Never use `trust` for remote connections.",
        code: "host all all <app-cidr> scram-sha-256",
      },
      {
        title: "3. Firewall the port",
        detail: "Restrict 5432 to your application tier.",
        code: "SG: allow 5432 from app-subnet only",
      },
      {
        title: "4. TLS + scoped roles",
        detail: "Encrypt traffic and give each app its own role.",
        code: "ssl = on; GRANT least privilege per role",
      },
    ],
    bestPractices: [
      { term: "Network segmentation", text: "Keep the cluster off any public-facing interface." },
      { term: "Authentication hardening", text: "Use scram-sha-256, never `trust`, for remote hosts." },
      { term: "Least privilege", text: "Per-application roles scoped to their own databases." },
      { term: "Patch management", text: "Track Postgres CVEs and upgrade minor releases promptly." },
    ],
  },
  {
    id: "as03",
    rank: 3,
    shortId: "AS03",
    title: "API Documentation Exposed",
    navTitle: "AS03 - API Docs Exposed",
    port: "HTTP/HTTPS",
    stat: "15%",
    cardDescription:
      "Public Swagger/OpenAPI or GraphQL introspection that maps every endpoint — including internal admin routes.",
    summary:
      "Swagger/OpenAPI UI, Redoc, or GraphQL introspection left publicly reachable hands an attacker a complete map of your API — every parameter, auth scheme, and often internal or admin-only route. It turns flaws that were merely obscure into a documented to-do list, dramatically lowering the effort to find and exploit them.",
    examples: [
      "Public /swagger or /api-docs",
      "GraphQL introspection enabled in prod",
      "Internal/admin endpoints documented",
    ],
    scan: [
      "$ curl -s https://target/swagger.json | jq '.paths | keys'",
      "[",
      '  "/api/v1/login",',
      '  "/api/internal/debug",',
      '  "/api/admin/users",',
      '  "/api/payments/refund"',
      "]",
    ],
    attackerNext:
      "Every parameter, auth scheme, and hidden admin route is now documented — the attacker skips reconnaissance and goes straight to abuse.",
    impact: [
      "Full enumeration of endpoints and parameters",
      "Discovery of undocumented admin/internal APIs",
      "Faster exploitation of broken-auth and IDOR flaws",
      "Complete schema disclosure via GraphQL introspection",
    ],
    fixes: [
      {
        title: "1. Disable docs in prod",
        detail: "Ship API docs to internal environments only.",
        code: "if (env === 'production') disableSwagger()",
      },
      {
        title: "2. Authenticate the docs",
        detail: "Put any exposed docs behind real authentication.",
        code: "Swagger UI behind SSO / auth proxy",
      },
      {
        title: "3. Turn off introspection",
        detail: "Disable GraphQL introspection in production.",
        code: "introspection: false (prod)",
      },
      {
        title: "4. Authorize every route",
        detail: "Don't rely on obscurity; enforce authz at the gateway.",
        code: "Gateway: authn + authz on all paths",
      },
    ],
    bestPractices: [
      { term: "No security by obscurity", text: "Assume attackers have your full API spec — secure each endpoint anyway." },
      { term: "Environment separation", text: "Docs and introspection enabled in dev, disabled in prod." },
      { term: "Gateway authorization", text: "Centralise authn/authz so no route is accidentally open." },
      { term: "Surface monitoring", text: "Scan your own domains for exposed /swagger, /api-docs, /graphql." },
    ],
  },
  {
    id: "as04",
    rank: 4,
    shortId: "AS04",
    title: "WordPress Admin Panel Exposed",
    navTitle: "AS04 - WordPress Admin",
    port: "HTTP/HTTPS",
    stat: "15%",
    cardDescription:
      "Public /wp-admin and /wp-login.php — relentless credential guessing and plugin/theme CVE exploitation.",
    summary:
      "A publicly reachable /wp-admin, /wp-login.php, and xmlrpc.php invite automated credential guessing and exploitation of the enormous WordPress plugin and theme ecosystem. WordPress powers a huge share of the web, which makes its login and management interfaces some of the most relentlessly attacked surfaces online.",
    examples: [
      "Brute-force on /wp-login.php",
      "xmlrpc.php amplified brute force",
      "Vulnerable plugin/theme exploitation",
    ],
    scan: [
      "$ wpscan --url https://target --enumerate u,vp",
      "[+] /wp-login.php  -> 200 OK",
      "[+] XML-RPC enabled (xmlrpc.php)",
      "[+] User(s): admin, editor",
      "[+] Plugin: contact-form 4.1.0 (known CVE)",
    ],
    attackerNext:
      "With users enumerated and a vulnerable plugin found, the attacker brute-forces the login or fires a public exploit to drop a webshell.",
    impact: [
      "Full admin takeover of the site",
      "Webshell upload and remote code execution",
      "SEO spam, defacement, and malware distribution",
      "Pivot from the web host into the rest of the environment",
    ],
    fixes: [
      {
        title: "1. Restrict the admin",
        detail: "Limit /wp-admin to known IPs or put it behind a VPN.",
        code: "Allow /wp-admin from office IPs / VPN only",
      },
      {
        title: "2. Disable XML-RPC",
        detail: "Turn off xmlrpc.php unless a feature truly needs it.",
        code: "block xmlrpc.php at the web server",
      },
      {
        title: "3. MFA + rate limiting",
        detail: "Enforce strong passwords, MFA, and login throttling.",
        code: "2FA plugin + fail2ban / login limiter",
      },
      {
        title: "4. Patch & prune",
        detail: "Keep core, themes, plugins current; remove unused ones.",
        code: "auto-update core; uninstall stale plugins",
      },
    ],
    bestPractices: [
      { term: "Minimise the panel", text: "Don't expose management interfaces to the whole internet." },
      { term: "Patch aggressively", text: "Plugin/theme CVEs are the #1 WordPress entry point." },
      { term: "Strong auth", text: "MFA and unique passwords for every admin account." },
      { term: "Monitoring", text: "Alert on login spikes and unexpected file changes." },
    ],
  },
  {
    id: "as05",
    rank: 5,
    shortId: "AS05",
    title: "Remote Desktop (RDP) Exposed",
    navTitle: "AS05 - RDP Exposed",
    port: "3389/tcp",
    stat: "11%",
    cardDescription:
      "RDP on 3389 facing the internet — one of the most common ransomware entry points.",
    summary:
      "RDP on port 3389 facing the internet remains one of the most common ransomware entry points. Attackers brute-force and password-spray credentials and exploit historical pre-authentication bugs such as BlueKeep (CVE-2019-0708). A single guessed password yields an interactive desktop on a server inside your network.",
    examples: [
      "Credential brute-force / password spray",
      "BlueKeep (CVE-2019-0708) exploitation",
      "Initial access for ransomware crews",
    ],
    scan: [
      "$ nmap -p 3389 --script rdp-vuln-ms12-020,rdp-ntlm-info 198.51.100.20",
      "PORT     STATE SERVICE",
      "3389/tcp open  ms-wbt-server",
      "| rdp-ntlm-info:",
      "|   Target_Name: CORP",
      "|   DNS_Computer_Name: FILESRV01.corp.local",
      "|_  NLA: not enforced",
    ],
    attackerNext:
      "The leaked hostname and domain feed a password-spray; without NLA, pre-auth exploits like BlueKeep are also on the table.",
    impact: [
      "Full interactive control of an internal server",
      "Ransomware deployed directly from the desktop session",
      "Lateral movement using harvested credentials",
      "Active Directory compromise from a domain-joined host",
    ],
    fixes: [
      {
        title: "1. Don't expose RDP",
        detail: "Reach it through a VPN, ZTNA, or RD Gateway only.",
        code: "RDP via VPN / RD Gateway — never 0.0.0.0:3389",
      },
      {
        title: "2. Enforce NLA + MFA",
        detail: "Require Network Level Authentication and MFA.",
        code: "Group Policy: NLA required; MFA at the gateway",
      },
      {
        title: "3. Lockout & throttling",
        detail: "Account lockout and rate limiting stop spraying.",
        code: "Account lockout after N failures",
      },
      {
        title: "4. Patch & restrict",
        detail: "Apply OS patches and limit source IPs.",
        code: "Patch BlueKeep; allow 3389 from jump host only",
      },
    ],
    bestPractices: [
      { term: "No direct exposure", text: "Remote admin belongs behind a VPN or zero-trust gateway." },
      { term: "Strong auth", text: "NLA plus MFA defeats almost all credential attacks." },
      { term: "Patch management", text: "Pre-auth RDP CVEs are wormable — patch fast." },
      { term: "Monitoring", text: "Alert on RDP login bursts from unfamiliar geographies." },
    ],
  },
  {
    id: "as06",
    rank: 6,
    shortId: "AS06",
    title: "SNMP Service Exposed",
    navTitle: "AS06 - SNMP Exposed",
    port: "161/udp",
    stat: "9%",
    cardDescription:
      "Internet-facing SNMP — leaks device inventory and topology, and amplifies DDoS attacks.",
    summary:
      "SNMP is built for internal monitoring. Exposed to the internet — especially v1/v2c with the default `public` community string — it leaks device inventory, interfaces, routing and ARP tables, and sometimes credentials. A writable `private` community is even worse, and open SNMP is also abused as a DDoS amplifier.",
    examples: [
      "Default `public`/`private` community strings",
      "Device and topology disclosure",
      "SNMP reflection / amplification DDoS",
    ],
    scan: [
      "$ snmpwalk -v2c -c public 203.0.113.5",
      "SNMPv2-MIB::sysDescr.0 = Cisco IOS Software, C2960",
      "SNMPv2-MIB::sysName.0 = core-sw-01",
      "IF-MIB::ifDescr.2 = GigabitEthernet0/1",
      "IP-MIB::ipAdEntAddr = 10.0.0.1, 10.0.5.0 ...",
    ],
    attackerNext:
      "The attacker now has an internal network map; a writable `private` string would let them change device configuration outright.",
    impact: [
      "Detailed internal network and device mapping",
      "Leakage of configuration and sometimes credentials",
      "Device reconfiguration via a writable community string",
      "Your host conscripted into reflection/amplification DDoS",
    ],
    fixes: [
      {
        title: "1. Don't expose 161/udp",
        detail: "SNMP should never face the public internet.",
        code: "Firewall: drop 161/udp from internet",
      },
      {
        title: "2. Use SNMPv3",
        detail: "Authenticated and encrypted; retire v1/v2c.",
        code: "snmpv3 auth+priv (authPriv)",
      },
      {
        title: "3. Replace defaults",
        detail: "Remove `public`/`private`; use strong strings.",
        code: "remove community 'public' / 'private'",
      },
      {
        title: "4. Restrict & read-only",
        detail: "Allow only monitoring hosts; prefer read-only views.",
        code: "ACL: 161 from NMS only; read-only view",
      },
    ],
    bestPractices: [
      { term: "Keep it internal", text: "Management protocols stay on the management network." },
      { term: "Authenticated SNMP", text: "SNMPv3 with auth+priv, never community strings." },
      { term: "Least privilege", text: "Read-only views scoped to what monitoring needs." },
      { term: "Anti-amplification", text: "Block spoofed/forwarded SNMP at the network edge." },
    ],
  },
  {
    id: "as07",
    rank: 7,
    shortId: "AS07",
    title: "phpMyAdmin Panel Exposed",
    navTitle: "AS07 - phpMyAdmin",
    port: "HTTP/HTTPS",
    stat: "8%",
    cardDescription:
      "A public phpMyAdmin login — a friendly browser gateway straight into MySQL/MariaDB.",
    summary:
      "A publicly reachable phpMyAdmin login is a direct web gateway to the underlying MySQL/MariaDB server. Attackers brute-force the login, fingerprint the version, and exploit known phpMyAdmin CVEs. On success they get full database control — read, write, dump, and in some configurations file write or code execution — all through a browser.",
    examples: [
      "Brute-force of the phpMyAdmin login",
      "Known phpMyAdmin CVE exploitation",
      "Full database control via the browser",
    ],
    scan: [
      "$ curl -sI https://target/phpmyadmin/",
      "HTTP/1.1 200 OK",
      "$ curl -s https://target/phpmyadmin/README | head -1",
      "phpMyAdmin 4.9.7",
      "[*] login form reachable -> ready for brute-force",
    ],
    attackerNext:
      "It's the same prize as an exposed database, but through a friendly UI: guess or exploit the login and the whole DB is one click away.",
    impact: [
      "Full read/write control of the database via the web",
      "Data exfiltration and ransom",
      "Code execution via SQL-to-file writes in some setups",
      "A web-facing foothold to pivot onto the host",
    ],
    fixes: [
      {
        title: "1. Don't expose it",
        detail: "Reach admin tools via VPN or an IP allowlist.",
        code: "Allow /phpmyadmin from admin IPs / VPN only",
      },
      {
        title: "2. Add an auth layer",
        detail: "Put a reverse-proxy auth + MFA in front of it.",
        code: "auth proxy + MFA before phpMyAdmin",
      },
      {
        title: "3. Remove if unused",
        detail: "Uninstall or rename the tool when not needed.",
        code: "uninstall phpMyAdmin on prod",
      },
      {
        title: "4. Patch & strong creds",
        detail: "Keep it current and use strong DB credentials.",
        code: "update phpMyAdmin; strong DB passwords",
      },
    ],
    bestPractices: [
      { term: "Minimise panels", text: "Database management UIs should never face the internet." },
      { term: "Defence in depth", text: "Network restriction + proxy auth + strong DB creds." },
      { term: "Patch management", text: "phpMyAdmin has a long CVE history — stay current." },
      { term: "Surface monitoring", text: "Scan for /phpmyadmin, /pma, /dbadmin on your domains." },
    ],
  },
  {
    id: "as08",
    rank: 8,
    shortId: "AS08",
    title: "UPnP Service Exposed",
    navTitle: "AS08 - UPnP Exposed",
    port: "1900/udp",
    stat: "8%",
    cardDescription:
      "Internet-facing UPnP — lets attackers rewrite NAT rules, map internal hosts, and amplify DDoS.",
    summary:
      "Universal Plug and Play is designed for trusted local networks. Exposed on the WAN side (SSDP/IGD), it lets attackers manipulate port-forwarding and NAT rules, enumerate internal services and hosts, and abuse the device for SSDP reflection DDoS. It is a classic example of a protocol that was never meant to be internet-facing.",
    examples: [
      "WAN-side port-forward manipulation",
      "Internal service/host disclosure",
      "SSDP reflection / amplification DDoS",
    ],
    scan: [
      "$ # SSDP discovery probe",
      "M-SEARCH * HTTP/1.1  ST: ssdp:all",
      "<- 200 OK  LOCATION: http://203.0.113.9:5000/rootDesc.xml",
      "$ curl -s http://203.0.113.9:5000/rootDesc.xml | grep controlURL",
      "<controlURL>/ctl/IPConn</controlURL>  (WANIPConnection)",
    ],
    attackerNext:
      "With the IGD control URL the attacker can add their own port-forwards — exposing internal hosts straight to the internet.",
    impact: [
      "Attacker-controlled NAT rules that expose internal services",
      "Reconnaissance of internal hosts and device details",
      "SSDP reflection amplifying DDoS against third parties",
      "Compromise of routers and IoT devices",
    ],
    fixes: [
      {
        title: "1. Disable WAN UPnP",
        detail: "Never run UPnP/IGD on the internet-facing interface.",
        code: "router: disable UPnP on WAN",
      },
      {
        title: "2. Block SSDP inbound",
        detail: "Drop 1900/udp arriving from the internet.",
        code: "Firewall: drop 1900/udp inbound",
      },
      {
        title: "3. Segment IoT",
        detail: "Isolate consumer/IoT gear from critical systems.",
        code: "VLAN: IoT segment, no lateral access",
      },
      {
        title: "4. Patch firmware",
        detail: "Update device firmware; use authenticated mgmt only.",
        code: "firmware updates; authenticated remote mgmt",
      },
    ],
    bestPractices: [
      { term: "LAN-only by design", text: "UPnP belongs on trusted internal segments, never the WAN." },
      { term: "Default-deny edge", text: "Block discovery/control protocols at the perimeter." },
      { term: "Segmentation", text: "Keep IoT and consumer devices off the corporate network." },
      { term: "Anti-amplification", text: "Filter spoofed traffic so your devices can't reflect DDoS." },
    ],
  },
  {
    id: "as09",
    rank: 9,
    shortId: "AS09",
    title: "NTP Service Exposed",
    navTitle: "AS09 - NTP Exposed",
    port: "123/udp",
    stat: "7%",
    cardDescription:
      "An open NTP server answering monlist — a powerful DDoS amplifier that also leaks recent clients.",
    summary:
      "An open NTP server that answers legacy `monlist` (and mode 6/7) queries is a powerful DDoS amplifier: a tiny spoofed request triggers a huge response aimed at the victim. It can also leak the list of recent clients, disclosing internal addresses and traffic patterns.",
    examples: [
      "monlist amplification (large factor)",
      "Recent-client list disclosure",
      "Participation in reflection DDoS",
    ],
    scan: [
      "$ ntpdc -n -c monlist 198.51.100.7",
      "remote address          count   m  ver",
      "10.0.4.21               1832    7  2",
      "10.0.4.22               1190    7  2",
      "203.0.113.40             640    7  2",
      "[*] small request -> large reply (amplification)",
    ],
    attackerNext:
      "A spoofed monlist request turns this server into a DDoS cannon, and the reply quietly leaks recent internal clients.",
    impact: [
      "Your server weaponised in reflection/amplification DDoS",
      "Disclosure of recent client and internal IP addresses",
      "Reputation damage and IP blocklisting",
      "Bandwidth and infrastructure costs from abuse",
    ],
    fixes: [
      {
        title: "1. Disable monlist",
        detail: "Upgrade ntpd and turn off the monitor query.",
        code: "disable monitor   # or use chrony",
      },
      {
        title: "2. Restrict queries",
        detail: "Default-deny status/config queries.",
        code: "restrict default nomodify noquery notrap",
      },
      {
        title: "3. Filter at the edge",
        detail: "Block 123/udp for hosts that aren't time servers.",
        code: "Firewall: 123/udp to NTP servers only",
      },
      {
        title: "4. Anti-spoofing",
        detail: "Deploy BCP38 ingress/egress filtering.",
        code: "BCP38 source-address validation",
      },
    ],
    bestPractices: [
      { term: "Modern daemon", text: "Use a current ntpd or chrony without the monlist command." },
      { term: "Default-deny", text: "Answer time, refuse status and config queries." },
      { term: "Edge filtering", text: "Only real time servers should answer 123/udp from outside." },
      { term: "Anti-amplification", text: "BCP38 filtering stops spoofed reflection at the source." },
    ],
  },
  {
    id: "as10",
    rank: 10,
    shortId: "AS10",
    title: "RPC Portmapper Exposed",
    navTitle: "AS10 - RPC Portmapper",
    port: "111/tcp+udp",
    stat: "7%",
    cardDescription:
      "An exposed rpcbind/portmapper — reveals internal RPC services (NFS, NIS) and amplifies DDoS.",
    summary:
      "The RPC portmapper (rpcbind) maps RPC programs such as NFS and NIS to their ports. It was never meant to face the internet, yet it remains accessible through misconfiguration. An exposed port 111 reveals which RPC services are running — a roadmap for targeting world-readable NFS exports and other legacy services — and is itself a DDoS amplification vector.",
    examples: [
      "RPC service enumeration via rpcinfo",
      "Exposed NFS/NIS discovery",
      "Portmap/rpcbind reflection DDoS",
    ],
    scan: [
      "$ rpcinfo -p 192.0.2.20",
      "   program vers proto   port  service",
      "    100000    4   tcp    111  portmapper",
      "    100003    3   tcp   2049  nfs",
      "    100005    3   udp  35412  mountd",
      "    100024    1   udp  47654  status",
    ],
    attackerNext:
      "The service list points the attacker straight at the NFS export (often world-readable) or another legacy RPC service to exploit.",
    impact: [
      "A roadmap of internal RPC services to target",
      "Data exposure via world-readable NFS exports",
      "Portmap/rpcbind abused for amplification DDoS",
      "Exploitation of legacy, unpatched RPC services",
    ],
    fixes: [
      {
        title: "1. Block port 111",
        detail: "Never expose the portmapper to the internet.",
        code: "Firewall: drop 111/tcp+udp from internet",
      },
      {
        title: "2. Disable if unused",
        detail: "Stop rpcbind where no RPC service needs it.",
        code: "systemctl disable --now rpcbind",
      },
      {
        title: "3. Restrict & lock NFS",
        detail: "Limit to trusted hosts; tighten NFS exports.",
        code: "/etc/exports: specific hosts, ro, root_squash",
      },
      {
        title: "4. Modernise",
        detail: "Use NFSv4 with authentication; segment legacy.",
        code: "NFSv4 + Kerberos; isolate legacy RPC",
      },
    ],
    bestPractices: [
      { term: "Perimeter default-deny", text: "Legacy RPC services must never be reachable from outside." },
      { term: "Disable the unused", text: "Turn off rpcbind/NFS where nothing depends on them." },
      { term: "Lock down NFS", text: "Specific host lists, read-only where possible, root_squash on." },
      { term: "Anti-amplification", text: "Filter spoofed 111/udp so rpcbind can't reflect DDoS." },
    ],
  },
];
