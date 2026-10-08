# OWASP Top 10 Presentation Guide (30-minute run sheet)

This guide covers the whole talk: the OWASP Top 10:2025 (Web), the OWASP Top 10
for LLM Applications (2025), and a short closing block of four tips for secure
coding with agents. The LLM half has its own script in
[`LLM_PRESENTATION_GUIDE.md`](./LLM_PRESENTATION_GUIDE.md).

The slot is 30 minutes. The 20 Top 10 items get about 75 seconds each. Every demo
in the app is one click: the input is prefilled with a payload that works. Say what
the item is, click, read the response, say the fix, move on. Do not type during
the talk.

## Before you start

- [ ] `npm run dev:all` from the repo root
- [ ] http://localhost:3001/health returns `VULNERABLE`
- [ ] http://localhost:3000/web, http://localhost:3000/llm and
      http://localhost:3000/agents load
- [ ] Browser zoom at 125% or more so the response box is readable
- [ ] No internet needed; run on an isolated network
- [ ] Click through every page once. The A01 privilege escalation and A06
      password reset change the database. Restart the backend before the talk to
      reset it.

## Schedule

| Time  | Block                     | Notes                          |
|-------|---------------------------|--------------------------------|
| 0:00  | Intro                     | 1 minute                       |
| 1:00  | Web Top 10 (A01 to A10)   | 13 minutes, ~75 s each         |
| 14:00 | LLM Top 10 (LLM01 to 10)  | 13 minutes, ~75 s each         |
| 27:00 | Agent coding tips (1 to 4)| 2 minutes, ~30 s each          |
| 29:00 | Wrap-up                   | 1 minute                       |

If you run late, skip the second demo on any page. The first demo on every page
is the one that matters.

## Intro (1 minute)

1. Open `/`. Say the app is intentionally vulnerable and never leaves this laptop.
2. Say what changed in the 2025 list: Security Misconfiguration is up to #2,
   Software Supply Chain Failures (#3) and Mishandling of Exceptional Conditions
   (#10) are new, and SSRF was merged into Broken Access Control (#1).
3. Click "Web Top 10".

## Web Top 10 (13 minutes)

Each page has a "How to Fix" section below the demos. Do not scroll to it during
the talk. Say the fix in one sentence instead.

### A01 Broken Access Control (`/web/a01`)
- Click **Access User Data** (user 1). Admin record with password and API key
  comes back with no login.
- If time: **Change User Role** makes user 2 an admin. **Fetch URL** makes the
  server call its own admin endpoint (SSRF, now part of A01).
- Fix: check authorization on the server for every object, deny by default,
  allow-list outbound URLs.

### A02 Security Misconfiguration (`/web/a02`)
- Click **Attempt Login** with admin/admin. Access granted.
- If time: **Fetch Debug Information** shows a production debug endpoint with
  database and cloud credentials in the environment.
- Fix: change defaults, disable debug in production, harden with a checklist.

### A03 Software Supply Chain Failures (`/web/a03`, new in 2025)
- Click **Scan Dependencies**. Old versions with known CVEs.
- If time: **Resolve Package** shows a public package shadowing the internal
  one. **Run postinstall (simulated)** shows what an install script can steal.
- Fix: lock files, integrity checks, scoped private registries, SBOM, signed
  artifacts.

### A04 Cryptographic Failures (`/web/a04`)
- Click **Hash with MD5**. Same input, same hash, rainbow tables work.
- If time: **Encode with Base64** shows Base64 decoded back in one step.
- Fix: bcrypt/argon2 for passwords, AES-GCM with managed keys for data.

### A05 Injection (`/web/a05`)
- Click **Search Posts** with `' OR 1=1--`. Private posts come back.
- If time: **Ping Host** with `8.8.8.8; ls` runs a second command on the server.
- Fix: parameterized queries, never build shell commands from input.

### A06 Insecure Design (`/web/a06`)
- Click **Reset Password**. The reset needs no proof of identity.
- If time: **Make Purchase** with a negative quantity gives a negative total.
- Fix: threat model the flow, validate business rules on the server.

### A07 Authentication Failures (`/web/a07`)
- Click **Attempt Login** (user / wrong-password) three times. Attempt counter
  rises, no lockout.
- If time: **Login for JWT** shows a token signed with a weak secret and no expiry.
- Fix: rate limit and lock out, strong secrets, short-lived tokens, MFA.

### A08 Software or Data Integrity Failures (`/web/a08`)
- Click **Deserialize Data**. The client-supplied object sets `role: admin`.
- If time: **Check for Updates** shows an update over HTTP with no checksum or
  signature.
- Fix: never trust serialized client data, sign updates and verify before use.

### A09 Security Logging and Alerting Failures (`/web/a09`)
- Click **Perform Action**. A role change happens and nothing is logged.
- If time: **Fetch Sensitive Logs** shows passwords and card numbers in the log.
- Fix: log security events without secrets, alert on them.

### A10 Mishandling of Exceptional Conditions (`/web/a10`, new in 2025)
- Click **Divide** by zero. Stack trace, file path and runtime version leak.
- Click **Look Up (vulnerable)**, then **Look Up (secure handling)**. Same failure, the
  secure one returns only a reference id.
- Fix: catch at the boundary, log server-side, return an opaque error, fail
  closed.

Then click "LLM Top 10" and follow the LLM guide.

## Agent coding tips (2 minutes)

Open `/agents` (the fourth card on `/`). It is one page with four cards and no
backend. Nothing to click: scroll from card to card. For each card, say the title,
point at the dark "What goes wrong" block, and read the first item under "What to
do". About 30 seconds per card.

Opening line: "Most of this code is now written by an agent. The two lists still
apply to it. Four habits."

1. **Write the security rules down.** The summary said all tests pass. The route
   still lets any user read any invoice. Nobody wrote the rule down. Put the rules
   in `AGENTS.md` or `CLAUDE.md`. Ask for a threat model before the code, and ask
   for the test that must fail before you approve: user B reads user A's invoice
   and gets 403.
2. **Limit what the agent can do.** Most of us run auto mode. A second model
   approves each action, not you. It blocks force pushes and production deploys.
   It allows reading `.env` and pushing to main, and it misses some actions. Deny
   and ask rules still apply in auto mode, so set them. Use a sandbox and keep
   production credentials off the machine.
3. **Treat everything the agent reads as untrusted.** A README or a web page can
   give it orders. Against a current model this rarely works on the first try. It
   works often enough that you must assume it will. The agent always holds
   private data (your code, its tokens), so limit what it reads from outside and
   where it can send data.
4. **Verify every dependency the agent adds.** Models invent package names and
   attackers register them. Read the study numbers from the card.

Each card ends with links to the Top 10 items that show the same risk. Use them if
someone asks a question. If you run late, do cards 2 and 3 only. For a full audit
of an existing repo, Cloudflare publishes a security-audit skill. The link is at
the bottom of the page.

## Wrap-up (1 minute)

- Every web demo was one missing server-side check. Every LLM demo was the model
  being trusted as if it were code.
- Ask the audience to pick one item and check their own app against it this week.
- Point to https://owasp.org/Top10/ and https://genai.owasp.org/.

## If a demo fails

- The backend prints every request. Look at the terminal.
- Restart the backend. It reseeds the database.
- Read the response shape out loud from this guide and move on.

## Bonus track: Top 10 Attack Surface Exposures

`/asm` is a single page with ten cards on services that should never be reachable
from the internet (open databases, admin panels, RDP, SNMP). It is not part of the
30-minute run. Use it as a five-minute extra if the room asks "how do attackers
get in at all?". Script in
[`ATTACK_SURFACE_PRESENTATION_GUIDE.md`](./ATTACK_SURFACE_PRESENTATION_GUIDE.md).
