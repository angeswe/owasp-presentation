# OWASP Top 10 Presentation Guide

## Pre-Presentation Setup

### Technical Requirements
- [ ] Application running on isolated network
- [ ] Backend API on http://localhost:3001
- [ ] Frontend app on http://localhost:3000
- [ ] Browser with developer tools
- [ ] Screen sharing/projection ready

### Safety Checklist
- [ ] Confirm no internet access during demo
- [ ] Verify isolated environment
- [ ] Backup slides in case of technical issues
- [ ] Test all demo endpoints beforehand

## Presentation Flow (60-90 minutes)

### Introduction (10 minutes)
1. **Opening Warning**
   - Emphasize educational purpose only
   - Explain intentional vulnerabilities
   - Stress isolation requirements

2. **OWASP Overview**
   - What is OWASP
   - Top 10 methodology
   - 2025 updates: Security Misconfiguration up to #2; new **Software Supply
     Chain Failures** (#3) and **Mishandling of Exceptional Conditions** (#10);
     SSRF merged into Broken Access Control (#1)

### Core Demonstrations (60 minutes - 6 min per vulnerability)

#### A01 - Broken Access Control (6 min)
**Demo Script:**
1. Navigate to `/web/a01`
2. Show direct object reference demo
   - Try user ID 1 (admin data exposed)
   - Try user ID 2 (regular user)
   - Explain authorization bypass
3. Demo admin panel access + privilege escalation
   - Show unrestricted admin functions
4. **SSRF (merged into A01 for 2025)** — Demos 4 & 5
   - Fetch an internal URL the server shouldn't reach
   - Port-scan localhost from the server's vantage point
5. **Key Points:**
   - Most common vulnerability
   - Leads to data breaches
   - Authorization vs authentication
   - SSRF is now an access-control failure at the network layer

#### A02 - Security Misconfiguration (6 min)
**Demo Script:**
1. Navigate to `/web/a02`
2. Show debug endpoint exposure
3. Demonstrate default credentials
4. **Key Points:**
   - Configuration management (now #2, up from #5 in 2021)
   - Default settings dangers
   - Security hardening

#### A03 - Software Supply Chain Failures (6 min) — *new in 2025*
**Demo Script:**
1. Navigate to `/web/a03`
2. Scan for outdated/vulnerable dependencies and unpatched CVEs
3. **Dependency confusion** — public package shadows the internal one
4. **Unsigned artifact** — deploy a tarball with no checksum/signature
5. **Malicious postinstall** — show what an install script would harvest
6. **Key Points:**
   - Broadens the old "Vulnerable & Outdated Components"
   - The whole chain is in scope: deps, build systems, distribution
   - Defences: SBOM, pinned/integrity-checked installs, scoped registries,
     signed artifacts (SLSA/sigstore)

#### A04 - Cryptographic Failures (6 min)
**Demo Script:**
1. Navigate to `/web/a04`
2. Show weak encryption demo
   - DES algorithm exposure
   - Key exposure in response
3. Demonstrate plain text passwords
4. **Key Points:**
   - Data in transit and at rest
   - Encryption vs encoding
   - Key management importance

#### A05 - Injection (6 min)
**Demo Script:**
1. Navigate to `/web/a05`
2. SQL injection demonstration
   - Try: `' OR 1=1--`
   - Show data extraction
   - Explain query structure
3. **Key Points:**
   - Input validation crucial
   - Parameterized queries
   - Multiple injection types

#### A06 - Insecure Design (6 min)
**Demo Script:**
1. Navigate to `/web/a06`
2. Show business logic flaws
3. **Key Points:**
   - Design vs implementation
   - Threat modeling importance
   - Security by design

#### A07 - Authentication Failures (6 min)
**Demo Script:**
1. Navigate to `/web/a07`
2. Show weak password demo
3. Demonstrate session issues
4. **Key Points:**
   - Authentication vs authorization
   - Session management
   - MFA importance

#### A08 - Software or Data Integrity Failures (6 min)
**Demo Script:**
1. Navigate to `/web/a08`
2. Show unsigned upload / insecure deserialization demo
3. **Key Points:**
   - Integrity of code and data
   - Code signing importance
   - CI/CD security

#### A09 - Security Logging and Alerting Failures (6 min)
**Demo Script:**
1. Navigate to `/web/a09`
2. Show missing logging
3. Demonstrate exposed logs
4. **Key Points:**
   - Incident response
   - Alerting importance (renamed from "Monitoring" in 2025)
   - Log security

#### A10 - Mishandling of Exceptional Conditions (6 min) — *new in 2025*
**Demo Script:**
1. Navigate to `/web/a10`
2. Trigger the divide-by-zero error — show the leaked stack trace, source
   path and runtime version returned to the client
3. Run the vulnerable lookup — show the leaked SQL exposing `password_hash`
   and `api_key`; then click the **secure** button to show the opaque,
   reference-id response for the same failure
4. **Key Points:**
   - Errors must be logged server-side, never returned to the client
   - Fail closed, not open (an exception in a check must deny)
   - Verbose errors hand attackers a free map of the internals

### Conclusion (10 minutes)
1. **Key Takeaways**
   - Security is a process
   - Multiple layers needed
   - Regular assessment important

2. **Next Steps**
   - Security training
   - Code review processes
   - Security testing integration

3. **Resources**
   - OWASP references
   - Training platforms
   - Security tools

## Bonus Track: Top 10 Attack Surface Exposures (2026)

This track shifts the lens from *application vulnerability classes* to *exposures* —
services and panels that should never have been reachable from the public internet.
It is based on an analysis of ~3,000 real-world attack surfaces (reported by The
Hacker News, "The Top 10 Attack Surface Exposures in 2026").

**Framing for the audience:** "The OWASP lists tell you how attackers break in. This
list is about the doors you left open." Lead with the headline stats:
- 60% had at least one HTTP panel exposed
- 49% exposed a risky port or service
- 42% had a database reachable directly from the internet
- 30% exposed files or information that shouldn't be

**Demo flow (navigate to `/asm`):** everything lives on a single page. Each of the ten
cards has a collapsible **"Talk-through details"** section — expand it to reveal the
simulated recon scan (what an attacker sees), the impact, and the remediation. Read the
title + stat + port, then expand to confirm. For a full per-exposure script, see
[`ATTACK_SURFACE_PRESENTATION_GUIDE.md`](./ATTACK_SURFACE_PRESENTATION_GUIDE.md).

| #    | Exposure                  | Seen on | Talking point                                  |
|------|---------------------------|---------|------------------------------------------------|
| AS01 | MySQL Database Exposed    | 26%     | Open 3306 + weak root password = ransomware    |
| AS02 | Postgres Database Exposed | 16%     | `trust` auth needs no password at all          |
| AS03 | API Documentation Exposed | 15%     | Swagger/GraphQL maps every admin endpoint      |
| AS04 | WordPress Admin Panel     | 15%     | /wp-login brute force + plugin CVEs            |
| AS05 | Remote Desktop (RDP)      | 11%     | Top ransomware entry point; BlueKeep           |
| AS06 | SNMP Service              | 9%      | Default `public` string leaks the network      |
| AS07 | phpMyAdmin Panel          | 8%      | A browser gateway straight into the DB         |
| AS08 | UPnP Service              | 8%      | WAN UPnP rewrites NAT; SSDP amplification      |
| AS09 | NTP Service               | 7%      | monlist amplification DDoS                      |
| AS10 | RPC Portmapper            | 7%      | rpcinfo enumerates NFS/NIS to target           |

**Key takeaway:** patching matters, but attack-surface *reduction* — turning off and
firewalling what never needed to be public — prevents whole classes of attack before
a single exploit is written.

## Presentation Tips

### Audience Engagement
- Ask questions throughout
- Encourage participation
- Relate to real-world incidents
- Use concrete examples

### Technical Demonstrations
- Show actual exploitation
- Explain what's happening
- Connect to business impact
- Demonstrate fixes

### Common Questions & Answers

**Q: Are these real vulnerabilities?**
A: Yes, these represent actual vulnerability patterns found in production applications.

**Q: How common are these issues?**
A: OWASP Top 10 represents the most critical and common security risks based on industry data.

**Q: What's the business impact?**
A: Data breaches, financial loss, reputation damage, regulatory fines, and legal liability.

**Q: How do we prevent these?**
A: Security training, secure coding practices, regular testing, and security-focused development processes.

**Q: What tools can help?**
A: Static analysis, dynamic testing, dependency scanners, and security frameworks.

## Emergency Procedures

### Technical Issues
1. Have backup slides ready
2. Use screenshots if demos fail
3. Continue with explanation
4. Address issues during break

### Security Concerns
1. Immediately disconnect network
2. Stop all services
3. Verify isolation
4. Address concerns transparently

## Post-Presentation

### Follow-up Actions
- Share presentation materials
- Provide resource links
- Schedule follow-up sessions
- Plan implementation steps

### Feedback Collection
- Gather audience feedback
- Note improvement areas
- Update presentation based on input
- Track security awareness impact

## Additional Resources

### Extended Demos
- More complex attack chains
- Real vulnerability examples
- Secure coding alternatives
- Testing methodology demos

### Advanced Topics
- Threat modeling
- Security architecture
- Incident response
- Compliance requirements