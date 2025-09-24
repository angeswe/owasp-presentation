import express from 'express';

const router = express.Router();

// VULNERABILITY A06: Vulnerable and Outdated Components
// This demonstrates using components with known vulnerabilities

// VULNERABILITY: Outdated dependencies info
router.get('/dependencies', (req, res) => {
  res.json({
    vulnerability: 'A06 - Vulnerable and Outdated Components',
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
    vulnerability: 'A06 - Vulnerable and Outdated Components',
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
    vulnerability: 'A06 - Vulnerable and Outdated Components',
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

export default router;