import express from 'express';

const router = express.Router();

// VULNERABILITY A05: Security Misconfiguration
// This demonstrates various security misconfigurations

// VULNERABILITY: Debug information exposure
router.get('/debug', (req, res) => {
  res.json({
    vulnerability: 'A05 - Security Misconfiguration',
    description: 'Debug information exposure',
    environment: process.env,
    nodejs_version: process.version,
    platform: process.platform,
    memory_usage: process.memoryUsage(),
    explanation: 'Debug endpoints expose sensitive system information'
  });
});

// VULNERABILITY: Default credentials
router.post('/admin-login', (req, res) => {
  const { username, password } = req.body;

  // VULNERABLE: Default admin credentials
  if (username === 'admin' && password === 'admin') {
    res.json({
      vulnerability: 'A05 - Security Misconfiguration',
      description: 'Default admin credentials accepted',
      message: 'Admin access granted',
      explanation: 'Default credentials should be changed immediately'
    });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// VULNERABILITY: Error details exposure
router.get('/error', (req, res) => {
  try {
    // Intentionally cause an error
    throw new Error('Database connection failed at /var/lib/mysql/sock with user root:password123');
  } catch (error) {
    // VULNERABLE: Exposing detailed error information
    const err = error as Error;
    res.status(500).json({
      vulnerability: 'A05 - Security Misconfiguration',
      description: 'Detailed error information exposure',
      error: err.message,
      stack: err.stack,
      explanation: 'Detailed errors can reveal system architecture and credentials'
    });
  }
});

// VULNERABILITY: Unnecessary features enabled
router.get('/features', (req, res) => {
  res.json({
    vulnerability: 'A05 - Security Misconfiguration',
    description: 'Unnecessary features enabled',
    features: {
      file_upload: true,
      remote_debugging: true,
      admin_interface: true,
      backup_downloads: true,
      system_info: true
    },
    explanation: 'Unnecessary features increase attack surface'
  });
});

export default router;