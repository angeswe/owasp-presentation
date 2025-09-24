import express from 'express';
import { UserModel } from '../models/User';

const router = express.Router();

// VULNERABILITY A09: Security Logging and Monitoring Failures

// VULNERABILITY: No logging of security events
router.post('/sensitive-action', async (req, res) => {
  const { user_id, action, target } = req.body;

  // VULNERABLE: No logging of sensitive actions
  // This should log who did what, when, and to what

  res.json({
    vulnerability: 'A09 - Security Logging and Monitoring Failures',
    description: 'No logging of sensitive security events',
    action_performed: action,
    target: target,
    user_id: user_id,
    explanation: 'Sensitive actions like privilege escalation are not logged'
  });
});

// VULNERABILITY: Insufficient login attempt logging
router.post('/login-attempt', async (req, res) => {
  const { username, password, ip } = req.body;

  try {
    const user = await UserModel.authenticate(username, password);

    if (user) {
      // VULNERABLE: Successful logins not properly logged
      res.json({
        vulnerability: 'A09 - Security Logging and Monitoring Failures',
        description: 'Insufficient login logging',
        status: 'success',
        message: 'Login successful - but not logged properly'
      });
    } else {
      // VULNERABLE: Failed attempts not logged with enough detail
      res.status(401).json({
        vulnerability: 'A09 - Security Logging and Monitoring Failures',
        status: 'failed',
        message: 'Login failed - suspicious activity not tracked'
      });
    }
  } catch (error) {
    res.status(500).json({ error: 'Login error' });
  }
});

// VULNERABILITY: No anomaly detection
router.get('/suspicious-activity', (req, res) => {
  const { user_id, activity_count } = req.query;

  // VULNERABLE: No detection of suspicious patterns
  // Multiple rapid requests should trigger alerts

  res.json({
    vulnerability: 'A09 - Security Logging and Monitoring Failures',
    description: 'No anomaly detection',
    user_id: user_id,
    activity_count: activity_count,
    warning: 'High activity detected but no alerts generated',
    explanation: 'System lacks monitoring for unusual patterns'
  });
});

// VULNERABILITY: Logs contain sensitive information
router.get('/logs', (req, res) => {
  // VULNERABLE: Exposing sensitive data in logs
  const sampleLogs = [
    '2024-01-01 10:00:00 - User admin logged in with password admin123',
    '2024-01-01 10:01:00 - API key abc123xyz used for request',
    '2024-01-01 10:02:00 - Credit card 4532-1234-5678-9012 processed',
    '2024-01-01 10:03:00 - Database query: SELECT * FROM users WHERE ssn=123-45-6789'
  ];

  res.json({
    vulnerability: 'A09 - Security Logging and Monitoring Failures',
    description: 'Sensitive data in logs',
    logs: sampleLogs,
    explanation: 'Logs contain passwords, API keys, and PII that should be redacted'
  });
});

// VULNERABILITY: No real-time monitoring
router.post('/admin-action', (req, res) => {
  const { action, target_user } = req.body;

  // VULNERABLE: Critical admin actions not monitored in real-time
  res.json({
    vulnerability: 'A09 - Security Logging and Monitoring Failures',
    description: 'No real-time monitoring of critical actions',
    admin_action: action,
    target: target_user,
    timestamp: new Date().toISOString(),
    alert_sent: false, // VULNERABLE: No alerts
    explanation: 'Admin actions like user deletion should trigger immediate alerts'
  });
});

// VULNERABILITY: Insufficient audit trail
router.get('/audit-trail/:user_id', (req, res) => {
  const { user_id } = req.params;

  // VULNERABLE: Incomplete audit trail
  const incompleteAudit = {
    user_id: user_id,
    last_login: '2024-01-01',
    // Missing: IP addresses, user agents, failure attempts, etc.
  };

  res.json({
    vulnerability: 'A09 - Security Logging and Monitoring Failures',
    description: 'Insufficient audit trail',
    audit: incompleteAudit,
    missing_data: [
      'IP addresses',
      'User agents',
      'Failed login attempts',
      'Permission changes',
      'Data access logs'
    ],
    explanation: 'Audit trails lack critical information for forensics'
  });
});

export default router;