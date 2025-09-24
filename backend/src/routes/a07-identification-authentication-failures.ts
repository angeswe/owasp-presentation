import express from 'express';
import jwt from 'jsonwebtoken';
import { UserModel } from '../models/User';

const router = express.Router();

// VULNERABILITY A07: Identification and Authentication Failures

// VULNERABILITY: Weak password policy
router.post('/register', async (req, res) => {
  const { username, password, email } = req.body;

  // VULNERABLE: No password strength validation
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const userId = await UserModel.create({ username, password, email, api_key: 'key-' + Date.now() });

    res.json({
      vulnerability: 'A07 - Identification and Authentication Failures',
      description: 'Weak password policy',
      user_id: userId,
      password: password, // VULNERABLE: Returning password
      explanation: 'No password complexity requirements enforced'
    });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// VULNERABILITY: Predictable session tokens
router.post('/login-session', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await UserModel.authenticate(username, password);
    if (user) {
      // VULNERABLE: Predictable session token
      const sessionToken = `${user.id}_${Date.now()}`;

      res.json({
        vulnerability: 'A07 - Identification and Authentication Failures',
        description: 'Predictable session tokens',
        session_token: sessionToken,
        user_id: user.id,
        explanation: 'Session tokens are predictable and can be guessed'
      });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// VULNERABILITY: Weak JWT secret and no expiration
router.post('/jwt-login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await UserModel.authenticate(username, password);
    if (user) {
      // VULNERABLE: Weak JWT secret and no expiration
      const token = jwt.sign(
        { userId: user.id, role: user.role },
        'weak-secret', // VULNERABLE: Weak secret
        // No expiration set - VULNERABLE
      );

      res.json({
        vulnerability: 'A07 - Identification and Authentication Failures',
        description: 'Weak JWT implementation',
        jwt_token: token,
        secret: 'weak-secret', // VULNERABLE: Exposing secret
        explanation: 'JWT uses weak secret and never expires'
      });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// VULNERABILITY: Brute force vulnerability
let loginAttempts: Record<string, { count: number; lastAttempt: number }> = {};

router.post('/brute-force-login', async (req, res) => {
  const { username, password } = req.body;

  // VULNERABLE: No rate limiting or account lockout
  const user = await UserModel.authenticate(username, password);

  if (user) {
    loginAttempts[username] = { count: 0, lastAttempt: Date.now() };
    res.json({
      vulnerability: 'A07 - Identification and Authentication Failures',
      description: 'No brute force protection',
      message: 'Login successful',
      attempts: loginAttempts[username]?.count || 0
    });
  } else {
    const currentAttempts = loginAttempts[username] || { count: 0, lastAttempt: Date.now() };
    currentAttempts.count += 1;
    currentAttempts.lastAttempt = Date.now();
    loginAttempts[username] = currentAttempts;

    res.status(401).json({
      vulnerability: 'A07 - Identification and Authentication Failures',
      error: 'Invalid credentials',
      attempts: currentAttempts.count,
      explanation: 'No account lockout after failed attempts'
    });
  }
});

// VULNERABILITY: Password recovery without proper verification
router.post('/forgot-password', async (req, res) => {
  const { username } = req.body;

  try {
    const user = await UserModel.findByUsername(username);
    if (user) {
      // VULNERABLE: Returning password in recovery
      res.json({
        vulnerability: 'A07 - Identification and Authentication Failures',
        description: 'Insecure password recovery',
        username: user.username,
        password: user.password, // VULNERABLE: Exposing password
        explanation: 'Password recovery exposes actual password'
      });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Recovery failed' });
  }
});

export default router;