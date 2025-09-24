import express from 'express';
import crypto from 'crypto';
import { UserModel } from '../models/User';

const router = express.Router();

// VULNERABILITY A02: Cryptographic Failures
// This route demonstrates various cryptographic weaknesses

// VULNERABILITY: Weak encryption algorithm
router.post('/weak-encryption', (req, res) => {
  const { data } = req.body;

  if (!data) {
    return res.status(400).json({ error: 'Data is required' });
  }

  try {
    // VULNERABLE: Using weak RC4 encryption (stream cipher with known vulnerabilities)
    const algorithm = 'rc4';
    const key = Buffer.from('weakkey123'); // VULNERABLE: Weak key
    const cipher = crypto.createCipheriv(algorithm, key, null); // RC4 doesn't use IV

    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    res.json({
      vulnerability: 'A02 - Cryptographic Failures',
      description: 'Using weak RC4 encryption with predictable key',
      encrypted: encrypted,
      algorithm: algorithm,
      key: key.toString(), // VULNERABLE: Exposing the key
      explanation: 'RC4 is cryptographically broken due to biases in the keystream and the key is exposed in the response'
    });
  } catch (error) {
    // Fallback to demonstrating weakness with simple MD5 hash
    const hash = crypto.createHash('md5').update(data).digest('hex');

    res.json({
      vulnerability: 'A02 - Cryptographic Failures',
      description: 'Using weak MD5 hash instead of encryption',
      encrypted: hash,
      algorithm: 'md5',
      original: data, // VULNERABLE: Exposing original data for comparison
      explanation: 'MD5 is cryptographically broken and can be cracked with tools like John the Ripper or hashcat',
      crack_instructions: {
        john_the_ripper: `echo "${hash}" > hash.txt && john --format=raw-md5 hash.txt`,
        hashcat: `hashcat -m 0 -a 3 ${hash} ?a?a?a?a?a?a?a?a`,
        online_tools: 'Try crackstation.net, md5decrypt.net, or similar'
      }
    });
  }
});

// VULNERABILITY: Plain text password storage and transmission
router.post('/login-plaintext', async (req, res) => {
  const { username, password } = req.body;

  try {
    // VULNERABLE: Authenticating with plain text passwords
    const user = await UserModel.authenticate(username, password);

    if (user) {
      res.json({
        vulnerability: 'A02 - Cryptographic Failures',
        description: 'Plain text password storage and authentication',
        user: {
          id: user.id,
          username: user.username,
          password: user.password, // VULNERABLE: Returning plain text password
          role: user.role
        },
        explanation: 'Passwords are stored and transmitted in plain text'
      });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// VULNERABILITY: Weak hashing algorithm
router.post('/weak-hash', (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }

  // VULNERABLE: Using MD5 for password hashing
  const hash = crypto.createHash('md5').update(password).digest('hex');

  res.json({
    vulnerability: 'A02 - Cryptographic Failures',
    description: 'Using MD5 for password hashing',
    password: password,
    hash: hash,
    explanation: 'MD5 is cryptographically broken and vulnerable to rainbow table attacks'
  });
});

// VULNERABILITY: Hardcoded cryptographic secrets
const HARDCODED_SECRET = 'super-secret-key-123'; // VULNERABLE: Hardcoded secret

router.post('/hardcoded-secret', (req, res) => {
  const { data } = req.body;

  if (!data) {
    return res.status(400).json({ error: 'Data is required' });
  }

  // VULNERABLE: Using hardcoded secret for HMAC
  const hmac = crypto.createHmac('sha256', HARDCODED_SECRET);
  hmac.update(data);
  const signature = hmac.digest('hex');

  res.json({
    vulnerability: 'A02 - Cryptographic Failures',
    description: 'Using hardcoded secret for HMAC',
    data: data,
    signature: signature,
    secret: HARDCODED_SECRET, // VULNERABLE: Exposing the secret
    explanation: 'Cryptographic secrets should never be hardcoded in source code'
  });
});

// VULNERABILITY: Insufficient key length and predictable IV
router.post('/weak-aes', (req, res) => {
  const { data } = req.body;

  if (!data) {
    return res.status(400).json({ error: 'Data is required' });
  }

  // VULNERABLE: Weak key and predictable IV
  const algorithm = 'aes-128-cbc';
  const key = Buffer.from('1234567890123456'); // VULNERABLE: Predictable key
  const iv = Buffer.from('1234567890123456');  // VULNERABLE: Static IV

  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  res.json({
    vulnerability: 'A02 - Cryptographic Failures',
    description: 'Weak AES encryption with predictable key and IV',
    encrypted: encrypted,
    key: key.toString('hex'),
    iv: iv.toString('hex'),
    explanation: 'Using predictable keys and static IVs makes encryption vulnerable'
  });
});

// VULNERABILITY: Insecure random number generation
router.get('/insecure-random', (req, res) => {
  // VULNERABLE: Using Math.random() for security-sensitive operations
  const insecureToken = Math.random().toString(36).substring(2);

  // VULNERABLE: Predictable session ID
  const sessionId = `session_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

  res.json({
    vulnerability: 'A02 - Cryptographic Failures',
    description: 'Insecure random number generation',
    insecure_token: insecureToken,
    session_id: sessionId,
    explanation: 'Math.random() is not cryptographically secure and predictable'
  });
});

// VULNERABILITY: Base64 encoding mistaken for encryption
router.post('/fake-encryption', (req, res) => {
  const { sensitive_data } = req.body;

  if (!sensitive_data) {
    return res.status(400).json({ error: 'Sensitive data is required' });
  }

  // VULNERABLE: Using Base64 encoding instead of encryption
  const encoded = Buffer.from(sensitive_data).toString('base64');

  res.json({
    vulnerability: 'A02 - Cryptographic Failures',
    description: 'Base64 encoding mistaken for encryption',
    original: sensitive_data,
    encoded: encoded,
    decoded: Buffer.from(encoded, 'base64').toString('utf8'),
    explanation: 'Base64 is encoding, not encryption - data is easily reversible'
  });
});

// VULNERABILITY: Weak key derivation
router.post('/weak-key-derivation', (req, res) => {
  const { password, salt } = req.body;

  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }

  // VULNERABLE: Weak salt and insufficient iterations
  const weakSalt = salt || 'salt';
  const iterations = 1; // VULNERABLE: Only 1 iteration

  const derived = crypto.pbkdf2Sync(password, weakSalt, iterations, 32, 'sha1');

  res.json({
    vulnerability: 'A02 - Cryptographic Failures',
    description: 'Weak key derivation function',
    password: password,
    salt: weakSalt,
    iterations: iterations,
    derived_key: derived.toString('hex'),
    explanation: 'Using weak salt and insufficient iterations makes brute force attacks feasible'
  });
});

// VULNERABILITY: Certificate validation bypass
router.get('/insecure-request', async (req, res) => {
  try {
    // VULNERABLE: This would bypass certificate validation in a real implementation
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

    res.json({
      vulnerability: 'A02 - Cryptographic Failures',
      description: 'TLS certificate validation bypass',
      warning: 'NODE_TLS_REJECT_UNAUTHORIZED set to 0',
      explanation: 'Bypassing certificate validation makes applications vulnerable to MITM attacks'
    });
  } catch (error) {
    res.status(500).json({ error: 'Request failed' });
  }
});

export default router;