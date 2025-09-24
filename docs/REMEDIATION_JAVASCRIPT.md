# OWASP Top 10 Remediation Examples - JavaScript/Node.js

This document provides secure coding examples to fix the vulnerabilities demonstrated in the application.

## A01 - Broken Access Control

### ❌ Vulnerable Code
```javascript
// Direct object reference without authorization
app.get('/user/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user);
});

// Admin endpoint without authentication
app.get('/admin/users', async (req, res) => {
  const users = await User.findAll();
  res.json(users);
});
```

### ✅ Secure Implementation
```javascript
// Middleware for authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Role-based authorization middleware
const requireRole = (role) => {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient privileges' });
    }
    next();
  };
};

// Secure user endpoint with authorization
app.get('/user/:id', authenticateToken, async (req, res) => {
  const requestedUserId = req.params.id;
  const currentUserId = req.user.id;
  const currentUserRole = req.user.role;

  // Users can only access their own data, admins can access any
  if (requestedUserId !== currentUserId && currentUserRole !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    const user = await User.findById(requestedUserId, {
      attributes: { exclude: ['password', 'api_key'] } // Don't expose sensitive data
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Secure admin endpoint
app.get('/admin/users', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: { exclude: ['password'] } // Never expose passwords
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Attribute-based access control example
const checkResourceAccess = async (req, res, next) => {
  const resource = await Resource.findById(req.params.id);

  if (!resource) {
    return res.status(404).json({ error: 'Resource not found' });
  }

  // Check if user owns resource or has admin role
  if (resource.ownerId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access denied' });
  }

  req.resource = resource;
  next();
};
```

## A02 - Cryptographic Failures

### ❌ Vulnerable Code
```javascript
// Plain text password storage
const user = {
  password: 'mypassword123'
};

// Weak encryption
const crypto = require('crypto');
const algorithm = 'des';
const key = 'weakkey1';
const encrypted = crypto.createCipher(algorithm, key);
```

### ✅ Secure Implementation
```javascript
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Secure password hashing
const hashPassword = async (password) => {
  const saltRounds = 12; // Adjust based on your security requirements
  return await bcrypt.hash(password, saltRounds);
};

const verifyPassword = async (password, hash) => {
  return await bcrypt.compare(password, hash);
};

// Strong encryption with proper key management
const encryptSensitiveData = (data) => {
  const algorithm = 'aes-256-gcm';
  const key = crypto.scryptSync(process.env.ENCRYPTION_KEY, 'salt', 32);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv(algorithm, key, iv);

  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
};

const decryptSensitiveData = (encryptedData) => {
  const algorithm = 'aes-256-gcm';
  const key = crypto.scryptSync(process.env.ENCRYPTION_KEY, 'salt', 32);

  const decipher = crypto.createDecipheriv(algorithm, key, Buffer.from(encryptedData.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));

  let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
};

// Secure random token generation
const generateSecureToken = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Secure session management
const createSession = (userId) => {
  const sessionId = generateSecureToken();
  const sessionData = {
    userId,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // 24 hours
  };

  // Store in secure session store (Redis, database, etc.)
  sessionStore.set(sessionId, sessionData);

  return sessionId;
};

// Environment variable validation
const validateEnvironment = () => {
  const requiredEnvVars = ['JWT_SECRET', 'ENCRYPTION_KEY', 'DATABASE_URL'];

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      throw new Error(`Missing required environment variable: ${envVar}`);
    }

    if (process.env[envVar].length < 32) {
      throw new Error(`Environment variable ${envVar} must be at least 32 characters`);
    }
  }
};
```

## A03 - Injection

### ❌ Vulnerable Code
```javascript
// SQL Injection
const getUserByUsername = (username) => {
  const query = `SELECT * FROM users WHERE username = '${username}'`;
  return db.query(query);
};

// Command Injection
const pingHost = (host) => {
  const command = `ping -c 1 ${host}`;
  return exec(command);
};
```

### ✅ Secure Implementation
```javascript
// Parameterized queries (SQL)
const getUserByUsername = async (username) => {
  const query = 'SELECT id, username, email, role FROM users WHERE username = ?';
  return await db.query(query, [username]);
};

// Using ORM (Sequelize example)
const User = require('./models/User');

const findUserSecurely = async (username) => {
  return await User.findOne({
    where: { username },
    attributes: ['id', 'username', 'email', 'role'] // Exclude sensitive fields
  });
};

// Input validation and sanitization
const Joi = require('joi');

const userSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(8).pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])')).required()
});

const validateUserInput = (userData) => {
  const { error, value } = userSchema.validate(userData);
  if (error) {
    throw new Error(`Validation error: ${error.details[0].message}`);
  }
  return value;
};

// Safe command execution
const { spawn } = require('child_process');

const pingHostSafely = (host) => {
  return new Promise((resolve, reject) => {
    // Validate hostname
    const hostnameRegex = /^[a-zA-Z0-9.-]+$/;
    if (!hostnameRegex.test(host)) {
      return reject(new Error('Invalid hostname format'));
    }

    // Use spawn instead of exec for better security
    const ping = spawn('ping', ['-c', '1', host]);

    let output = '';
    let errorOutput = '';

    ping.stdout.on('data', (data) => {
      output += data.toString();
    });

    ping.stderr.on('data', (data) => {
      errorOutput += data.toString();
    });

    ping.on('close', (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(new Error(`Ping failed: ${errorOutput}`));
      }
    });

    // Set timeout
    setTimeout(() => {
      ping.kill();
      reject(new Error('Command timeout'));
    }, 5000);
  });
};

// NoSQL Injection prevention (MongoDB)
const findUserNoSQL = async (username) => {
  // Ensure username is a string to prevent object injection
  if (typeof username !== 'string') {
    throw new Error('Invalid username type');
  }

  return await User.findOne({ username: username });
};

// GraphQL injection prevention
const { GraphQLScalarType } = require('graphql');
const { GraphQLError } = require('graphql/error');

const SafeStringType = new GraphQLScalarType({
  name: 'SafeString',
  serialize: value => String(value),
  parseValue: value => {
    if (typeof value !== 'string') {
      throw new GraphQLError('Value must be a string');
    }

    // Sanitize input
    return value.replace(/[<>'"]/g, '');
  },
  parseLiteral: ast => {
    if (ast.kind !== 'StringValue') {
      throw new GraphQLError('Value must be a string literal');
    }
    return ast.value.replace(/[<>'"]/g, '');
  }
});
```

## A04 - Insecure Design

### ❌ Vulnerable Code
```javascript
// No rate limiting
app.post('/password-reset', async (req, res) => {
  const { email } = req.body;
  await sendPasswordResetEmail(email);
  res.json({ message: 'Reset email sent' });
});

// Business logic flaw
app.post('/transfer', async (req, res) => {
  const { amount, toAccount } = req.body;
  await transferMoney(req.user.id, toAccount, amount);
});
```

### ✅ Secure Implementation
```javascript
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

// Rate limiting
const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // Limit each IP to 3 requests per windowMs
  message: 'Too many password reset attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false,
});

// Secure password reset with proper verification
app.post('/password-reset',
  passwordResetLimiter,
  [
    body('email').isEmail().normalizeEmail(),
    body('captcha').notEmpty().withMessage('Captcha required')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, captcha } = req.body;

    // Verify captcha
    const captchaValid = await verifyCaptcha(captcha);
    if (!captchaValid) {
      return res.status(400).json({ error: 'Invalid captcha' });
    }

    // Check if user exists (don't reveal if email is valid)
    const user = await User.findOne({ email });

    if (user) {
      // Generate secure reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

      // Store token with expiration
      await PasswordReset.create({
        userId: user.id,
        token: hashedToken,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
      });

      // Send reset email
      await sendPasswordResetEmail(email, resetToken);
    }

    // Always return same response to prevent email enumeration
    res.json({ message: 'If an account with that email exists, a reset link has been sent' });
  }
);

// Secure money transfer with business logic validation
const transferLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // Limit transfers
  keyGenerator: (req) => req.user.id, // Limit per user
});

app.post('/transfer',
  authenticateToken,
  transferLimiter,
  [
    body('amount').isFloat({ min: 0.01, max: 10000 }).withMessage('Invalid amount'),
    body('toAccount').isAlphanumeric().isLength({ min: 8, max: 20 }),
    body('description').optional().isLength({ max: 100 }).trim()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { amount, toAccount, description } = req.body;
    const fromUserId = req.user.id;

    try {
      // Start transaction
      await db.transaction(async (transaction) => {
        // Get and lock user account
        const fromUser = await User.findByPk(fromUserId, {
          lock: true,
          transaction
        });

        // Business logic validations
        if (fromUser.balance < amount) {
          throw new Error('Insufficient funds');
        }

        if (fromUser.dailyTransferLimit < amount) {
          throw new Error('Amount exceeds daily transfer limit');
        }

        // Check if recipient account exists
        const toUser = await User.findOne({
          where: { accountNumber: toAccount },
          transaction
        });

        if (!toUser) {
          throw new Error('Recipient account not found');
        }

        // Prevent self-transfer
        if (fromUserId === toUser.id) {
          throw new Error('Cannot transfer to yourself');
        }

        // Check daily transfer count
        const dailyTransfers = await Transfer.count({
          where: {
            fromUserId,
            createdAt: {
              [Op.gte]: new Date().setHours(0, 0, 0, 0)
            }
          },
          transaction
        });

        if (dailyTransfers >= 10) {
          throw new Error('Daily transfer limit exceeded');
        }

        // Perform transfer
        await fromUser.decrement('balance', { by: amount, transaction });
        await toUser.increment('balance', { by: amount, transaction });

        // Log transaction
        await Transfer.create({
          fromUserId,
          toUserId: toUser.id,
          amount,
          description,
          status: 'completed'
        }, { transaction });

        // Send notifications
        await sendTransferNotification(fromUser, toUser, amount);

        res.json({
          message: 'Transfer completed successfully',
          transactionId: transfer.id
        });
      });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }
);

// Secure file upload with proper validation
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'secure_uploads/');
  },
  filename: (req, file, cb) => {
    // Generate secure filename
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const sanitizedName = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '');
    cb(null, `${uniqueSuffix}-${sanitizedName}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif'];

  const fileExtension = path.extname(file.originalname).toLowerCase();

  if (allowedTypes.includes(file.mimetype) && allowedExtensions.includes(fileExtension)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
    files: 1
  }
});
```

## A05 - Security Misconfiguration

### ❌ Vulnerable Code
```javascript
// Exposed debug information
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    environment: process.env
  });
});

// Missing security headers
app.use(cors({ origin: '*' }));
```

### ✅ Secure Implementation
```javascript
const helmet = require('helmet');
const compression = require('compression');

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Secure CORS configuration
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Request compression with security considerations
app.use(compression({
  level: 6,
  threshold: 1024,
  filter: (req, res) => {
    // Don't compress responses that might contain secrets
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  }
}));

// Secure session configuration
const session = require('express-session');
const RedisStore = require('connect-redis')(session);

app.use(session({
  store: new RedisStore({
    client: redisClient,
    prefix: 'sess:'
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'sessionId', // Don't use default name
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true, // Prevent XSS
    maxAge: 30 * 60 * 1000, // 30 minutes
    sameSite: 'strict' // CSRF protection
  }
}));

// Environment-specific error handling
const errorHandler = (err, req, res, next) => {
  // Log error for debugging
  logger.error({
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Generic error response for production
  if (process.env.NODE_ENV === 'production') {
    res.status(500).json({
      error: 'Internal server error',
      timestamp: new Date().toISOString(),
      requestId: req.id
    });
  } else {
    // Detailed errors for development only
    res.status(500).json({
      error: err.message,
      stack: err.stack,
      timestamp: new Date().toISOString()
    });
  }
};

// Security middleware
const securityMiddleware = (req, res, next) => {
  // Remove sensitive headers
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');

  // Add security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  next();
};

app.use(securityMiddleware);

// Configuration validation
const validateConfiguration = () => {
  const requiredConfig = [
    'NODE_ENV',
    'JWT_SECRET',
    'DATABASE_URL',
    'SESSION_SECRET',
    'REDIS_URL'
  ];

  const missing = requiredConfig.filter(key => !process.env[key]);

  if (missing.length > 0) {
    throw new Error(`Missing required configuration: ${missing.join(', ')}`);
  }

  // Validate secret lengths
  if (process.env.JWT_SECRET.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters');
  }
};

// Initialize app with security checks
const initializeApp = () => {
  validateConfiguration();

  if (process.env.NODE_ENV === 'production') {
    console.log('Starting in production mode');

    // Additional production security
    app.disable('x-powered-by');
    app.set('trust proxy', 1);
  }
};
```

## A06 - Vulnerable and Outdated Components

### ❌ Vulnerable Code
```javascript
// Using outdated packages with known vulnerabilities
const express = require('express'); // Old version
const lodash = require('lodash'); // Vulnerable to prototype pollution
const moment = require('moment'); // Deprecated
```

### ✅ Secure Implementation
```javascript
// Updated package.json with security-focused packages
{
  "dependencies": {
    "express": "^5.0.0",
    "helmet": "^7.0.0",
    "express-rate-limit": "^6.0.0",
    "express-validator": "^7.0.0",
    "bcrypt": "^5.1.0",
    "jsonwebtoken": "^9.0.0",
    "node-cache": "^5.1.2"
  },
  "scripts": {
    "audit": "npm audit",
    "audit-fix": "npm audit fix",
    "update-check": "npx npm-check-updates",
    "security-scan": "npx audit-ci --moderate"
  }
}

// Dependency management utilities
const fs = require('fs');
const path = require('path');

// Check for known vulnerabilities
const checkDependencySecurity = () => {
  const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  const vulnerablePackages = [
    'lodash@<4.17.21', // Prototype pollution
    'moment@*', // Deprecated
    'request@*', // Deprecated
    'node-uuid@<1.4.8' // Cryptographically insecure
  ];

  console.log('Checking for vulnerable dependencies...');
  // Implementation would check against vulnerability database
};

// Secure utility functions without vulnerable dependencies
const safeObjectMerge = (target, ...sources) => {
  // Safe alternative to lodash merge
  for (const source of sources) {
    for (const key in source) {
      if (Object.prototype.hasOwnProperty.call(source, key)) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
          continue; // Skip dangerous keys
        }
        target[key] = source[key];
      }
    }
  }
  return target;
};

// Modern date handling (alternative to moment)
const formatDate = (date) => {
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short'
  }).format(new Date(date));
};

// Automated security scanning
const runSecurityScan = async () => {
  const { exec } = require('child_process');

  return new Promise((resolve, reject) => {
    exec('npm audit --json', (error, stdout, stderr) => {
      if (error && error.code !== 1) { // Code 1 means vulnerabilities found
        return reject(error);
      }

      try {
        const auditResult = JSON.parse(stdout);
        const vulnerabilities = auditResult.vulnerabilities || {};

        const highSeverity = Object.values(vulnerabilities)
          .filter(vuln => vuln.severity === 'high' || vuln.severity === 'critical');

        if (highSeverity.length > 0) {
          console.warn(`Found ${highSeverity.length} high/critical vulnerabilities`);
          // Log details or fail build in CI/CD
        }

        resolve(auditResult);
      } catch (parseError) {
        reject(parseError);
      }
    });
  });
};

// Content Security Policy for preventing malicious scripts
const cspConfig = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      // Only allow scripts from trusted CDNs with SRI
      "https://cdn.jsdelivr.net",
      "https://cdnjs.cloudflare.com"
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'", // Only if absolutely necessary
      "https://fonts.googleapis.com"
    ],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
    upgradeInsecureRequests: []
  }
};
```

## A07 - Identification and Authentication Failures

### ❌ Vulnerable Code
```javascript
// Weak password validation
const isValidPassword = (password) => password.length >= 6;

// Insecure session handling
const sessions = {}; // In-memory storage
const sessionId = Math.random().toString();
```

### ✅ Secure Implementation
```javascript
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Strong password validation
const passwordSchema = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  maxConsecutive: 3,
  preventCommonPasswords: true
};

const validatePassword = (password) => {
  const errors = [];

  if (password.length < passwordSchema.minLength) {
    errors.push(`Password must be at least ${passwordSchema.minLength} characters`);
  }

  if (passwordSchema.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain uppercase letters');
  }

  if (passwordSchema.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain lowercase letters');
  }

  if (passwordSchema.requireNumbers && !/\d/.test(password)) {
    errors.push('Password must contain numbers');
  }

  if (passwordSchema.requireSpecialChars && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain special characters');
  }

  // Check for consecutive repeated characters
  const consecutivePattern = new RegExp(`(.)\\1{${passwordSchema.maxConsecutive},}`);
  if (consecutivePattern.test(password)) {
    errors.push(`Password cannot have more than ${passwordSchema.maxConsecutive} consecutive identical characters`);
  }

  // Check against common passwords
  if (passwordSchema.preventCommonPasswords && commonPasswords.includes(password.toLowerCase())) {
    errors.push('Password is too common');
  }

  return {
    isValid: errors.length === 0,
    errors
  };
};

// Secure authentication with rate limiting
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

const authenticateUser = async (username, password, req) => {
  const clientIP = req.ip;
  const attemptKey = `${username}:${clientIP}`;

  // Check rate limiting
  const attempts = loginAttempts.get(attemptKey) || { count: 0, lastAttempt: Date.now() };

  if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
    const timeRemaining = LOCKOUT_TIME - (Date.now() - attempts.lastAttempt);
    if (timeRemaining > 0) {
      throw new Error(`Account locked. Try again in ${Math.ceil(timeRemaining / 60000)} minutes`);
    } else {
      // Reset attempts after lockout period
      loginAttempts.delete(attemptKey);
    }
  }

  try {
    const user = await User.findOne({
      where: { username },
      include: [{ model: UserSecurity, as: 'security' }]
    });

    if (!user) {
      // Perform dummy hash to prevent timing attacks
      await bcrypt.hash('dummy', 12);
      throw new Error('Invalid credentials');
    }

    // Check if account is locked
    if (user.security.isLocked && user.security.lockedUntil > new Date()) {
      throw new Error('Account is temporarily locked');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      // Increment failed attempts
      attempts.count++;
      attempts.lastAttempt = Date.now();
      loginAttempts.set(attemptKey, attempts);

      // Lock account after max attempts
      if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
        await user.security.update({
          isLocked: true,
          lockedUntil: new Date(Date.now() + LOCKOUT_TIME)
        });
      }

      throw new Error('Invalid credentials');
    }

    // Successful login - reset attempts
    loginAttempts.delete(attemptKey);

    // Update login statistics
    await user.security.update({
      lastLoginAt: new Date(),
      lastLoginIP: clientIP,
      failedLoginAttempts: 0,
      isLocked: false,
      lockedUntil: null
    });

    return user;
  } catch (error) {
    // Increment failed attempts on any error
    const currentAttempts = loginAttempts.get(attemptKey) || { count: 0, lastAttempt: Date.now() };
    currentAttempts.count++;
    currentAttempts.lastAttempt = Date.now();
    loginAttempts.set(attemptKey, currentAttempts);

    throw error;
  }
};

// Two-factor authentication implementation
const setupTwoFactor = async (userId) => {
  const secret = speakeasy.generateSecret({
    name: `MyApp (${userId})`,
    issuer: 'MySecureApp'
  });

  // Store secret securely
  await UserSecurity.update({
    twoFactorSecret: encrypt(secret.base32)
  }, {
    where: { userId }
  });

  // Generate QR code for user
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

  return {
    secret: secret.base32,
    qrCode: qrCodeUrl
  };
};

const verifyTwoFactor = async (userId, token) => {
  const userSecurity = await UserSecurity.findOne({ where: { userId } });

  if (!userSecurity.twoFactorSecret) {
    throw new Error('Two-factor authentication not set up');
  }

  const decryptedSecret = decrypt(userSecurity.twoFactorSecret);

  const verified = speakeasy.totp.verify({
    secret: decryptedSecret,
    encoding: 'base32',
    token: token,
    window: 2 // Allow 2 time steps (60 seconds) variance
  });

  return verified;
};

// Secure session management
const SessionManager = {
  createSession: async (userId, req) => {
    const sessionId = crypto.randomBytes(32).toString('hex');
    const sessionData = {
      userId,
      createdAt: new Date(),
      lastAccessedAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      isActive: true
    };

    // Store in Redis or secure database
    await sessionStore.set(`session:${sessionId}`, JSON.stringify(sessionData), 'EX', 86400);

    return sessionId;
  },

  validateSession: async (sessionId, req) => {
    const sessionData = await sessionStore.get(`session:${sessionId}`);

    if (!sessionData) {
      throw new Error('Invalid session');
    }

    const session = JSON.parse(sessionData);

    // Check expiration
    if (new Date() > new Date(session.expiresAt)) {
      await SessionManager.destroySession(sessionId);
      throw new Error('Session expired');
    }

    // Validate IP (optional, can be disabled for mobile users)
    if (session.ipAddress !== req.ip) {
      await SessionManager.destroySession(sessionId);
      throw new Error('Session security violation');
    }

    // Update last accessed time
    session.lastAccessedAt = new Date();
    await sessionStore.set(`session:${sessionId}`, JSON.stringify(session), 'EX', 86400);

    return session;
  },

  destroySession: async (sessionId) => {
    await sessionStore.del(`session:${sessionId}`);
  },

  destroyAllUserSessions: async (userId) => {
    const keys = await sessionStore.keys('session:*');
    for (const key of keys) {
      const sessionData = await sessionStore.get(key);
      if (sessionData) {
        const session = JSON.parse(sessionData);
        if (session.userId === userId) {
          await sessionStore.del(key);
        }
      }
    }
  }
};

// Password reset with secure tokens
const initiatePasswordReset = async (email) => {
  const user = await User.findOne({ where: { email } });

  if (user) {
    // Generate cryptographically secure token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    // Store with short expiration
    await PasswordReset.create({
      userId: user.id,
      token: hashedToken,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
      isUsed: false
    });

    // Send email with token
    await sendPasswordResetEmail(email, resetToken);

    // Log security event
    await SecurityLog.create({
      userId: user.id,
      event: 'PASSWORD_RESET_REQUESTED',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });
  }

  // Always return same response to prevent email enumeration
  return { message: 'If an account exists, a reset email has been sent' };
};
```

## A08 - Software and Data Integrity Failures

### ❌ Vulnerable Code
```javascript
// Accepting unsigned packages
app.post('/upload', upload.single('package'), (req, res) => {
  const packagePath = req.file.path;
  deployPackage(packagePath);
});

// Insecure deserialization
app.post('/data', (req, res) => {
  const data = JSON.parse(req.body.serialized);
  processData(data);
});
```

### ✅ Secure Implementation
```javascript
const crypto = require('crypto');
const { execSync } = require('child_process');

// Package integrity verification
const verifyPackageIntegrity = async (packagePath, expectedHash, signature) => {
  // Verify file hash
  const fileBuffer = fs.readFileSync(packagePath);
  const actualHash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

  if (actualHash !== expectedHash) {
    throw new Error('Package integrity check failed: hash mismatch');
  }

  // Verify digital signature
  const publicKey = fs.readFileSync('trusted-publisher.pub');
  const verifier = crypto.createVerify('SHA256');
  verifier.update(fileBuffer);

  const isSignatureValid = verifier.verify(publicKey, signature, 'hex');
  if (!isSignatureValid) {
    throw new Error('Package signature verification failed');
  }

  return true;
};

// Secure package deployment
app.post('/deploy-package',
  authenticateToken,
  requireRole('admin'),
  upload.single('package'),
  async (req, res) => {
    try {
      const { expectedHash, signature, version } = req.body;
      const packagePath = req.file.path;

      // Verify package integrity and signature
      await verifyPackageIntegrity(packagePath, expectedHash, signature);

      // Check package metadata
      const packageInfo = await validatePackageMetadata(packagePath);

      if (packageInfo.version !== version) {
        throw new Error('Version mismatch');
      }

      // Scan for vulnerabilities
      await scanPackageForVulnerabilities(packagePath);

      // Deploy in isolated environment
      await deployPackageSecurely(packagePath, packageInfo);

      // Log deployment
      await DeploymentLog.create({
        packageName: packageInfo.name,
        version: packageInfo.version,
        deployedBy: req.user.id,
        packageHash: expectedHash,
        status: 'success'
      });

      res.json({ message: 'Package deployed successfully' });

    } catch (error) {
      // Clean up uploaded file
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }

      res.status(400).json({ error: error.message });
    }
  }
);

// Secure deserialization with validation
const Joi = require('joi');

const dataSchema = Joi.object({
  type: Joi.string().valid('user', 'product', 'order').required(),
  data: Joi.object().required(),
  timestamp: Joi.date().iso().required(),
  version: Joi.string().pattern(/^\d+\.\d+\.\d+$/).required()
});

const secureDeserialize = (serializedData) => {
  try {
    // Parse JSON safely
    const parsed = JSON.parse(serializedData);

    // Validate structure
    const { error, value } = dataSchema.validate(parsed);
    if (error) {
      throw new Error(`Validation failed: ${error.details[0].message}`);
    }

    // Additional type-specific validation
    switch (value.type) {
      case 'user':
        return validateUserData(value.data);
      case 'product':
        return validateProductData(value.data);
      case 'order':
        return validateOrderData(value.data);
      default:
        throw new Error('Unknown data type');
    }

  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error('Invalid JSON format');
    }
    throw error;
  }
};

// CI/CD pipeline security
const validateCICD = {
  // Verify build environment
  validateBuildEnvironment: () => {
    const requiredEnvVars = ['CI', 'BUILD_ID', 'COMMIT_SHA'];

    for (const envVar of requiredEnvVars) {
      if (!process.env[envVar]) {
        throw new Error(`Missing required CI/CD environment variable: ${envVar}`);
      }
    }
  },

  // Verify source code integrity
  verifySourceIntegrity: (commitSha) => {
    try {
      const currentSha = execSync('git rev-parse HEAD').toString().trim();

      if (currentSha !== commitSha) {
        throw new Error('Source code integrity check failed');
      }

      // Check for unsigned commits
      const signedCommit = execSync(`git verify-commit ${commitSha}`, { stdio: 'pipe' });

    } catch (error) {
      throw new Error('Commit signature verification failed');
    }
  },

  // Dependency verification
  verifyDependencies: async () => {
    // Check package-lock.json integrity
    const packageLock = JSON.parse(fs.readFileSync('package-lock.json'));

    // Verify all dependencies have integrity hashes
    const checkIntegrity = (deps) => {
      for (const [name, info] of Object.entries(deps)) {
        if (!info.integrity) {
          throw new Error(`Missing integrity hash for dependency: ${name}`);
        }

        if (info.dependencies) {
          checkIntegrity(info.dependencies);
        }
      }
    };

    if (packageLock.dependencies) {
      checkIntegrity(packageLock.dependencies);
    }

    // Run security audit
    try {
      execSync('npm audit --audit-level=moderate', { stdio: 'inherit' });
    } catch (error) {
      throw new Error('Security audit failed');
    }
  }
};

// Software supply chain validation
const validateSupplyChain = {
  // Verify npm packages
  verifyNpmPackage: async (packageName, version) => {
    const response = await fetch(`https://registry.npmjs.org/${packageName}/${version}`);
    const packageData = await response.json();

    // Check publisher verification
    if (!packageData.dist.signatures) {
      console.warn(`Package ${packageName}@${version} is not signed`);
    }

    // Verify integrity
    const expectedIntegrity = packageData.dist.integrity;
    if (!expectedIntegrity) {
      throw new Error(`No integrity hash for ${packageName}@${version}`);
    }

    return packageData;
  },

  // Check for known malicious packages
  checkMaliciousPackages: async (packageName) => {
    // Check against known malicious package lists
    const maliciousPackages = await fetch('https://api.security-service.com/malicious-packages');
    const maliciousList = await maliciousPackages.json();

    if (maliciousList.includes(packageName)) {
      throw new Error(`Package ${packageName} is known to be malicious`);
    }
  }
};

// Secure update mechanism
const secureUpdater = {
  checkForUpdates: async () => {
    const currentVersion = process.env.APP_VERSION;
    const updateEndpoint = 'https://secure-updates.example.com/latest';

    const response = await fetch(updateEndpoint, {
      headers: {
        'User-Agent': `MyApp/${currentVersion}`,
        'Authorization': `Bearer ${process.env.UPDATE_TOKEN}`
      }
    });

    const updateInfo = await response.json();

    // Verify update signature
    const publicKey = fs.readFileSync('update-public-key.pem');
    const verifier = crypto.createVerify('SHA256');
    verifier.update(JSON.stringify(updateInfo.package));

    const isValid = verifier.verify(publicKey, updateInfo.signature, 'base64');
    if (!isValid) {
      throw new Error('Update signature verification failed');
    }

    return updateInfo;
  },

  applyUpdate: async (updateInfo) => {
    // Download update package
    const updatePath = await downloadUpdate(updateInfo.downloadUrl);

    // Verify integrity
    const updateBuffer = fs.readFileSync(updatePath);
    const actualHash = crypto.createHash('sha256').update(updateBuffer).digest('hex');

    if (actualHash !== updateInfo.hash) {
      throw new Error('Update integrity verification failed');
    }

    // Create backup
    await createBackup();

    try {
      // Apply update
      await extractAndApplyUpdate(updatePath);

      // Verify application still works
      await healthCheck();

    } catch (error) {
      // Rollback on failure
      await restoreBackup();
      throw error;
    }
  }
};
```

This completes the JavaScript remediation examples. Each section shows the vulnerable pattern followed by a secure implementation with proper validation, authentication, encryption, and security controls.

The examples demonstrate:
- Input validation and sanitization
- Proper authentication and authorization
- Secure cryptographic practices
- Rate limiting and abuse prevention
- Security headers and configuration
- Dependency management
- Secure session handling
- Integrity verification
- Error handling without information disclosure

These patterns can be adapted to specific application requirements while maintaining security best practices.