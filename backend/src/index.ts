import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { initializeDatabase } from './models/database';

// Import all vulnerability routes
import a01Routes from './routes/a01-broken-access-control';
import a02Routes from './routes/a02-cryptographic-failures';
import a03Routes from './routes/a03-injection';
import a04Routes from './routes/a04-insecure-design';
import a05Routes from './routes/a05-security-misconfiguration';
import a06Routes from './routes/a06-vulnerable-components';
import a07Routes from './routes/a07-identification-authentication-failures';
import a08Routes from './routes/a08-software-data-integrity-failures';
import a09Routes from './routes/a09-security-logging-monitoring-failures';
import a10Routes from './routes/a10-server-side-request-forgery';

// Import LLM Top 10 vulnerability routes
import llm01Routes from './routes/llm01-prompt-injection';
import llm02Routes from './routes/llm02-sensitive-info-disclosure';
import llm03Routes from './routes/llm03-supply-chain';
import llm04Routes from './routes/llm04-data-poisoning';
import llm05Routes from './routes/llm05-improper-output-handling';
import llm06Routes from './routes/llm06-excessive-agency';
import llm07Routes from './routes/llm07-system-prompt-leakage';
import llm08Routes from './routes/llm08-vector-embedding-weaknesses';
import llm09Routes from './routes/llm09-misinformation';
import llm10Routes from './routes/llm10-unbounded-consumption';

const app = express();
const PORT = process.env.PORT || 3001;

// WARNING: This application contains intentional security vulnerabilities for educational purposes
// DO NOT deploy to production or expose to the internet

// Basic middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS - intentionally permissive for demo purposes
app.use(cors({
  origin: true, // VULNERABILITY: Allows any origin
  credentials: true
}));

// Helmet - intentionally disabled some protections for demo
app.use(helmet({
  contentSecurityPolicy: false, // VULNERABILITY: CSP disabled
  frameguard: false // VULNERABILITY: X-Frame-Options disabled
}));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'VULNERABLE',
    message: 'OWASP Top 10 Demo Server - FOR EDUCATIONAL USE ONLY',
    timestamp: new Date().toISOString()
  });
});

// OWASP Top 10 Vulnerability Routes
app.use('/api/a01', a01Routes); // Broken Access Control
app.use('/api/a02', a02Routes); // Cryptographic Failures
app.use('/api/a03', a03Routes); // Injection
app.use('/api/a04', a04Routes); // Insecure Design
app.use('/api/a05', a05Routes); // Security Misconfiguration
app.use('/api/a06', a06Routes); // Vulnerable Components
app.use('/api/a07', a07Routes); // Identification and Authentication Failures
app.use('/api/a08', a08Routes); // Software and Data Integrity Failures
app.use('/api/a09', a09Routes); // Security Logging and Monitoring Failures
app.use('/api/a10', a10Routes); // Server-Side Request Forgery

// OWASP Top 10 for LLM Applications (2025) Routes
app.use('/api/llm01', llm01Routes); // Prompt Injection
app.use('/api/llm02', llm02Routes); // Sensitive Information Disclosure
app.use('/api/llm03', llm03Routes); // Supply Chain
app.use('/api/llm04', llm04Routes); // Data and Model Poisoning
app.use('/api/llm05', llm05Routes); // Improper Output Handling
app.use('/api/llm06', llm06Routes); // Excessive Agency
app.use('/api/llm07', llm07Routes); // System Prompt Leakage
app.use('/api/llm08', llm08Routes); // Vector and Embedding Weaknesses
app.use('/api/llm09', llm09Routes); // Misinformation
app.use('/api/llm10', llm10Routes); // Unbounded Consumption

// API endpoints overview
app.get('/api', (req, res) => {
  res.json({
    message: 'OWASP Top 10 Vulnerability Demonstration API',
    warning: '⚠️ This API contains intentional security vulnerabilities',
    endpoints: {
      'A01 - Broken Access Control': '/api/a01',
      'A02 - Cryptographic Failures': '/api/a02',
      'A03 - Injection': '/api/a03',
      'A04 - Insecure Design': '/api/a04',
      'A05 - Security Misconfiguration': '/api/a05',
      'A06 - Vulnerable Components': '/api/a06',
      'A07 - Identification and Authentication Failures': '/api/a07',
      'A08 - Software and Data Integrity Failures': '/api/a08',
      'A09 - Security Logging and Monitoring Failures': '/api/a09',
      'A10 - Server-Side Request Forgery': '/api/a10'
    },
    llmEndpoints: {
      'LLM01 - Prompt Injection': '/api/llm01',
      'LLM02 - Sensitive Information Disclosure': '/api/llm02',
      'LLM03 - Supply Chain': '/api/llm03',
      'LLM04 - Data and Model Poisoning': '/api/llm04',
      'LLM05 - Improper Output Handling': '/api/llm05',
      'LLM06 - Excessive Agency': '/api/llm06',
      'LLM07 - System Prompt Leakage': '/api/llm07',
      'LLM08 - Vector and Embedding Weaknesses': '/api/llm08',
      'LLM09 - Misinformation': '/api/llm09',
      'LLM10 - Unbounded Consumption': '/api/llm10'
    }
  });
});

// Initialize database and start server
async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(`⚠️  VULNERABLE SERVER RUNNING ON PORT ${PORT} ⚠️`);
      console.log('🔥 This server contains intentional security flaws');
      console.log('📚 For educational purposes only - DO NOT expose to internet');
      console.log(`🌐 Health check: http://localhost:${PORT}/health`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();