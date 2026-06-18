import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { initializeDatabase } from './models/database';

// Import all OWASP Top 10:2025 vulnerability routes.
// Files are named by slug (not rank) and mounted in 2025 order, so a future
// reshuffle is just a reorder here — no file renames. SSRF is folded into A01.
import brokenAccessControlRoutes from './routes/broken-access-control';         // A01 (incl. SSRF)
import securityMisconfigurationRoutes from './routes/security-misconfiguration'; // A02
import supplyChainRoutes from './routes/software-supply-chain-failures';        // A03
import cryptographicFailuresRoutes from './routes/cryptographic-failures';      // A04
import injectionRoutes from './routes/injection';                               // A05
import insecureDesignRoutes from './routes/insecure-design';                    // A06
import authenticationFailuresRoutes from './routes/authentication-failures';    // A07
import dataIntegrityFailuresRoutes from './routes/data-integrity-failures';     // A08
import securityLoggingRoutes from './routes/security-logging-alerting-failures'; // A09
import mishandlingRoutes from './routes/mishandling-exceptional-conditions';    // A10 (new)

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

// OWASP Top 10:2025 Vulnerability Routes — mounted by slug so ranks can be
// reshuffled without changing any URL.
app.use('/api/broken-access-control', brokenAccessControlRoutes);          // A01 (SSRF at /ssrf)
app.use('/api/security-misconfiguration', securityMisconfigurationRoutes); // A02
app.use('/api/software-supply-chain-failures', supplyChainRoutes);         // A03
app.use('/api/cryptographic-failures', cryptographicFailuresRoutes);       // A04
app.use('/api/injection', injectionRoutes);                                // A05
app.use('/api/insecure-design', insecureDesignRoutes);                     // A06
app.use('/api/authentication-failures', authenticationFailuresRoutes);     // A07
app.use('/api/data-integrity-failures', dataIntegrityFailuresRoutes);      // A08
app.use('/api/security-logging-alerting-failures', securityLoggingRoutes); // A09
app.use('/api/mishandling-exceptional-conditions', mishandlingRoutes);     // A10 (new)

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
      'A01 - Broken Access Control (incl. SSRF)': '/api/broken-access-control',
      'A02 - Security Misconfiguration': '/api/security-misconfiguration',
      'A03 - Software Supply Chain Failures': '/api/software-supply-chain-failures',
      'A04 - Cryptographic Failures': '/api/cryptographic-failures',
      'A05 - Injection': '/api/injection',
      'A06 - Insecure Design': '/api/insecure-design',
      'A07 - Authentication Failures': '/api/authentication-failures',
      'A08 - Software or Data Integrity Failures': '/api/data-integrity-failures',
      'A09 - Security Logging and Alerting Failures': '/api/security-logging-alerting-failures',
      'A10 - Mishandling of Exceptional Conditions': '/api/mishandling-exceptional-conditions'
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