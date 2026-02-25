<p align="center">
  <img src="https://owasp.org/assets/images/logo.png" alt="OWASP Logo" width="200">
</p>

# OWASP Top 10 Vulnerabilities Demo

⚠️ **CRITICAL WARNING** ⚠️

This application contains **intentional security vulnerabilities** for educational purposes only.

**NEVER:**
- Deploy this to production
- Expose this to the internet
- Use in any public environment
- Use with real sensitive data

**ONLY USE:**
- In controlled, isolated environments
- For educational and training purposes
- In local development environments
- For security awareness demonstrations

## Overview

This is an interactive demonstration of the **OWASP Top 10 (2021)** web application vulnerabilities and the **OWASP Top 10 for LLM Applications (2025)**. It includes:

- **Frontend**: React TypeScript application with navigation through all 20 vulnerabilities
- **Backend**: Node.js Express API with intentionally vulnerable endpoints
- **Database**: SQLite with vulnerable schema and sample data
- **LLM Simulation**: Simulated LLM responses streamed token-by-token via SSE

## Architecture

```
owasp-dangers/
├── frontend/          # React TypeScript application
│   ├── src/
│   │   ├── components/        # OWASP Top 10 vulnerability components
│   │   ├── components/llm/    # LLM Top 10 vulnerability components
│   │   ├── hooks/             # Shared React hooks (useLLMStream)
│   │   └── ...
├── backend/           # Node.js Express API
│   ├── src/
│   │   ├── routes/        # Vulnerable API endpoints (A01-A10, LLM01-LLM10)
│   │   ├── models/        # Database models with vulnerabilities
│   │   ├── utils/         # Shared utilities (SSE streaming)
│   │   └── ...
├── database/          # SQLite database files
└── docs/              # Documentation and presentation materials
```

## OWASP Top 10 (2021) Coverage

1. **A01 - Broken Access Control**
   - Direct object references
   - Missing authorization
   - Privilege escalation

2. **A02 - Cryptographic Failures**
   - Plain text passwords
   - Weak encryption algorithms
   - Hardcoded secrets

3. **A03 - Injection**
   - SQL injection
   - Command injection
   - NoSQL injection

4. **A04 - Insecure Design**
   - Missing security controls
   - Business logic flaws
   - Unlimited resource consumption

5. **A05 - Security Misconfiguration**
   - Default credentials
   - Debug information exposure
   - Unnecessary features

6. **A06 - Vulnerable and Outdated Components**
   - Outdated dependencies
   - Known vulnerabilities
   - Deprecated methods

7. **A07 - Identification and Authentication Failures**
   - Weak passwords
   - Session hijacking
   - Brute force vulnerabilities

8. **A08 - Software and Data Integrity Failures**
   - Unsigned updates
   - Insecure deserialization
   - CI/CD vulnerabilities

9. **A09 - Security Logging and Monitoring Failures**
   - Missing audit logs
   - Insufficient monitoring
   - No anomaly detection

10. **A10 - Server-Side Request Forgery (SSRF)**
    - Internal network access
    - Cloud metadata exposure
    - Port scanning

## OWASP Top 10 for LLM Applications (2025) Coverage

1. **LLM01 - Prompt Injection**
   - Direct prompt override
   - Indirect injection via data
   - Role-playing attacks

2. **LLM02 - Sensitive Information Disclosure**
   - Training data memorization
   - PII and credential extraction
   - Cross-session data leakage

3. **LLM03 - Supply Chain**
   - Tampered/unverified models
   - Malicious plugins with excessive permissions
   - Weak integrity verification

4. **LLM04 - Data and Model Poisoning**
   - Unvalidated training data submission
   - Bias injection
   - Backdoor triggers

5. **LLM05 - Improper Output Handling**
   - XSS via LLM-generated HTML
   - SQL injection via LLM output
   - Command injection via generated shell commands

6. **LLM06 - Excessive Agency**
   - Overprivileged agent tools
   - Actions without human approval
   - Ambiguous request interpretation

7. **LLM07 - System Prompt Leakage**
   - Direct prompt extraction
   - Indirect reformulation attacks
   - Context window manipulation

8. **LLM08 - Vector and Embedding Weaknesses**
   - RAG without access control
   - Cross-department document exposure
   - Embedding inversion attacks

9. **LLM09 - Misinformation**
   - Hallucinated medical advice
   - Fabricated legal citations
   - False technical facts with confidence

10. **LLM10 - Unbounded Consumption**
    - No rate limiting
    - No input size or budget caps
    - Resource exhaustion attacks

## Setup Instructions

### Prerequisites

- Git
- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/) (Recommended)
- Node.js 16+ and npm (for manual setup)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd owasp-dangers
   ```

2. **Install root dependencies:**
   ```bash
   npm install
   ```

3. **Install frontend dependencies:**
   ```bash
   cd frontend
   npm install
   cd ..
   ```

4. **Install backend dependencies:**
   ```bash
   cd backend
   npm install
   cd ..
   ```

### Running the Application

#### Running with Docker (Recommended)

This is the easiest and recommended way to run the application.

1.  **Build and run the application:**
    From the root of the project, run:
    ```bash
    docker-compose up --build
    ```

2.  **Access the application:**
    - Frontend will be available at `http://localhost:3000`
    - Backend API will be available at `http://localhost:3001`

To stop the application, press `Ctrl+C` in the terminal where docker-compose is running, and then run `docker-compose down` to remove the containers.

#### Manual Setup (Alternative)

If you prefer not to use Docker, you can run the services manually.

**Run both frontend and backend simultaneously:**

```bash
npm run dev:all
```

This will start:
- Backend API server on `http://localhost:3001`
- Frontend React app on `http://localhost:3000`

**Or, run them in separate terminals:**

*Backend:*
```bash
cd backend
npm run dev
```

*Frontend:*
```bash
cd frontend
npm start
```

### Building for Demo

**Build backend:**
```bash
cd backend
npm run build
npm start
```

**Build frontend:**
```bash
cd frontend
npm run build
```

## Usage for Presentations

### Navigation Flow

The application is designed for step-by-step presentations:

1. Start at the home page (`/`) for overview
2. Navigate through A01 → A02 → ... → A10
3. Each page includes:
   - Vulnerability description
   - Interactive demos
   - Attack examples
   - Remediation guidance
   - Navigation to next vulnerability

### Demo Guidelines

1. **Preparation:**
   - Ensure application is running locally
   - Test all demo endpoints before presentation
   - Prepare network isolation (no internet access)

2. **Presentation Tips:**
   - Start with the warning about intentional vulnerabilities
   - Explain educational purpose
   - Demonstrate attacks live
   - Show remediation techniques
   - Emphasize real-world impact

3. **Interactive Elements:**
   - Each vulnerability has working examples
   - Audience can see actual exploitation
   - Response data shows vulnerability impact
   - Code examples show secure alternatives

## API Endpoints

### Health Check
- `GET /health` - Server status

### Vulnerability Endpoints
- `GET /api` - API overview
- `/api/a01/*` - Broken Access Control demos
- `/api/a02/*` - Cryptographic Failures demos
- `/api/a03/*` - Injection demos
- `/api/a04/*` - Insecure Design demos
- `/api/a05/*` - Security Misconfiguration demos
- `/api/a06/*` - Vulnerable Components demos
- `/api/a07/*` - Authentication Failures demos
- `/api/a08/*` - Integrity Failures demos
- `/api/a09/*` - Logging Failures demos
- `/api/a10/*` - SSRF demos

### LLM Vulnerability Endpoints
- `/api/llm01/*` - Prompt Injection demos (SSE streaming)
- `/api/llm02/*` - Sensitive Information Disclosure demos (SSE streaming)
- `/api/llm03/*` - Supply Chain demos
- `/api/llm04/*` - Data and Model Poisoning demos (SSE streaming)
- `/api/llm05/*` - Improper Output Handling demos (SSE streaming)
- `/api/llm06/*` - Excessive Agency demos (SSE streaming)
- `/api/llm07/*` - System Prompt Leakage demos (SSE streaming)
- `/api/llm08/*` - Vector and Embedding Weaknesses demos (SSE streaming)
- `/api/llm09/*` - Misinformation demos (SSE streaming)
- `/api/llm10/*` - Unbounded Consumption demos (SSE streaming)

## Security Notes

### Intentional Vulnerabilities

This application includes the following intentional security flaws:

- **SQL Injection**: Direct string concatenation in queries
- **Plain Text Passwords**: No hashing or encryption
- **Missing Authorization**: No access control checks
- **Weak Cryptography**: MD5, DES, hardcoded secrets
- **Command Injection**: Direct command execution
- **SSRF**: Unvalidated URL fetching
- **Insecure Deserialization**: Unsafe JSON parsing
- **Default Credentials**: admin/admin, etc.
- **Information Disclosure**: Verbose error messages
- **Missing Security Headers**: Disabled CSP, CORS

### Risk Mitigation

- Database contains only sample data
- Application binds only to localhost
- Clear warnings throughout interface
- Educational context emphasized
- Remediation examples provided

## Development

### Project Structure

```
backend/src/
├── index.ts           # Main server file
├── models/
│   ├── database.ts    # Database initialization
│   ├── User.ts        # User model (vulnerable)
│   └── Post.ts        # Post model (vulnerable)
└── routes/
    ├── a01-broken-access-control.ts
    ├── a02-cryptographic-failures.ts
    └── ... (A03-A10)

frontend/src/
├── App.tsx            # Main application
├── components/
│   ├── HomePage.tsx   # Landing page
│   ├── Navigation.tsx # Navigation component
│   ├── A01BrokenAccessControl.tsx
│   └── ... (A02-A10)
└── ...
```

### Adding New Vulnerabilities

1. Create new route in `backend/src/routes/`
2. Add route to `backend/src/index.ts`
3. Create corresponding React component
4. Add component to App.tsx routing
5. Update navigation in Navigation.tsx

### Code Standards

- TypeScript for type safety
- Clear vulnerability markers in comments
- Educational explanations in responses
- Secure alternatives in documentation

## Troubleshooting

### Common Issues

1. **Port conflicts:**
   - Backend runs on 3001, frontend on 3000
   - Change ports in package.json if needed

2. **Database issues:**
   - Database auto-initializes on first run
   - Delete `database/vulnerable.db` to reset

3. **CORS errors:**
   - Ensure backend is running
   - Check axios requests use correct URLs

4. **Build errors:**
   - Ensure all dependencies installed
   - Check TypeScript compilation

### Getting Help

- Check console for error messages
- Verify all services are running
- Review network requests in browser dev tools

## Educational Resources

### OWASP References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)

### Security Learning

- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [SANS Secure Coding Practices](https://www.sans.org/white-papers/2172/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## License

MIT License - Educational use only

## Disclaimer

This software is provided for educational purposes only. The authors are not responsible for any misuse or damage caused by this software. Users must ensure they comply with all applicable laws and regulations.