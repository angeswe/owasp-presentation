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

This is an interactive demonstration of the **OWASP Top 10 (2025)** web application vulnerabilities and the **OWASP Top 10 for LLM Applications (2025)**. It includes:

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

## OWASP Top 10 (2025) Coverage

> Updated to the OWASP Top 10:2025. Versus 2021: Security Misconfiguration rose
> to #2; **Software Supply Chain Failures** (#3) is new and absorbs the old
> "Vulnerable & Outdated Components"; **Mishandling of Exceptional Conditions**
> (#10) is new; and SSRF was merged into Broken Access Control (#1).

1. **A01 - Broken Access Control**
   - Direct object references
   - Missing authorization / privilege escalation
   - Server-Side Request Forgery (SSRF) — *merged into A01 in 2025*

2. **A02 - Security Misconfiguration**
   - Default credentials
   - Debug information exposure
   - Unnecessary features

3. **A03 - Software Supply Chain Failures** *(new in 2025)*
   - Vulnerable & outdated components
   - Dependency confusion
   - Unsigned artifacts & malicious install scripts

4. **A04 - Cryptographic Failures**
   - Plain text passwords
   - Weak encryption algorithms
   - Hardcoded secrets

5. **A05 - Injection**
   - SQL injection
   - Command injection
   - NoSQL injection

6. **A06 - Insecure Design**
   - Missing security controls
   - Business logic flaws
   - Unlimited resource consumption

7. **A07 - Authentication Failures**
   - Weak passwords
   - Session hijacking
   - Brute force vulnerabilities

8. **A08 - Software or Data Integrity Failures**
   - Unsigned updates
   - Insecure deserialization
   - CI/CD vulnerabilities

9. **A09 - Security Logging and Alerting Failures**
   - Missing audit logs
   - Insufficient alerting
   - No anomaly detection

10. **A10 - Mishandling of Exceptional Conditions** *(new in 2025)*
    - Verbose error / stack-trace leakage
    - Leaked database errors (schema disclosure)
    - Fail-open on exception

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

Mounted by slug (not rank), so a future reshuffle never changes a URL:

- `GET /api` - API overview
- `/api/broken-access-control/*` - Broken Access Control demos (incl. SSRF at `/ssrf/*`)
- `/api/security-misconfiguration/*` - Security Misconfiguration demos
- `/api/software-supply-chain-failures/*` - Software Supply Chain Failures demos
- `/api/cryptographic-failures/*` - Cryptographic Failures demos
- `/api/injection/*` - Injection demos
- `/api/insecure-design/*` - Insecure Design demos
- `/api/authentication-failures/*` - Authentication Failures demos
- `/api/data-integrity-failures/*` - Software or Data Integrity Failures demos
- `/api/security-logging-alerting-failures/*` - Security Logging & Alerting Failures demos
- `/api/mishandling-exceptional-conditions/*` - Mishandling of Exceptional Conditions demos

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
└── routes/           # named by slug, not rank
    ├── broken-access-control.ts        # A01 (mounts server-side-request-forgery.ts at /ssrf)
    ├── security-misconfiguration.ts    # A02
    ├── software-supply-chain-failures.ts  # A03
    └── ... (one file per vulnerability, mounted in 2025 order by index.ts)

frontend/src/
├── App.tsx            # Main application (routes derived from the registry)
├── components/
│   ├── LandingPage.tsx   # Landing page
│   ├── Navigation.tsx    # Web nav (derived from the registry)
│   ├── WebHomePage.tsx   # Web home grid (derived from the registry)
│   └── web/
│       ├── webTop10.ts            # single source of truth: rank/order/title/route/apiBase
│       ├── types.ts               # WebVuln / WebVulnProps
│       ├── BrokenAccessControl.tsx
│       └── ... (one file per vulnerability, named by slug not rank)
└── ...
```

### Adding or Re-ranking Web Vulnerabilities

The Web track is registry-driven, so updates are localized:

1. Create a slug-named route in `backend/src/routes/` and mount it in `backend/src/index.ts`
2. Create a slug-named React component in `frontend/src/components/web/` (props: `WebVulnProps`)
3. Add (or reorder) the entry in `frontend/src/components/web/webTop10.ts`

App routing, the Navigation, the home grid and every "Next" button all derive
from that registry — there is nothing else to edit for a re-rank.

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

- [OWASP Top 10 2025](https://owasp.org/Top10/2025/)
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