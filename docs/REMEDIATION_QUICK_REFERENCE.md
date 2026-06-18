# OWASP Top 10 Remediation Quick Reference

This document provides a quick reference to secure coding practices for fixing OWASP Top 10 vulnerabilities in both JavaScript/Node.js and C#/.NET applications.

## 📋 Quick Fix Checklist

> Ordered to the **OWASP Top 10:2025**. SSRF is now part of A01; A03 and A10 are
> new/expanded categories.

### A01 - Broken Access Control
- [ ] Implement authentication middleware/attributes
- [ ] Add authorization checks before resource access
- [ ] Use role-based and resource-based access control
- [ ] Validate user permissions on every request
- [ ] Log unauthorized access attempts
- [ ] **SSRF (merged into A01 in 2025):** validate/allowlist outbound URLs, block internal IPs & cloud metadata, don't follow redirects

**JavaScript:** JWT middleware + role checks; URL allowlisting for outbound fetches
**C#:** `[Authorize]` attributes + Claims-based authorization; validated HttpClient

### A02 - Security Misconfiguration
- [ ] Remove debug information in production
- [ ] Set security headers (CSP, HSTS, etc.)
- [ ] Configure secure CORS policies
- [ ] Use secure session configuration
- [ ] Implement proper error handling

**JavaScript:** helmet + secure middleware
**C#:** Security headers + proper error pages

### A03 - Software Supply Chain Failures
- [ ] Keep dependencies updated; run audits (`npm audit` / `dotnet list package --vulnerable`)
- [ ] Pin versions with integrity-checked lockfiles; remove unused dependencies
- [ ] Pin internal scopes to a private registry to defeat dependency confusion
- [ ] Verify artifact signatures & checksums; adopt SLSA provenance and an SBOM
- [ ] Disable install lifecycle scripts (`npm ci --ignore-scripts`)

**JavaScript:** npm audit + dependabot, `--ignore-scripts`, scoped registries
**C#:** NuGet scanning + `packageSourceMapping`, signed packages

### A04 - Cryptographic Failures
- [ ] Hash passwords with bcrypt/PBKDF2 (12+ rounds)
- [ ] Use strong encryption (AES-256-GCM)
- [ ] Generate cryptographically secure random tokens
- [ ] Store secrets in environment variables
- [ ] Implement proper key management

**JavaScript:** bcrypt + crypto.randomBytes()
**C#:** KeyDerivation.Pbkdf2 + Data Protection API

### A05 - Injection
- [ ] Use parameterized queries/prepared statements
- [ ] Validate and sanitize all user inputs
- [ ] Implement input length limits
- [ ] Use ORM/query builders when possible
- [ ] Escape output when building dynamic content

**JavaScript:** Use query parameters with db libraries
**C#:** Use Entity Framework LINQ or parameterized SQL

### A06 - Insecure Design
- [ ] Implement rate limiting on sensitive endpoints
- [ ] Add business logic validation
- [ ] Use secure design patterns
- [ ] Implement proper workflow controls
- [ ] Add resource consumption limits

**JavaScript:** express-rate-limit + validation middleware
**C#:** Rate limiting middleware + business rule services

### A07 - Authentication Failures
- [ ] Enforce strong password policies
- [ ] Implement account lockout mechanisms
- [ ] Use secure session management
- [ ] Add multi-factor authentication
- [ ] Monitor authentication events

**JavaScript:** passport.js + secure sessions
**C#:** Identity framework + JWT tokens

### A08 - Software or Data Integrity Failures
- [ ] Verify digital signatures on packages
- [ ] Implement checksum validation
- [ ] Use secure CI/CD pipelines
- [ ] Validate serialized data
- [ ] Monitor software supply chain

**JavaScript:** package-lock.json + integrity checks
**C#:** Package verification + secure deserialization

### A09 - Security Logging and Alerting Failures
- [ ] Log all security-relevant events
- [ ] Implement real-time monitoring
- [ ] Set up alerting for suspicious activities
- [ ] Ensure log integrity and retention
- [ ] Monitor for anomalies

**JavaScript:** winston + structured logging
**C#:** Serilog + Application Insights

### A10 - Mishandling of Exceptional Conditions
- [ ] Return generic client errors — never leak stack traces, SQL or file paths
- [ ] Centralize error handling at a single boundary
- [ ] Fail closed: an exception in a security check must deny, not allow
- [ ] Disable debug/developer error pages in production
- [ ] Log full detail server-side with a correlation id the client can quote

**JavaScript:** Express error middleware + `app.set('env', 'production')`
**C#:** `app.UseExceptionHandler` + `IsDevelopment()` guard

## 🛠️ Essential Security Libraries

### JavaScript/Node.js
```bash
npm install helmet express-rate-limit bcrypt jsonwebtoken
npm install express-validator joi morgan winston
npm install cors cookie-parser express-session
```

### C#/.NET
```xml
<PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" />
<PackageReference Include="Microsoft.AspNetCore.DataProtection" />
<PackageReference Include="Microsoft.AspNetCore.RateLimiting" />
<PackageReference Include="Serilog.AspNetCore" />
<PackageReference Include="FluentValidation.AspNetCore" />
```

## 🔧 Common Security Patterns

### Authentication Middleware
```javascript
// JavaScript
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};
```

```csharp
// C#
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
public class SecureController : ControllerBase
{
    // All actions require authentication
}
```

### Input Validation
```javascript
// JavaScript
const { body, validationResult } = require('express-validator');

app.post('/user',
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 12 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // Process valid input
  }
);
```

```csharp
// C#
public class CreateUserRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [MinLength(12)]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).*$")]
    public string Password { get; set; }
}
```

### Rate Limiting
```javascript
// JavaScript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts
  message: 'Too many login attempts'
});

app.post('/login', loginLimiter, loginHandler);
```

```csharp
// C#
services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("Login", limiterOptions =>
    {
        limiterOptions.PermitLimit = 5;
        limiterOptions.Window = TimeSpan.FromMinutes(15);
    });
});

[EnableRateLimiting("Login")]
public async Task<IActionResult> Login(LoginRequest request) { }
```

## 🔍 Security Testing Commands

### JavaScript/Node.js
```bash
# Security audit
npm audit
npm audit fix

# Check for vulnerabilities
npx audit-ci --moderate

# Static analysis
npx eslint . --ext .js,.ts
npx semgrep --config=auto .

# Dependency updates
npx npm-check-updates
```

### C#/.NET
```bash
# Security scan
dotnet list package --vulnerable
dotnet list package --outdated

# Static analysis
dotnet build --verbosity normal
dotnet format --verify-no-changes

# Security-focused linting
dotnet add package SecurityCodeScan.VS2019
```

## 📚 Additional Resources

### Documentation
- [OWASP Top 10 2025](https://owasp.org/Top10/2025/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [.NET Security Guidelines](https://docs.microsoft.com/en-us/dotnet/standard/security/)

### Training Platforms
- [OWASP WebGoat](https://github.com/WebGoat/WebGoat)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [TryHackMe](https://tryhackme.com/)
- [Hack The Box](https://www.hackthebox.eu/)

### Security Tools
- **Static Analysis:** SonarQube, CodeQL, Semgrep
- **Dependency Scanning:** Snyk, WhiteSource, OWASP Dependency Check
- **Dynamic Testing:** OWASP ZAP, Burp Suite
- **Infrastructure:** Docker security scanning, Kubernetes security policies

## 🚨 Emergency Response

If you discover a vulnerability in production:

1. **Assess Impact:** Determine severity and potential data exposure
2. **Immediate Mitigation:** Block attack vectors, revoke compromised credentials
3. **Apply Fixes:** Deploy secure code following these patterns
4. **Monitor:** Watch for continued attack attempts
5. **Document:** Record incident details for future prevention
6. **Notify:** Inform stakeholders and potentially affected users

Remember: Security is an ongoing process, not a one-time fix. Regular security reviews, testing, and updates are essential for maintaining a secure application.