import React, { useState } from "react";
import axios from "axios";
import "./VulnerabilityPage.css";

const A07AuthenticationFailures: React.FC = () => {
  const [username, setUsername] = useState("user");
  const [password, setPassword] = useState("wrong-password");
  const [jwtUsername, setJwtUsername] = useState("admin");
  const [jwtPassword, setJwtPassword] = useState("new_password_123");
  const [recoveryUsername, setRecoveryUsername] = useState("user");
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const handleBruteForceLogin = async () => {
    setLoading(true);
    try {
      const res = await axios.post(
        "http://localhost:3001/api/a07/brute-force-login",
        {
          username,
          password,
        }
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleJwtLogin = async () => {
    setLoading(true);
    try {
      const res = await axios.post("http://localhost:3001/api/a07/jwt-login", {
        username: jwtUsername,
        password: jwtPassword,
      });
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handlePasswordRecovery = async () => {
    setLoading(true);
    try {
      const res = await axios.post(
        "http://localhost:3001/api/a07/forgot-password",
        {
          username: recoveryUsername,
        }
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>A07 - Identification and Authentication Failures</h1>
        <div className="vulnerability-badge">OWASP #7</div>
      </div>
      <div className="vuln-description">
        <p>
          Failures in identification and authentication can allow an attacker to
          impersonate legitimate users, either by compromising their passwords,
          session tokens, or by exploiting other implementation flaws.
        </p>
      </div>

      <div className="demo-section">
        <h2>🛡️ Demo 1: Brute-Force Login</h2>
        <p>
          This login form has no rate-limiting or account lockout mechanism. An
          attacker can make unlimited login attempts to guess a user's password.
          Try submitting incorrect credentials multiple times.
        </p>
        <div className="demo-controls">
          <label>
            Username:
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </label>
          <label>
            Password:
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <button onClick={handleBruteForceLogin} disabled={loading}>
            Attempt Login
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>🔑 Demo 2: Weak JWT Generation</h2>
        <p>
          This demo shows a login that returns a JSON Web Token (JWT) generated
          with a weak, hardcoded secret and no expiration date. An attacker could
          easily crack the secret to forge tokens or use a stolen token forever.
        </p>
        <div className="demo-controls">
          <label>
            Username:
            <input
              type="text"
              value={jwtUsername}
              onChange={(e) => setJwtUsername(e.target.value)}
            />
          </label>
          <label>
            Password:
            <input
              type="password"
              value={jwtPassword}
              onChange={(e) => setJwtPassword(e.target.value)}
            />
          </label>
          <button onClick={handleJwtLogin} disabled={loading}>
            Login for JWT
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>🔓 Demo 3: Insecure Password Recovery</h2>
        <p>
          This demo shows a password recovery function that is fundamentally
          broken. Instead of sending a secure reset link, it returns the user's
          plaintext password directly, exposing it to attackers.
        </p>
        <div className="demo-controls">
          <label>
            Username to Recover:
            <input
              type="text"
              value={recoveryUsername}
              onChange={(e) => setRecoveryUsername(e.target.value)}
            />
          </label>
          <button onClick={handlePasswordRecovery} disabled={loading}>
            Recover Password
          </button>
        </div>
      </div>

      {response && (
        <div className="response-section">
          <h3>Response:</h3>
          <pre className="response-box">
            {JSON.stringify(response, null, 2)}
          </pre>
        </div>
      )}

      <div className="remediation-section">
        <h2>🛡️ How to Fix This</h2>

        <div className="code-examples">
          <div className="code-example">
            <div
              className="code-example-header"
              onClick={() => setShowCSharpExamples(!showCSharpExamples)}
              style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', marginBottom: '10px' }}
            >
              <h3 style={{ margin: 0 }}>C#/.NET - Secure Authentication</h3>
              <span style={{ marginLeft: '10px', fontSize: '14px' }}>
                {showCSharpExamples ? '▼ Hide' : '▶ Show'}
              </span>
            </div>
            {showCSharpExamples && (
              <pre className="code-block">
                {`// Secure authentication service
public class AuthenticationService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ITokenService _tokenService;
    private readonly ILogger<AuthenticationService> _logger;

    // Password validation
    public class PasswordValidator : IPasswordValidator<ApplicationUser>
    {
        public Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user, string password)
        {
            var errors = new List<IdentityError>();

            if (password.Length < 8)
                errors.Add(new IdentityError { Description = "Password must be at least 8 characters long" });

            if (!password.Any(char.IsUpper))
                errors.Add(new IdentityError { Description = "Password must contain uppercase letter" });

            if (!password.Any(char.IsLower))
                errors.Add(new IdentityError { Description = "Password must contain lowercase letter" });

            if (!password.Any(char.IsDigit))
                errors.Add(new IdentityError { Description = "Password must contain number" });

            if (!password.Any(ch => !char.IsLetterOrDigit(ch)))
                errors.Add(new IdentityError { Description = "Password must contain special character" });

            return Task.FromResult(errors.Any() ?
                IdentityResult.Failed(errors.ToArray()) :
                IdentityResult.Success);
        }
    }

    // Secure registration
    public async Task<AuthResult> RegisterAsync(RegisterRequest request)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            EmailConfirmed = false,
            LockoutEnabled = true,
            AccessFailedCount = 0
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (!result.Succeeded)
        {
            return new AuthResult { Errors = result.Errors.Select(e => e.Description) };
        }

        // Generate email confirmation token
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        await _emailService.SendConfirmationEmailAsync(user.Email, token);

        return new AuthResult { Success = true, Message = "Registration successful. Please confirm email." };
    }

    // Secure login with lockout
    public async Task<AuthResult> LoginAsync(LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);

        if (user == null)
        {
            // Prevent user enumeration - always take same time
            await Task.Delay(TimeSpan.FromMilliseconds(500));
            return new AuthResult { Errors = new[] { "Invalid credentials" } };
        }

        // Check if account is locked
        if (await _userManager.IsLockedOutAsync(user))
        {
            _logger.LogWarning("Login attempt for locked account: {Email}", request.Email);
            return new AuthResult { Errors = new[] { "Account is temporarily locked" } };
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);

        if (!result.Succeeded)
        {
            if (result.IsLockedOut)
            {
                _logger.LogWarning("Account locked due to failed attempts: {Email}", request.Email);
                return new AuthResult { Errors = new[] { "Account locked due to multiple failed attempts" } };
            }

            return new AuthResult { Errors = new[] { "Invalid credentials" } };
        }

        // Generate JWT token
        var token = await _tokenService.GenerateJwtTokenAsync(user);

        // Update last login
        user.LastLogin = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        return new AuthResult
        {
            Success = true,
            Token = token,
            User = new UserDto { Id = user.Id, Email = user.Email }
        };
    }
}

// JWT Token Service
public class TokenService : ITokenService
{
    public async Task<string> GenerateJwtTokenAsync(ApplicationUser user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:SecretKey"]);

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat,
                new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64)
        };

        var roles = await _userManager.GetRolesAsync(user);
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(15),
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"],
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}`}
              </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Strong Password Policy</h4>
            <p>Enforce complex password requirements</p>
            <code>8+ chars, mixed case, numbers, symbols</code>
          </div>
          <div className="fix-item">
            <h4>2. Account Lockout</h4>
            <p>Implement account lockout after failed attempts</p>
            <code>5 attempts → 2 hour lockout</code>
          </div>
          <div className="fix-item">
            <h4>3. Multi-Factor Authentication</h4>
            <p>Add second factor authentication</p>
            <code>TOTP, SMS, hardware tokens</code>
          </div>
          <div className="fix-item">
            <h4>4. Secure Session Management</h4>
            <p>Use secure session configurations</p>
            <code>HttpOnly, Secure, SameSite cookies</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Password Hashing:</strong> Use bcrypt, scrypt, or Argon2
              for password hashing
            </li>
            <li>
              <strong>Session Security:</strong> Use secure session management
              with proper timeouts
            </li>
            <li>
              <strong>Failed Login Protection:</strong> Implement account
              lockout and rate limiting
            </li>
            <li>
              <strong>Multi-Factor Authentication:</strong> Enable MFA for
              sensitive accounts
            </li>
            <li>
              <strong>Password Recovery:</strong> Use secure password reset
              flows with token expiration
            </li>
            <li>
              <strong>Audit Logging:</strong> Log all authentication events for
              monitoring
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/web/a08" className="next-button">
          Next: A08 - Integrity Failures →
        </a>
      </div>
    </div>
  );
};

export default A07AuthenticationFailures;
