import React, { useState } from "react";
import axios from "axios";
import "./VulnerabilityPage.css";

const A04InsecureDesign: React.FC = () => {
  const [resetUsername, setResetUsername] = useState("admin");
  const [newPassword, setNewPassword] = useState("new_password_123");
  const [itemId, setItemId] = useState("item-123");
  const [quantity, setQuantity] = useState(5);
  const [purchaseUserId, setPurchaseUserId] = useState(2);
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const handlePasswordReset = async () => {
    setLoading(true);
    try {
      const res = await axios.post(
        "http://localhost:3001/api/a04/password-reset",
        {
          username: resetUsername,
          new_password: newPassword,
        }
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handlePurchase = async () => {
    setLoading(true);
    try {
      const res = await axios.post(
        "http://localhost:3001/api/a04/purchase",
        {
          item_id: itemId,
          quantity: quantity,
          user_id: purchaseUserId,
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
        <h1>A04 - Insecure Design</h1>
        <div className="vulnerability-badge">OWASP #4</div>
      </div>
      <div className="vuln-description">
        <p>
          Insecure design represents flaws in the design and architecture that
          cannot be fixed with a simple implementation change. It focuses on the
          need for threat modeling and secure design patterns.
        </p>
      </div>

      <div className="demo-section">
        <h2>🔓 Demo 1: Insecure Password Reset</h2>
        <p>
          This demo shows a password reset feature that lacks proper identity
          verification. An attacker can reset any user's password if they know
          their username, completely taking over the account.
        </p>
        <div className="demo-controls">
          <label>
            Username to Reset:
            <input
              type="text"
              value={resetUsername}
              onChange={(e) => setResetUsername(e.target.value)}
            />
          </label>
          <label>
            New Password:
            <input
              type="text"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </label>
          <button onClick={handlePasswordReset} disabled={loading}>
            Reset Password
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>💸 Demo 2: Business Logic Bypass</h2>
        <p>
          This demo simulates a purchase flow with a critical design flaw: the
          price of an item is negative. This allows an attacker to receive a
          credit instead of being charged. The system lacks validation to
          prevent negative prices or quantities.
        </p>
        <div className="demo-controls">
          <label>
            Item ID:
            <input
              type="text"
              value={itemId}
              onChange={(e) => setItemId(e.target.value)}
            />
          </label>
          <label>
            Quantity:
            <input
              type="number"
              value={quantity}
              onChange={(e) => setQuantity(parseInt(e.target.value, 10))}
            />
          </label>
          <label>
            User ID:
            <input
              type="number"
              value={purchaseUserId}
              onChange={(e) =>
                setPurchaseUserId(parseInt(e.target.value, 10))
              }
            />
          </label>
          <button onClick={handlePurchase} disabled={loading}>
            Make Purchase
          </button>
        </div>
        <div className="vulnerability-explanation">
          <h4>🚨 Why this is dangerous:</h4>
          <ul>
            <li>
              Attackers can exploit business logic to gain financial benefits.
            </li>
            <li>
              The system trusts client-side input without server-side
              validation.
            </li>
            <li>
              Lack of checks for edge cases (like negative values) can lead to
              unexpected behavior.
            </li>
          </ul>
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
              <h3 style={{ margin: 0 }}>C#/.NET - Secure Design Implementation</h3>
              <span style={{ marginLeft: '10px', fontSize: '14px' }}>
                {showCSharpExamples ? '▼ Hide' : '▶ Show'}
              </span>
            </div>
            {showCSharpExamples && (
            <pre className="code-block">
              {`// Rate limiting with AspNetCoreRateLimit
public void ConfigureServices(IServiceCollection services)
{
    services.AddMemoryCache();
    services.Configure<IpRateLimitOptions>(Configuration.GetSection("IpRateLimiting"));
    services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
    services.AddInMemoryRateLimiting();
}

// Account lockout configuration
public void ConfigureServices(IServiceCollection services)
{
    services.Configure<IdentityOptions>(options =>
    {
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.AllowedForNewUsers = true;
    });
}

// Secure password reset implementation
public class PasswordResetService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IEmailService _emailService;

    public async Task<bool> InitiatePasswordResetAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);

        // Always return true to prevent email enumeration
        if (user == null)
            return true;

        // Generate secure token
        var token = await _userManager.GeneratePasswordResetTokenAsync(user);

        // Create reset URL with token
        var resetUrl = $"{_clientUrl}/reset-password?token={WebUtility.UrlEncode(token)}&email={WebUtility.UrlEncode(email)}";

        // Send email
        await _emailService.SendPasswordResetEmailAsync(user.Email, resetUrl);

        return true;
    }
}

// Multi-factor authentication with TOTP
public class MfaService
{
    public string GenerateSetupCode(string userEmail)
    {
        var key = KeyGeneration.GenerateRandomKey(20);
        var setupInfo = $"otpauth://totp/YourApp:{userEmail}?secret={Base32Encoding.ToString(key)}&issuer=YourApp";

        return setupInfo;
    }

    public bool ValidateTotp(string secretKey, string userCode)
    {
        var otp = new Totp(Base32Encoding.ToBytes(secretKey));
        return otp.VerifyTotp(userCode, out long timeStepMatched, VerificationWindow.RfcSpecifiedNetworkDelay);
    }
}`}
            </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Threat Modeling</h4>
            <p>Conduct threat modeling during design phase</p>
            <code>Identify assets, threats, and controls</code>
          </div>
          <div className="fix-item">
            <h4>2. Secure Development Lifecycle</h4>
            <p>Integrate security into all development phases</p>
            <code>Security reviews at each milestone</code>
          </div>
          <div className="fix-item">
            <h4>3. Defense in Depth</h4>
            <p>Implement multiple layers of security controls</p>
            <code>Rate limiting + MFA + monitoring</code>
          </div>
          <div className="fix-item">
            <h4>4. Security Architecture Review</h4>
            <p>Regular review of security architecture</p>
            <code>Quarterly security design reviews</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Security by Design:</strong> Build security into the
              architecture from the start
            </li>
            <li>
              <strong>Principle of Least Privilege:</strong> Grant minimum
              necessary access and permissions
            </li>
            <li>
              <strong>Fail Securely:</strong> Ensure system fails to a secure
              state when errors occur
            </li>
            <li>
              <strong>Defense in Depth:</strong> Use multiple layers of security
              controls
            </li>
            <li>
              <strong>Zero Trust Architecture:</strong> Never trust, always
              verify every request
            </li>
            <li>
              <strong>Regular Security Reviews:</strong> Conduct periodic
              architecture security assessments
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/web/a05" className="next-button">
          Next: A05 - Security Misconfiguration →
        </a>
      </div>
    </div>
  );
};

export default A04InsecureDesign;
