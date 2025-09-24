import React, { useState } from "react";
import axios from "axios";
import "./VulnerabilityPage.css";

const A02CryptographicFailures: React.FC = () => {
  const [hashInput, setHashInput] = useState("password");
  const [base64Input, setBase64Input] = useState("sensitive-data");
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const testBase64Encoding = async () => {
    setLoading(true);
    try {
      const res = await axios.post(
        "http://localhost:3001/api/a02/fake-encryption",
        {
          sensitive_data: base64Input,
        }
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const testWeakHash = async () => {
    setLoading(true);
    try {
      const res = await axios.post(
        "http://localhost:3001/api/a02/weak-hash",
        {
          password: hashInput,
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
        <h1>A02 - Cryptographic Failures</h1>
        <div className="vulnerability-badge">OWASP #2</div>
      </div>

      <div className="vuln-description">
        <p>
          Previously known as Sensitive Data Exposure, this vulnerability occurs
          when cryptographic protections are missing or improperly implemented,
          leading to exposure of sensitive data.
        </p>
      </div>

      <div className="demo-section">
        <h2>#️⃣ Demo 1: Weak Hashing (MD5)</h2>
        <p>
          This demo hashes a password using MD5, a broken hashing algorithm.
          The response will include the hash, which can often be reversed using
          online tools or rainbow tables.
        </p>
        <div className="demo-controls">
          <label>
            Password to hash:
            <input
              type="text"
              value={hashInput}
              onChange={(e) => setHashInput(e.target.value)}
            />
          </label>
          <button onClick={testWeakHash} disabled={loading}>
            Hash with MD5
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>🚫 Demo 2: Base64 is Not Encryption</h2>
        <p>
          This demo shows that Base64 is an encoding scheme, not encryption.
          It's easily reversible and should never be used to protect sensitive
          data.
        </p>
        <div className="demo-controls">
          <label>
            Data to encode:
            <input
              type="text"
              value={base64Input}
              onChange={(e) => setBase64Input(e.target.value)}
            />
          </label>
          <button onClick={testBase64Encoding} disabled={loading}>
            Encode with Base64
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
              style={{
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                marginBottom: "10px",
              }}
            >
              <h3 style={{ margin: 0 }}>C#/.NET - Secure Cryptography</h3>
              <span style={{ marginLeft: "10px", fontSize: "14px" }}>
                {showCSharpExamples ? "▼ Hide" : "▶ Show"}
              </span>
            </div>
            {showCSharpExamples && (
              <pre className="code-block">
                {`// Secure password hashing with BCrypt
using BCrypt.Net;

public string HashPassword(string password)
{
    return BCrypt.HashPassword(password, BCrypt.GenerateSalt(12));
}

public bool VerifyPassword(string password, string hash)
{
    return BCrypt.Verify(password, hash);
}

// Secure AES encryption with Data Protection API
using Microsoft.AspNetCore.DataProtection;

public class SecureEncryption
{
    private readonly IDataProtector _protector;

    public SecureEncryption(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("MyApp.Encryption");
    }

    public string Encrypt(string plaintext)
    {
        return _protector.Protect(plaintext);
    }

    public string Decrypt(string ciphertext)
    {
        return _protector.Unprotect(ciphertext);
    }
}

// Secure random token generation
using System.Security.Cryptography;

public string GenerateSecureToken()
{
    using var rng = RandomNumberGenerator.Create();
    var bytes = new byte[32];
    rng.GetBytes(bytes);
    return Convert.ToBase64String(bytes);
}

// Secure JWT implementation
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

public string CreateSecureJWT(ClaimsPrincipal user)
{
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
    var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: _configuration["JWT:Issuer"],
        audience: _configuration["JWT:Audience"],
        claims: user.Claims,
        expires: DateTime.UtcNow.AddHours(1),
        signingCredentials: credentials
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
}`}
              </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Use Strong Encryption</h4>
            <p>Use AES-256 or equivalent with proper key management</p>
            <code>AES-256-GCM with random IV</code>
          </div>
          <div className="fix-item">
            <h4>2. Secure Password Hashing</h4>
            <p>Use bcrypt, scrypt, or Argon2 with high work factors</p>
            <code>bcrypt.hash(password, 12)</code>
          </div>
          <div className="fix-item">
            <h4>3. Proper Key Management</h4>
            <p>Store keys securely and rotate them regularly</p>
            <code>Use environment variables or key vaults</code>
          </div>
          <div className="fix-item">
            <h4>4. Use HTTPS/TLS</h4>
            <p>Encrypt data in transit with TLS 1.2+</p>
            <code>app.use(helmet.hsts())</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Never Hardcode Secrets:</strong> Use environment variables
              or secure vaults
            </li>
            <li>
              <strong>Use Standard Libraries:</strong> Don't implement custom
              crypto algorithms
            </li>
            <li>
              <strong>Random initialization vector (IV):</strong> Always use cryptographically secure
              random IVs
            </li>
            <li>
              <strong>Key Rotation:</strong> Implement regular key rotation
              policies
            </li>
            <li>
              <strong>Certificate Validation:</strong> Never disable TLS
              certificate validation
            </li>
            <li>
              <strong>Strong Work Factors:</strong> Use appropriate rounds for
              password hashing
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/a03" className="next-button">
          Next: A03 - Injection →
        </a>
      </div>
    </div>
  );
};

export default A02CryptographicFailures;
