import React, { useState } from "react";
import axios from "axios";
import "./VulnerabilityPage.css";

const A09LoggingFailures: React.FC = () => {
  const [userId, setUserId] = useState("1");
  const [action, setAction] = useState("update_role");
  const [target, setTarget] = useState("user:2");
  const [loginUsername, setLoginUsername] = useState("user");
  const [loginPassword, setLoginPassword] = useState("password");
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const handleSensitiveAction = async () => {
    setLoading(true);
    try {
      const res = await axios.post(
        "http://localhost:3001/api/a09/sensitive-action",
        {
          user_id: userId,
          action: action,
          target: target,
        }
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleInsufficientLogin = async () => {
    setLoading(true);
    try {
      const res = await axios.post(
        "http://localhost:3001/api/a09/login-attempt",
        {
          username: loginUsername,
          password: loginPassword,
        }
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleFetchSensitiveLogs = async () => {
    setLoading(true);
    try {
      const res = await axios.get("http://localhost:3001/api/a09/logs");
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>A09 - Security Logging and Monitoring Failures</h1>
        <div className="vulnerability-badge">OWASP #9</div>
      </div>
      <div className="vuln-description">
        <p>
          Insufficient logging, monitoring, and alerting make it difficult to
          detect and respond to attacks. Attackers can exploit this lack of
          visibility to maintain persistence, pivot to other systems, and tamper
          with data without being noticed.
        </p>
      </div>

      <div className="demo-section">
        <h2>🕵️ Demo 1: No Logging for Sensitive Actions</h2>
        <p>
          This demo simulates performing a sensitive action, such as changing a
          user's role. The action succeeds, but the system fails to log this
          critical security event, making it impossible to audit or detect
          malicious behavior.
        </p>
        <div className="demo-controls">
          <label>
            User ID Performing Action:
            <input
              type="text"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
            />
          </label>
          <label>
            Action:
            <input
              type="text"
              value={action}
              onChange={(e) => setAction(e.target.value)}
            />
          </label>
          <label>
            Target:
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </label>
          <button onClick={handleSensitiveAction} disabled={loading}>
            Perform Action
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>📝 Demo 2: Insufficient Login Logging</h2>
        <p>
          This demo simulates a login attempt. Whether successful or not, the
          system fails to log critical details like the source IP address, user
          agent, or a timestamp, making it hard to trace suspicious activity.
        </p>
        <div className="demo-controls">
          <label>
            Username:
            <input
              type="text"
              value={loginUsername}
              onChange={(e) => setLoginUsername(e.target.value)}
            />
          </label>
          <label>
            Password:
            <input
              type="password"
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
            />
          </label>
          <button onClick={handleInsufficientLogin} disabled={loading}>
            Attempt Login
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>📄 Demo 3: Sensitive Data in Logs</h2>
        <p>
          This demo simulates fetching application logs that improperly contain
          sensitive data like passwords, API keys, and PII. Exposing this
          information in logs creates a huge security risk.
        </p>
        <div className="demo-controls">
          <button onClick={handleFetchSensitiveLogs} disabled={loading}>
            Fetch Sensitive Logs
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
              <h3 style={{ margin: 0 }}>
                C#/.NET - Secure Logging & Monitoring
              </h3>
              <span style={{ marginLeft: "10px", fontSize: "14px" }}>
                {showCSharpExamples ? "▼ Hide" : "▶ Show"}
              </span>
            </div>
            {showCSharpExamples && (
              <pre className="code-block">
                {`// Comprehensive logging with Serilog and Application Insights
using Serilog;
using Microsoft.ApplicationInsights;

public class SecurityLoggingService
{
    private readonly ILogger<SecurityLoggingService> _logger;
    private readonly TelemetryClient _telemetryClient;

    public SecurityLoggingService(
        ILogger<SecurityLoggingService> logger,
        TelemetryClient telemetryClient)
    {
        _logger = logger;
        _telemetryClient = telemetryClient;
    }

    public void LogAuthenticationSuccess(string userId, string ipAddress)
    {
        _logger.LogInformation("Authentication successful for user {UserId} from {IpAddress}",
            userId, ipAddress);

        _telemetryClient.TrackEvent("AuthenticationSuccess", new Dictionary<string, string>
        {
            { "UserId", userId },
            { "IpAddress", ipAddress },
            { "Timestamp", DateTime.UtcNow.ToString("O") }
        });
    }

    public void LogAuthenticationFailure(string username, string ipAddress)
    {
        _logger.LogWarning("Authentication failed for username {Username} from {IpAddress}",
            username, ipAddress);

        _telemetryClient.TrackEvent("AuthenticationFailure", new Dictionary<string, string>
        {
            { "Username", username },
            { "IpAddress", ipAddress },
            { "Timestamp", DateTime.UtcNow.ToString("O") }
        });
    }

    public void LogSuspiciousActivity(string activityType, string details, string userId = null)
    {
        _logger.LogWarning("Suspicious activity detected: {ActivityType} - {Details} for user {UserId}",
            activityType, details, userId ?? "Anonymous");

        _telemetryClient.TrackEvent("SuspiciousActivity", new Dictionary<string, string>
        {
            { "ActivityType", activityType },
            { "Details", details },
            { "UserId", userId ?? "Anonymous" },
            { "Timestamp", DateTime.UtcNow.ToString("O") }
        });
    }
}

// Authentication event logging middleware
public class AuthenticationLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SecurityLoggingService _securityLogger;

    public AuthenticationLoggingMiddleware(RequestDelegate next, SecurityLoggingService securityLogger)
    {
        _next = next;
        _securityLogger = securityLogger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments("/api/auth"))
        {
            var originalBodyStream = context.Response.Body;
            using var responseBody = new MemoryStream();
            context.Response.Body = responseBody;

            await _next(context);

            var ipAddress = context.Connection.RemoteIpAddress?.ToString();

            if (context.Response.StatusCode == 200)
            {
                var userId = context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                _securityLogger.LogAuthenticationSuccess(userId, ipAddress);
            }
            else if (context.Response.StatusCode == 401)
            {
                _securityLogger.LogAuthenticationFailure("Unknown", ipAddress);
            }

            responseBody.Seek(0, SeekOrigin.Begin);
            await responseBody.CopyToAsync(originalBodyStream);
        }
        else
        {
            await _next(context);
        }
    }
}`}
              </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Comprehensive Logging</h4>
            <p>Log all security-relevant events with sufficient detail</p>
            <code>logger.info('User login', &#123;userId, ip&#125;)</code>
          </div>
          <div className="fix-item">
            <h4>2. Real-time Monitoring</h4>
            <p>Implement alerting for suspicious activities</p>
            <code>alerting.trigger('MULTIPLE_FAILED_LOGINS')</code>
          </div>
          <div className="fix-item">
            <h4>3. Centralized Logging</h4>
            <p>Use centralized logging systems for analysis</p>
            <code>ELK Stack, Splunk, or Azure Monitor</code>
          </div>
          <div className="fix-item">
            <h4>4. Incident Response</h4>
            <p>Integrate with incident response procedures</p>
            <code>SIEM integration and automated responses</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Log Security Events:</strong> Authentication,
              authorization, data access, and admin actions
            </li>
            <li>
              <strong>Structured Logging:</strong> Use JSON format for easy
              parsing and analysis
            </li>
            <li>
              <strong>Sensitive Data Protection:</strong> Never log passwords,
              tokens, or PII
            </li>
            <li>
              <strong>Real-time Alerting:</strong> Set up alerts for suspicious
              patterns and failed attempts
            </li>
            <li>
              <strong>Log Retention:</strong> Maintain logs for sufficient time
              for forensic analysis
            </li>
            <li>
              <strong>Regular Review:</strong> Periodically review logs and
              update monitoring rules
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/web/a10" className="next-button">
          Next: A10 - SSRF →
        </a>
      </div>
    </div>
  );
};

export default A09LoggingFailures;
