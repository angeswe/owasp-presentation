import React, { useState } from "react";
import axios from "axios";
import "./VulnerabilityPage.css";

const A05SecurityMisconfiguration: React.FC = () => {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const handleDefaultLogin = async () => {
    setLoading(true);
    try {
      const res = await axios.post(
        "http://localhost:3001/api/a05/admin-login",
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

  const handleErrorTrigger = async () => {
    setLoading(true);
    try {
      // This request is expected to fail and return a detailed error
      await axios.get("http://localhost:3001/api/a05/error");
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handleDebugInfo = async () => {
    setLoading(true);
    try {
      const res = await axios.get("http://localhost:3001/api/a05/debug");
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>A05 - Security Misconfiguration</h1>
        <div className="vulnerability-badge">OWASP #5</div>
      </div>
      <div className="vuln-description">
        <p>
          Security misconfiguration is commonly a result of using default
          configurations, having incomplete or ad-hoc configurations, open cloud
          storage, misconfigured HTTP headers, and verbose error messages
          containing sensitive information.
        </p>
      </div>

      <div className="demo-section">
        <h2>🔑 Demo 1: Default Credentials</h2>
        <p>
          Many systems ship with default credentials that are often left
          unchanged. This demo shows how an attacker can gain admin access by
          trying common default usernames and passwords.
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
          <button onClick={handleDefaultLogin} disabled={loading}>
            Attempt Login
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>🐞 Demo 2: Verbose Error Messages</h2>
        <p>
          Exposing detailed error messages in a production environment can leak
          sensitive information about the system's architecture, libraries, and
          even credentials. Click the button to trigger a simulated server error.
        </p>
        <div className="demo-controls">
          <button onClick={handleErrorTrigger} disabled={loading}>
            Trigger Server Error
          </button>
        </div>
      </div>

      <div className="demo-section">
        <h2>🐛 Demo 3: Exposed Debug Endpoint</h2>
        <p>
          Debug endpoints are often left enabled in production environments by
          mistake. These can expose a wealth of sensitive information, including
          environment variables, system paths, and library versions.
        </p>
        <div className="demo-controls">
          <button onClick={handleDebugInfo} disabled={loading}>
            Fetch Debug Information
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
              <h3 style={{ margin: 0 }}>C#/.NET - Secure Configuration</h3>
              <span style={{ marginLeft: '10px', fontSize: '14px' }}>
                {showCSharpExamples ? '▼ Hide' : '▶ Show'}
              </span>
            </div>
            {showCSharpExamples && (
            <pre className="code-block">
              {`// Startup.cs - Secure configuration
public void ConfigureServices(IServiceCollection services)
{
    // HTTPS redirection
    services.AddHttpsRedirection(options =>
    {
        options.RedirectStatusCode = StatusCodes.Status307TemporaryRedirect;
        options.HttpsPort = 443;
    });

    // HSTS configuration
    services.AddHsts(options =>
    {
        options.Preload = true;
        options.IncludeSubDomains = true;
        options.MaxAge = TimeSpan.FromDays(365);
    });

    // CORS configuration
    services.AddCors(options =>
    {
        options.AddPolicy("SecurePolicy", builder =>
        {
            builder.WithOrigins(Configuration.GetSection("AllowedOrigins").Get<string[]>())
                   .AllowCredentials()
                   .AllowAnyMethod()
                   .AllowAnyHeader();
        });
    });

    // Authentication configuration
    services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = Configuration["Jwt:Issuer"],
                ValidAudience = Configuration["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(Configuration["Jwt:SecretKey"]))
            };
        });
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
    else
    {
        // Production error handling
        app.UseExceptionHandler("/Error");
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    // Security headers
    app.Use(async (context, next) =>
    {
        context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Add("X-Frame-Options", "DENY");
        context.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
        context.Response.Headers.Add("Referrer-Policy", "strict-origin-when-cross-origin");

        await next();
    });

    app.UseCors("SecurePolicy");
    app.UseAuthentication();
    app.UseAuthorization();
}

// appsettings.json configuration validation
public class ConfigurationValidator
{
    public static void ValidateConfiguration(IConfiguration config)
    {
        var requiredSettings = new[]
        {
            "ConnectionStrings:DefaultConnection",
            "Jwt:SecretKey",
            "Jwt:Issuer",
            "Jwt:Audience"
        };

        foreach (var setting in requiredSettings)
        {
            if (string.IsNullOrEmpty(config[setting]))
            {
                throw new InvalidOperationException($"Required configuration '{setting}' is missing");
            }
        }
    }
}`}
            </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Security Headers</h4>
            <p>Implement comprehensive security headers</p>
            <code>helmet(), HSTS, CSP, X-Frame-Options</code>
          </div>
          <div className="fix-item">
            <h4>2. Environment Configuration</h4>
            <p>Secure environment variable management</p>
            <code>dotenv, secrets management</code>
          </div>
          <div className="fix-item">
            <h4>3. Default Configuration Review</h4>
            <p>Change all default passwords and settings</p>
            <code>Custom admin credentials</code>
          </div>
          <div className="fix-item">
            <h4>4. Error Handling</h4>
            <p>Implement secure error handling</p>
            <code>No sensitive data in error messages</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Minimal Installation:</strong> Only install necessary
              components and features
            </li>
            <li>
              <strong>Secure Defaults:</strong> Configure secure defaults for
              all services and frameworks
            </li>
            <li>
              <strong>Regular Updates:</strong> Keep all components updated with
              latest security patches
            </li>
            <li>
              <strong>Security Headers:</strong> Implement comprehensive
              security headers
            </li>
            <li>
              <strong>Configuration Management:</strong> Use secure
              configuration management practices
            </li>
            <li>
              <strong>Environment Separation:</strong> Maintain separate
              configurations for different environments
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/a06" className="next-button">
          Next: A06 - Vulnerable Components →
        </a>
      </div>
    </div>
  );
};

export default A05SecurityMisconfiguration;
