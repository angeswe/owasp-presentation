import React, { useState } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import "../VulnerabilityPage.css";
import { WebVulnProps } from "./types";

const MishandlingExceptionalConditions: React.FC<WebVulnProps> = ({ meta, next }) => {
  const [a, setA] = useState("10");
  const [b, setB] = useState("0");
  const [lookupId, setLookupId] = useState("1' OR '1'='1");
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const handleDivide = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${meta.apiBase}/divide`, {
        a: Number(a),
        b: Number(b),
      });
      setResponse(res.data);
    } catch (error: any) {
      // The server returns 500 with the full leaked payload — show it verbatim.
      setResponse(error.response?.data || { error: error.message });
    }
    setLoading(false);
  };

  const handleLookup = async () => {
    setLoading(true);
    try {
      const res = await axios.get(
        `${meta.apiBase}/lookup?id=${encodeURIComponent(lookupId)}`
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse(error.response?.data || { error: error.message });
    }
    setLoading(false);
  };

  const handleLookupSafe = async () => {
    setLoading(true);
    try {
      const res = await axios.get(
        `${meta.apiBase}/lookup-safe?id=${encodeURIComponent(lookupId)}`
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse(error.response?.data || { error: error.message });
    }
    setLoading(false);
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>{meta.code} - {meta.title}</h1>
        <div className="vulnerability-badge">OWASP #{meta.rank}</div>
      </div>

      <div className="vuln-description">
        <p>
          New in OWASP 2025. When an application fails to handle errors safely it
          leaks stack traces, absolute file paths, library versions and the
          failing database query straight back to the client — handing an
          attacker a free map of the system internals. The same root cause also
          produces <em>fail-open</em> behaviour, where a check that throws is
          treated as success.
        </p>
      </div>

      <div className="demo-section">
        <h2>💥 Demo 1: Verbose Error &amp; Stack-Trace Leak</h2>
        <p>
          This endpoint does no safe error handling. Divide by zero (or pass a
          non-numeric operand) and the server returns a 500 with the full stack
          trace, the absolute source path, the working directory and the runtime
          version.
        </p>
        <div className="demo-controls">
          <label>
            a:
            <input type="number" value={a} onChange={(e) => setA(e.target.value)} />
          </label>
          <label>
            b:
            <input type="number" value={b} onChange={(e) => setB(e.target.value)} />
          </label>
          <button onClick={handleDivide} disabled={loading}>
            Divide
          </button>
        </div>
        <div className="demo-tips">
          <h4>💡 Try this:</h4>
          <ul>
            <li>a = 10, b = 0 — division by zero throws and leaks the stack</li>
            <li>Inspect <code>stack</code>, <code>source_file</code> and <code>working_directory</code> in the response</li>
          </ul>
        </div>
      </div>

      <div className="demo-section">
        <h2>🗄️ Demo 2: Leaked Database Error</h2>
        <p>
          A failed lookup returns the raw driver error verbatim — including the
          exact SQL and its table and column names (<code>password_hash</code>,{" "}
          <code>api_key</code>). That schema disclosure is a direct aid to SQL
          injection and data theft.
        </p>
        <div className="demo-controls">
          <label>
            User ID:
            <input
              type="text"
              value={lookupId}
              onChange={(e) => setLookupId(e.target.value)}
              style={{ width: "300px" }}
            />
          </label>
          <button onClick={handleLookup} disabled={loading}>
            Look Up (vulnerable)
          </button>
          <button onClick={handleLookupSafe} disabled={loading}>
            Look Up (secure handling)
          </button>
        </div>

        <div className="vulnerability-explanation">
          <h4>🚨 Why this is dangerous:</h4>
          <ul>
            <li>Stack traces fingerprint the framework and versions</li>
            <li>Leaked SQL reveals the schema and sensitive columns</li>
            <li>File paths expose the server's directory layout</li>
            <li>Compare the two buttons: the secure handler leaks nothing</li>
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
            <h3>JavaScript/Node.js - Safe Error Handling</h3>
            <pre className="code-block">
              {`// Centralized error handler (Express) — log internally, return generic message
const { randomUUID } = require('crypto');

app.use((err, req, res, next) => {
  const referenceId = randomUUID();
  // Full detail stays in the server log only:
  console.error(\`[\${referenceId}] \${req.method} \${req.path}\`, err);

  // The client gets an opaque message — never the stack, query or paths:
  res.status(500).json({
    error: 'An unexpected error occurred. Please try again later.',
    referenceId,
  });
});

// Fail CLOSED, not open: a check that throws must deny, not allow
function authorize(token) {
  try {
    return verify(token);          // returns true/false
  } catch (e) {
    return false;                  // exception => denied, never granted
  }
}

// Hide framework error pages in production
app.set('env', 'production');      // disables Express stack traces in responses`}
            </pre>
          </div>

          <div className="code-example">
            <div
              className="code-example-header"
              onClick={() => setShowCSharpExamples(!showCSharpExamples)}
              style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', marginBottom: '10px' }}
            >
              <h3 style={{ margin: 0 }}>C#/.NET - Safe Error Handling</h3>
              <span style={{ marginLeft: '10px', fontSize: '14px' }}>
                {showCSharpExamples ? '▼ Hide' : '▶ Show'}
              </span>
            </div>
            {showCSharpExamples && (
              <pre className="code-block">
                {`// Program.cs - generic error page in production (no stack traces to clients)
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();   // detailed errors ONLY in dev
}
else
{
    app.UseExceptionHandler("/error"); // generic handler in production
}

// A controller that logs detail server-side and returns an opaque response
[ApiController]
public class ErrorController : ControllerBase
{
    private readonly ILogger<ErrorController> _logger;
    public ErrorController(ILogger<ErrorController> logger) => _logger = logger;

    [Route("/error")]
    public IActionResult HandleError()
    {
        var feature = HttpContext.Features.Get<IExceptionHandlerFeature>();
        var referenceId = Guid.NewGuid().ToString();

        // Full exception detail goes to the log, never to the response:
        _logger.LogError(feature?.Error, "Unhandled exception {ReferenceId}", referenceId);

        return StatusCode(500, new
        {
            error = "An unexpected error occurred. Please try again later.",
            referenceId
        });
    }
}

// Fail closed: an exception during an authorization check must DENY
public bool IsAuthorized(string token)
{
    try { return _validator.Validate(token); }
    catch { return false; }   // never 'return true' in a catch block
}`}
              </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Generic Client Errors</h4>
            <p>Return an opaque message; keep detail in the server log</p>
            <code>500 + referenceId, never the stack</code>
          </div>
          <div className="fix-item">
            <h4>2. Centralized Handler</h4>
            <p>One error boundary so nothing leaks by accident</p>
            <code>app.UseExceptionHandler / Express error mw</code>
          </div>
          <div className="fix-item">
            <h4>3. Fail Closed</h4>
            <p>An exception in a check must deny, not allow</p>
            <code>catch =&gt; return false</code>
          </div>
          <div className="fix-item">
            <h4>4. Disable Debug in Prod</h4>
            <p>No developer error pages or verbose stacks in production</p>
            <code>env=production, IsDevelopment() guard</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Never Leak Internals:</strong> No stack traces, SQL, paths
              or versions in any client-facing response
            </li>
            <li>
              <strong>Correlation IDs:</strong> Return a reference id the client
              can quote so support can find the real log entry
            </li>
            <li>
              <strong>Fail Securely:</strong> On error, default to denying access
              and rolling back, never to granting or committing
            </li>
            <li>
              <strong>Handle Every Path:</strong> Validate input and catch
              exceptions at well-defined boundaries
            </li>
            <li>
              <strong>Test the Sad Path:</strong> Assert on malformed input and
              failure cases, not just the happy path
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        {next ? (
          <Link to={next.path} className="next-button">
            Next: {next.code} - {next.title} &rarr;
          </Link>
        ) : (
          <Link to="/web" className="next-button">
            Presentation Complete - Return to Web Top 10 &rarr;
          </Link>
        )}
      </div>
    </div>
  );
};

export default MishandlingExceptionalConditions;
