import React, { useState } from "react";
import axios from "axios";
import "./VulnerabilityPage.css";

const A03Injection: React.FC = () => {
  const [searchQuery, setSearchQuery] = useState("' OR 1=1--");
  const [commandHost, setCommandHost] = useState("8.8.8.8; ls");
  const [loginUsername, setLoginUsername] = useState("admin'--");
  const [loginPassword, setLoginPassword] = useState("password");
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const testSQLInjection = async () => {
    setLoading(true);
    try {
      const res = await axios.get(
        `http://localhost:3001/api/a03/search?query=${encodeURIComponent(
          searchQuery
        )}`
      );
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const testCommandInjection = async () => {
    setLoading(true);
    try {
      const res = await axios.post("http://localhost:3001/api/a03/ping", {
        host: commandHost,
      });
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const testSqlLoginInjection = async () => {
    setLoading(true);
    try {
      const res = await axios.post("http://localhost:3001/api/a03/login", {
        username: loginUsername,
        password: loginPassword,
      });
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>A03 - Injection</h1>
        <div className="vulnerability-badge">OWASP #3</div>
      </div>

      <div className="vuln-description">
        <p>
          Injection flaws occur when untrusted data is sent to an interpreter as
          part of a command or query. The attacker's hostile data can trick the
          interpreter into executing unintended commands.
        </p>
      </div>

      <div className="demo-section">
        <h2>💉 Demo 1: SQL Injection</h2>
        <p>
          This demo shows how a vulnerable search query can be exploited to bypass
          filters or dump sensitive data from the database. The input is directly
          concatenated into a SQL query.
        </p>
        <div className="demo-controls">
          <label>
            Search Query:
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Try: ' OR 1=1--"
            />
          </label>
          <button onClick={testSQLInjection} disabled={loading}>
            Search Posts
          </button>
        </div>

        <div className="attack-examples">
          <h4>🚨 Try these SQL injection attacks:</h4>
          <code>' OR 1=1--</code>
          <code>' UNION SELECT username, password FROM users--</code>
          <code>'; DROP TABLE posts;--</code>
        </div>
      </div>

      <div className="demo-section">
        <h2>💻 Demo 2: Command Injection</h2>
        <p>
          This demo allows you to execute a `ping` command on the server. By
          chaining commands with a semicolon (;) or ampersand (&&), an attacker
          can execute arbitrary commands on the host operating system.
        </p>
        <div className="demo-controls">
          <label>
            Host to Ping:
            <input
              type="text"
              value={commandHost}
              onChange={(e) => setCommandHost(e.target.value)}
              placeholder="e.g., 8.8.8.8; ls"
            />
          </label>
          <button onClick={testCommandInjection} disabled={loading}>
            Ping Host
          </button>
        </div>
        <div className="attack-examples">
          <h4>🚨 Try these command injection attacks:</h4>
          <code>8.8.8.8; ls -l</code>
          <code>8.8.8.8 && whoami</code>
          <code>; cat /etc/passwd</code>
        </div>
      </div>

      <div className="demo-section">
        <h2>🔑 Demo 3: SQL Injection Login Bypass</h2>
        <p>
          This demo showcases how SQL injection can be used to bypass a login
          form. By injecting a query fragment into the username field, an
          attacker can log in without a valid password.
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
          <button onClick={testSqlLoginInjection} disabled={loading}>
            Attempt Login
          </button>
        </div>
        <div className="attack-examples">
          <h4>🚨 Try this login bypass attack:</h4>
          <code>Username: admin'--</code>
          <p style={{ margin: '0.5rem 0 0 0', color: '#721c24' }}>
            The '--' comments out the rest of the SQL query, so the password is
            never checked.
          </p>
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
              <h3 style={{ margin: 0 }}>C#/.NET - SQL Parameters with Entity Framework</h3>
              <span style={{ marginLeft: '10px', fontSize: '14px' }}>
                {showCSharpExamples ? '▼ Hide' : '▶ Show'}
              </span>
            </div>
            {showCSharpExamples && (
            <pre className="code-block">
              {`

public async Task<User> FindUserByUsernameAsync(string username)
{
    using var connection = new SqlConnection(connectionString);
    using var command = new SqlCommand(
        "SELECT Id, Username, Email FROM Users WHERE Username = @username",
        connection);

    command.Parameters.AddWithValue("@username", username);

    await connection.OpenAsync();
    using var reader = await command.ExecuteReaderAsync();

    if (await reader.ReadAsync())
    {
        return new User
        {
            Id = reader.GetInt32("Id"),
            Username = reader.GetString("Username"),
            Email = reader.GetString("Email")
        };
    }

    return null;
}`}
            </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Use Parameterized Queries</h4>
            <p>
              Always use parameter placeholders instead of string concatenation
            </p>
            <code>SELECT * FROM users WHERE id = ?</code>
          </div>
          <div className="fix-item">
            <h4>2. Input Validation</h4>
            <p>Validate and sanitize all user inputs</p>
            <code>validate.isLength(input, &#123;min: 1, max: 100&#125;)</code>
          </div>
          <div className="fix-item">
            <h4>3. Use ORM/Query Builders</h4>
            <p>Leverage ORMs that handle parameterization automatically</p>
            <code>User.findOne(&#123;where: &#123;username&#125;&#125;)</code>
          </div>
          <div className="fix-item">
            <h4>4. Escape Special Characters</h4>
            <p>
              When parameterization isn't possible, escape dangerous characters
            </p>
            <code>mysql.escape(userInput)</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Never Trust User Input:</strong> Always validate and
              parameterize user data
            </li>
            <li>
              <strong>Use Prepared Statements:</strong> They prevent SQL
              injection by design
            </li>
            <li>
              <strong>Principle of Least Privilege:</strong> Use database
              accounts with minimal necessary permissions
            </li>
            <li>
              <strong>Input Validation:</strong> Whitelist acceptable characters
              and formats
            </li>
            <li>
              <strong>Regular Security Testing:</strong> Use automated tools to
              detect injection vulnerabilities
              <code>e.g., SonarQube (SAST), OWASP ZAP (DAST), SonarLint (IDE extension)</code>
            </li>
            <li>
              <strong>Error Handling:</strong> Don't reveal database structure
              in error messages
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/a04" className="next-button">
          Next: A04 - Insecure Design →
        </a>
      </div>
    </div>
  );
};

export default A03Injection;
