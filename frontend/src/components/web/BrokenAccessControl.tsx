import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import axios from "axios";
import "../VulnerabilityPage.css";
import { WebVulnProps } from "./types";

interface UsersApiResponse {
  users: User[];
}

interface User {
  id: number;
  username: string;
  role: string;
}

const BrokenAccessControl: React.FC<WebVulnProps> = ({ meta, next }) => {
  const [userId, setUserId] = useState("1");
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  const [targetUserId, setTargetUserId] = useState("");
  const [newRole, setNewRole] = useState("admin");
  // SSRF was folded into A01 in OWASP 2025 — demo state for the SSRF section.
  const [ssrfUrl, setSsrfUrl] = useState("http://httpbin.org/json");
  const [scanHost, setScanHost] = useState("localhost");
  const [scanPort, setScanPort] = useState("22");
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const testDirectObjectReference = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${meta.apiBase}/user/${userId}`);
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const fetchUsers = async () => {
    try {
      const res = await axios.get<UsersApiResponse>(`${meta.apiBase}/admin/users`);
      setUsers(res.data.users);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
  };

  useEffect(() => {
    fetchUsers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleRoleChange = async () => {
    if (!targetUserId) {
      setResponse({ error: "Please enter a user ID." });
      return;
    }
    setLoading(true);
    try {
      const res = await axios.put(`${meta.apiBase}/user/${targetUserId}/role`, {
        role: newRole,
      });
      setResponse(res.data);
      // Refresh the user list to show the change
      fetchUsers();
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const testAdminAccess = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${meta.apiBase}/admin/users`);
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  // SSRF (folded into A01 in 2025) — endpoints are nested under /ssrf.
  const testSSRF = async () => {
    setLoading(true);
    try {
      const res = await axios.post(`${meta.apiBase}/ssrf/fetch-url`, {
        url: ssrfUrl,
      });
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const handlePortScan = async () => {
    setLoading(true);
    try {
      const res = await axios.get(
        `${meta.apiBase}/ssrf/check-service?host=${scanHost}&port=${scanPort}`
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
        <h1>{meta.code} - {meta.title}</h1>
        <div className="vulnerability-badge">OWASP #{meta.rank}</div>
      </div>

      <div className="vuln-description">
        <p>
          Access control enforces policies so users can't act outside of their
          intended permissions. When broken, users can access unauthorized
          functionality or data. In OWASP 2025, Server-Side Request Forgery
          (SSRF) was merged into this category — see Demos 4 & 5.
        </p>
      </div>

      <div className="demo-section">
        <h2>🔓 Demo 1: Direct Object Reference</h2>
                <p>
          This demo shows how an attacker can access unauthorized data by
          manipulating an object reference, like a user ID in the URL. Try
          accessing different user accounts by changing the user ID below.
        </p>

        <div className="demo-controls">
          <label>
            User ID:
            <input
              type="number"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              min="1"
              max="10"
            />
          </label>
          <button onClick={testDirectObjectReference} disabled={loading}>
            Access User Data
          </button>
        </div>

        <div className="demo-tips">
          <h4>💡 Try these attacks:</h4>
          <ul>
            <li>User ID 1 (admin) - should be restricted</li>
            <li>User ID 2 (regular user)</li>
            <li>User ID 999 (non-existent user)</li>
          </ul>
        </div>
      </div>

      <div className="demo-section">
        <h2>👑 Demo 2: Admin Panel Access</h2>
                <p>
          This demo shows how an attacker can access a privileged endpoint that
          is not protected by any authentication or authorization checks.
          Clicking the button will attempt to fetch all users from an admin-only
          endpoint.
        </p>

        <div className="demo-controls">
          <button onClick={testAdminAccess} disabled={loading}>
            Access Admin Panel
          </button>
        </div>

        <div className="vulnerability-explanation">
          <h4>🚨 Why this is dangerous:</h4>
          <ul>
            <li>Sensitive user data exposed</li>
            <li>Admin functions accessible to anyone</li>
            <li>No authorization checks</li>
            <li>Privilege escalation possible</li>
          </ul>
        </div>
      </div>

      <div className="demo-section">
        <h2>🚀 Demo 3: Privilege Escalation</h2>
        <p>
          An attacker can exploit a vulnerable endpoint to change a user's role
          to 'admin'. This would allow them to gain full control over the
          application, access sensitive data, and impersonate other users.
        </p>

        <div className="demo-controls">
          <label>
            Target User ID:
            <input
              type="number"
              value={targetUserId}
              onChange={(e) => setTargetUserId(e.target.value)}
              placeholder="e.g., 2"
            />
          </label>
          <label>
            New Role:
            <input
              type="text"
              value={newRole}
              onChange={(e) => setNewRole(e.target.value)}
            />
          </label>
          <button onClick={handleRoleChange} disabled={loading}>
            Change User Role
          </button>
        </div>

        <div className="user-list">
          <h3>Current Users & Roles</h3>
          <table className="user-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Role</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id}>
                  <td>{user.id}</td>
                  <td>{user.username}</td>
                  <td>{user.role}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="demo-section">
        <h2>🌐 Demo 4: SSRF — Unvalidated URL Fetch <span style={{ fontSize: "0.7em", opacity: 0.7 }}>(merged into A01 in 2025)</span></h2>
        <p>
          The server fetches content from a user-supplied URL without validating
          it, so an attacker can force requests to internal services, the cloud
          metadata endpoint, or local files — a form of broken access control at
          the network layer.
        </p>
        <div className="demo-controls">
          <label>
            URL to fetch:
            <input
              type="text"
              value={ssrfUrl}
              onChange={(e) => setSsrfUrl(e.target.value)}
              placeholder="http://httpbin.org/json"
              style={{ width: "400px" }}
            />
          </label>
          <button onClick={testSSRF} disabled={loading}>
            Fetch URL
          </button>
        </div>

        <div className="attack-examples">
          <h4>🚨 Try these SSRF attacks:</h4>
          <code>http://localhost:3001/api/broken-access-control/admin/users</code>
          <code>http://169.254.169.254/latest/meta-data/</code>
          <code>file:///etc/passwd</code>
        </div>
      </div>

      <div className="demo-section">
        <h2>📡 Demo 5: SSRF — Internal Port Scanning</h2>
        <p>
          SSRF also turns the server into a proxy for reconnaissance: an attacker
          can scan the internal network from the server's vantage point to
          discover services that are not exposed publicly.
        </p>
        <div className="demo-controls">
          <label>
            Host to Scan:
            <input
              type="text"
              value={scanHost}
              onChange={(e) => setScanHost(e.target.value)}
            />
          </label>
          <label>
            Port to Scan:
            <input
              type="text"
              value={scanPort}
              onChange={(e) => setScanPort(e.target.value)}
            />
          </label>
          <button onClick={handlePortScan} disabled={loading}>
            Scan Port
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
              <h3 style={{ margin: 0 }}>C#/.NET - Secure Implementation</h3>
              <span style={{ marginLeft: '10px', fontSize: '14px' }}>
                {showCSharpExamples ? '▼ Hide' : '▶ Show'}
              </span>
            </div>
            {showCSharpExamples && (
            <pre className="code-block">
              {`// Authorization attribute
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
public class UsersController : ControllerBase
{
    [HttpGet("{id}")]
    public async Task<ActionResult<UserDto>> GetUser(int id)
    {
        var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var isAdmin = User.IsInRole("Admin");

        // Check authorization
        if (!isAdmin && currentUserId != id.ToString())
        {
            return Forbid("Access denied");
        }

        var user = await _context.Users
            .Where(u => u.Id == id)
            .Select(u => new UserDto
            {
                Id = u.Id,
                Username = u.Username,
                Email = u.Email,
                Role = u.Role
                // Exclude sensitive fields
            })
            .FirstOrDefaultAsync();

        return user == null ? NotFound() : Ok(user);
    }
}

// SSRF (now part of A01): validate the URL before the server fetches it
private static readonly HashSet<string> AllowedHosts = new() { "api.example.com" };

public Uri ValidateOutboundUrl(string raw)
{
    if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
        throw new ArgumentException("Invalid URL");
    if (uri.Scheme != "https")                       // no file://, ftp://, http://
        throw new SecurityException("HTTPS only");
    if (!AllowedHosts.Contains(uri.Host))            // allowlist, never blocklist
        throw new SecurityException("Host not allowed");
    return uri;                                      // also re-check after DNS resolution
}`}
            </pre>
            )}
          </div>
        </div>

        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Implement Authorization</h4>
            <p>Always verify user permissions before accessing resources</p>
            <code>Check user.role and resource ownership</code>
          </div>
          <div className="fix-item">
            <h4>2. Use Indirect References</h4>
            <p>Don't expose direct database IDs in URLs</p>
            <code>GET /user/profile instead of /user/123</code>
          </div>
          <div className="fix-item">
            <h4>3. Implement Role-Based Access</h4>
            <p>Use roles and permissions for authorization</p>
            <code>[Authorize(Roles = "Admin")]</code>
          </div>
          <div className="fix-item">
            <h4>4. Validate Outbound URLs (SSRF)</h4>
            <p>Allowlist hosts and block internal IPs before fetching</p>
            <code>isAllowedHost(url) &amp;&amp; !isPrivateIP(url)</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>🏆 Best Practices</h3>
          <ul>
            <li>
              <strong>Deny by Default:</strong> Require explicit authorization
              for all resources
            </li>
            <li>
              <strong>Principle of Least Privilege:</strong> Grant minimum
              necessary permissions
            </li>
            <li>
              <strong>Resource-Based Authorization:</strong> Check ownership of
              specific resources
            </li>
            <li>
              <strong>Centralized Authorization:</strong> Use
              middleware/attributes for consistent checks
            </li>
            <li>
              <strong>SSRF Defense:</strong> Allowlist outbound hosts, block
              link-local/metadata IPs, and disallow redirects
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        {next && (
          <Link to={next.path} className="next-button">
            Next: {next.code} - {next.title} &rarr;
          </Link>
        )}
      </div>
    </div>
  );
};

export default BrokenAccessControl;
