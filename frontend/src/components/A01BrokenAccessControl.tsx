import React, { useState, useEffect } from "react";
import axios from "axios";
import "./VulnerabilityPage.css";

const API_BASE = "http://localhost:3001/api";

interface UsersApiResponse {
  users: User[];
}

interface User {
  id: number;
  username: string;
  role: string;
}

const A01BrokenAccessControl: React.FC = () => {
  const [userId, setUserId] = useState("1");
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [users, setUsers] = useState<User[]>([]);
  const [targetUserId, setTargetUserId] = useState("");
  const [newRole, setNewRole] = useState("admin");
  const [showCSharpExamples, setShowCSharpExamples] = useState(false);

  const testDirectObjectReference = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/a01/user/${userId}`);
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  const fetchUsers = async () => {
    try {
      const res = await axios.get<UsersApiResponse>(
        `${API_BASE}/a01/admin/users`
      );
      setUsers(res.data.users);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleRoleChange = async () => {
    if (!targetUserId) {
      setResponse({ error: "Please enter a user ID." });
      return;
    }
    setLoading(true);
    try {
      const res = await axios.put(`${API_BASE}/a01/user/${targetUserId}/role`, {
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
      const res = await axios.get(`${API_BASE}/a01/admin/users`);
      setResponse(res.data);
    } catch (error: any) {
      setResponse({ error: error.response?.data || error.message });
    }
    setLoading(false);
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>A01 - Broken Access Control</h1>
        <div className="vulnerability-badge">OWASP #1</div>
      </div>

      <div className="vuln-description">
        <p>
          Access control enforces policies so users can't act outside of their
          intended permissions. When broken, users can access unauthorized
          functionality or data.
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
            <h4>4. Log Access Attempts</h4>
            <p>Monitor and alert on unauthorized access attempts</p>
            <code>logger.warn("Unauthorized access attempt")</code>
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
              <strong>Regular Audits:</strong> Review access controls
              periodically
            </li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/a02" className="next-button">
          Next: A02 - Cryptographic Failures →
        </a>
      </div>
    </div>
  );
};

export default A01BrokenAccessControl;
