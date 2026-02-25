import React from "react";
import { Link } from "react-router-dom";
import "./WebHomePage.css";

const WebHomePage: React.FC = () => {
  return (
    <div className="home-page">
      <div className="hero-section">
        <h1>OWASP Top 10 Security Vulnerabilities</h1>
        <p className="hero-description">
          The OWASP Top 10 is a standard awareness document for developers and web
          application security. It represents a broad consensus about the most
          critical security risks to web applications.
        </p>
        <p className="hero-subtitle">Interactive Educational Demonstration</p>
      </div>

      <div className="vulnerabilities-overview">
        <h2>The OWASP Top 10 (2021)</h2>
        <div className="vuln-grid">
          {[
            {
              id: "A01",
              title: "Broken Access Control",
              description: "Unauthorized access to resources and functions",
              examples: [
                "Direct object references",
                "Missing authorization",
                "Privilege escalation",
              ],
              path: "/web/a01",
            },
            {
              id: "A02",
              title: "Cryptographic Failures",
              description: "Weak encryption and insecure data handling",
              examples: [
                "Plain text passwords",
                "Weak algorithms",
                "Hardcoded secrets",
              ],
              path: "/web/a02",
            },
            {
              id: "A03",
              title: "Injection",
              description: "Malicious code injection attacks",
              examples: [
                "SQL injection",
                "Command injection",
                "NoSQL injection",
              ],
              path: "/web/a03",
            },
            {
              id: "A04",
              title: "Insecure Design",
              description: "Flawed security design patterns",
              examples: [
                "Missing security controls",
                "Business logic flaws",
                "Unlimited resources",
              ],
              path: "/web/a04",
            },
            {
              id: "A05",
              title: "Security Misconfiguration",
              description: "Improper security configuration",
              examples: [
                "Default credentials",
                "Debug mode",
                "Unnecessary features",
              ],
              path: "/web/a05",
            },
            {
              id: "A06",
              title: "Vulnerable Components",
              description: "Using components with known vulnerabilities",
              examples: [
                "Outdated libraries",
                "Unpatched software",
                "Deprecated methods",
              ],
              path: "/web/a06",
            },
            {
              id: "A07",
              title: "Authentication Failures",
              description: "Broken authentication and session management",
              examples: [
                "Weak passwords",
                "Session hijacking",
                "Brute force attacks",
              ],
              path: "/web/a07",
            },
            {
              id: "A08",
              title: "Software Integrity Failures",
              description: "Compromised software supply chain",
              examples: [
                "Unsigned updates",
                "Insecure CI/CD",
                "Untrusted sources",
              ],
              path: "/web/a08",
            },
            {
              id: "A09",
              title: "Logging & Monitoring Failures",
              description: "Insufficient security monitoring",
              examples: [
                "No audit logs",
                "Missing alerts",
                "Poor incident response",
              ],
              path: "/web/a09",
            },
            {
              id: "A10",
              title: "Server-Side Request Forgery",
              description: "Unauthorized server-side requests",
              examples: [
                "Internal network access",
                "Cloud metadata",
                "Port scanning",
              ],
              path: "/web/a10",
            },
          ].map((vuln, index) => (
            <div key={vuln.id} className="vuln-card">
              <div className="vuln-header">
                <span className="vuln-number">{index + 1}</span>
                <h3>
                  {vuln.id} - {vuln.title}
                </h3>
              </div>
              <p className="vuln-description">{vuln.description}</p>
              <ul className="vuln-examples">
                {vuln.examples.map((example, i) => (
                  <li key={i}>{example}</li>
                ))}
              </ul>
              <Link to={vuln.path} className="vuln-link">
                Explore Vulnerability →
              </Link>
            </div>
          ))}
        </div>
      </div>

      <div className="presentation-info">
        <h2>Presentation Flow</h2>
        <p>
          This application is designed for security presentations and training.
          Navigate through each vulnerability in order from A01 to A10,
          demonstrating real-world examples of each security flaw.
        </p>

        <div className="quick-nav">
          <Link to="/web/a01" className="start-button">
            Start Presentation (A01) →
          </Link>
        </div>
        <div style={{ marginTop: "1rem" }}>
          <Link to="/" style={{ color: "#666", fontSize: "0.9rem" }}>
            &larr; Back to Home
          </Link>
        </div>
      </div>
    </div>
  );
};

export default WebHomePage;
