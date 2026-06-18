import React from "react";
import { Link } from "react-router-dom";
import "./WebHomePage.css";
import { webTop10 } from "./web/webTop10";

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
        <h2>The OWASP Top 10 (2025)</h2>
        <div className="vuln-grid">
          {webTop10.map((vuln) => (
            <div key={vuln.code} className="vuln-card">
              <div className="vuln-header">
                <span className="vuln-number">{vuln.rank}</span>
                <h3>
                  {vuln.code} - {vuln.title}
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
