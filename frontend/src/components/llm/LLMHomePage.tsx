import React from "react";
import { Link } from "react-router-dom";
import { llmTop10 } from "./llmTop10";
import "./LLMHomePage.css";

const LLMHomePage: React.FC = () => {
  const first = llmTop10[0];

  return (
    <div className="llm-home-page">
      <div className="llm-hero-section">
        <h1>OWASP Top 10 for LLM Applications</h1>
        <p className="llm-hero-description">
          The OWASP Top 10 for Large Language Model Applications identifies the
          most critical security risks specific to AI/LLM systems, from prompt
          injection to unbounded consumption.
        </p>
        <span className="llm-hero-subtitle">Interactive Educational Demonstration (2025)</span>
      </div>

      <div>
        <h2>The OWASP LLM Top 10 (2025)</h2>
        <div className="llm-vuln-grid">
          {llmTop10.map((vuln) => (
            <div key={vuln.code} className="llm-vuln-card">
              <div className="vuln-header">
                <span className="vuln-number">{vuln.rank}</span>
                <h3>{vuln.code} - {vuln.title}</h3>
              </div>
              <p className="vuln-description">{vuln.description}</p>
              <ul className="vuln-examples">
                {vuln.examples.map((example, i) => (
                  <li key={i}>{example}</li>
                ))}
              </ul>
              <Link to={vuln.path} className="vuln-link">
                Explore Vulnerability &rarr;
              </Link>
            </div>
          ))}
        </div>
      </div>

      <div className="llm-presentation-info">
        <h2>Presentation Flow</h2>
        <p>
          Navigate through each LLM vulnerability in order from LLM01 to LLM10.
          Each page features interactive demos with simulated LLM responses
          streamed in real-time. Use the Secure mode toggle on each page to see
          the same request against a hardened backend.
        </p>
        <div>
          <Link to={first.path} className="llm-start-button">
            Start Presentation ({first.code}) &rarr;
          </Link>
        </div>
        <div>
          <Link to="/" className="llm-back-link">
            &larr; Back to OWASP Top 10
          </Link>
        </div>
      </div>
    </div>
  );
};

export default LLMHomePage;
