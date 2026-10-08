import React from "react";
import { Link } from "react-router-dom";
import { agentTips, furtherReading, relatedEntries } from "./agentTips";
import "./AgentTipsPage.css";

const AgentTipsPage: React.FC = () => {
  return (
    <div className="agent-tips-page">
      <div className="agent-hero-section">
        <h1>Secure Agent Coding</h1>
        <p className="agent-hero-description">
          Most of our code is now written by agents. The Top 10 lists still
          apply to that code. These four habits keep the code, and the agent
          that writes it, safe.
        </p>
        <span className="agent-hero-subtitle">4 Tips &amp; Tricks</span>
      </div>

      <div className="agent-tip-list">
        {agentTips.map((tip) => (
          <section key={tip.id} id={tip.id} className="agent-tip-card">
            <div className="agent-tip-header">
              <span className="agent-tip-number">{tip.rank}</span>
              <h2>{tip.title}</h2>
              <span className="agent-chip">{tip.theme}</span>
            </div>
            <p className="agent-tip-description">{tip.description}</p>

            <div className="agent-tip-body">
              <div className="agent-tip-column">
                <h3>⚠️ What goes wrong</h3>
                <pre className="agent-code agent-code--wrong">{tip.wrong.join("\n")}</pre>
                <p className="agent-wrong-note">{tip.wrongNote}</p>
                {tip.source && (
                  <p className="agent-source">
                    Source:{" "}
                    <a href={tip.source.url} target="_blank" rel="noopener noreferrer">
                      {tip.source.label}
                    </a>
                  </p>
                )}
              </div>

              <div className="agent-tip-column">
                <h3>🛡️ What to do</h3>
                <ul className="agent-actions">
                  {tip.actions.map((action) => (
                    <li key={action}>{action}</li>
                  ))}
                </ul>
                <pre className="agent-code agent-code--fix">{tip.fix.join("\n")}</pre>
              </div>
            </div>

            <div className="agent-related">
              <span className="agent-related-label">Same risk in the Top 10:</span>
              {relatedEntries(tip).map((entry) => (
                <Link key={entry.code} to={entry.path} className="agent-related-link">
                  {entry.code} {entry.title}
                </Link>
              ))}
            </div>
          </section>
        ))}
      </div>

      <div className="agent-further-reading">
        <h2>Further Reading</h2>
        <ul className="agent-reading-list">
          {furtherReading.map((item) => (
            <li key={item.url}>
              <a href={item.url} target="_blank" rel="noopener noreferrer">
                {item.label}
              </a>
            </li>
          ))}
        </ul>
        <div>
          <Link to="/" className="agent-back-link">
            &larr; Back to OWASP Top 10
          </Link>
        </div>
      </div>
    </div>
  );
};

export default AgentTipsPage;
