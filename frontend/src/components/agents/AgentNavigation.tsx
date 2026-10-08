import React from "react";
import { Link } from "react-router-dom";
import { agentTips } from "./agentTips";
import "./AgentNavigation.css";

// Rendered only on /agents, the track's single page, so that link is always active.
const AgentNavigation: React.FC = () => {
  return (
    <nav className="agent-navigation">
      <div className="agent-nav-container">
        <Link to="/" className="agent-nav-item agent-home-link">
          🏠 Home
        </Link>
        <Link to="/agents" className="agent-nav-item agent-home-link active">
          Agent Coding Tips
        </Link>
        {agentTips.map((tip) => (
          <a key={tip.id} href={`#${tip.id}`} className="agent-nav-item">
            <span className="agent-nav-number">{tip.rank}</span>
            {tip.theme}
          </a>
        ))}
      </div>
    </nav>
  );
};

export default AgentNavigation;
