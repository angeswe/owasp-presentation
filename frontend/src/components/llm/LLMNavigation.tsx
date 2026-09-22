import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { llmTop10 } from './llmTop10';
import './LLMNavigation.css';

const LLMNavigation: React.FC = () => {
  const location = useLocation();

  return (
    <nav className="llm-navigation">
      <div className="llm-nav-container">
        <Link to="/" className="llm-nav-item llm-home-link">
          🏠 Home
        </Link>
        <Link
          to="/llm"
          className={`llm-nav-item llm-home-link ${location.pathname === '/llm' ? 'active' : ''}`}
        >
          LLM Top 10
        </Link>

        <div className="llm-vulnerability-grid">
          {llmTop10.map((vuln) => (
            <Link
              key={vuln.code}
              to={vuln.path}
              className={`llm-nav-item vulnerability-link ${location.pathname === vuln.path ? 'active' : ''}`}
            >
              <span className="vuln-number">{vuln.rank}</span>
              <span className="vuln-title">{`${vuln.code} - ${vuln.navTitle}`}</span>
            </Link>
          ))}
        </div>
      </div>
    </nav>
  );
};

export default LLMNavigation;
