import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import './LLMNavigation.css';

const vulnerabilities = [
  { id: 'l01', title: 'LLM01 - Prompt Injection', path: '/llm/l01' },
  { id: 'l02', title: 'LLM02 - Sensitive Info Disclosure', path: '/llm/l02' },
  { id: 'l03', title: 'LLM03 - Supply Chain', path: '/llm/l03' },
  { id: 'l04', title: 'LLM04 - Data Poisoning', path: '/llm/l04' },
  { id: 'l05', title: 'LLM05 - Improper Output', path: '/llm/l05' },
  { id: 'l06', title: 'LLM06 - Excessive Agency', path: '/llm/l06' },
  { id: 'l07', title: 'LLM07 - Prompt Leakage', path: '/llm/l07' },
  { id: 'l08', title: 'LLM08 - Vector Weaknesses', path: '/llm/l08' },
  { id: 'l09', title: 'LLM09 - Misinformation', path: '/llm/l09' },
  { id: 'l10', title: 'LLM10 - Unbounded Consumption', path: '/llm/l10' },
];

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
          {vulnerabilities.map((vuln, index) => (
            <Link
              key={vuln.id}
              to={vuln.path}
              className={`llm-nav-item vulnerability-link ${location.pathname === vuln.path ? 'active' : ''}`}
            >
              <span className="vuln-number">{index + 1}</span>
              <span className="vuln-title">{vuln.title}</span>
            </Link>
          ))}
        </div>
      </div>
    </nav>
  );
};

export default LLMNavigation;
