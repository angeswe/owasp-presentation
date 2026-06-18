import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Navigation.css';
import { webTop10 } from './web/webTop10';

const Navigation: React.FC = () => {
  const location = useLocation();

  return (
    <nav className="owasp-navigation">
      <div className="nav-container">
        <Link to="/" className="nav-item home-link">
          🏠 Home
        </Link>
        <Link to="/web" className={`nav-item home-link ${location.pathname === '/web' ? 'active' : ''}`}>
          Web Top 10
        </Link>

        <div className="vulnerability-grid">
          {webTop10.map((vuln) => (
            <Link
              key={vuln.code}
              to={vuln.path}
              className={`nav-item vulnerability-link ${location.pathname === vuln.path ? 'active' : ''}`}
            >
              <span className="vuln-number">{vuln.rank}</span>
              <span className="vuln-title">{vuln.code} - {vuln.navTitle}</span>
            </Link>
          ))}
        </div>
      </div>
    </nav>
  );
};

export default Navigation;