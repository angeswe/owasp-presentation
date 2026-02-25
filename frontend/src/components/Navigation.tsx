import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Navigation.css';

const vulnerabilities = [
  { id: 'a01', title: 'A01 - Broken Access Control', path: '/web/a01' },
  { id: 'a02', title: 'A02 - Cryptographic Failures', path: '/web/a02' },
  { id: 'a03', title: 'A03 - Injection', path: '/web/a03' },
  { id: 'a04', title: 'A04 - Insecure Design', path: '/web/a04' },
  { id: 'a05', title: 'A05 - Security Misconfiguration', path: '/web/a05' },
  { id: 'a06', title: 'A06 - Vulnerable Components', path: '/web/a06' },
  { id: 'a07', title: 'A07 - Authentication Failures', path: '/web/a07' },
  { id: 'a08', title: 'A08 - Integrity Failures', path: '/web/a08' },
  { id: 'a09', title: 'A09 - Logging Failures', path: '/web/a09' },
  { id: 'a10', title: 'A10 - SSRF', path: '/web/a10' }
];

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
          {vulnerabilities.map((vuln, index) => (
            <Link
              key={vuln.id}
              to={vuln.path}
              className={`nav-item vulnerability-link ${location.pathname === vuln.path ? 'active' : ''}`}
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

export default Navigation;