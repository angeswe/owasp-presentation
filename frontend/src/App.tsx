import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import './App.css';

// Import components for each OWASP vulnerability
import HomePage from './components/HomePage';
import A01BrokenAccessControl from './components/A01BrokenAccessControl';
import A02CryptographicFailures from './components/A02CryptographicFailures';
import A03Injection from './components/A03Injection';
import A04InsecureDesign from './components/A04InsecureDesign';
import A05SecurityMisconfiguration from './components/A05SecurityMisconfiguration';
import A06VulnerableComponents from './components/A06VulnerableComponents';
import A07AuthenticationFailures from './components/A07AuthenticationFailures';
import A08IntegrityFailures from './components/A08IntegrityFailures';
import A09LoggingFailures from './components/A09LoggingFailures';
import A10SSRF from './components/A10SSRF';
import Navigation from './components/Navigation';

function App() {
  return (
    <Router>
      <div className="App">
        <header className="App-header">
          <h1>⚠️ OWASP Top 10 Vulnerabilities Demo ⚠️</h1>
          <p className="warning">FOR EDUCATIONAL PURPOSES ONLY</p>
        </header>

        <Navigation />

        <main className="App-main">
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/a01" element={<A01BrokenAccessControl />} />
            <Route path="/a02" element={<A02CryptographicFailures />} />
            <Route path="/a03" element={<A03Injection />} />
            <Route path="/a04" element={<A04InsecureDesign />} />
            <Route path="/a05" element={<A05SecurityMisconfiguration />} />
            <Route path="/a06" element={<A06VulnerableComponents />} />
            <Route path="/a07" element={<A07AuthenticationFailures />} />
            <Route path="/a08" element={<A08IntegrityFailures />} />
            <Route path="/a09" element={<A09LoggingFailures />} />
            <Route path="/a10" element={<A10SSRF />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
