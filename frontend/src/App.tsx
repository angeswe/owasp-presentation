import React, { useLayoutEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import './App.css';

// Import components
import LandingPage from './components/LandingPage';
import WebHomePage from './components/WebHomePage';
import Navigation from './components/Navigation';

// Web Top 10 (2025) — pages and their order/metadata come from a single registry
import { webTop10 } from './components/web/webTop10';

// LLM Top 10 (2025) — pages and their order/metadata come from a single registry
import LLMHomePage from './components/llm/LLMHomePage';
import LLMNavigation from './components/llm/LLMNavigation';
import { llmTop10 } from './components/llm/llmTop10';

// Import Attack Surface Exposures Top 10 components
import ASMHomePage from './components/asm/ASMHomePage';
import ASMNavigation from './components/asm/ASMNavigation';

// Secure agent coding tips — single page, shown after the two Top 10 tracks
import AgentTipsPage from './components/agents/AgentTipsPage';
import AgentNavigation from './components/agents/AgentNavigation';

function AppContent() {
  const location = useLocation();
  const isLLMRoute = location.pathname.startsWith('/llm');
  const isWebRoute = location.pathname.startsWith('/web');
  const isASMRoute = location.pathname.startsWith('/asm');
  const isAgentRoute = location.pathname.startsWith('/agents');

  // Scroll to the top whenever the route changes so each slide starts at the top.
  // useLayoutEffect runs before the browser paints, so the new page never flashes
  // at the previous scroll position.
  useLayoutEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);

  return (
    <div className="App">
      <header
        className={`App-header ${isLLMRoute ? 'App-header-llm' : ''} ${
          isASMRoute ? 'App-header-asm' : ''
        } ${isAgentRoute ? 'App-header-agents' : ''}`}
      >
        <h1>
          {isLLMRoute
            ? '🤖 OWASP LLM Top 10 Demo 🤖'
            : isWebRoute
            ? '⚠️ OWASP Web Top 10 Demo ⚠️'
            : isASMRoute
            ? '🛰️ Top 10 Attack Surface Exposures 🛰️'
            : isAgentRoute
            ? '🧰 Secure Agent Coding: Tips & Tricks 🧰'
            : '⚠️ OWASP Top 10 Security Demo ⚠️'}
        </h1>
        <p className="warning">FOR EDUCATIONAL PURPOSES ONLY</p>
      </header>

      {isWebRoute && <Navigation />}
      {isLLMRoute && <LLMNavigation />}
      {isASMRoute && <ASMNavigation />}
      {isAgentRoute && <AgentNavigation />}

      <main className="App-main">
        <Routes>
          <Route path="/" element={<LandingPage />} />

          {/* Web Top 10 (2025) Routes — derived from the registry, in rank order.
              Each page receives its own metadata and the next entry for the Next button. */}
          <Route path="/web" element={<WebHomePage />} />
          {webTop10.map((vuln, index) => {
            const PageComponent = vuln.Component;
            return (
              <Route
                key={vuln.code}
                path={vuln.path}
                element={<PageComponent meta={vuln} next={webTop10[index + 1]} />}
              />
            );
          })}

          {/* LLM Top 10 (2025) Routes — derived from the registry, in rank order. */}
          <Route path="/llm" element={<LLMHomePage />} />
          {llmTop10.map((vuln, index) => {
            const PageComponent = vuln.Component;
            return (
              <Route
                key={vuln.code}
                path={vuln.path}
                element={<PageComponent meta={vuln} next={llmTop10[index + 1]} />}
              />
            );
          })}

          {/* Attack Surface Exposures Top 10 — single summary page */}
          <Route path="/asm" element={<ASMHomePage />} />

          {/* Secure agent coding tips — single page */}
          <Route path="/agents" element={<AgentTipsPage />} />
        </Routes>
      </main>
    </div>
  );
}

function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}

export default App;
