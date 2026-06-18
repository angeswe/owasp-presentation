import React, { useLayoutEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import './App.css';

// Import components
import LandingPage from './components/LandingPage';
import WebHomePage from './components/WebHomePage';
import Navigation from './components/Navigation';

// Web Top 10 (2025) — pages and their order/metadata come from a single registry
import { webTop10 } from './components/web/webTop10';

// Import LLM Top 10 components
import LLMHomePage from './components/llm/LLMHomePage';
import LLMNavigation from './components/llm/LLMNavigation';
import LLM01PromptInjection from './components/llm/LLM01PromptInjection';
import LLM02SensitiveInfoDisclosure from './components/llm/LLM02SensitiveInfoDisclosure';
import LLM03SupplyChain from './components/llm/LLM03SupplyChain';
import LLM04DataPoisoning from './components/llm/LLM04DataPoisoning';
import LLM05ImproperOutputHandling from './components/llm/LLM05ImproperOutputHandling';
import LLM06ExcessiveAgency from './components/llm/LLM06ExcessiveAgency';
import LLM07SystemPromptLeakage from './components/llm/LLM07SystemPromptLeakage';
import LLM08VectorEmbeddingWeaknesses from './components/llm/LLM08VectorEmbeddingWeaknesses';
import LLM09Misinformation from './components/llm/LLM09Misinformation';
import LLM10UnboundedConsumption from './components/llm/LLM10UnboundedConsumption';

// Import Attack Surface Exposures Top 10 components
import ASMHomePage from './components/asm/ASMHomePage';
import ASMNavigation from './components/asm/ASMNavigation';

function AppContent() {
  const location = useLocation();
  const isLLMRoute = location.pathname.startsWith('/llm');
  const isWebRoute = location.pathname.startsWith('/web');
  const isASMRoute = location.pathname.startsWith('/asm');

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
        }`}
      >
        <h1>
          {isLLMRoute
            ? '🤖 OWASP LLM Top 10 Demo 🤖'
            : isWebRoute
            ? '⚠️ OWASP Web Top 10 Demo ⚠️'
            : isASMRoute
            ? '🛰️ Top 10 Attack Surface Exposures 🛰️'
            : '⚠️ OWASP Top 10 Security Demo ⚠️'}
        </h1>
        <p className="warning">FOR EDUCATIONAL PURPOSES ONLY</p>
      </header>

      {isWebRoute && <Navigation />}
      {isLLMRoute && <LLMNavigation />}
      {isASMRoute && <ASMNavigation />}

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

          {/* LLM Top 10 Routes */}
          <Route path="/llm" element={<LLMHomePage />} />
          <Route path="/llm/l01" element={<LLM01PromptInjection />} />
          <Route path="/llm/l02" element={<LLM02SensitiveInfoDisclosure />} />
          <Route path="/llm/l03" element={<LLM03SupplyChain />} />
          <Route path="/llm/l04" element={<LLM04DataPoisoning />} />
          <Route path="/llm/l05" element={<LLM05ImproperOutputHandling />} />
          <Route path="/llm/l06" element={<LLM06ExcessiveAgency />} />
          <Route path="/llm/l07" element={<LLM07SystemPromptLeakage />} />
          <Route path="/llm/l08" element={<LLM08VectorEmbeddingWeaknesses />} />
          <Route path="/llm/l09" element={<LLM09Misinformation />} />
          <Route path="/llm/l10" element={<LLM10UnboundedConsumption />} />

          {/* Attack Surface Exposures Top 10 — single summary page */}
          <Route path="/asm" element={<ASMHomePage />} />
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
