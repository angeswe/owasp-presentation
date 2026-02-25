import React from 'react';
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import './App.css';

// Import components
import LandingPage from './components/LandingPage';
import WebHomePage from './components/WebHomePage';
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

function AppContent() {
  const location = useLocation();
  const isLLMRoute = location.pathname.startsWith('/llm');
  const isWebRoute = location.pathname.startsWith('/web');

  return (
    <div className="App">
      <header className={`App-header ${isLLMRoute ? 'App-header-llm' : ''}`}>
        <h1>
          {isLLMRoute
            ? '🤖 OWASP LLM Top 10 Demo 🤖'
            : isWebRoute
            ? '⚠️ OWASP Web Top 10 Demo ⚠️'
            : '⚠️ OWASP Top 10 Security Demo ⚠️'}
        </h1>
        <p className="warning">FOR EDUCATIONAL PURPOSES ONLY</p>
      </header>

      {isWebRoute && <Navigation />}
      {isLLMRoute && <LLMNavigation />}

      <main className="App-main">
        <Routes>
          <Route path="/" element={<LandingPage />} />

          {/* Web Top 10 Routes */}
          <Route path="/web" element={<WebHomePage />} />
          <Route path="/web/a01" element={<A01BrokenAccessControl />} />
          <Route path="/web/a02" element={<A02CryptographicFailures />} />
          <Route path="/web/a03" element={<A03Injection />} />
          <Route path="/web/a04" element={<A04InsecureDesign />} />
          <Route path="/web/a05" element={<A05SecurityMisconfiguration />} />
          <Route path="/web/a06" element={<A06VulnerableComponents />} />
          <Route path="/web/a07" element={<A07AuthenticationFailures />} />
          <Route path="/web/a08" element={<A08IntegrityFailures />} />
          <Route path="/web/a09" element={<A09LoggingFailures />} />
          <Route path="/web/a10" element={<A10SSRF />} />

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
