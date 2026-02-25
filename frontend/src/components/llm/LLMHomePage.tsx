import React from "react";
import { Link } from "react-router-dom";
import "./LLMHomePage.css";

const vulnerabilities = [
  {
    id: "LLM01",
    title: "Prompt Injection",
    description: "Crafted inputs that override system instructions and safety guidelines",
    examples: ["Direct prompt override", "Indirect injection via data", "Role-playing attacks"],
    path: "/llm/l01",
  },
  {
    id: "LLM02",
    title: "Sensitive Information Disclosure",
    description: "Unauthorized exposure of PII, credentials, and training data",
    examples: ["Training data memorization", "PII extraction", "Cross-session leakage"],
    path: "/llm/l02",
  },
  {
    id: "LLM03",
    title: "Supply Chain",
    description: "Compromised models, plugins, and training data from untrusted sources",
    examples: ["Tampered models", "Malicious plugins", "Unverified packages"],
    path: "/llm/l03",
  },
  {
    id: "LLM04",
    title: "Data and Model Poisoning",
    description: "Manipulation of training data to introduce biases and backdoors",
    examples: ["Biased training data", "Backdoor triggers", "Fine-tuning attacks"],
    path: "/llm/l04",
  },
  {
    id: "LLM05",
    title: "Improper Output Handling",
    description: "LLM outputs rendered or executed without sanitization",
    examples: ["XSS via LLM output", "SQL injection via LLM", "Command injection"],
    path: "/llm/l05",
  },
  {
    id: "LLM06",
    title: "Excessive Agency",
    description: "AI agents with overprivileged tools and unchecked autonomy",
    examples: ["Mass data deletion", "Unauthorized emails", "Production changes"],
    path: "/llm/l06",
  },
  {
    id: "LLM07",
    title: "System Prompt Leakage",
    description: "Extraction of confidential system prompts containing secrets and rules",
    examples: ["Direct extraction", "Indirect reformulation", "Context window attacks"],
    path: "/llm/l07",
  },
  {
    id: "LLM08",
    title: "Vector and Embedding Weaknesses",
    description: "RAG systems with weak access controls exposing confidential documents",
    examples: ["Unauthorized document access", "Embedding inversion", "Cross-tenant leakage"],
    path: "/llm/l08",
  },
  {
    id: "LLM09",
    title: "Misinformation",
    description: "Generation of plausible but fabricated facts, citations, and recommendations",
    examples: ["Fake medical advice", "Hallucinated legal cases", "False technical facts"],
    path: "/llm/l09",
  },
  {
    id: "LLM10",
    title: "Unbounded Consumption",
    description: "No rate limiting, budget caps, or resource controls on LLM usage",
    examples: ["Denial of service", "Financial exhaustion", "Resource abuse"],
    path: "/llm/l10",
  },
];

const LLMHomePage: React.FC = () => {
  return (
    <div className="llm-home-page">
      <div className="llm-hero-section">
        <h1>OWASP Top 10 for LLM Applications</h1>
        <p className="llm-hero-description">
          The OWASP Top 10 for Large Language Model Applications identifies the
          most critical security risks specific to AI/LLM systems, from prompt
          injection to unbounded consumption.
        </p>
        <span className="llm-hero-subtitle">Interactive Educational Demonstration (2025)</span>
      </div>

      <div>
        <h2>The OWASP LLM Top 10 (2025)</h2>
        <div className="llm-vuln-grid">
          {vulnerabilities.map((vuln, index) => (
            <div key={vuln.id} className="llm-vuln-card">
              <div className="vuln-header">
                <span className="vuln-number">{index + 1}</span>
                <h3>{vuln.id} - {vuln.title}</h3>
              </div>
              <p className="vuln-description">{vuln.description}</p>
              <ul className="vuln-examples">
                {vuln.examples.map((example, i) => (
                  <li key={i}>{example}</li>
                ))}
              </ul>
              <Link to={vuln.path} className="vuln-link">
                Explore Vulnerability &rarr;
              </Link>
            </div>
          ))}
        </div>
      </div>

      <div className="llm-presentation-info">
        <h2>Presentation Flow</h2>
        <p>
          Navigate through each LLM vulnerability in order from LLM01 to LLM10.
          Each page features interactive demos with simulated LLM responses
          streamed in real-time.
        </p>
        <div>
          <Link to="/llm/l01" className="llm-start-button">
            Start Presentation (LLM01) &rarr;
          </Link>
        </div>
        <div>
          <Link to="/" className="llm-back-link">
            &larr; Back to OWASP Top 10
          </Link>
        </div>
      </div>
    </div>
  );
};

export default LLMHomePage;
