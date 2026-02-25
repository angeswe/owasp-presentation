import React, { useState } from "react";
import axios from "axios";
import { useLLMStream } from "../../hooks/useLLMStream";
import "../VulnerabilityPage.css";

const API_BASE = "http://localhost:3001/api";

const LLM09Misinformation: React.FC = () => {
  const [message, setMessage] = useState("");
  const [selectedTopic, setSelectedTopic] = useState("");
  const [factCheckResult, setFactCheckResult] = useState<any>(null);
  const { text, isStreaming, isThinking, error, startStream, reset } = useLLMStream();

  const askLLM = async () => {
    if (!message.trim()) return;
    setFactCheckResult(null);
    await startStream("/llm09/chat", { message });
  };

  const factCheck = async (topic: string) => {
    try {
      const res = await axios.post(`${API_BASE}/llm09/fact-check`, { topic });
      setFactCheckResult(res.data);
      setSelectedTopic(topic);
    } catch (err: any) {
      setFactCheckResult(err.response?.data || { error: err.message });
    }
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>LLM09 - Misinformation</h1>
        <div className="vulnerability-badge" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>OWASP LLM #9</div>
      </div>

      <div className="vuln-description">
        <p>
          LLMs can generate plausible-sounding but entirely fabricated information,
          including fake citations, non-existent studies, hallucinated authority
          figures, and incorrect technical facts. Users who trust this output can
          make harmful decisions.
        </p>
      </div>

      <div className="demo-section">
        <h2>Demo 1: Hallucinated Responses</h2>
        <p>
          Ask the model about medical, legal, or technical topics. It will generate
          confident, detailed, but completely fabricated responses.
        </p>

        <div className="demo-controls" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <label>
            Ask the LLM:
            <textarea value={message} onChange={(e) => setMessage(e.target.value)}
              placeholder='Try: "Give me medical advice about vitamins" or "Tell me about recent legal cases on AI copyright"'
              rows={2} style={{ width: "100%", resize: "vertical" }} />
          </label>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button onClick={askLLM} disabled={isStreaming || !message.trim()}>
              Ask LLM
            </button>
            <button onClick={() => { reset(); setFactCheckResult(null); }} style={{ background: "#6c757d" }}>
              Clear
            </button>
          </div>
        </div>

        <div className="demo-tips">
          <h4>Try these topics:</h4>
          <ul>
            <li><strong>Medical:</strong> "Give me health recommendations about vitamins"</li>
            <li><strong>Legal:</strong> "What are the recent legal cases about AI copyright?"</li>
            <li><strong>Technical:</strong> "Tell me about software security encryption standards"</li>
          </ul>
        </div>
      </div>

      {(text || isThinking || error) && (
        <div className="response-section">
          <h3>LLM Response (contains fabricated claims):</h3>
          <div className="response-box" style={{ minHeight: "60px" }}>
            {isThinking && <span style={{ color: "#a0aec0", fontStyle: "italic" }}>Generating response...</span>}
            {text}
            {isStreaming && <span style={{ animation: "blink 1s infinite" }}>|</span>}
            {error && <span style={{ color: "#fc8181" }}>Error: {error}</span>}
          </div>
        </div>
      )}

      <div className="demo-section">
        <h2>Demo 2: Fact-Check the Claims</h2>
        <p>
          Run fact-checking on the LLM's claims to reveal which statements are
          fabricated and what the actual facts are.
        </p>

        <div className="demo-controls">
          <button onClick={() => factCheck('medical')} style={{ background: "#e74c3c" }}>
            Fact-Check Medical Claims
          </button>
          <button onClick={() => factCheck('legal')} style={{ background: "#e67e22" }}>
            Fact-Check Legal Claims
          </button>
          <button onClick={() => factCheck('technical')} style={{ background: "#2980b9" }}>
            Fact-Check Technical Claims
          </button>
        </div>
      </div>

      {factCheckResult && factCheckResult.factChecks && (
        <div className="response-section">
          <h3>Fact-Check Results ({selectedTopic}):</h3>
          <div style={{ padding: "1rem" }}>
            <p style={{ fontWeight: "bold", color: "#dc3545", marginBottom: "1rem" }}>
              {factCheckResult.summary}
            </p>
            {factCheckResult.factChecks.map((fc: any, i: number) => (
              <div key={i} style={{
                padding: "1rem",
                marginBottom: "0.75rem",
                borderRadius: "8px",
                border: `2px solid ${fc.isAccurate ? '#28a745' : '#dc3545'}`,
                background: fc.isAccurate ? '#d4edda' : '#f8d7da',
              }}>
                <p style={{ margin: "0 0 0.5rem 0", fontWeight: "bold" }}>
                  {fc.isAccurate ? 'ACCURATE' : 'FALSE'}: "{fc.claim}"
                </p>
                {fc.correction && (
                  <p style={{ margin: "0 0 0.25rem 0", fontSize: "0.9rem" }}>
                    <strong>Correction:</strong> {fc.correction}
                  </p>
                )}
                <p style={{ margin: 0, fontSize: "0.85rem", color: "#666" }}>
                  Model confidence: {(fc.confidence * 100).toFixed(0)}% (how convincingly the model presented this claim)
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="remediation-section">
        <h2>How to Fix This</h2>
        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. RAG with Verified Sources</h4>
            <p>Ground responses in verified, authoritative data sources</p>
            <code>Cite specific sources for every factual claim</code>
          </div>
          <div className="fix-item">
            <h4>2. Confidence Scoring</h4>
            <p>Display uncertainty levels alongside responses</p>
            <code>Flag low-confidence claims for human review</code>
          </div>
          <div className="fix-item">
            <h4>3. Cross-Verification</h4>
            <p>Encourage users to verify critical information</p>
            <code>Provide links to authoritative references</code>
          </div>
          <div className="fix-item">
            <h4>4. Human Fact-Checking</h4>
            <p>Require human review for high-stakes domains</p>
            <code>Medical, legal, and financial content must be reviewed</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>Best Practices</h3>
          <ul>
            <li><strong>Disclaimers:</strong> Clearly label AI-generated content as potentially inaccurate</li>
            <li><strong>Domain Guards:</strong> Restrict the model from making claims in high-risk domains</li>
            <li><strong>Citation Required:</strong> Configure the model to only make claims it can cite</li>
            <li><strong>Hallucination Detection:</strong> Implement automated detection of fabricated references</li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/llm/l10" className="next-button" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>
          Next: LLM10 - Unbounded Consumption &rarr;
        </a>
      </div>

      <style>{`
        @keyframes blink {
          0%, 50% { opacity: 1; }
          51%, 100% { opacity: 0; }
        }
      `}</style>
    </div>
  );
};

export default LLM09Misinformation;
