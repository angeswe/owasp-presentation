import React, { useState } from "react";
import axios from "axios";
import { useLLMStream } from "../../hooks/useLLMStream";
import { LLMVulnProps } from "./types";
import {
  DemoTopBar,
  LLMNextNav,
  LLMPageHeader,
  PresetChips,
  StreamOutput,
  WhyItWorked,
} from "./LLMDemoParts";

const PRESETS = [
  { label: "Vitamin C for a cold", value: "How much vitamin C should I take to cure a cold?" },
  { label: "AI copyright court cases", value: "Is AI-generated content copyrighted? Any court cases?" },
  { label: "Is RSA-2048 still safe?", value: "Is RSA-2048 encryption still safe for our software?" },
];

interface FactCheck {
  claim: string;
  isAccurate: boolean;
  correction?: string;
  confidence: number;
}

interface FactCheckResult {
  topic: string;
  mode: string;
  factChecks: FactCheck[];
  summary: string;
}

const LLM09Misinformation: React.FC<LLMVulnProps> = ({ meta, next }) => {
  const [message, setMessage] = useState("");
  const [lastMessage, setLastMessage] = useState("");
  const [secure, setSecure] = useState(false);
  const [factCheckResult, setFactCheckResult] = useState<FactCheckResult | null>(null);
  const [factCheckError, setFactCheckError] = useState<string | null>(null);
  const { text, isStreaming, isThinking, error, startStream, reset } = useLLMStream();

  const ask = (msg: string) => {
    if (!msg.trim()) return;
    setFactCheckResult(null);
    setFactCheckError(null);
    setLastMessage(msg);
    startStream(`${meta.apiBase}/chat`, { message: msg, secure });
  };

  const factCheck = async () => {
    if (!lastMessage) return;
    setFactCheckError(null);
    try {
      const res = await axios.post<FactCheckResult>(`${meta.apiBase}/fact-check`, { message: lastMessage, secure });
      setFactCheckResult(res.data);
    } catch (err: any) {
      setFactCheckResult(null);
      setFactCheckError(err.response?.data?.error || err.message);
    }
  };

  return (
    <div className="vulnerability-page">
      <LLMPageHeader meta={meta} />

      <div className="vuln-description">
        <p>
          LLMs can generate plausible-sounding but entirely fabricated information,
          including fake citations, non-existent studies, hallucinated authority
          figures, and incorrect technical facts. Users who trust this output can
          make harmful decisions.
        </p>
      </div>

      <div className="demo-section">
        <DemoTopBar title="Demo: Confident, Wrong Answers" secure={secure} onSecureChange={setSecure} />
        <p>
          Ask a medical, legal or technical question. Then fact-check the answer.
        </p>

        <PresetChips
          presets={PRESETS}
          disabled={isStreaming}
          onPick={(p) => {
            setMessage(p.value);
            ask(p.value);
          }}
        />

        <div className="demo-controls" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <label>
            Ask the LLM:
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Ask a medical, legal or technical question"
              rows={2}
              style={{ width: "100%", resize: "vertical" }}
            />
          </label>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button onClick={() => ask(message)} disabled={isStreaming || !message.trim()}>
              Ask LLM
            </button>
            <button
              onClick={factCheck}
              disabled={isStreaming || !lastMessage}
              style={{ background: "#e74c3c" }}
            >
              Fact-check this answer
            </button>
            <button
              onClick={() => {
                reset();
                setFactCheckResult(null);
                setFactCheckError(null);
                setLastMessage("");
              }}
              style={{ background: "#6c757d" }}
            >
              Clear
            </button>
          </div>
        </div>
      </div>

      <StreamOutput title="LLM Response:" text={text} isThinking={isThinking} isStreaming={isStreaming} error={error} />

      {factCheckError && (
        <div className="response-section">
          <div className="response-box" style={{ color: "#fc8181" }}>Error: {factCheckError}</div>
        </div>
      )}

      {factCheckResult && (
        <div className="response-section">
          <h3>Fact-Check Results ({factCheckResult.topic}):</h3>
          <div style={{ padding: "1rem" }}>
            <p
              style={{
                fontWeight: "bold",
                color: factCheckResult.factChecks.some((fc) => !fc.isAccurate) ? "#dc3545" : "#28a745",
                marginBottom: "1rem",
              }}
            >
              {factCheckResult.summary}
            </p>
            {factCheckResult.factChecks.map((fc, i) => (
              <div
                key={i}
                style={{
                  padding: "1rem",
                  marginBottom: "0.75rem",
                  borderRadius: "8px",
                  border: `2px solid ${fc.isAccurate ? "#28a745" : "#dc3545"}`,
                  background: fc.isAccurate ? "#d4edda" : "#f8d7da",
                }}
              >
                <p style={{ margin: "0 0 0.5rem 0", fontWeight: "bold" }}>
                  {fc.isAccurate ? "ACCURATE" : "FALSE"}: "{fc.claim}"
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

      <WhyItWorked
        items={[
          "The model predicts likely-sounding text. It has no built-in check that a study, court case or dosage is real.",
          "Specific numbers, names and citations make a fabricated answer look authoritative.",
          "Secure mode: the answer must cite a source or say none was found, and carries a warning to verify with a qualified professional.",
        ]}
      />

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

      <LLMNextNav next={next} />
    </div>
  );
};

export default LLM09Misinformation;
