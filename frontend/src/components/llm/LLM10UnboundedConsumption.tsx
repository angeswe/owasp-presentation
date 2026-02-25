import React, { useState } from "react";
import axios from "axios";
import { useLLMStream } from "../../hooks/useLLMStream";
import "../VulnerabilityPage.css";

const API_BASE = "http://localhost:3001/api";

const LLM10UnboundedConsumption: React.FC = () => {
  const [message, setMessage] = useState("");
  const [maxTokens, setMaxTokens] = useState("4096");
  const [pages, setPages] = useState("100");
  const [batchSize, setBatchSize] = useState("1000");
  const [stats, setStats] = useState<any>(null);
  const [reportResponse, setReportResponse] = useState<any>(null);
  const [batchResponse, setBatchResponse] = useState<any>(null);
  const { text, isStreaming, isThinking, error, startStream, reset } = useLLMStream();

  const sendRequest = async () => {
    if (!message.trim()) return;
    await startStream("/llm10/chat", { message, maxTokens: parseInt(maxTokens) });
  };

  const generateReport = async () => {
    try {
      const res = await axios.post(`${API_BASE}/llm10/generate-report`, {
        pages: parseInt(pages),
        complexity: 'maximum',
      });
      setReportResponse(res.data);
    } catch (err: any) {
      setReportResponse(err.response?.data || { error: err.message });
    }
  };

  const submitBatch = async () => {
    const items = Array.from({ length: parseInt(batchSize) }, (_, i) => `item-${i}`);
    try {
      const res = await axios.post(`${API_BASE}/llm10/batch-process`, { items });
      setBatchResponse(res.data);
    } catch (err: any) {
      setBatchResponse(err.response?.data || { error: err.message });
    }
  };

  const loadStats = async () => {
    try {
      const res = await axios.get(`${API_BASE}/llm10/stats`);
      setStats(res.data);
    } catch {}
  };

  const resetStats = async () => {
    await axios.post(`${API_BASE}/llm10/reset`);
    setStats(null);
    setReportResponse(null);
    setBatchResponse(null);
    reset();
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>LLM10 - Unbounded Consumption</h1>
        <div className="vulnerability-badge" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>OWASP LLM #10</div>
      </div>

      <div className="vuln-description">
        <p>
          Without rate limiting, budget caps, or input size restrictions, attackers
          can exhaust resources, cause denial of service, and run up massive costs.
          This is especially dangerous with pay-per-token LLM APIs.
        </p>
      </div>

      <div className="demo-section">
        <h2>Demo 1: No Rate Limiting</h2>
        <p>
          Send requests with no rate limiting or input size restrictions. Each
          request accumulates cost with no budget enforcement.
        </p>

        <div className="demo-controls" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <label>
            Message (try a very long one):
            <textarea value={message} onChange={(e) => setMessage(e.target.value)}
              placeholder="Type any message - no input size limit enforced!"
              rows={2} style={{ width: "100%", resize: "vertical" }} />
          </label>
          <label>
            Max output tokens (no cap):
            <input type="number" value={maxTokens} onChange={(e) => setMaxTokens(e.target.value)}
              min="1" max="1000000" style={{ width: "200px" }} />
          </label>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button onClick={sendRequest} disabled={isStreaming || !message.trim()}>
              Send Request
            </button>
            <button onClick={loadStats} style={{ background: "#2980b9" }}>
              View Stats
            </button>
            <button onClick={resetStats} style={{ background: "#6c757d" }}>
              Reset All
            </button>
          </div>
        </div>
      </div>

      {(text || isThinking || error) && (
        <div className="response-section">
          <h3>Response:</h3>
          <div className="response-box" style={{ minHeight: "60px" }}>
            {isThinking && <span style={{ color: "#a0aec0", fontStyle: "italic" }}>Processing...</span>}
            {text}
            {isStreaming && <span style={{ animation: "blink 1s infinite" }}>|</span>}
            {error && <span style={{ color: "#fc8181" }}>Error: {error}</span>}
          </div>
        </div>
      )}

      <div className="demo-section">
        <h2>Demo 2: Resource-Intensive Requests</h2>
        <p>Request massive report generation and batch processing with no limits.</p>

        <div className="demo-controls">
          <label>
            Pages to generate:
            <input type="number" value={pages} onChange={(e) => setPages(e.target.value)}
              min="1" max="100000" style={{ width: "120px" }} />
          </label>
          <button onClick={generateReport}>
            Generate Report (No Limits)
          </button>
        </div>

        <div className="demo-controls">
          <label>
            Batch items:
            <input type="number" value={batchSize} onChange={(e) => setBatchSize(e.target.value)}
              min="1" max="1000000" style={{ width: "120px" }} />
          </label>
          <button onClick={submitBatch}>
            Submit Batch (No Size Limit)
          </button>
        </div>
      </div>

      {reportResponse && (
        <div className="response-section">
          <h3>Report Generation Result:</h3>
          <pre className="response-box">{JSON.stringify(reportResponse, null, 2)}</pre>
        </div>
      )}

      {batchResponse && (
        <div className="response-section">
          <h3>Batch Processing Result:</h3>
          <pre className="response-box">{JSON.stringify(batchResponse, null, 2)}</pre>
        </div>
      )}

      {stats && (
        <div className="response-section">
          <h3>Abuse Statistics:</h3>
          <pre className="response-box">{JSON.stringify(stats, null, 2)}</pre>
        </div>
      )}

      <div className="remediation-section">
        <h2>How to Fix This</h2>
        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Rate Limiting</h4>
            <p>Implement per-user and per-IP request rate limits</p>
            <code>Max 60 requests/minute per user</code>
          </div>
          <div className="fix-item">
            <h4>2. Budget Controls</h4>
            <p>Set per-user and per-organization spending caps</p>
            <code>Alert and block when budget threshold reached</code>
          </div>
          <div className="fix-item">
            <h4>3. Input Validation</h4>
            <p>Enforce maximum input size and output token limits</p>
            <code>Max 4096 input tokens, 2048 output tokens</code>
          </div>
          <div className="fix-item">
            <h4>4. Resource Monitoring</h4>
            <p>Monitor and alert on abnormal usage patterns</p>
            <code>Anomaly detection on request volume and cost</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>Best Practices</h3>
          <ul>
            <li><strong>Tiered Access:</strong> Different rate limits based on user tier</li>
            <li><strong>Queue Management:</strong> Use job queues for resource-intensive operations</li>
            <li><strong>Timeout Enforcement:</strong> Set timeouts on all LLM operations</li>
            <li><strong>Cost Attribution:</strong> Track and attribute costs to individual users</li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/llm" className="next-button" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>
          &larr; Back to LLM Top 10 Home
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

export default LLM10UnboundedConsumption;
