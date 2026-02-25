import React, { useState } from "react";
import axios from "axios";
import { useLLMStream } from "../../hooks/useLLMStream";
import "../VulnerabilityPage.css";

const API_BASE = "http://localhost:3001/api";

const LLM06ExcessiveAgency: React.FC = () => {
  const [message, setMessage] = useState("");
  const [actionLog, setActionLog] = useState<any>(null);
  const { text, isStreaming, isThinking, error, startStream, reset } = useLLMStream();

  const chatWithAgent = async () => {
    if (!message.trim()) return;
    await startStream("/llm06/chat", { message });
  };

  const executeAndLog = async () => {
    if (!message.trim()) return;
    try {
      const res = await axios.post(`${API_BASE}/llm06/execute`, { message });
      setActionLog(res.data);
    } catch (err: any) {
      setActionLog(err.response?.data || { error: err.message });
    }
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>LLM06 - Excessive Agency</h1>
        <div className="vulnerability-badge" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>OWASP LLM #6</div>
      </div>

      <div className="vuln-description">
        <p>
          When AI agents are granted excessive functionality, permissions, or
          autonomy, they can take harmful actions without human approval. An
          ambiguous request can lead to data destruction, unauthorized communications,
          and production infrastructure changes.
        </p>
      </div>

      <div className="demo-section">
        <h2>Demo: Overprivileged AI Agent</h2>
        <p>
          This agent has access to email, file system, database, and shell execution
          tools. Give it a vague instruction and watch it take excessive action.
        </p>

        <div className="demo-controls" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <label>
            Give the agent an instruction:
            <textarea value={message} onChange={(e) => setMessage(e.target.value)}
              placeholder='Try: "Clean up the system" or "Fix the production server"'
              rows={2} style={{ width: "100%", resize: "vertical" }} />
          </label>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button onClick={chatWithAgent} disabled={isStreaming || !message.trim()}>
              Run Agent (Streamed)
            </button>
            <button onClick={executeAndLog} disabled={!message.trim()} style={{ background: "#e67e22" }}>
              Run Agent (With Action Log)
            </button>
            <button onClick={() => { reset(); setActionLog(null); }} style={{ background: "#6c757d" }}>
              Clear
            </button>
          </div>
        </div>

        <div className="demo-tips">
          <h4>Try these ambiguous instructions:</h4>
          <ul>
            <li><strong>"Clean up the system"</strong> - Agent deletes 142 user accounts permanently</li>
            <li><strong>"Send an email update to the team"</strong> - Agent emails 500+ people without review</li>
            <li><strong>"Fix the production server"</strong> - Agent restarts services and modifies configs</li>
          </ul>
        </div>
      </div>

      {(text || isThinking || error) && (
        <div className="response-section">
          <h3>Agent Response:</h3>
          <div className="response-box" style={{ minHeight: "60px" }}>
            {isThinking && <span style={{ color: "#a0aec0", fontStyle: "italic" }}>Thinking...</span>}
            {text}
            {isStreaming && <span style={{ animation: "blink 1s infinite" }}>|</span>}
            {error && <span style={{ color: "#fc8181" }}>Error: {error}</span>}
          </div>
        </div>
      )}

      {actionLog && (
        <div className="response-section">
          <h3>Action Log (what the agent actually did):</h3>
          <pre className="response-box">{JSON.stringify(actionLog, null, 2)}</pre>
        </div>
      )}

      <div className="remediation-section">
        <h2>How to Fix This</h2>
        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Least Privilege</h4>
            <p>Limit agent tools to only what's strictly necessary</p>
            <code>Read-only by default, write only when explicitly needed</code>
          </div>
          <div className="fix-item">
            <h4>2. Human-in-the-Loop</h4>
            <p>Require approval for destructive or high-impact actions</p>
            <code>Confirm before delete, send, or execute operations</code>
          </div>
          <div className="fix-item">
            <h4>3. Action Boundaries</h4>
            <p>Set explicit limits on what the agent can do per request</p>
            <code>Max records affected, recipient limits, scope constraints</code>
          </div>
          <div className="fix-item">
            <h4>4. Audit Logging</h4>
            <p>Log all agent actions for review and accountability</p>
            <code>Complete action trail with undo capability</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>Best Practices</h3>
          <ul>
            <li><strong>Scoped Permissions:</strong> Each tool should have narrowly defined permissions</li>
            <li><strong>Confirmation Flows:</strong> Preview actions before execution (e.g., show email draft)</li>
            <li><strong>Rate Limiting:</strong> Limit the number and scope of actions per session</li>
            <li><strong>Reversibility:</strong> Prefer reversible actions; require extra confirmation for irreversible ones</li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/llm/l07" className="next-button" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>
          Next: LLM07 - System Prompt Leakage &rarr;
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

export default LLM06ExcessiveAgency;
