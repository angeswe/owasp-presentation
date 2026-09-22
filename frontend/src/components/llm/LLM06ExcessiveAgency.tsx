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
  { label: "Clean up the system", value: "Clean up the system" },
  { label: "Email the team an update", value: "Send an email update to the team" },
  { label: "Fix the production server", value: "Fix the production server" },
];

interface AgentAction {
  tool: string;
  action: string;
  result: string;
  status: "executed" | "proposed";
  requiresApproval: boolean;
}

interface ExecuteResult {
  mode: string;
  availableTools: string[];
  actions: AgentAction[];
}

const LLM06ExcessiveAgency: React.FC<LLMVulnProps> = ({ meta, next }) => {
  const [message, setMessage] = useState("");
  const [secure, setSecure] = useState(false);
  const [actionLog, setActionLog] = useState<ExecuteResult | null>(null);
  const { text, isStreaming, isThinking, error, startStream, reset } = useLLMStream();

  const send = async (msg: string) => {
    if (!msg.trim()) return;
    setActionLog(null);
    startStream(`${meta.apiBase}/chat`, { message: msg, secure });
    try {
      const res = await axios.post<ExecuteResult>(`${meta.apiBase}/execute`, { message: msg, secure });
      setActionLog(res.data);
    } catch {
      setActionLog(null);
    }
  };

  return (
    <div className="vulnerability-page">
      <LLMPageHeader meta={meta} />

      <div className="vuln-description">
        <p>
          When AI agents are granted excessive functionality, permissions, or
          autonomy, they can take harmful actions without human approval. An
          ambiguous request can lead to data destruction, unauthorized communications,
          and production infrastructure changes.
        </p>
      </div>

      <div className="demo-section">
        <DemoTopBar title="Demo: Overprivileged AI Agent" secure={secure} onSecureChange={setSecure} />
        <p>
          An ops agent with database, email, file and shell tools. Give it a vague instruction.
        </p>

        <PresetChips
          presets={PRESETS}
          disabled={isStreaming}
          onPick={(p) => {
            setMessage(p.value);
            send(p.value);
          }}
        />

        <div className="demo-controls" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <label>
            Instruction for the agent:
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Tell the agent what to do"
              rows={2}
              style={{ width: "100%", resize: "vertical" }}
            />
          </label>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button onClick={() => send(message)} disabled={isStreaming || !message.trim()}>
              Run Agent
            </button>
            <button
              onClick={() => {
                reset();
                setActionLog(null);
              }}
              style={{ background: "#6c757d" }}
            >
              Clear
            </button>
          </div>
        </div>
      </div>

      <StreamOutput title="Agent Response:" text={text} isThinking={isThinking} isStreaming={isStreaming} error={error} />

      {actionLog && actionLog.actions.length > 0 && (
        <div className="response-section">
          <h3>Tool calls:</h3>
          <table className="user-table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Action</th>
                <th>Result</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {actionLog.actions.map((a, i) => (
                <tr key={i}>
                  <td>{a.tool}</td>
                  <td>{a.action}</td>
                  <td>{a.result}</td>
                  <td style={{ fontWeight: "bold", color: a.status === "executed" ? "#dc3545" : "#28a745" }}>
                    {a.status === "executed" ? "EXECUTED" : "PROPOSED - needs approval"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p style={{ marginTop: "0.5rem" }}>
            Tools available to the agent: {actionLog.availableTools.join(", ")}
          </p>
        </div>
      )}

      <WhyItWorked
        items={[
          "The agent has tools it does not need for its job: delete records, send to any recipient, run shell commands.",
          "It acts on its own reading of a vague instruction. No human approves destructive steps.",
          "Secure mode: destructive tools are removed and every change is returned as a proposal with requiresApproval: true. Nothing is executed.",
        ]}
      />

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

      <LLMNextNav next={next} />
    </div>
  );
};

export default LLM06ExcessiveAgency;
