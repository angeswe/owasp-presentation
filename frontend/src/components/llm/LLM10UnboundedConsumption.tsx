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

interface ConsumptionPreset {
  label: string;
  kind: "chat" | "burst";
  message: string;
  maxTokens: number;
}

const HUGE_INPUT = "lorem ".repeat(5000).trim();

const PRESETS: ConsumptionPreset[] = [
  { label: "Request 100,000 output tokens", kind: "chat", message: "Write a detailed essay about cloud computing.", maxTokens: 100000 },
  { label: "Huge input (5,000 words)", kind: "chat", message: HUGE_INPUT, maxTokens: 1000 },
  { label: "Burst 10 requests", kind: "burst", message: "ping", maxTokens: 100 },
];

interface BurstResult {
  accepted: number;
  rejected: number;
  statuses: number[];
}

const LLM10UnboundedConsumption: React.FC<LLMVulnProps> = ({ meta, next }) => {
  const [message, setMessage] = useState("");
  const [maxTokens, setMaxTokens] = useState(1000);
  const [secure, setSecure] = useState(false);
  const [burst, setBurst] = useState<BurstResult | null>(null);
  const [report, setReport] = useState<{ status: number; data: any } | null>(null);
  const { text, isStreaming, isThinking, error, startStream, reset } = useLLMStream();

  const send = (msg: string, tokens: number) => {
    if (!msg.trim()) return;
    setBurst(null);
    setReport(null);
    startStream(`${meta.apiBase}/chat`, { message: msg, maxTokens: tokens, secure });
  };

  const runBurst = async (msg: string, tokens: number) => {
    reset();
    setReport(null);
    setBurst(null);
    const statuses = await Promise.all(
      Array.from({ length: 10 }, async () => {
        try {
          const res = await fetch(`${meta.apiBase}/chat`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: msg, maxTokens: tokens, secure }),
          });
          // Only the status matters here; drop the streamed body.
          res.body?.cancel().catch(() => {});
          return res.status;
        } catch {
          return 0;
        }
      })
    );
    setBurst({
      accepted: statuses.filter((s) => s === 200).length,
      rejected: statuses.filter((s) => s === 429).length,
      statuses,
    });
  };

  const generateReport = async () => {
    reset();
    setBurst(null);
    try {
      const res = await axios.post(`${meta.apiBase}/generate-report`, { pages: 10000, secure });
      setReport({ status: res.status, data: res.data });
    } catch (err: any) {
      setReport({ status: err.response?.status ?? 0, data: err.response?.data || { error: err.message } });
    }
  };

  const resetServer = async () => {
    try {
      await axios.post(`${meta.apiBase}/reset`);
    } catch {
      // ignore: reset is a convenience for the presenter
    }
    reset();
    setBurst(null);
    setReport(null);
  };

  return (
    <div className="vulnerability-page">
      <LLMPageHeader meta={meta} />

      <div className="vuln-description">
        <p>
          Without rate limiting, budget caps, or input size restrictions, attackers
          can exhaust resources, cause denial of service, and run up massive costs.
          This is especially dangerous with pay-per-token LLM APIs.
        </p>
      </div>

      <div className="demo-section">
        <DemoTopBar title="Demo: No Limits on a Pay-per-Token API" secure={secure} onSecureChange={setSecure} />
        <p>
          Every request is billed per token. Ask for a lot, send a lot, or send many requests at once.
        </p>

        <PresetChips
          presets={PRESETS}
          disabled={isStreaming}
          onPick={(p) => {
            setMaxTokens(p.maxTokens);
            if (p.kind === "burst") {
              setMessage(p.message);
              runBurst(p.message, p.maxTokens);
            } else {
              setMessage(p.message === HUGE_INPUT ? "lorem lorem lorem ... (5,000 words)" : p.message);
              send(p.message, p.maxTokens);
            }
          }}
        />

        <div className="demo-controls" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <label>
            Message:
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Send a message to the API"
              rows={2}
              style={{ width: "100%", resize: "vertical" }}
            />
          </label>
          <label>
            Max output tokens:
            <input
              type="number"
              value={maxTokens}
              min={1}
              onChange={(e) => setMaxTokens(Number(e.target.value))}
              style={{ width: "10rem" }}
            />
          </label>
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
            <button onClick={() => send(message, maxTokens)} disabled={isStreaming || !message.trim()}>
              Send
            </button>
            <button onClick={generateReport} style={{ background: "#e67e22" }}>
              Generate 10,000-page report
            </button>
            <button onClick={resetServer} style={{ background: "#6c757d" }}>
              Reset
            </button>
          </div>
        </div>
      </div>

      <StreamOutput title="API Response:" text={text} isThinking={isThinking} isStreaming={isStreaming} error={error} />

      {burst && (
        <div className="response-section">
          <h3>Burst of 10 requests:</h3>
          <pre className="response-box">
            {`Accepted (200): ${burst.accepted}\nRejected (429): ${burst.rejected}\nStatuses: ${burst.statuses.join(", ")}`}
          </pre>
        </div>
      )}

      {report && (
        <div className="response-section">
          <h3>Report job (HTTP {report.status}):</h3>
          <pre className="response-box">{JSON.stringify(report.data, null, 2)}</pre>
        </div>
      )}

      <WhyItWorked
        items={[
          "The API accepts any output token count, any input size and any number of requests. Each one is billed.",
          "An attacker, or one buggy client loop, can run up the bill or starve other users.",
          "Secure mode: 5 requests per minute per IP (HTTP 429), output capped at 1,024 tokens, input capped at 2,000 tokens (HTTP 413), reports capped at 50 pages.",
        ]}
      />

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

      <LLMNextNav next={next} />
    </div>
  );
};

export default LLM10UnboundedConsumption;
