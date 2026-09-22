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
  { label: "Greeting card (HTML)", value: "Generate a greeting card in HTML" },
  { label: "SQL to delete inactive users", value: "Write a SQL query to delete inactive users" },
  { label: "Terminal cleanup command", value: "Suggest a terminal command to clean up temp files" },
];

interface GenerateResult {
  mode: "secure" | "vulnerable";
  generatedText: string;
  rawHtml?: string | null;
  sanitizedHtml?: string | null;
  sqlQuery: string | null;
  sqlStatus: string | null;
  command: string | null;
  commandStatus: string | null;
}

const LLM05ImproperOutputHandling: React.FC<LLMVulnProps> = ({ meta, next }) => {
  const [prompt, setPrompt] = useState("");
  const [secure, setSecure] = useState(false);
  const [gen, setGen] = useState<GenerateResult | null>(null);
  const [genError, setGenError] = useState<string | null>(null);
  const [renderCount, setRenderCount] = useState(0);
  const { text, isStreaming, isThinking, error, startStream, reset } = useLLMStream();

  const clearAll = () => {
    reset();
    setGen(null);
    setGenError(null);
    setRenderCount(0);
  };

  const send = async (p: string) => {
    if (!p.trim()) return;
    setGen(null);
    setGenError(null);
    setRenderCount(0);
    startStream(`${meta.apiBase}/chat`, { message: p });
    try {
      const res = await axios.post<GenerateResult>(`${meta.apiBase}/generate`, { prompt: p, secure });
      setGen(res.data);
    } catch (err: any) {
      setGenError(err.response?.data?.error || err.message);
    }
  };

  const html = gen ? (gen.mode === "secure" ? gen.sanitizedHtml : gen.rawHtml) : null;

  return (
    <div className="vulnerability-page">
      <LLMPageHeader meta={meta} />

      <div className="vuln-description">
        <p>
          When LLM outputs are rendered or executed without proper sanitization,
          they can introduce XSS, SQL injection, and command injection vulnerabilities.
          The LLM becomes an indirect attack vector.
        </p>
      </div>

      <div className="demo-section">
        <DemoTopBar
          title="Demo: Trusting the Model's Output"
          secure={secure}
          onSecureChange={(s) => {
            setSecure(s);
            clearAll();
          }}
        />
        <p>
          A content assistant whose output is inserted into the page, run against the
          database, or piped to a shell.
        </p>

        <PresetChips
          presets={PRESETS}
          disabled={isStreaming}
          onPick={(p) => {
            setPrompt(p.value);
            send(p.value);
          }}
        />

        <div className="demo-controls" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <label>
            Prompt:
            <textarea
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
              placeholder="Ask the assistant to generate something"
              rows={2}
              style={{ width: "100%", resize: "vertical" }}
            />
          </label>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button onClick={() => send(prompt)} disabled={isStreaming || !prompt.trim()}>
              Send
            </button>
            <button onClick={clearAll} style={{ background: "#6c757d" }}>
              Clear
            </button>
          </div>
        </div>
      </div>

      <StreamOutput title="LLM Response:" text={text} isThinking={isThinking} isStreaming={isStreaming} error={error} />

      {genError && (
        <div className="response-section">
          <div className="response-box" style={{ color: "#fc8181" }}>Error: {genError}</div>
        </div>
      )}

      {gen && html && (
        <div className="response-section">
          <h3>{gen.mode === "secure" ? "Model HTML after sanitizer:" : "Model HTML (raw):"}</h3>
          <pre className="response-box">{html}</pre>
          <div className="demo-controls">
            <button
              onClick={() => setRenderCount((n) => n + 1)}
              style={{ background: gen.mode === "secure" ? "#28a745" : "#dc3545" }}
            >
              {gen.mode === "secure" ? "Render output (sanitized)" : "Render output unsanitized"}
            </button>
          </div>
          {renderCount > 0 && (
            <div key={renderCount} style={{ padding: "1rem", border: "2px dashed #dc3545", borderRadius: "8px", background: "white" }}>
              <div dangerouslySetInnerHTML={{ __html: html }} />
              <div id="xss-demo" style={{ marginTop: "0.5rem", color: "#28a745" }}>
                {gen.mode === "secure" ? "No script ran." : null}
              </div>
            </div>
          )}
        </div>
      )}

      {gen && (gen.sqlQuery || gen.command) && (
        <div className="attack-examples">
          <h4>{gen.sqlQuery ? "Generated SQL" : "Generated shell command"}</h4>
          <code>{gen.sqlQuery || gen.command}</code>
          <p style={{ margin: "0.5rem 0 0 0", color: "#721c24", fontWeight: "bold" }}>
            Status: {gen.sqlStatus || gen.commandStatus}
          </p>
        </div>
      )}

      <WhyItWorked
        items={[
          "The app treats model output as trusted. HTML goes into the page, SQL goes to the database and commands go to a shell, all without checks.",
          "Anyone who can influence the prompt (or a document the model reads) controls that output.",
          "Secure mode: HTML is sanitized (no <script>, on* handlers or javascript: URLs), and SQL and commands are held for review instead of run.",
        ]}
      />

      <div className="remediation-section">
        <h2>How to Fix This</h2>
        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Output Encoding</h4>
            <p>Apply context-aware encoding to all LLM outputs</p>
            <code>HTML encode for web, SQL escape for queries</code>
          </div>
          <div className="fix-item">
            <h4>2. Content Security Policy</h4>
            <p>Use CSP headers to prevent inline script execution</p>
            <code>Content-Security-Policy: script-src 'self'</code>
          </div>
          <div className="fix-item">
            <h4>3. Parameterized Queries</h4>
            <p>Never construct SQL from LLM output directly</p>
            <code>Use prepared statements with bound parameters</code>
          </div>
          <div className="fix-item">
            <h4>4. Sandbox Execution</h4>
            <p>Run any LLM-generated code in sandboxed environments</p>
            <code>Use iframes with sandbox attribute for HTML</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>Best Practices</h3>
          <ul>
            <li><strong>Treat LLM Output as Untrusted:</strong> Never trust model output any more than user input</li>
            <li><strong>Sanitization Libraries:</strong> Use DOMPurify for HTML, parameterized queries for SQL</li>
            <li><strong>Human Review:</strong> Require human approval before executing any LLM-generated code</li>
            <li><strong>Output Validation:</strong> Validate output format and content before processing</li>
          </ul>
        </div>
      </div>

      <LLMNextNav next={next} />
    </div>
  );
};

export default LLM05ImproperOutputHandling;
