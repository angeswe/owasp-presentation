import React, { useState } from "react";
import axios from "axios";
import { useLLMStream } from "../../hooks/useLLMStream";
import "../VulnerabilityPage.css";

const API_BASE = "http://localhost:3001/api";

const LLM05ImproperOutputHandling: React.FC = () => {
  const [prompt, setPrompt] = useState("");
  const [generateResponse, setGenerateResponse] = useState<any>(null);
  const [renderHtml, setRenderHtml] = useState(false);
  const { text, isStreaming, isThinking, error, startStream, reset } = useLLMStream();

  const chatWithLLM = async () => {
    if (!prompt.trim()) return;
    await startStream("/llm05/chat", { message: prompt });
  };

  const generateOutput = async () => {
    if (!prompt.trim()) return;
    try {
      const res = await axios.post(`${API_BASE}/llm05/generate`, { prompt });
      setGenerateResponse(res.data);
      setRenderHtml(false);
    } catch (err: any) {
      setGenerateResponse(err.response?.data || { error: err.message });
    }
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>LLM05 - Improper Output Handling</h1>
        <div className="vulnerability-badge" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>OWASP LLM #5</div>
      </div>

      <div className="vuln-description">
        <p>
          When LLM outputs are rendered or executed without proper sanitization,
          they can introduce XSS, SQL injection, and command injection vulnerabilities.
          The LLM becomes an indirect attack vector.
        </p>
      </div>

      <div className="demo-section">
        <h2>Demo 1: Streamed Response</h2>
        <p>
          Ask the LLM to generate content. The streamed response shows what the model produces.
        </p>

        <div className="demo-controls" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <label>
            Prompt:
            <textarea value={prompt} onChange={(e) => setPrompt(e.target.value)}
              placeholder='Try: "Generate a greeting card" or "Write a SQL query to delete inactive users"'
              rows={2} style={{ width: "100%", resize: "vertical" }} />
          </label>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button onClick={chatWithLLM} disabled={isStreaming || !prompt.trim()}>
              Stream Response
            </button>
            <button onClick={generateOutput} disabled={!prompt.trim()}>
              Generate Raw Output
            </button>
            <button onClick={() => { reset(); setGenerateResponse(null); setRenderHtml(false); }} style={{ background: "#6c757d" }}>
              Clear
            </button>
          </div>
        </div>

        <div className="demo-tips">
          <h4>Try these prompts:</h4>
          <ul>
            <li><strong>XSS via HTML:</strong> "Generate a greeting card" (contains script/onerror tags)</li>
            <li><strong>SQL injection:</strong> "Write a SQL query to delete inactive users"</li>
            <li><strong>Malicious markdown:</strong> "Create a formatted markdown document"</li>
            <li><strong>Command injection:</strong> "Suggest a terminal command to clean up files"</li>
          </ul>
        </div>
      </div>

      {(text || isThinking || error) && (
        <div className="response-section">
          <h3>Streamed Response:</h3>
          <div className="response-box" style={{ minHeight: "60px" }}>
            {isThinking && <span style={{ color: "#a0aec0", fontStyle: "italic" }}>Thinking...</span>}
            {text}
            {isStreaming && <span style={{ animation: "blink 1s infinite" }}>|</span>}
            {error && <span style={{ color: "#fc8181" }}>Error: {error}</span>}
          </div>
        </div>
      )}

      {generateResponse && (
        <div className="demo-section">
          <h2>Demo 2: Raw vs Rendered Output</h2>
          <p>
            The raw output below contains potentially dangerous content. Click
            "Render Unsanitized" to see what happens when it's trusted and rendered as HTML.
          </p>

          <pre className="response-box">{JSON.stringify(generateResponse, null, 2)}</pre>

          {generateResponse.rawHtml && (
            <>
              <div className="demo-controls" style={{ marginTop: "1rem" }}>
                <button onClick={() => setRenderHtml(!renderHtml)}
                  style={{ background: renderHtml ? "#6c757d" : "#dc3545" }}>
                  {renderHtml ? "Hide Rendered Output" : "Render Unsanitized HTML (Dangerous!)"}
                </button>
              </div>

              {renderHtml && (
                <div style={{ marginTop: "1rem" }}>
                  <div id="xss-demo" style={{ padding: "1rem", border: "2px dashed #dc3545", borderRadius: "8px" }}>
                    <div dangerouslySetInnerHTML={{ __html: generateResponse.rawHtml }} />
                  </div>
                  <p style={{ color: "#dc3545", fontWeight: "bold", marginTop: "0.5rem" }}>
                    The HTML above was rendered without sanitization - any embedded scripts could execute!
                  </p>
                </div>
              )}
            </>
          )}

          {generateResponse.sqlQuery && (
            <div className="attack-examples" style={{ marginTop: "1rem" }}>
              <h4>Generated SQL (would be executed directly):</h4>
              <code>{generateResponse.sqlQuery}</code>
            </div>
          )}
        </div>
      )}

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

      <div className="navigation-section">
        <a href="/llm/l06" className="next-button" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>
          Next: LLM06 - Excessive Agency &rarr;
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

export default LLM05ImproperOutputHandling;
