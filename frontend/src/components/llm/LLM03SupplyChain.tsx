import React, { useState, useEffect } from "react";
import axios from "axios";
import "../VulnerabilityPage.css";

const API_BASE = "http://localhost:3001/api";

const LLM03SupplyChain: React.FC = () => {
  const [registry, setRegistry] = useState<any>(null);
  const [selectedModel, setSelectedModel] = useState("");
  const [selectedPlugin, setSelectedPlugin] = useState("");
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    axios.get(`${API_BASE}/llm03/registry`).then(res => setRegistry(res.data)).catch(() => {});
  }, []);

  const loadModel = async () => {
    if (!selectedModel) return;
    setLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/llm03/load-model`, { modelName: selectedModel });
      setResponse(res.data);
    } catch (err: any) {
      setResponse(err.response?.data || { error: err.message });
    }
    setLoading(false);
  };

  const installPlugin = async () => {
    if (!selectedPlugin) return;
    setLoading(true);
    try {
      const res = await axios.post(`${API_BASE}/llm03/install-plugin`, { pluginName: selectedPlugin });
      setResponse(res.data);
    } catch (err: any) {
      setResponse(err.response?.data || { error: err.message });
    }
    setLoading(false);
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>LLM03 - Supply Chain</h1>
        <div className="vulnerability-badge" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>OWASP LLM #3</div>
      </div>

      <div className="vuln-description">
        <p>
          LLM supply chains are vulnerable to tampered models, malicious plugins,
          and compromised training data. Without integrity verification, attackers
          can introduce backdoors that remain dormant until triggered.
        </p>
      </div>

      <div className="demo-section">
        <h2>Demo 1: Unverified Model Loading</h2>
        <p>
          Load models from a registry without checking their integrity, publisher
          verification, or hash signatures. Some models contain backdoors.
        </p>

        <div className="demo-controls">
          <label>
            Select Model:
            <select value={selectedModel} onChange={(e) => setSelectedModel(e.target.value)}>
              <option value="">-- Choose a model --</option>
              {registry?.models?.map((m: string) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </label>
          <button onClick={loadModel} disabled={loading || !selectedModel}>
            Load Model (No Verification)
          </button>
        </div>

        <div className="demo-tips">
          <h4>Try these models:</h4>
          <ul>
            <li><strong>gpt-helper-v2</strong> - Verified model with valid hash</li>
            <li><strong>finance-llm-pro</strong> - Unverified model with embedded backdoor</li>
            <li><strong>medical-assistant-v3</strong> - Tampered model with weak MD5 hash</li>
          </ul>
        </div>
      </div>

      <div className="demo-section">
        <h2>Demo 2: Malicious Plugin Installation</h2>
        <p>
          Install plugins that request excessive permissions from untrusted sources.
          Permissions are auto-granted without review.
        </p>

        <div className="demo-controls">
          <label>
            Select Plugin:
            <select value={selectedPlugin} onChange={(e) => setSelectedPlugin(e.target.value)}>
              <option value="">-- Choose a plugin --</option>
              {registry?.plugins?.map((p: string) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </label>
          <button onClick={installPlugin} disabled={loading || !selectedPlugin}>
            Install Plugin (Auto-Grant Permissions)
          </button>
        </div>

        <div className="vulnerability-explanation">
          <h4>Why this is dangerous:</h4>
          <ul>
            <li>No signature verification on downloaded models</li>
            <li>Plugins get all requested permissions automatically</li>
            <li>Backdoors can remain dormant until specific trigger inputs</li>
            <li>Weak hash algorithms (MD5) can be spoofed</li>
          </ul>
        </div>
      </div>

      {response && (
        <div className="response-section">
          <h3>Response:</h3>
          <pre className="response-box">{JSON.stringify(response, null, 2)}</pre>
        </div>
      )}

      <div className="remediation-section">
        <h2>How to Fix This</h2>
        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Integrity Verification</h4>
            <p>Verify model hashes using strong algorithms (SHA-256+)</p>
            <code>Compare cryptographic signatures before loading</code>
          </div>
          <div className="fix-item">
            <h4>2. Publisher Verification</h4>
            <p>Only load models from verified, trusted publishers</p>
            <code>Maintain an allowlist of approved model sources</code>
          </div>
          <div className="fix-item">
            <h4>3. Permission Review</h4>
            <p>Require explicit human approval for plugin permissions</p>
            <code>Principle of least privilege for all extensions</code>
          </div>
          <div className="fix-item">
            <h4>4. SBOM Tracking</h4>
            <p>Maintain a Software Bill of Materials for all components</p>
            <code>Track and audit all dependencies and their versions</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>Best Practices</h3>
          <ul>
            <li><strong>Signed Models:</strong> Require cryptographic signatures on all model artifacts</li>
            <li><strong>Dependency Scanning:</strong> Regularly scan for known vulnerabilities in dependencies</li>
            <li><strong>Sandbox Execution:</strong> Run untrusted plugins in isolated sandbox environments</li>
            <li><strong>Supply Chain Audits:</strong> Regularly audit the full chain from data to deployment</li>
          </ul>
        </div>
      </div>

      <div className="navigation-section">
        <a href="/llm/l04" className="next-button" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>
          Next: LLM04 - Data and Model Poisoning &rarr;
        </a>
      </div>
    </div>
  );
};

export default LLM03SupplyChain;
