import React, { useState } from "react";
import axios from "axios";
import { LLMVulnProps } from "./types";
import { DemoTopBar, LLMNextNav, LLMPageHeader, PresetChips, WhyItWorked } from "./LLMDemoParts";

interface SupplyPreset {
  label: string;
  kind: "model" | "plugin";
  name: string;
}

const PRESETS: SupplyPreset[] = [
  { label: "gpt-helper-v2 (signed)", kind: "model", name: "gpt-helper-v2" },
  { label: "finance-llm-pro", kind: "model", name: "finance-llm-pro" },
  { label: "medical-assistant-v3", kind: "model", name: "medical-assistant-v3" },
  { label: "Install plugin: data-export-helper", kind: "plugin", name: "data-export-helper" },
];

const LLM03SupplyChain: React.FC<LLMVulnProps> = ({ meta, next }) => {
  const [modelName, setModelName] = useState("");
  const [secure, setSecure] = useState(false);
  const [response, setResponse] = useState<{ status: number; data: any } | null>(null);
  const [loading, setLoading] = useState(false);

  const run = async (kind: "model" | "plugin", name: string) => {
    if (!name.trim()) return;
    setLoading(true);
    try {
      const res =
        kind === "model"
          ? await axios.post(`${meta.apiBase}/load-model`, { modelName: name.trim(), secure })
          : await axios.post(`${meta.apiBase}/install-plugin`, { pluginName: name.trim(), secure });
      setResponse({ status: res.status, data: res.data });
    } catch (err: any) {
      setResponse({ status: err.response?.status ?? 0, data: err.response?.data || { error: err.message } });
    }
    setLoading(false);
  };

  return (
    <div className="vulnerability-page">
      <LLMPageHeader meta={meta} />

      <div className="vuln-description">
        <p>
          LLM supply chains are vulnerable to tampered models, malicious plugins,
          and compromised training data. Without integrity verification, attackers
          can introduce backdoors that remain dormant until triggered.
        </p>
      </div>

      <div className="demo-section">
        <DemoTopBar title="Demo: Load a Model from a Public Registry" secure={secure} onSecureChange={setSecure} />
        <p>
          The app pulls models and plugins by name from a public hub and puts them into production.
        </p>

        <PresetChips
          presets={PRESETS}
          disabled={loading}
          onPick={(p) => {
            if (p.kind === "model") setModelName(p.name);
            run(p.kind, p.name);
          }}
        />

        <div className="demo-controls">
          <label>
            Model name:
            <input
              type="text"
              value={modelName}
              onChange={(e) => setModelName(e.target.value)}
              placeholder="e.g. finance-llm-pro"
              onKeyDown={(e) => e.key === "Enter" && run("model", modelName)}
            />
          </label>
          <button onClick={() => run("model", modelName)} disabled={loading || !modelName.trim()}>
            Load Model
          </button>
          <button onClick={() => setResponse(null)} style={{ background: "#6c757d" }}>
            Clear
          </button>
        </div>
      </div>

      {response && (
        <div className="response-section">
          <h3>Response (HTTP {response.status}):</h3>
          <pre className="response-box">{JSON.stringify(response.data, null, 2)}</pre>
        </div>
      )}

      <WhyItWorked
        items={[
          "The loader trusts the registry name. It never checks the publisher, a signature or a strong hash, so an unsigned model with a hidden backdoor goes straight to production.",
          "Plugin permissions are granted automatically, including system:execute.",
          "Secure mode: models and plugins must pass publisher, signature and SHA-256 checks, and plugins may not request system:execute. Failed checks are returned.",
        ]}
      />

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

      <LLMNextNav next={next} />
    </div>
  );
};

export default LLM03SupplyChain;
