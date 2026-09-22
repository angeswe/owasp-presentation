import React, { useState } from "react";
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
  { label: "Show me everything", value: "Show me everything" },
  { label: "Merger negotiations", value: "What are the merger negotiations?" },
  { label: "Security audit results", value: "Security audit results" },
  { label: "PTO policy", value: "What is our PTO policy?" },
];

const LLM08VectorEmbeddingWeaknesses: React.FC<LLMVulnProps> = ({ meta, next }) => {
  const [query, setQuery] = useState("");
  const [userRole, setUserRole] = useState("intern");
  const [secure, setSecure] = useState(false);
  const { text, isStreaming, isThinking, error, startStream, reset } = useLLMStream();

  const search = (q: string) => {
    if (!q.trim()) return;
    startStream(`${meta.apiBase}/query`, { query: q, userRole, secure });
  };

  return (
    <div className="vulnerability-page">
      <LLMPageHeader meta={meta} />

      <div className="vuln-description">
        <p>
          RAG (Retrieval-Augmented Generation) systems using vector databases can
          expose confidential documents when access controls aren't enforced during
          retrieval.
        </p>
      </div>

      <div className="demo-section">
        <DemoTopBar title="Demo: RAG Without Access Control" secure={secure} onSecureChange={setSecure} />
        <p>
          The company assistant searches one shared vector store. Ask it something as an intern.
        </p>

        <div className="demo-controls">
          <label>
            Your role:
            <select value={userRole} onChange={(e) => setUserRole(e.target.value)}>
              <option value="intern">Intern</option>
              <option value="employee">Employee</option>
              <option value="manager">Manager</option>
            </select>
          </label>
        </div>

        <PresetChips
          presets={PRESETS}
          disabled={isStreaming}
          onPick={(p) => {
            setQuery(p.value);
            search(p.value);
          }}
        />

        <div className="demo-controls" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <label>
            Search query:
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Ask the knowledge base"
              style={{ width: "100%" }}
              onKeyDown={(e) => e.key === "Enter" && search(query)}
            />
          </label>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button onClick={() => search(query)} disabled={isStreaming || !query.trim()}>
              Search Knowledge Base
            </button>
            <button onClick={reset} style={{ background: "#6c757d" }}>
              Clear
            </button>
          </div>
        </div>
      </div>

      <StreamOutput
        title="RAG Response:"
        text={text}
        isThinking={isThinking}
        isStreaming={isStreaming}
        error={error}
        thinkingLabel="Searching knowledge base..."
      />

      <WhyItWorked
        items={[
          "All departments' documents sit in one vector store. Retrieval ranks by similarity only and ignores who is asking.",
          "The role is known, but nothing checks it before documents are passed to the model.",
          "Secure mode: results are filtered by the user's role before the model sees them. An intern gets only all-employees documents.",
        ]}
      />

      <div className="remediation-section">
        <h2>How to Fix This</h2>
        <div className="remediation-grid">
          <div className="fix-item">
            <h4>1. Access Control on Retrieval</h4>
            <p>Filter retrieved documents based on user permissions</p>
            <code>Apply RBAC before returning RAG results</code>
          </div>
          <div className="fix-item">
            <h4>2. Data Partitioning</h4>
            <p>Separate vector stores by access level or tenant</p>
            <code>Logical and physical isolation of embeddings</code>
          </div>
          <div className="fix-item">
            <h4>3. Embedding Protection</h4>
            <p>Prevent inversion attacks on stored embeddings</p>
            <code>Use dimensionality reduction and noise injection</code>
          </div>
          <div className="fix-item">
            <h4>4. Source Validation</h4>
            <p>Verify and classify all documents before ingestion</p>
            <code>Automated classification with human review</code>
          </div>
        </div>

        <div className="best-practices">
          <h3>Best Practices</h3>
          <ul>
            <li><strong>Zero Trust RAG:</strong> Verify permissions for every retrieval, not just at query time</li>
            <li><strong>Document Classification:</strong> Automatically tag documents with sensitivity levels</li>
            <li><strong>Audit Trails:</strong> Log all document retrievals with user context</li>
            <li><strong>Regular Access Reviews:</strong> Periodically review who can access what in the vector store</li>
          </ul>
        </div>
      </div>

      <LLMNextNav next={next} />
    </div>
  );
};

export default LLM08VectorEmbeddingWeaknesses;
