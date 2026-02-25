import React, { useState, useEffect } from "react";
import axios from "axios";
import { useLLMStream } from "../../hooks/useLLMStream";
import "../VulnerabilityPage.css";

const API_BASE = "http://localhost:3001/api";

const LLM08VectorEmbeddingWeaknesses: React.FC = () => {
  const [query, setQuery] = useState("");
  const [userRole, setUserRole] = useState("intern");
  const [documents, setDocuments] = useState<any[]>([]);
  const [embeddingId, setEmbeddingId] = useState("");
  const [inversionResult, setInversionResult] = useState<any>(null);
  const { text, isStreaming, isThinking, error, startStream, reset } = useLLMStream();

  useEffect(() => {
    axios.get<{ documents: any[] }>(`${API_BASE}/llm08/documents`).then(res => setDocuments(res.data.documents)).catch(() => {});
  }, []);

  const searchRAG = async () => {
    if (!query.trim()) return;
    await startStream("/llm08/query", { query, userRole });
  };

  const invertEmbedding = async () => {
    if (!embeddingId) return;
    try {
      const res = await axios.post(`${API_BASE}/llm08/invert-embedding`, { embeddingId });
      setInversionResult(res.data);
    } catch (err: any) {
      setInversionResult(err.response?.data || { error: err.message });
    }
  };

  return (
    <div className="vulnerability-page">
      <div className="vuln-header">
        <h1>LLM08 - Vector and Embedding Weaknesses</h1>
        <div className="vulnerability-badge" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>OWASP LLM #8</div>
      </div>

      <div className="vuln-description">
        <p>
          RAG (Retrieval-Augmented Generation) systems using vector databases can
          expose confidential documents when access controls aren't enforced during
          retrieval. Embedding inversion can also recover original text from vectors.
        </p>
      </div>

      <div className="demo-section">
        <h2>Demo 1: RAG Without Access Control</h2>
        <p>
          Search the knowledge base as a low-privilege user. The system returns
          confidential and restricted documents without checking your access level.
        </p>

        <div className="demo-controls">
          <label>
            Your Role:
            <select value={userRole} onChange={(e) => setUserRole(e.target.value)}>
              <option value="intern">Intern</option>
              <option value="employee">Employee</option>
              <option value="manager">Manager</option>
            </select>
          </label>
        </div>

        <div className="demo-controls" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <label>
            Search query:
            <input type="text" value={query} onChange={(e) => setQuery(e.target.value)}
              placeholder='Try: "everything" or "confidential" or "merger"'
              style={{ width: "100%" }}
              onKeyDown={(e) => e.key === "Enter" && searchRAG()} />
          </label>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button onClick={searchRAG} disabled={isStreaming || !query.trim()}>
              Search Knowledge Base
            </button>
            <button onClick={reset} style={{ background: "#6c757d" }}>Clear</button>
          </div>
        </div>

        <div className="demo-tips">
          <h4>Try these queries as an intern:</h4>
          <ul>
            <li><strong>"everything"</strong> - Returns all documents across all departments</li>
            <li><strong>"confidential"</strong> - Accesses executive-level financial data</li>
            <li><strong>"security"</strong> - Retrieves security audit results and credentials</li>
            <li><strong>"merger"</strong> - Exposes confidential M&A negotiations</li>
          </ul>
        </div>
      </div>

      {(text || isThinking || error) && (
        <div className="response-section">
          <h3>RAG Response:</h3>
          <div className="response-box" style={{ minHeight: "60px" }}>
            {isThinking && <span style={{ color: "#a0aec0", fontStyle: "italic" }}>Searching knowledge base...</span>}
            {text}
            {isStreaming && <span style={{ animation: "blink 1s infinite" }}>|</span>}
            {error && <span style={{ color: "#fc8181" }}>Error: {error}</span>}
          </div>
        </div>
      )}

      <div className="demo-section">
        <h2>Demo 2: Embedding Inversion</h2>
        <p>
          Recover original document content from stored embeddings. Select a document
          ID to see its full content recovered without access checks.
        </p>

        {documents.length > 0 && (
          <div style={{ marginBottom: "1rem" }}>
            <table className="user-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Department</th>
                  <th>Classification</th>
                  <th>Access Level</th>
                </tr>
              </thead>
              <tbody>
                {documents.map(doc => (
                  <tr key={doc.id}>
                    <td>{doc.id}</td>
                    <td>{doc.department}</td>
                    <td><strong>{doc.classification}</strong></td>
                    <td>{doc.accessLevel}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="demo-controls">
          <label>
            Document ID:
            <select value={embeddingId} onChange={(e) => setEmbeddingId(e.target.value)}>
              <option value="">-- Select a document --</option>
              {documents.map(doc => (
                <option key={doc.id} value={doc.id}>{doc.id} ({doc.classification})</option>
              ))}
            </select>
          </label>
          <button onClick={invertEmbedding} disabled={!embeddingId}>
            Invert Embedding
          </button>
        </div>
      </div>

      {inversionResult && (
        <div className="response-section">
          <h3>Recovered Content:</h3>
          <pre className="response-box">{JSON.stringify(inversionResult, null, 2)}</pre>
        </div>
      )}

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

      <div className="navigation-section">
        <a href="/llm/l09" className="next-button" style={{ background: "linear-gradient(135deg, #00ced1, #8a2be2)" }}>
          Next: LLM09 - Misinformation &rarr;
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

export default LLM08VectorEmbeddingWeaknesses;
