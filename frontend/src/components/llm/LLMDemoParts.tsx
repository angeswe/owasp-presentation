import React from "react";
import { Link } from "react-router-dom";
import { LLMVuln } from "./types";
import "../VulnerabilityPage.css";
import "./LLMDemo.css";

// Building blocks shared by the ten LLM pages, so each page only holds its own
// demo logic and text.

export const LLM_GRADIENT = "linear-gradient(135deg, #00ced1, #8a2be2)";

export const LLMPageHeader: React.FC<{ meta: LLMVuln }> = ({ meta }) => (
  <div className="vuln-header">
    <h1>
      {meta.code} - {meta.title}
    </h1>
    <div className="vulnerability-badge" style={{ background: LLM_GRADIENT }}>
      OWASP LLM #{meta.rank}
    </div>
  </div>
);

// Section title plus the "Secure mode" switch on the right.
export const DemoTopBar: React.FC<{
  title: string;
  secure: boolean;
  onSecureChange: (secure: boolean) => void;
}> = ({ title, secure, onSecureChange }) => (
  <div className="llm-demo-topbar">
    <h2>{title}</h2>
    <label className={`llm-secure-toggle ${secure ? "on" : ""}`}>
      <input
        type="checkbox"
        checked={secure}
        onChange={(e) => onSecureChange(e.target.checked)}
      />
      🔒 Secure mode {secure ? "ON" : "OFF"}
    </label>
  </div>
);

export interface Preset {
  label: string;
}

// One-click attack buttons: each fills the input and sends it.
export function PresetChips<T extends Preset>({
  presets,
  onPick,
  disabled,
}: {
  presets: T[];
  onPick: (preset: T) => void;
  disabled?: boolean;
}) {
  return (
    <div className="llm-preset-chips">
      <span className="llm-preset-label">Try:</span>
      {presets.map((p) => (
        <button
          key={p.label}
          type="button"
          className="llm-preset-chip"
          onClick={() => onPick(p)}
          disabled={disabled}
        >
          {p.label}
        </button>
      ))}
    </div>
  );
}

export const StreamOutput: React.FC<{
  title: string;
  text: string;
  isThinking: boolean;
  isStreaming: boolean;
  error: string | null;
  thinkingLabel?: string;
}> = ({ title, text, isThinking, isStreaming, error, thinkingLabel = "Thinking..." }) => {
  if (!text && !isThinking && !error) return null;
  return (
    <div className="response-section">
      <h3>{title}</h3>
      <div className="response-box" style={{ minHeight: "60px" }}>
        {isThinking && (
          <span style={{ color: "#a0aec0", fontStyle: "italic" }}>{thinkingLabel}</span>
        )}
        {text}
        {isStreaming && <span className="llm-cursor">|</span>}
        {error && <span style={{ color: "#fc8181" }}>Error: {error}</span>}
      </div>
    </div>
  );
};

export const WhyItWorked: React.FC<{ items: React.ReactNode[] }> = ({ items }) => (
  <div className="vulnerability-explanation">
    <h4>Why this worked</h4>
    <ul>
      {items.map((item, i) => (
        <li key={i}>{item}</li>
      ))}
    </ul>
  </div>
);

export const LLMNextNav: React.FC<{ next?: LLMVuln }> = ({ next }) => (
  <div className="navigation-section">
    {next ? (
      <Link to={next.path} className="next-button" style={{ background: LLM_GRADIENT }}>
        Next: {next.code} - {next.title} &rarr;
      </Link>
    ) : (
      <Link to="/llm" className="next-button" style={{ background: LLM_GRADIENT }}>
        &larr; Back to LLM Top 10 Home
      </Link>
    )}
  </div>
);
