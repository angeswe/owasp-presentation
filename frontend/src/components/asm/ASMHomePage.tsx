import React from "react";
import { Link } from "react-router-dom";
import { exposures, surfaceStats } from "./asmExposures";
import "./ASMHomePage.css";

const ASMHomePage: React.FC = () => {
  return (
    <div className="asm-home-page">
      <div className="asm-hero-section">
        <h1>Top 10 Attack Surface Exposures</h1>
        <p className="asm-hero-description">
          Beyond application bugs, the fastest way in is often a service that
          should never have been reachable at all — an exposed database, admin
          panel, or legacy protocol. These are the ten exposures found most often
          across the internet.
        </p>
        <span className="asm-hero-subtitle">Attack Surface Analysis (2026)</span>
      </div>

      <div className="asm-stats-strip">
        <p className="asm-stats-caption">{surfaceStats.analysed}</p>
        <div className="asm-stats-grid">
          {surfaceStats.highlights.map((s) => (
            <div key={s.value} className="asm-stat">
              <span className="asm-stat__value">{s.value}</span>
              <span className="asm-stat__label">{s.label}</span>
            </div>
          ))}
        </div>
        <p className="asm-source">
          Source:{" "}
          <a
            href={surfaceStats.source.url}
            target="_blank"
            rel="noopener noreferrer"
          >
            {surfaceStats.source.label}
          </a>
        </p>
      </div>

      <div>
        <h2>The Top 10 Exposures (2026)</h2>
        <div className="asm-vuln-grid">
          {exposures.map((exposure) => (
            <div key={exposure.id} className="asm-vuln-card">
              <div className="vuln-header">
                <span className="vuln-number">{exposure.rank}</span>
                <h3>
                  {exposure.shortId} - {exposure.title}
                </h3>
              </div>
              <div className="asm-vuln-meta">
                <span className="asm-chip asm-chip--stat">{exposure.stat} of surfaces</span>
                <span className="asm-chip asm-chip--port">{exposure.port}</span>
              </div>
              <p className="vuln-description">{exposure.cardDescription}</p>
              <ul className="vuln-examples">
                {exposure.examples.map((example, i) => (
                  <li key={i}>{example}</li>
                ))}
              </ul>

              <details className="asm-card-details">
                <summary>Talk-through details</summary>

                <p className="asm-card-summary">{exposure.summary}</p>

                <div className="asm-detail-block">
                  <h4>🔎 What an attacker sees</h4>
                  <pre className="asm-scan">{exposure.scan.join("\n")}</pre>
                  <p className="asm-attacker-next">{exposure.attackerNext}</p>
                </div>

                <div className="asm-detail-block">
                  <h4>💥 Impact</h4>
                  <ul className="asm-impact">
                    {exposure.impact.map((item, i) => (
                      <li key={i}>{item}</li>
                    ))}
                  </ul>
                </div>

                <div className="asm-detail-block">
                  <h4>🛡️ How to fix it</h4>
                  <ul className="asm-fixes">
                    {exposure.fixes.map((fix) => (
                      <li key={fix.title}>
                        <strong>{fix.title}</strong> — {fix.detail}
                        <code>{fix.code}</code>
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="asm-detail-block">
                  <h4>🏆 Best practices</h4>
                  <ul className="asm-best-practices">
                    {exposure.bestPractices.map((bp) => (
                      <li key={bp.term}>
                        <strong>{bp.term}:</strong> {bp.text}
                      </li>
                    ))}
                  </ul>
                </div>
              </details>
            </div>
          ))}
        </div>
      </div>

      <div className="asm-presentation-info">
        <h2>Presentation Flow</h2>
        <p>
          Walk the room through the exposures from AS01 to AS10. Each card shows
          the service, the port it listens on, the share of attack surfaces it
          affects, and what an attacker does with it — enough to talk through the
          real-world impact and how to close the door.
        </p>
        <div>
          <Link to="/" className="asm-back-link">
            &larr; Back to OWASP Top 10
          </Link>
        </div>
      </div>
    </div>
  );
};

export default ASMHomePage;
