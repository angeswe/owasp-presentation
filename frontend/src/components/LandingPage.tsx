import React from "react";
import { Link } from "react-router-dom";
import "./LandingPage.css";

const LandingPage: React.FC = () => {
  return (
    <div className="landing-page">
      <div className="landing-hero">
        <h1>OWASP Top 10 Security Vulnerabilities</h1>
        <p>
          Interactive educational demonstrations of the most critical security
          risks to web applications and AI/LLM systems.
        </p>
        <p className="landing-subtitle">Choose a topic to explore</p>
      </div>

      <div className="landing-cards">
        <Link to="/web" className="landing-card landing-card--web">
          <span className="landing-card__year">2021</span>
          <h2>OWASP Web Top 10</h2>
          <p>
            The standard awareness document for web application security — from
            broken access control to server-side request forgery.
          </p>
          <span className="landing-card__cta">Explore Web Top 10 &rarr;</span>
        </Link>

        <Link to="/llm" className="landing-card landing-card--llm">
          <span className="landing-card__year">2025</span>
          <h2>OWASP LLM Top 10</h2>
          <p>
            Security risks specific to AI and Large Language Models — from prompt
            injection to unbounded consumption.
          </p>
          <span className="landing-card__cta">Explore LLM Top 10 &rarr;</span>
        </Link>
      </div>
    </div>
  );
};

export default LandingPage;
