import React from "react";
import { Link, useLocation } from "react-router-dom";
import "./ASMNavigation.css";

const ASMNavigation: React.FC = () => {
  const location = useLocation();

  return (
    <nav className="asm-navigation">
      <div className="asm-nav-container">
        <Link to="/" className="asm-nav-item asm-home-link">
          🏠 Home
        </Link>
        <Link
          to="/asm"
          className={`asm-nav-item asm-home-link ${location.pathname === "/asm" ? "active" : ""}`}
        >
          Attack Surface Top 10
        </Link>
      </div>
    </nav>
  );
};

export default ASMNavigation;
