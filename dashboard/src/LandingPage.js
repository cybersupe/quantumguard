import React from "react";

export default function LandingPage({ onStart }) {
  return (
    <div style={{ fontFamily: "Segoe UI", background: "#f8faf8" }}>

      {/* NAVBAR */}
      <nav style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "14px 20px",
        background: "white",
        borderBottom: "1px solid #e5e7eb",
        position: "sticky",
        top: 0
      }}>
        <h2 style={{ color: "#16a34a" }}>QuantumGuard</h2>

        <div style={{ display: "flex", gap: 15 }}>
          <a href="#features">Features</a>
          <a href="#how">How It Works</a>
          <a href="#pricing">Pricing</a>
          <a href="#docs">Docs</a>
        </div>

        <button onClick={onStart} style={{
          background: "#16a34a",
          color: "white",
          padding: "8px 14px",
          border: "none",
          borderRadius: 8,
          cursor: "pointer"
        }}>
          Start
        </button>
      </nav>

      {/* HERO */}
      <section style={{ padding: "50px 20px", textAlign: "center" }}>
        <h1>Find Quantum Vulnerabilities.</h1>
        <p style={{ color: "#555" }}>
          Scan your code for RSA, ECC, SHA-1 risks before quantum attacks.
        </p>
        <button onClick={onStart} style={{
          background: "#16a34a",
          color: "white",
          padding: "12px 20px",
          border: "none",
          borderRadius: 8
        }}>
          Run Scan
        </button>
      </section>

      {/* FEATURES */}
      <section id="features" style={{ padding: 40 }}>
        <h2>Features</h2>
        <p>Detect RSA, ECC, SHA-1</p>
        <p>Quantum readiness score</p>
      </section>

      {/* HOW */}
      <section id="how" style={{ padding: 40 }}>
        <h2>How It Works</h2>
        <p>Upload code → Scan → Get report</p>
      </section>

      {/* PRICING */}
      <section id="pricing" style={{ padding: 40 }}>
        <h2>Pricing</h2>
        <p>Free / Pro / Enterprise</p>
      </section>

      {/* DOCS */}
      <section id="docs" style={{ padding: 40 }}>
        <h2>Documentation</h2>
        <p>Coming soon...</p>
      </section>

    </div>
  );
}