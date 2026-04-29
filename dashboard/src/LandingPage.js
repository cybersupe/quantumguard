import React from "react";

export default function LandingPage({ onStart }) {
  return (
    <div
      style={{
        fontFamily: "Segoe UI, Arial",
        background: "#f8faf8",
        minHeight: "100vh",
      }}
    >
      {/* NAVBAR */}
      <nav
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "14px 20px",
          background: "white",
          borderBottom: "1px solid #e5e7eb",
          position: "sticky",
          top: 0,
          zIndex: 10,
        }}
      >
        <h2 style={{ color: "#16a34a", margin: 0 }}>QuantumGuard</h2>

        <button
          onClick={onStart}
          style={{
            background: "#16a34a",
            color: "white",
            padding: "8px 14px",
            border: "none",
            borderRadius: 8,
            cursor: "pointer",
            fontSize: 14,
          }}
        >
          Start Scan
        </button>
      </nav>

      {/* HERO */}
      <section
        style={{
          padding: "50px 20px",
          textAlign: "center",
        }}
      >
        <h1
          style={{
            fontSize: "36px",
            marginBottom: 16,
          }}
        >
          Find Quantum Vulnerabilities.
        </h1>

        <p
          style={{
            color: "#555",
            maxWidth: 600,
            margin: "0 auto 24px",
            fontSize: 15,
          }}
        >
          Scan your code for RSA, ECC, SHA-1 and other cryptographic risks before
          quantum computers break them.
        </p>

        <button
          onClick={onStart}
          style={{
            background: "#16a34a",
            color: "white",
            padding: "12px 24px",
            border: "none",
            borderRadius: 10,
            fontSize: 15,
            cursor: "pointer",
          }}
        >
          Run Free Scan
        </button>
      </section>

      {/* FEATURES */}
      <section style={{ padding: "30px 20px" }}>
        <h2 style={{ textAlign: "center", marginBottom: 20 }}>
          Features
        </h2>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: 16,
          }}
        >
          {[
            "Detect RSA, ECC, MD5, SHA-1",
            "Quantum readiness score",
            "PDF & CSV reports",
            "Migration recommendations",
          ].map((item, i) => (
            <div
              key={i}
              style={{
                background: "white",
                padding: 16,
                borderRadius: 10,
                border: "1px solid #e5e7eb",
                textAlign: "center",
                fontSize: 14,
              }}
            >
              {item}
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section
        style={{
          background: "#16a34a",
          color: "white",
          padding: "40px 20px",
          textAlign: "center",
        }}
      >
        <h2 style={{ marginBottom: 10 }}>
          Start securing your code today
        </h2>

        <button
          onClick={onStart}
          style={{
            marginTop: 10,
            background: "white",
            color: "#16a34a",
            padding: "10px 20px",
            border: "none",
            borderRadius: 8,
            cursor: "pointer",
            fontWeight: "bold",
          }}
        >
          Open Scanner
        </button>
      </section>
    </div>
  );
}
