import React from "react";

export default function LandingPage({ onStart }) {
return (
<div style={{ fontFamily: "Segoe UI", background: "#f8faf8", minHeight: "100vh" }}>

```
  {/* NAVBAR */}
  <nav style={{
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "16px 24px",
    background: "white",
    borderBottom: "1px solid #e5e7eb",
    position: "sticky",
    top: 0
  }}>
    <h2 style={{ color: "#16a34a" }}>QuantumGuard</h2>

    <button
      onClick={onStart}
      style={{
        background: "#16a34a",
        color: "white",
        padding: "10px 16px",
        border: "none",
        borderRadius: 8,
        cursor: "pointer"
      }}
    >
      Start Scan
    </button>
  </nav>

  {/* HERO */}
  <section style={{
    padding: "60px 20px",
    textAlign: "center"
  }}>
    <h1 style={{
      fontSize: "42px",
      marginBottom: 20
    }}>
      Find Quantum Vulnerabilities.
    </h1>

    <p style={{
      color: "#555",
      maxWidth: 600,
      margin: "0 auto 30px"
    }}>
      Scan your code for RSA, ECC, SHA-1 and other cryptographic risks before quantum computers break them.
    </p>

    <button
      onClick={onStart}
      style={{
        background: "#16a34a",
        color: "white",
        padding: "14px 28px",
        border: "none",
        borderRadius: 10,
        fontSize: 16,
        cursor: "pointer"
      }}
    >
      Run Free Scan
    </button>
  </section>

  {/* FEATURES */}
  <section style={{ padding: "40px 20px" }}>
    <h2 style={{ textAlign: "center", marginBottom: 30 }}>
      Features
    </h2>

    <div style={{
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit, minmax(250px, 1fr))",
      gap: 20
    }}>
      {[
        "Detect RSA, ECC, MD5, SHA-1",
        "Quantum readiness score",
        "PDF & CSV reports",
        "Migration recommendations"
      ].map((f, i) => (
        <div key={i} style={{
          background: "white",
          padding: 20,
          borderRadius: 12,
          border: "1px solid #e5e7eb"
        }}>
          {f}
        </div>
      ))}
    </div>
  </section>

  {/* CTA */}
  <section style={{
    background: "#16a34a",
    color: "white",
    padding: "50px 20px",
    textAlign: "center"
  }}>
    <h2>Start securing your code today</h2>
    <button
      onClick={onStart}
      style={{
        marginTop: 20,
        background: "white",
        color: "#16a34a",
        padding: "12px 24px",
        border: "none",
        borderRadius: 8,
        cursor: "pointer"
      }}
    >
      Open Scanner
    </button>
  </section>

</div>
```

);
}
