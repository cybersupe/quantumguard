import { useState } from "react";

export default function UnifiedRisk() {
  const [github, setGithub] = useState("");
  const [domain, setDomain] = useState("");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const runScan = async () => {
    setLoading(true);
    const res = await fetch("https://quantumguard-api.onrender.com/unified-risk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        github_url: github,
        domain: domain
      })
    });

    const json = await res.json();
    setData(json);
    setLoading(false);
  };

  return (
    <div style={{ padding: 20 }}>
      <h2>Unified Risk Dashboard</h2>

      <input
        placeholder="GitHub Repo URL"
        value={github}
        onChange={(e) => setGithub(e.target.value)}
        style={{ width: "100%", marginBottom: 10 }}
      />

      <input
        placeholder="Domain (example: google.com)"
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        style={{ width: "100%", marginBottom: 10 }}
      />

      <button onClick={runScan}>
        {loading ? "Scanning..." : "Run Unified Scan"}
      </button>

      {data && (
        <div style={{ marginTop: 20 }}>

          <h3>Overall Risk</h3>
          <h1>{data.unified_risk.quantum_risk_score}/100</h1>
          <p>{data.unified_risk.risk_level}</p>

          <h3>Component Scores</h3>
          <p>Code: {data.unified_risk.component_scores.code_crypto_score}</p>
          <p>Agility: {data.unified_risk.component_scores.crypto_agility_score}</p>
          <p>TLS: {data.unified_risk.component_scores.tls_score}</p>

          <h3>Top Findings</h3>
          {data.top_findings?.map((f, i) => (
            <p key={i}>⚠ {f}</p>
          ))}

          <h3>Priority Actions</h3>
          {data.priority_actions?.map((a, i) => (
            <p key={i}>👉 {a}</p>
          ))}

        </div>
      )}
    </div>
  );
}
