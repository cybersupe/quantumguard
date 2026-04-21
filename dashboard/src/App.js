import { useState } from "react";

function App() {
  const [directory, setDirectory] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const handleScan = async () => {
    if (!directory) return;
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ directory }),
      });
      const data = await res.json();
      setResult(data);
    } catch (e) {
      alert("API not running! Start uvicorn first.");
    }
    setLoading(false);
  };

  const getScoreColor = (score) => {
    if (score >= 70) return "#1D9E75";
    if (score >= 40) return "#BA7517";
    return "#E24B4A";
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0f0f1a", color: "#fff", fontFamily: "sans-serif", padding: "40px 20px" }}>
      <div style={{ maxWidth: 800, margin: "0 auto" }}>
        <h1 style={{ fontSize: 32, color: "#7F77DD", marginBottom: 8 }}>QuantumGuard</h1>
        <p style={{ color: "#888", marginBottom: 32 }}>AI-powered quantum cryptography vulnerability scanner</p>

        <div style={{ display: "flex", gap: 12, marginBottom: 32 }}>
          <input
            value={directory}
            onChange={(e) => setDirectory(e.target.value)}
            placeholder="Enter directory path e.g. C:\Users\thisi\quantumguard\tests"
            style={{ flex: 1, padding: "12px 16px", borderRadius: 8, border: "1px solid #333", background: "#1a1a2e", color: "#fff", fontSize: 14 }}
          />
          <button
            onClick={handleScan}
            disabled={loading}
            style={{ padding: "12px 24px", borderRadius: 8, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 14, fontWeight: 500 }}
          >
            {loading ? "Scanning..." : "Scan"}
          </button>
        </div>

        {result && (
          <div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
              <div style={{ background: "#1a1a2e", borderRadius: 12, padding: 24, textAlign: "center" }}>
                <div style={{ fontSize: 48, fontWeight: 700, color: getScoreColor(result.quantum_readiness_score) }}>
                  {result.quantum_readiness_score}
                </div>
                <div style={{ color: "#888", fontSize: 14 }}>Quantum Readiness Score</div>
              </div>
              <div style={{ background: "#1a1a2e", borderRadius: 12, padding: 24, textAlign: "center" }}>
                <div style={{ fontSize: 48, fontWeight: 700, color: "#E24B4A" }}>
                  {result.total_findings}
                </div>
                <div style={{ color: "#888", fontSize: 14 }}>Vulnerabilities Found</div>
              </div>
            </div>

            <div style={{ background: "#1a1a2e", borderRadius: 12, padding: 24 }}>
              <h3 style={{ marginBottom: 16, color: "#7F77DD" }}>Findings</h3>
              {result.findings.map((f, i) => (
                <div key={i} style={{ borderLeft: `3px solid ${f.severity === "CRITICAL" ? "#E24B4A" : f.severity === "HIGH" ? "#BA7517" : "#1D9E75"}`, paddingLeft: 16, marginBottom: 16 }}>
                  <div style={{ display: "flex", gap: 8, marginBottom: 4 }}>
                    <span style={{ background: f.severity === "CRITICAL" ? "#E24B4A22" : f.severity === "HIGH" ? "#BA751722" : "#1D9E7522", color: f.severity === "CRITICAL" ? "#E24B4A" : f.severity === "HIGH" ? "#BA7517" : "#1D9E75", padding: "2px 8px", borderRadius: 4, fontSize: 12 }}>{f.severity}</span>
                    <span style={{ color: "#888", fontSize: 12 }}>{f.file}:{f.line}</span>
                  </div>
                  <div style={{ fontFamily: "monospace", background: "#0f0f1a", padding: "8px 12px", borderRadius: 6, fontSize: 13, marginBottom: 4 }}>{f.code}</div>
                  <div style={{ fontSize: 12, color: "#888" }}>Fix: Replace with <span style={{ color: "#7F77DD" }}>{f.replacement}</span></div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;