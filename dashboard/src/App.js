import { useState } from "react";

const API = "https://web-production-16177f.up.railway.app";
const KEY = "quantumguard-secret-2026";

function App() {
  const [mode, setMode] = useState("zip");
  const [input, setInput] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showScanner, setShowScanner] = useState(false);

  const handleScan = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      let res;
      if (mode === "zip") {
        if (!file) throw new Error("Please select a ZIP file");
        const formData = new FormData();
        formData.append("file", file);
        res = await fetch(`${API}/scan-zip`, {
          method: "POST",
          headers: { "x-api-key": KEY },
          body: formData,
        });
      } else {
        if (!input) throw new Error("Please enter a path");
        res = await fetch(`${API}/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-api-key": KEY },
          body: JSON.stringify({ directory: input }),
        });
      }
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Scan failed");
      setResult(data);
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  };

  const getScoreColor = (score) => {
    if (score >= 70) return "#1D9E75";
    if (score >= 40) return "#BA7517";
    return "#E24B4A";
  };

  if (!showScanner) {
    return (
      <div style={{ minHeight: "100vh", background: "#0f0f1a", color: "#fff", fontFamily: "sans-serif" }}>
        
        {/* Hero Section */}
        <div style={{ textAlign: "center", padding: "80px 20px 40px" }}>
          <div style={{ display: "inline-block", background: "#534AB722", border: "1px solid #534AB7", borderRadius: 20, padding: "6px 16px", fontSize: 12, color: "#7F77DD", marginBottom: 20 }}>
            NIST PQC Standards 2024
          </div>
          <h1 style={{ fontSize: 48, fontWeight: 700, color: "#fff", marginBottom: 16, lineHeight: 1.2 }}>
            Find Weak Encryption<br/>
            <span style={{ color: "#7F77DD" }}>Before Quantum Computers Do</span>
          </h1>
          <p style={{ fontSize: 18, color: "#888", maxWidth: 600, margin: "0 auto 40px", lineHeight: 1.6 }}>
            QuantumGuard scans your codebase and finds every encryption algorithm that quantum computers will break. Get a clear migration plan in seconds.
          </p>
          <button
            onClick={() => setShowScanner(true)}
            style={{ padding: "16px 40px", borderRadius: 10, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 16, fontWeight: 600 }}>
            Scan Your Code — Free
          </button>
          <p style={{ color: "#555", fontSize: 13, marginTop: 12 }}>No signup required. Upload ZIP or scan directly.</p>
        </div>

        {/* Stats */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, maxWidth: 700, margin: "0 auto 60px", padding: "0 20px" }}>
          {[
            { num: "6+", label: "Algorithms Detected" },
            { num: "3", label: "Languages Supported" },
            { num: "2030", label: "Quantum Deadline" },
          ].map((s, i) => (
            <div key={i} style={{ background: "#1a1a2e", borderRadius: 12, padding: 24, textAlign: "center" }}>
              <div style={{ fontSize: 32, fontWeight: 700, color: "#7F77DD" }}>{s.num}</div>
              <div style={{ color: "#888", fontSize: 13, marginTop: 4 }}>{s.label}</div>
            </div>
          ))}
        </div>

        {/* How it works */}
        <div style={{ maxWidth: 800, margin: "0 auto 60px", padding: "0 20px" }}>
          <h2 style={{ textAlign: "center", fontSize: 28, marginBottom: 32, color: "#fff" }}>How it works</h2>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
            {[
              { step: "1", title: "Upload your code", desc: "Upload a ZIP of your project or enter a path" },
              { step: "2", title: "Instant scan", desc: "We detect RSA, ECC, DH, MD5, SHA-1 vulnerabilities" },
              { step: "3", title: "Get your report", desc: "See your Quantum Readiness Score and exact fixes" },
            ].map((s, i) => (
              <div key={i} style={{ background: "#1a1a2e", borderRadius: 12, padding: 24 }}>
                <div style={{ width: 36, height: 36, borderRadius: "50%", background: "#534AB7", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, fontWeight: 700, marginBottom: 12 }}>{s.step}</div>
                <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 8 }}>{s.title}</div>
                <div style={{ fontSize: 13, color: "#888", lineHeight: 1.5 }}>{s.desc}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Example Output */}
        <div style={{ maxWidth: 800, margin: "0 auto 60px", padding: "0 20px" }}>
          <h2 style={{ textAlign: "center", fontSize: 28, marginBottom: 32, color: "#fff" }}>Example Output</h2>
          <div style={{ background: "#1a1a2e", borderRadius: 12, padding: 24 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
              <div style={{ background: "#0f0f1a", borderRadius: 8, padding: 16, textAlign: "center" }}>
                <div style={{ fontSize: 40, fontWeight: 700, color: "#E24B4A" }}>0</div>
                <div style={{ color: "#888", fontSize: 13 }}>Quantum Readiness Score</div>
              </div>
              <div style={{ background: "#0f0f1a", borderRadius: 8, padding: 16, textAlign: "center" }}>
                <div style={{ fontSize: 40, fontWeight: 700, color: "#E24B4A" }}>48</div>
                <div style={{ color: "#888", fontSize: 13 }}>Vulnerabilities Found</div>
              </div>
            </div>
            <div style={{ borderLeft: "3px solid #E24B4A", paddingLeft: 16, marginBottom: 12 }}>
              <div style={{ display: "flex", gap: 8, marginBottom: 4 }}>
                <span style={{ background: "#E24B4A22", color: "#E24B4A", padding: "2px 8px", borderRadius: 4, fontSize: 11 }}>CRITICAL</span>
                <span style={{ color: "#888", fontSize: 11 }}>src/auth.py:34</span>
              </div>
              <div style={{ fontFamily: "monospace", background: "#0f0f1a", padding: "6px 10px", borderRadius: 4, fontSize: 12, marginBottom: 4 }}>key = RSA.generate(2048)</div>
              <div style={{ fontSize: 11, color: "#888" }}>Fix: Replace with <span style={{ color: "#7F77DD" }}>CRYSTALS-Kyber</span></div>
            </div>
          </div>
        </div>

        {/* CTA */}
        <div style={{ textAlign: "center", padding: "40px 20px 80px" }}>
          <h2 style={{ fontSize: 28, marginBottom: 16 }}>Ready to quantum-proof your code?</h2>
          <button
            onClick={() => setShowScanner(true)}
            style={{ padding: "16px 40px", borderRadius: 10, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 16, fontWeight: 600 }}>
            Start Free Scan
          </button>
        </div>

        {/* Footer */}
        <div style={{ textAlign: "center", padding: "20px", borderTop: "1px solid #1a1a2e", color: "#555", fontSize: 13 }}>
          QuantumGuard — Open Source — github.com/cybersupe/quantumguard
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: "100vh", background: "#0f0f1a", color: "#fff", fontFamily: "sans-serif", padding: "40px 20px" }}>
      <div style={{ maxWidth: 800, margin: "0 auto" }}>
        <button onClick={() => { setShowScanner(false); setResult(null); setError(null); }} style={{ background: "transparent", border: "1px solid #333", color: "#888", padding: "6px 14px", borderRadius: 6, cursor: "pointer", marginBottom: 24, fontSize: 13 }}>
          ← Back
        </button>
        <h1 style={{ fontSize: 32, color: "#7F77DD", marginBottom: 8 }}>QuantumGuard</h1>
        <p style={{ color: "#888", marginBottom: 24 }}>Scan your codebase for quantum vulnerabilities</p>

        <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
          <button onClick={() => setMode("zip")} style={{ padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer", background: mode === "zip" ? "#534AB7" : "#1a1a2e", color: "#fff", fontSize: 13 }}>
            Upload ZIP
          </button>
          <button onClick={() => setMode("path")} style={{ padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer", background: mode === "path" ? "#534AB7" : "#1a1a2e", color: "#fff", fontSize: 13 }}>
            Server Path
          </button>
        </div>

        {mode === "zip" ? (
          <div style={{ display: "flex", gap: 12, marginBottom: 32 }}>
            <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files[0])} style={{ flex: 1, padding: "12px 16px", borderRadius: 8, border: "1px solid #333", background: "#1a1a2e", color: "#fff", fontSize: 14 }} />
            <button onClick={handleScan} disabled={loading} style={{ padding: "12px 24px", borderRadius: 8, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 14, fontWeight: 500 }}>
              {loading ? "Scanning..." : "Scan"}
            </button>
          </div>
        ) : (
          <div style={{ display: "flex", gap: 12, marginBottom: 32 }}>
            <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="/app/tests" style={{ flex: 1, padding: "12px 16px", borderRadius: 8, border: "1px solid #333", background: "#1a1a2e", color: "#fff", fontSize: 14 }} />
            <button onClick={handleScan} disabled={loading} style={{ padding: "12px 24px", borderRadius: 8, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 14, fontWeight: 500 }}>
              {loading ? "Scanning..." : "Scan"}
            </button>
          </div>
        )}

        {error && <div style={{ background: "#E24B4A22", border: "1px solid #E24B4A", borderRadius: 8, padding: 16, marginBottom: 24, color: "#E24B4A" }}>{error}</div>}

        {result && (
          <div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
              <div style={{ background: "#1a1a2e", borderRadius: 12, padding: 24, textAlign: "center" }}>
                <div style={{ fontSize: 48, fontWeight: 700, color: getScoreColor(result.quantum_readiness_score) }}>{result.quantum_readiness_score}</div>
                <div style={{ color: "#888", fontSize: 14 }}>Quantum Readiness Score</div>
              </div>
              <div style={{ background: "#1a1a2e", borderRadius: 12, padding: 24, textAlign: "center" }}>
                <div style={{ fontSize: 48, fontWeight: 700, color: "#E24B4A" }}>{result.total_findings}</div>
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