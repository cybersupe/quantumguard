import { useState } from "react";

const API = "https://web-production-16177f.up.railway.app";
const KEY = "quantumguard-secret-2026";

function Navbar() {
  return (
    <nav style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 40px", borderBottom: "1px solid #1a1a2e", position: "sticky", top: 0, background: "#0f0f1a", zIndex: 100 }}>
      <div style={{ fontSize: 20, fontWeight: 700, color: "#7F77DD" }}>⚛ QuantumGuard</div>
      <div style={{ display: "flex", gap: 24, alignItems: "center" }}>
        <a href="#how" style={{ color: "#888", textDecoration: "none", fontSize: 14 }}>How it works</a>
        <a href="#pricing" style={{ color: "#888", textDecoration: "none", fontSize: 14 }}>Pricing</a>
        <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ color: "#888", textDecoration: "none", fontSize: 14 }}>GitHub</a>
        <a href="#scan" style={{ background: "#534AB7", color: "#fff", padding: "8px 18px", borderRadius: 8, textDecoration: "none", fontSize: 14, fontWeight: 500 }}>Start Scan</a>
      </div>
    </nav>
  );
}

function Scanner() {
  const [mode, setMode] = useState("zip");
  const [input, setInput] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [copied, setCopied] = useState(false);

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

  const filteredFindings = result ? result.findings.filter(f => {
    const matchFilter = filter === "ALL" || f.severity === filter;
    const matchSearch = search === "" || f.file.toLowerCase().includes(search.toLowerCase()) || f.vulnerability.toLowerCase().includes(search.toLowerCase());
    return matchFilter && matchSearch;
  }) : [];

  const handleCopy = () => {
    if (!result) return;
    const text = `QuantumGuard Scan Report\n========================\nQuantum Readiness Score: ${result.quantum_readiness_score}/100\nTotal Vulnerabilities: ${result.total_findings}\n\nFindings:\n${result.findings.map(f => `[${f.severity}] ${f.file}:${f.line}\n  Code: ${f.code}\n  Fix: Replace with ${f.replacement}`).join('\n\n')}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePDF = () => {
    if (!result) return;
    const content = `<html><head><title>QuantumGuard Report</title><style>body{font-family:Arial,sans-serif;padding:40px;color:#333;}h1{color:#534AB7;}.score{font-size:48px;font-weight:bold;color:${getScoreColor(result.quantum_readiness_score)};}.finding{border-left:3px solid #E24B4A;padding:10px 16px;margin:12px 0;background:#f9f9f9;}.critical{border-color:#E24B4A;}.high{border-color:#BA7517;}.medium{border-color:#1D9E75;}code{background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:12px;}</style></head><body><h1>⚛ QuantumGuard Security Report</h1><p>Generated: ${new Date().toLocaleString()}</p><hr/><div class="score">${result.quantum_readiness_score}/100</div><p>Quantum Readiness Score</p><p><strong>Total Vulnerabilities Found: ${result.total_findings}</strong></p><hr/><h2>Findings</h2>${result.findings.map(f => `<div class="finding ${f.severity.toLowerCase()}"><strong>[${f.severity}]</strong> ${f.file}:${f.line}<br/><code>${f.code}</code><br/>Fix: Replace with <strong>${f.replacement}</strong></div>`).join('')}</body></html>`;
    const win = window.open('', '_blank');
    win.document.write(content);
    win.document.close();
    win.print();
  };

  return (
    <div id="scan" style={{ maxWidth: 860, margin: "0 auto", padding: "60px 20px" }}>
      <h2 style={{ fontSize: 28, textAlign: "center", marginBottom: 8 }}>Scan Your Code</h2>
      <p style={{ color: "#888", textAlign: "center", marginBottom: 32, fontSize: 14 }}>Upload a ZIP file or use server path</p>

      <div style={{ display: "flex", gap: 8, marginBottom: 16, justifyContent: "center" }}>
        <button onClick={() => setMode("zip")} style={{ padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer", background: mode === "zip" ? "#534AB7" : "#1a1a2e", color: "#fff", fontSize: 13 }}>Upload ZIP</button>
        <button onClick={() => setMode("path")} style={{ padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer", background: mode === "path" ? "#534AB7" : "#1a1a2e", color: "#fff", fontSize: 13 }}>Server Path</button>
      </div>

      {mode === "zip" ? (
        <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
          <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files[0])} style={{ flex: 1, padding: "12px 16px", borderRadius: 8, border: "1px solid #333", background: "#1a1a2e", color: "#fff", fontSize: 14 }} />
          <button onClick={handleScan} disabled={loading} style={{ padding: "12px 24px", borderRadius: 8, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 14, fontWeight: 500 }}>{loading ? "Scanning..." : "Scan"}</button>
        </div>
      ) : (
        <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
          <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="/app/tests" style={{ flex: 1, padding: "12px 16px", borderRadius: 8, border: "1px solid #333", background: "#1a1a2e", color: "#fff", fontSize: 14 }} />
          <button onClick={handleScan} disabled={loading} style={{ padding: "12px 24px", borderRadius: 8, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 14, fontWeight: 500 }}>{loading ? "Scanning..." : "Scan"}</button>
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
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 8 }}>
              <h3 style={{ color: "#7F77DD", margin: 0 }}>Findings</h3>
              <div style={{ display: "flex", gap: 8 }}>
                <button onClick={handleCopy} style={{ padding: "6px 14px", borderRadius: 6, background: copied ? "#1D9E75" : "#0f0f1a", color: "#fff", border: "1px solid #333", cursor: "pointer", fontSize: 12 }}>{copied ? "Copied!" : "Copy Report"}</button>
                <button onClick={handlePDF} style={{ padding: "6px 14px", borderRadius: 6, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 12 }}>Download PDF</button>
              </div>
            </div>

            <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
              {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map(f => (
                <button key={f} onClick={() => setFilter(f)} style={{ padding: "4px 12px", borderRadius: 20, border: "1px solid #333", background: filter === f ? "#534AB7" : "transparent", color: filter === f ? "#fff" : "#888", cursor: "pointer", fontSize: 12 }}>{f}</button>
              ))}
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search files..." style={{ padding: "4px 12px", borderRadius: 20, border: "1px solid #333", background: "#0f0f1a", color: "#fff", fontSize: 12, width: 150 }} />
            </div>

            <div style={{ fontSize: 12, color: "#888", marginBottom: 12 }}>Showing {filteredFindings.length} of {result.total_findings} findings</div>

            {filteredFindings.map((f, i) => (
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
  );
}

export default function App() {
  return (
    <div style={{ minHeight: "100vh", background: "#0f0f1a", color: "#fff", fontFamily: "sans-serif" }}>
      <Navbar />

      {/* Hero */}
      <div style={{ textAlign: "center", padding: "80px 20px 60px" }}>
        <div style={{ display: "inline-flex", gap: 8, marginBottom: 20 }}>
          <span style={{ background: "#534AB722", border: "1px solid #534AB7", borderRadius: 20, padding: "4px 14px", fontSize: 12, color: "#7F77DD" }}>NIST PQC 2024</span>
          <span style={{ background: "#1D9E7522", border: "1px solid #1D9E75", borderRadius: 20, padding: "4px 14px", fontSize: 12, color: "#1D9E75" }}>Open Source</span>
          <span style={{ background: "#E24B4A22", border: "1px solid #E24B4A", borderRadius: 20, padding: "4px 14px", fontSize: 12, color: "#E24B4A" }}>Free to Use</span>
        </div>
        <h1 style={{ fontSize: 52, fontWeight: 700, lineHeight: 1.2, marginBottom: 20, maxWidth: 700, margin: "0 auto 20px" }}>
          Find Weak Encryption<br />
          <span style={{ color: "#7F77DD" }}>Before Quantum Computers Do</span>
        </h1>
        <p style={{ fontSize: 18, color: "#888", maxWidth: 560, margin: "0 auto 40px", lineHeight: 1.6 }}>
          Scan your codebase for quantum-vulnerable encryption. Get a Quantum Readiness Score and exact migration steps in seconds.
        </p>
        <div style={{ display: "flex", gap: 12, justifyContent: "center" }}>
          <a href="#scan" style={{ background: "#534AB7", color: "#fff", padding: "14px 32px", borderRadius: 10, textDecoration: "none", fontSize: 15, fontWeight: 600 }}>Scan Your Code — Free</a>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ background: "#1a1a2e", color: "#fff", padding: "14px 32px", borderRadius: 10, textDecoration: "none", fontSize: 15, border: "1px solid #333" }}>View on GitHub</a>
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, maxWidth: 800, margin: "0 auto 80px", padding: "0 20px" }}>
        {[{ num: "6+", label: "Algorithms Detected" }, { num: "4", label: "Languages Supported" }, { num: "2030", label: "Quantum Deadline" }, { num: "100%", label: "Open Source" }].map((s, i) => (
          <div key={i} style={{ background: "#1a1a2e", borderRadius: 12, padding: 20, textAlign: "center" }}>
            <div style={{ fontSize: 28, fontWeight: 700, color: "#7F77DD" }}>{s.num}</div>
            <div style={{ color: "#888", fontSize: 12, marginTop: 4 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* How it works - 5 steps */}
      <div id="how" style={{ maxWidth: 700, margin: "0 auto 80px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: 32, marginBottom: 8 }}>How it works</h2>
        <p style={{ textAlign: "center", color: "#888", marginBottom: 48, fontSize: 15 }}>Five simple steps to quantum-proof your code</p>
        <div style={{ position: "relative" }}>
          <div style={{ position: "absolute", left: 20, top: 0, bottom: 0, width: 2, background: "#1a1a2e" }}></div>
          {[
            { step: "1", icon: "📁", title: "Upload Your Code", desc: "Upload a ZIP of your project or paste a directory path. Supports Python, JavaScript, Java and TypeScript." },
            { step: "2", icon: "🔍", title: "Scanner Runs", desc: "Our engine scans every file line by line — detecting RSA, ECC, DH, DSA, MD5 and SHA-1 patterns instantly." },
            { step: "3", icon: "⚠️", title: "Vulnerabilities Found", desc: "Every vulnerable line is flagged with file name, line number, severity level and the exact code snippet." },
            { step: "4", icon: "📊", title: "Review Findings", desc: "Filter by CRITICAL, HIGH or MEDIUM severity. Search specific files. See your Quantum Readiness Score from 0 to 100." },
            { step: "5", icon: "📄", title: "Download Your Report", desc: "Download a PDF report or copy findings to clipboard. Share with your security team or present to your board." },
          ].map((s, i) => (
            <div key={i} style={{ display: "flex", gap: 24, marginBottom: 32, position: "relative" }}>
              <div style={{ width: 42, height: 42, borderRadius: "50%", background: "#534AB7", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, flexShrink: 0, zIndex: 1 }}>
                {s.icon}
              </div>
              <div style={{ background: "#1a1a2e", borderRadius: 16, padding: "20px 24px", flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  <span style={{ background: "#534AB722", color: "#7F77DD", padding: "2px 10px", borderRadius: 20, fontSize: 12, fontWeight: 600 }}>Step {s.step}</span>
                  <span style={{ fontSize: 15, fontWeight: 600 }}>{s.title}</span>
                </div>
                <div style={{ fontSize: 13, color: "#888", lineHeight: 1.6 }}>{s.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* What We Detect */}
      <div style={{ maxWidth: 900, margin: "0 auto 80px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: 32, marginBottom: 8 }}>What We Detect</h2>
        <p style={{ textAlign: "center", color: "#888", marginBottom: 40, fontSize: 15 }}>All algorithms flagged by NIST as quantum-vulnerable</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
          {[
            { name: "RSA", severity: "CRITICAL", fix: "CRYSTALS-Kyber" },
            { name: "ECC / ECDSA", severity: "CRITICAL", fix: "CRYSTALS-Dilithium" },
            { name: "Diffie-Hellman", severity: "HIGH", fix: "CRYSTALS-Kyber" },
            { name: "DSA", severity: "HIGH", fix: "CRYSTALS-Dilithium" },
            { name: "MD5", severity: "MEDIUM", fix: "SHA-3 / SPHINCS+" },
            { name: "SHA-1", severity: "MEDIUM", fix: "SHA-3 / SPHINCS+" },
          ].map((v, i) => (
            <div key={i} style={{ background: "#1a1a2e", borderRadius: 12, padding: 16, borderLeft: `3px solid ${v.severity === "CRITICAL" ? "#E24B4A" : v.severity === "HIGH" ? "#BA7517" : "#1D9E75"}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <span style={{ fontWeight: 600, fontSize: 15 }}>{v.name}</span>
                <span style={{ fontSize: 11, padding: "2px 8px", borderRadius: 4, background: v.severity === "CRITICAL" ? "#E24B4A22" : v.severity === "HIGH" ? "#BA751722" : "#1D9E7522", color: v.severity === "CRITICAL" ? "#E24B4A" : v.severity === "HIGH" ? "#BA7517" : "#1D9E75" }}>{v.severity}</span>
              </div>
              <div style={{ fontSize: 12, color: "#888" }}>Fix: <span style={{ color: "#7F77DD" }}>{v.fix}</span></div>
            </div>
          ))}
        </div>
      </div>

      {/* Pricing */}
      <div id="pricing" style={{ maxWidth: 900, margin: "0 auto 80px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: 32, marginBottom: 8 }}>Pricing</h2>
        <p style={{ textAlign: "center", color: "#888", marginBottom: 40, fontSize: 15 }}>Start free, upgrade when you need more</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16 }}>
          {[
            { name: "Free", price: "$0", desc: "For developers", features: ["CLI tool", "Basic scan", "JSON report", "GitHub open source"], cta: "Get Started", highlight: false },
            { name: "Pro", price: "$299/mo", desc: "For security teams", features: ["Web dashboard", "AI reports", "ZIP upload", "PDF export", "Email support"], cta: "Coming Soon", highlight: true },
            { name: "Enterprise", price: "Custom", desc: "For large companies", features: ["Everything in Pro", "CI/CD integration", "Custom reports", "Dedicated support", "Compliance exports"], cta: "Contact Us", highlight: false },
          ].map((p, i) => (
            <div key={i} style={{ background: "#1a1a2e", borderRadius: 16, padding: 28, border: p.highlight ? "2px solid #534AB7" : "1px solid #222", position: "relative" }}>
              {p.highlight && <div style={{ position: "absolute", top: -12, left: "50%", transform: "translateX(-50%)", background: "#534AB7", color: "#fff", padding: "3px 16px", borderRadius: 20, fontSize: 11, fontWeight: 600, whiteSpace: "nowrap" }}>Most Popular</div>}
              <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>{p.name}</div>
              <div style={{ fontSize: 28, fontWeight: 700, color: "#7F77DD", marginBottom: 4 }}>{p.price}</div>
              <div style={{ fontSize: 13, color: "#888", marginBottom: 20 }}>{p.desc}</div>
              {p.features.map((f, j) => <div key={j} style={{ fontSize: 13, color: "#ccc", marginBottom: 8 }}>✓ {f}</div>)}
              <button style={{ width: "100%", marginTop: 20, padding: "10px", borderRadius: 8, background: p.highlight ? "#534AB7" : "transparent", color: "#fff", border: p.highlight ? "none" : "1px solid #534AB7", cursor: "pointer", fontSize: 14, fontWeight: 500 }}>{p.cta}</button>
            </div>
          ))}
        </div>
      </div>

      {/* FAQ */}
      <div style={{ maxWidth: 700, margin: "0 auto 80px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: 32, marginBottom: 40 }}>FAQ</h2>
        {[
          { q: "Is my code safe when I upload it?", a: "Yes. Your code is scanned in memory and immediately deleted after scanning. We never store your code." },
          { q: "What languages are supported?", a: "Python, JavaScript, Java and TypeScript. More languages coming soon." },
          { q: "What is the Quantum Readiness Score?", a: "A score from 0-100. Every CRITICAL finding reduces score by 10, HIGH by 6, MEDIUM by 3. Higher is better." },
          { q: "Is QuantumGuard free?", a: "The CLI tool and basic web scan are completely free. Pro features like AI reports are coming soon." },
        ].map((f, i) => (
          <div key={i} style={{ background: "#1a1a2e", borderRadius: 12, padding: 20, marginBottom: 12 }}>
            <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 15 }}>{f.q}</div>
            <div style={{ color: "#888", fontSize: 14, lineHeight: 1.6 }}>{f.a}</div>
          </div>
        ))}
      </div>

      {/* CTA */}
      <div style={{ textAlign: "center", padding: "60px 20px", background: "#1a1a2e" }}>
        <h2 style={{ fontSize: 32, marginBottom: 16 }}>Ready to quantum-proof your code?</h2>
        <p style={{ color: "#888", marginBottom: 32, fontSize: 15 }}>Join developers and security teams protecting their code from quantum threats.</p>
        <a href="#scan" style={{ background: "#534AB7", color: "#fff", padding: "14px 40px", borderRadius: 10, textDecoration: "none", fontSize: 15, fontWeight: 600 }}>Start Free Scan</a>
      </div>

      <Scanner />

      {/* Footer */}
      <div style={{ textAlign: "center", padding: "24px 20px", borderTop: "1px solid #1a1a2e", color: "#555", fontSize: 13 }}>
        <div style={{ marginBottom: 8 }}>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ color: "#555", textDecoration: "none", marginRight: 20 }}>GitHub</a>
          <a href="#how" style={{ color: "#555", textDecoration: "none", marginRight: 20 }}>How it works</a>
          <a href="#pricing" style={{ color: "#555", textDecoration: "none" }}>Pricing</a>
        </div>
        QuantumGuard by MANGSRI — Open Source Quantum Security Scanner — 2026
      </div>
    </div>
  );
}