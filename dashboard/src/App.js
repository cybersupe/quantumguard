import { useState } from "react";

const API = "https://web-production-16177f.up.railway.app";

function Navbar({ darkMode, setDarkMode }) {
  const bg = darkMode ? "#0f0f1a" : "#ffffff";
  const muted = darkMode ? "#888" : "#666";
  const border = darkMode ? "#1a1a2e" : "#e5e5e5";
  return (
    <nav style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 40px", borderBottom: `1px solid ${border}`, position: "sticky", top: 0, background: bg, zIndex: 100 }}>
      <div style={{ fontSize: 20, fontWeight: 700, color: "#7F77DD" }}>⚛ QuantumGuard</div>
      <div style={{ display: "flex", gap: 24, alignItems: "center" }}>
        <a href="#features" style={{ color: muted, textDecoration: "none", fontSize: 14 }}>Features</a>
        <a href="#how" style={{ color: muted, textDecoration: "none", fontSize: 14 }}>How it works</a>
        <a href="#pricing" style={{ color: muted, textDecoration: "none", fontSize: 14 }}>Pricing</a>
        <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ color: muted, textDecoration: "none", fontSize: 14 }}>GitHub</a>
        <button onClick={() => setDarkMode(!darkMode)} style={{ background: "transparent", border: `1px solid ${border}`, borderRadius: 8, padding: "6px 12px", cursor: "pointer", color: muted, fontSize: 13 }}>
          {darkMode ? "☀️" : "🌙"}
        </button>
        <a href="#scan" style={{ background: "#534AB7", color: "#fff", padding: "8px 20px", borderRadius: 8, textDecoration: "none", fontSize: 14, fontWeight: 500 }}>Start Free Scan</a>
      </div>
    </nav>
  );
}

function Scanner({ darkMode }) {
  const [mode, setMode] = useState("zip");
  const [input, setInput] = useState("");
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [copied, setCopied] = useState(false);
  const [checklist, setChecklist] = useState({});

  const bg = darkMode ? "#0f0f1a" : "#f5f5f5";
  const card = darkMode ? "#1a1a2e" : "#ffffff";
  const text = darkMode ? "#ffffff" : "#111111";
  const muted = darkMode ? "#888" : "#666";
  const border = darkMode ? "#333" : "#e5e5e5";

  const handleScan = async () => {
    setLoading(true);
    setProgress(0);
    setError(null);
    setResult(null);
    setChecklist({});
    const interval = setInterval(() => setProgress(p => p < 90 ? p + 10 : p), 300);
    try {
      let res;
      if (mode === "zip") {
        if (!file) throw new Error("Please select a ZIP file");
        const formData = new FormData();
        formData.append("file", file);
        res = await fetch(`${API}/public-scan-zip`, { method: "POST", body: formData });
      } else {
        if (!input) throw new Error("Please enter a path");
        res = await fetch(`${API}/scan`, { method: "POST", headers: { "Content-Type": "application/json", "x-api-key": "quantumguard-secret-2026" }, body: JSON.stringify({ directory: input }) });
      }
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Scan failed");
      setProgress(100);
      setResult(data);
    } catch (e) { setError(e.message); }
    clearInterval(interval);
    setLoading(false);
  };

  const getScoreColor = (s) => s >= 70 ? "#1D9E75" : s >= 40 ? "#BA7517" : "#E24B4A";
  const filteredFindings = result ? result.findings.filter(f => (filter === "ALL" || f.severity === filter) && (search === "" || f.file.toLowerCase().includes(search.toLowerCase()))) : [];
  const severityCounts = result ? { CRITICAL: result.findings.filter(f => f.severity === "CRITICAL").length, HIGH: result.findings.filter(f => f.severity === "HIGH").length, MEDIUM: result.findings.filter(f => f.severity === "MEDIUM").length } : null;
  const fileBreakdown = result ? result.findings.reduce((acc, f) => { const n = f.file.split('/').pop(); acc[n] = (acc[n] || 0) + 1; return acc; }, {}) : null;
  const detectedLanguages = result ? [...new Set(result.findings.map(f => ({ py: 'Python', js: 'JavaScript', java: 'Java', ts: 'TypeScript' })[f.file.split('.').pop()] || f.file.split('.').pop()))] : [];

  const handleCopy = () => {
    if (!result) return;
    navigator.clipboard.writeText(`QuantumGuard Scan Report\nScore: ${result.quantum_readiness_score}/100\nVulnerabilities: ${result.total_findings}\n\n${result.findings.map(f => `[${f.severity}] ${f.file}:${f.line}\n${f.code}\nFix: ${f.replacement}`).join('\n\n')}`);
    setCopied(true); setTimeout(() => setCopied(false), 2000);
  };

  const handlePDF = () => {
    if (!result) return;
    const win = window.open('', '_blank');
    win.document.write(`<html><head><title>QuantumGuard Report</title><style>body{font-family:Arial,sans-serif;padding:40px;color:#333;}h1{color:#534AB7;}.score{font-size:48px;font-weight:bold;color:${getScoreColor(result.quantum_readiness_score)};}.finding{border-left:3px solid #E24B4A;padding:10px 16px;margin:12px 0;background:#f9f9f9;}code{background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:12px;}</style></head><body><h1>⚛ QuantumGuard Security Report</h1><p>Generated: ${new Date().toLocaleString()}</p><hr/><div class="score">${result.quantum_readiness_score}/100</div><p>Quantum Readiness Score</p><p><strong>Total Vulnerabilities: ${result.total_findings}</strong></p><hr/><h2>Findings</h2>${result.findings.map(f => `<div class="finding"><strong>[${f.severity}]</strong> ${f.file}:${f.line}<br/><code>${f.code}</code><br/>Fix: <strong>${f.replacement}</strong></div>`).join('')}</body></html>`);
    win.document.close(); win.print();
  };

  const handleShare = () => {
    if (!result) return;
    window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(`I scanned my codebase with QuantumGuard!\n\nQuantum Readiness Score: ${result.quantum_readiness_score}/100\nVulnerabilities: ${result.total_findings}\n\nquantumguard-one.vercel.app\n\n#QuantumSecurity #CyberSecurity`)}`, '_blank');
  };

  return (
    <div id="scan" style={{ maxWidth: 860, margin: "0 auto", padding: "60px 20px", background: bg }}>
      <h2 style={{ fontSize: 28, textAlign: "center", marginBottom: 8, color: text }}>Scan Your Code</h2>
      <p style={{ color: muted, textAlign: "center", marginBottom: 32, fontSize: 14 }}>Upload a ZIP — free, instant, secure. No signup required.</p>

      <div style={{ display: "flex", gap: 8, marginBottom: 16, justifyContent: "center" }}>
        <button onClick={() => setMode("zip")} style={{ padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer", background: mode === "zip" ? "#534AB7" : card, color: mode === "zip" ? "#fff" : muted, fontSize: 13 }}>Upload ZIP</button>
        <button onClick={() => setMode("path")} style={{ padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer", background: mode === "path" ? "#534AB7" : card, color: mode === "path" ? "#fff" : muted, fontSize: 13 }}>Server Path</button>
      </div>

      {mode === "zip" ? (
        <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
          <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files[0])} style={{ flex: 1, padding: "12px 16px", borderRadius: 8, border: `1px solid ${border}`, background: card, color: text, fontSize: 14 }} />
          <button onClick={handleScan} disabled={loading} style={{ padding: "12px 24px", borderRadius: 8, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 14, fontWeight: 500 }}>{loading ? "Scanning..." : "Scan"}</button>
        </div>
      ) : (
        <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
          <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="/app/tests" style={{ flex: 1, padding: "12px 16px", borderRadius: 8, border: `1px solid ${border}`, background: card, color: text, fontSize: 14 }} />
          <button onClick={handleScan} disabled={loading} style={{ padding: "12px 24px", borderRadius: 8, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 14, fontWeight: 500 }}>{loading ? "Scanning..." : "Scan"}</button>
        </div>
      )}

      {loading && (
        <div style={{ marginBottom: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, color: muted, marginBottom: 6 }}>
            <span>Scanning your code...</span><span>{progress}%</span>
          </div>
          <div style={{ background: border, borderRadius: 4, height: 6 }}>
            <div style={{ background: "#534AB7", height: 6, borderRadius: 4, width: `${progress}%`, transition: "width 0.3s" }}></div>
          </div>
        </div>
      )}

      {error && <div style={{ background: "#E24B4A22", border: "1px solid #E24B4A", borderRadius: 8, padding: 16, marginBottom: 24, color: "#E24B4A" }}>{error}</div>}

      {result && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
            <div style={{ background: card, borderRadius: 12, padding: 24, textAlign: "center", border: `1px solid ${border}` }}>
              <div style={{ fontSize: 48, fontWeight: 700, color: getScoreColor(result.quantum_readiness_score) }}>{result.quantum_readiness_score}</div>
              <div style={{ color: muted, fontSize: 14 }}>Quantum Readiness Score</div>
            </div>
            <div style={{ background: card, borderRadius: 12, padding: 24, textAlign: "center", border: `1px solid ${border}` }}>
              <div style={{ fontSize: 48, fontWeight: 700, color: "#E24B4A" }}>{result.total_findings}</div>
              <div style={{ color: muted, fontSize: 14 }}>Vulnerabilities Found</div>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 8, marginBottom: 16 }}>
            {[{ key: "CRITICAL", color: "#E24B4A" }, { key: "HIGH", color: "#BA7517" }, { key: "MEDIUM", color: "#1D9E75" }].map(s => (
              <div key={s.key} style={{ background: card, borderRadius: 8, padding: "12px 16px", textAlign: "center", border: `1px solid ${border}` }}>
                <div style={{ fontSize: 24, fontWeight: 700, color: s.color }}>{severityCounts[s.key]}</div>
                <div style={{ fontSize: 11, color: muted }}>{s.key}</div>
              </div>
            ))}
          </div>

          {detectedLanguages.length > 0 && (
            <div style={{ background: card, borderRadius: 8, padding: "12px 16px", marginBottom: 16, border: `1px solid ${border}` }}>
              <span style={{ fontSize: 13, color: muted, marginRight: 8 }}>Languages:</span>
              {detectedLanguages.map((l, i) => <span key={i} style={{ background: "#534AB722", color: "#7F77DD", padding: "2px 10px", borderRadius: 20, fontSize: 12, marginRight: 6 }}>{l}</span>)}
            </div>
          )}

          {fileBreakdown && (
            <div style={{ background: card, borderRadius: 8, padding: 16, marginBottom: 16, border: `1px solid ${border}` }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: text, marginBottom: 10 }}>File Breakdown</div>
              {Object.entries(fileBreakdown).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([file, count], i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                  <span style={{ fontSize: 12, color: muted, fontFamily: "monospace" }}>{file}</span>
                  <span style={{ fontSize: 12, background: "#E24B4A22", color: "#E24B4A", padding: "2px 8px", borderRadius: 20 }}>{count} issues</span>
                </div>
              ))}
            </div>
          )}

          <div style={{ background: card, borderRadius: 12, padding: 24, border: `1px solid ${border}` }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 8 }}>
              <h3 style={{ color: "#7F77DD", margin: 0 }}>Findings</h3>
              <div style={{ display: "flex", gap: 8 }}>
                <button onClick={handleCopy} style={{ padding: "6px 14px", borderRadius: 6, background: copied ? "#1D9E75" : "transparent", color: copied ? "#fff" : muted, border: `1px solid ${border}`, cursor: "pointer", fontSize: 12 }}>{copied ? "Copied!" : "Copy"}</button>
                <button onClick={handlePDF} style={{ padding: "6px 14px", borderRadius: 6, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 12 }}>PDF</button>
                <button onClick={handleShare} style={{ padding: "6px 14px", borderRadius: 6, background: "#1DA1F2", color: "#fff", border: "none", cursor: "pointer", fontSize: 12 }}>Share</button>
              </div>
            </div>

            <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
              {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map(f => (
                <button key={f} onClick={() => setFilter(f)} style={{ padding: "4px 12px", borderRadius: 20, border: `1px solid ${border}`, background: filter === f ? "#534AB7" : "transparent", color: filter === f ? "#fff" : muted, cursor: "pointer", fontSize: 12 }}>
                  {f} {f !== "ALL" && severityCounts ? `(${severityCounts[f]})` : ""}
                </button>
              ))}
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search..." style={{ padding: "4px 12px", borderRadius: 20, border: `1px solid ${border}`, background: bg, color: text, fontSize: 12, width: 120 }} />
            </div>

            <div style={{ fontSize: 12, color: muted, marginBottom: 12 }}>Showing {filteredFindings.length} of {result.total_findings} findings</div>

            {filteredFindings.map((f, i) => {
              const key = `${f.file}:${f.line}`;
              return (
                <div key={i} style={{ borderLeft: `3px solid ${f.severity === "CRITICAL" ? "#E24B4A" : f.severity === "HIGH" ? "#BA7517" : "#1D9E75"}`, paddingLeft: 16, marginBottom: 16, opacity: checklist[key] ? 0.5 : 1 }}>
                  <div style={{ display: "flex", gap: 8, marginBottom: 4, alignItems: "center" }}>
                    <input type="checkbox" checked={!!checklist[key]} onChange={() => setChecklist(p => ({ ...p, [key]: !p[key] }))} style={{ cursor: "pointer" }} />
                    <span style={{ background: f.severity === "CRITICAL" ? "#E24B4A22" : f.severity === "HIGH" ? "#BA751722" : "#1D9E7522", color: f.severity === "CRITICAL" ? "#E24B4A" : f.severity === "HIGH" ? "#BA7517" : "#1D9E75", padding: "2px 8px", borderRadius: 4, fontSize: 12 }}>{f.severity}</span>
                    <span style={{ color: muted, fontSize: 12 }}>{f.file}:{f.line}</span>
                    {checklist[key] && <span style={{ fontSize: 11, color: "#1D9E75" }}>✓ Fixed</span>}
                  </div>
                  <div style={{ fontFamily: "monospace", background: bg, padding: "8px 12px", borderRadius: 6, fontSize: 13, marginBottom: 4, color: text }}>{f.code}</div>
                  <div style={{ fontSize: 12, color: muted }}>Fix: Replace with <span style={{ color: "#7F77DD" }}>{f.replacement}</span></div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [darkMode, setDarkMode] = useState(true);
  const bg = darkMode ? "#0f0f1a" : "#f5f5f5";
  const card = darkMode ? "#1a1a2e" : "#ffffff";
  const text = darkMode ? "#ffffff" : "#111111";
  const muted = darkMode ? "#888" : "#666";
  const border = darkMode ? "#222" : "#e5e5e5";

  return (
    <div style={{ minHeight: "100vh", background: bg, color: text, fontFamily: "sans-serif" }}>
      <Navbar darkMode={darkMode} setDarkMode={setDarkMode} />

      {/* Hero */}
      <div style={{ textAlign: "center", padding: "100px 20px 60px" }}>
        <div style={{ display: "inline-flex", gap: 8, marginBottom: 24 }}>
          <span style={{ background: "#534AB722", border: "1px solid #534AB7", borderRadius: 20, padding: "4px 14px", fontSize: 12, color: "#7F77DD" }}>NIST PQC 2024</span>
          <span style={{ background: "#1D9E7522", border: "1px solid #1D9E75", borderRadius: 20, padding: "4px 14px", fontSize: 12, color: "#1D9E75" }}>Open Source</span>
          <span style={{ background: "#E24B4A22", border: "1px solid #E24B4A", borderRadius: 20, padding: "4px 14px", fontSize: 12, color: "#E24B4A" }}>Free Forever</span>
        </div>
        <h1 style={{ fontSize: 56, fontWeight: 700, lineHeight: 1.15, marginBottom: 24, maxWidth: 800, margin: "0 auto 24px", color: text }}>
          Find Weak Encryption<br />
          <span style={{ color: "#7F77DD" }}>Before Quantum Computers Do</span>
        </h1>
        <p style={{ fontSize: 19, color: muted, maxWidth: 600, margin: "0 auto 48px", lineHeight: 1.7 }}>
          QuantumGuard scans your codebase and finds every encryption algorithm that quantum computers will break. Get a clear migration plan aligned with NIST 2024 standards.
        </p>
        <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
          <a href="#scan" style={{ background: "#534AB7", color: "#fff", padding: "16px 36px", borderRadius: 10, textDecoration: "none", fontSize: 16, fontWeight: 600 }}>Start Free Scan →</a>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ background: card, color: text, padding: "16px 36px", borderRadius: 10, textDecoration: "none", fontSize: 16, border: `1px solid ${border}` }}>View on GitHub</a>
        </div>
        <p style={{ color: muted, fontSize: 13, marginTop: 16 }}>No signup. No credit card. Upload ZIP and scan instantly.</p>
      </div>

      {/* Stats */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16, maxWidth: 860, margin: "0 auto 100px", padding: "0 20px" }}>
        {[{ num: "11+", label: "Vulnerabilities Detected" }, { num: "4", label: "Languages Supported" }, { num: "2030", label: "Quantum Deadline" }, { num: "100%", label: "Free & Open Source" }].map((s, i) => (
          <div key={i} style={{ background: card, borderRadius: 12, padding: 24, textAlign: "center", border: `1px solid ${border}` }}>
            <div style={{ fontSize: 32, fontWeight: 700, color: "#7F77DD" }}>{s.num}</div>
            <div style={{ color: muted, fontSize: 13, marginTop: 6 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Features */}
      <div id="features" style={{ maxWidth: 900, margin: "0 auto 100px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: 36, marginBottom: 8, color: text }}>Everything you need</h2>
        <p style={{ textAlign: "center", color: muted, marginBottom: 48, fontSize: 16 }}>Built for developers and security teams who need to act now</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 20 }}>
          {[
            { icon: "🔍", title: "Deep scanning", desc: "Scans every file line by line across Python, JS, Java, TypeScript codebases" },
            { icon: "📊", title: "Readiness score", desc: "Get a clear 0-100 Quantum Readiness Score with severity breakdown" },
            { icon: "🛡️", title: "11+ vulnerabilities", desc: "Detects RSA, ECC, DH, DSA, MD5, SHA-1, RC4, DES, ECB mode, weak TLS, hardcoded secrets" },
            { icon: "📄", title: "PDF reports", desc: "Download professional PDF reports to share with your team or board" },
            { icon: "🎯", title: "NIST approved fixes", desc: "Every finding comes with a CRYSTALS-Kyber or Dilithium migration recommendation" },
            { icon: "⚡", title: "Instant results", desc: "Upload ZIP and get results in seconds. No waiting, no queues" },
          ].map((f, i) => (
            <div key={i} style={{ background: card, borderRadius: 16, padding: 28, border: `1px solid ${border}` }}>
              <div style={{ fontSize: 28, marginBottom: 12 }}>{f.icon}</div>
              <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 8, color: text }}>{f.title}</div>
              <div style={{ fontSize: 13, color: muted, lineHeight: 1.6 }}>{f.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* How it works */}
      <div id="how" style={{ maxWidth: 700, margin: "0 auto 100px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: 36, marginBottom: 8, color: text }}>How it works</h2>
        <p style={{ textAlign: "center", color: muted, marginBottom: 48, fontSize: 16 }}>Five steps to quantum-proof your codebase</p>
        <div style={{ position: "relative" }}>
          <div style={{ position: "absolute", left: 20, top: 0, bottom: 0, width: 2, background: border }}></div>
          {[
            { icon: "📁", title: "Upload your code", desc: "ZIP your project and upload. Supports Python, JavaScript, Java and TypeScript." },
            { icon: "🔍", title: "Scanner runs", desc: "Line-by-line analysis detects RSA, ECC, DH, DSA, MD5, SHA-1, RC4, DES, ECB, weak TLS, hardcoded secrets." },
            { icon: "⚠️", title: "Vulnerabilities flagged", desc: "Every issue shown with exact file, line number, severity and vulnerable code." },
            { icon: "📊", title: "Review findings", desc: "Filter by severity, search files, see Quantum Readiness Score 0-100." },
            { icon: "📄", title: "Get your report", desc: "Download PDF, copy to clipboard, or share. Present to your board." },
          ].map((s, i) => (
            <div key={i} style={{ display: "flex", gap: 24, marginBottom: 32 }}>
              <div style={{ width: 42, height: 42, borderRadius: "50%", background: "#534AB7", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, flexShrink: 0, zIndex: 1 }}>{s.icon}</div>
              <div style={{ background: card, borderRadius: 16, padding: "20px 24px", flex: 1, border: `1px solid ${border}` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  <span style={{ background: "#534AB722", color: "#7F77DD", padding: "2px 10px", borderRadius: 20, fontSize: 12, fontWeight: 600 }}>Step {i + 1}</span>
                  <span style={{ fontSize: 15, fontWeight: 600, color: text }}>{s.title}</span>
                </div>
                <div style={{ fontSize: 13, color: muted, lineHeight: 1.6 }}>{s.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* What we detect */}
      <div style={{ maxWidth: 900, margin: "0 auto 100px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: 36, marginBottom: 8, color: text }}>What we detect</h2>
        <p style={{ textAlign: "center", color: muted, marginBottom: 48, fontSize: 16 }}>11+ vulnerability types across all major encryption algorithms</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12 }}>
          {[
            { name: "RSA", severity: "CRITICAL", fix: "CRYSTALS-Kyber" },
            { name: "ECC / ECDSA", severity: "CRITICAL", fix: "CRYSTALS-Dilithium" },
            { name: "RC4", severity: "CRITICAL", fix: "AES-256-GCM" },
            { name: "DES / 3DES", severity: "CRITICAL", fix: "AES-256-GCM" },
            { name: "Diffie-Hellman", severity: "HIGH", fix: "CRYSTALS-Kyber" },
            { name: "DSA", severity: "HIGH", fix: "CRYSTALS-Dilithium" },
            { name: "ECB Mode", severity: "HIGH", fix: "AES-GCM" },
            { name: "Weak TLS", severity: "HIGH", fix: "TLS 1.3" },
            { name: "Hardcoded Secrets", severity: "HIGH", fix: "Secret Manager" },
            { name: "MD5", severity: "MEDIUM", fix: "SHA-3 / SPHINCS+" },
            { name: "SHA-1", severity: "MEDIUM", fix: "SHA-3 / SPHINCS+" },
          ].map((v, i) => (
            <div key={i} style={{ background: card, borderRadius: 12, padding: 16, borderLeft: `3px solid ${v.severity === "CRITICAL" ? "#E24B4A" : v.severity === "HIGH" ? "#BA7517" : "#1D9E75"}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <span style={{ fontWeight: 600, fontSize: 14, color: text }}>{v.name}</span>
                <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 4, background: v.severity === "CRITICAL" ? "#E24B4A22" : v.severity === "HIGH" ? "#BA751722" : "#1D9E7522", color: v.severity === "CRITICAL" ? "#E24B4A" : v.severity === "HIGH" ? "#BA7517" : "#1D9E75" }}>{v.severity}</span>
              </div>
              <div style={{ fontSize: 11, color: muted }}>→ <span style={{ color: "#7F77DD" }}>{v.fix}</span></div>
            </div>
          ))}
        </div>
      </div>

      {/* Pricing */}
      <div id="pricing" style={{ maxWidth: 900, margin: "0 auto 100px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: 36, marginBottom: 8, color: text }}>Simple pricing</h2>
        <p style={{ textAlign: "center", color: muted, marginBottom: 48, fontSize: 16 }}>Start free. Upgrade when you're ready.</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 20 }}>
          {[
            { name: "Free", price: "$0", period: "forever", desc: "For individual developers", features: ["CLI tool", "Web dashboard", "ZIP upload", "PDF reports", "Basic scan up to 10MB", "GitHub open source"], cta: "Start Free", highlight: false },
            { name: "Pro", price: "$299", period: "/month", desc: "For security teams", features: ["Everything in Free", "AI-powered reports", "Unlimited file size", "Priority support", "Scan history", "API access"], cta: "Coming Soon", highlight: true },
            { name: "Enterprise", price: "Custom", period: "", desc: "For large organizations", features: ["Everything in Pro", "CI/CD integration", "SSO login", "Custom reports", "Dedicated support", "SOC2 compliance exports"], cta: "Contact Us", highlight: false },
          ].map((p, i) => (
            <div key={i} style={{ background: card, borderRadius: 20, padding: 32, border: p.highlight ? "2px solid #534AB7" : `1px solid ${border}`, position: "relative" }}>
              {p.highlight && <div style={{ position: "absolute", top: -14, left: "50%", transform: "translateX(-50%)", background: "#534AB7", color: "#fff", padding: "4px 20px", borderRadius: 20, fontSize: 12, fontWeight: 600, whiteSpace: "nowrap" }}>Most Popular</div>}
              <div style={{ fontSize: 18, fontWeight: 600, marginBottom: 4, color: text }}>{p.name}</div>
              <div style={{ display: "flex", alignItems: "baseline", gap: 4, marginBottom: 4 }}>
                <span style={{ fontSize: 36, fontWeight: 700, color: "#7F77DD" }}>{p.price}</span>
                <span style={{ fontSize: 14, color: muted }}>{p.period}</span>
              </div>
              <div style={{ fontSize: 13, color: muted, marginBottom: 24, paddingBottom: 24, borderBottom: `1px solid ${border}` }}>{p.desc}</div>
              {p.features.map((f, j) => (
                <div key={j} style={{ display: "flex", gap: 8, alignItems: "flex-start", marginBottom: 10 }}>
                  <span style={{ color: "#1D9E75", fontSize: 14 }}>✓</span>
                  <span style={{ fontSize: 13, color: muted }}>{f}</span>
                </div>
              ))}
              <button style={{ width: "100%", marginTop: 24, padding: "12px", borderRadius: 10, background: p.highlight ? "#534AB7" : "transparent", color: p.highlight ? "#fff" : "#534AB7", border: `1px solid #534AB7`, cursor: "pointer", fontSize: 14, fontWeight: 600 }}>{p.cta}</button>
            </div>
          ))}
        </div>
      </div>

      {/* FAQ */}
      <div style={{ maxWidth: 700, margin: "0 auto 100px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: 36, marginBottom: 48, color: text }}>FAQ</h2>
        {[
          { q: "Is my code safe when I upload it?", a: "Yes. Your code is scanned in memory and immediately deleted after scanning. We never store, log, or share your code." },
          { q: "What languages are supported?", a: "Python, JavaScript, Java and TypeScript. Go, Rust and C++ coming soon." },
          { q: "What is the Quantum Readiness Score?", a: "A score from 0-100. CRITICAL findings reduce score by 10, HIGH by 6, MEDIUM by 3. Score 80+ is good, below 40 needs immediate attention." },
          { q: "Why should I care about quantum computers now?", a: "NIST finalized post-quantum standards in 2024. Migration takes years. Start now to be ready when quantum computers arrive around 2030." },
          { q: "Is QuantumGuard really free?", a: "Yes! CLI tool and web scanner are completely free and open source forever. Pro features coming soon for teams." },
        ].map((f, i) => (
          <div key={i} style={{ background: card, borderRadius: 12, padding: 24, marginBottom: 12, border: `1px solid ${border}` }}>
            <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 15, color: text }}>{f.q}</div>
            <div style={{ color: muted, fontSize: 14, lineHeight: 1.7 }}>{f.a}</div>
          </div>
        ))}
      </div>

      {/* CTA */}
      <div style={{ textAlign: "center", padding: "80px 20px", background: card, borderTop: `1px solid ${border}`, borderBottom: `1px solid ${border}` }}>
        <h2 style={{ fontSize: 40, marginBottom: 16, color: text }}>Ready to quantum-proof your code?</h2>
        <p style={{ color: muted, marginBottom: 40, fontSize: 16, maxWidth: 500, margin: "0 auto 40px" }}>Join developers and security teams protecting their code from the quantum threat.</p>
        <div style={{ display: "flex", gap: 12, justifyContent: "center" }}>
          <a href="#scan" style={{ background: "#534AB7", color: "#fff", padding: "16px 40px", borderRadius: 10, textDecoration: "none", fontSize: 16, fontWeight: 600 }}>Start Free Scan →</a>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ background: "transparent", color: text, padding: "16px 40px", borderRadius: 10, textDecoration: "none", fontSize: 16, border: `1px solid ${border}` }}>GitHub</a>
        </div>
      </div>

      <Scanner darkMode={darkMode} />

      {/* Footer */}
      <div style={{ textAlign: "center", padding: "32px 20px", borderTop: `1px solid ${border}`, color: muted, fontSize: 13 }}>
        <div style={{ marginBottom: 12 }}>
          <a href="#features" style={{ color: muted, textDecoration: "none", marginRight: 24 }}>Features</a>
          <a href="#how" style={{ color: muted, textDecoration: "none", marginRight: 24 }}>How it works</a>
          <a href="#pricing" style={{ color: muted, textDecoration: "none", marginRight: 24 }}>Pricing</a>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ color: muted, textDecoration: "none" }}>GitHub</a>
        </div>
        <div>QuantumGuard by MANGSRI — Open Source Quantum Security Scanner — 2026</div>
      </div>
    </div>
  );
}