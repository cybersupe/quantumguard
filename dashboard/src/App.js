import { useState, useEffect, useRef } from "react";
import "./App.css";
import emailjs from "@emailjs/browser";
import { auth, db, signInWithGoogle, logOut, canUserScan, incrementScanCount, getUserProfile } from "./firebase";
import { onAuthStateChanged, signOut } from "firebase/auth";
import { collection, addDoc, getDocs, query, where, orderBy } from "firebase/firestore";

const API = "https://web-production-16177f.up.railway.app";

const COLORS = {
  bg: "#0a0a0f",
  sidebar: "#0d0d1a",
  card: "#111127",
  cardBorder: "#1e1e3a",
  purple: "#6C63FF",
  purpleLight: "#8B85FF",
  red: "#FF3B3B",
  green: "#00D4AA",
  amber: "#FFB800",
  text: "#E8E8F0",
  muted: "#6B6B8A",
  white: "#FFFFFF",
};

const SCAN_STEPS = [
  "Initializing scan engine...",
  "Connecting to target...",
  "Analyzing file structure...",
  "Running vulnerability checks...",
  "Calculating risk score...",
  "Generating threat report...",
];

function Sidebar({ active, setActive, user, onLogin, onLogout, darkMode, setDarkMode }) {
  const navItems = [
    { id: "scan", icon: "⚡", label: "Scanner" },
    { id: "history", icon: "📋", label: "Scan History" },
    { id: "migration", icon: "🔄", label: "Migration" },
    { id: "dashboard", icon: "📊", label: "Analytics" },
    { id: "docs", icon: "📖", label: "Docs" },
  ];
  return (
    <div style={{ width: 220, minHeight: "100vh", background: COLORS.sidebar, borderRight: `1px solid ${COLORS.cardBorder}`, display: "flex", flexDirection: "column", position: "fixed", left: 0, top: 0, zIndex: 100 }}>
      <div style={{ padding: "24px 20px", borderBottom: `1px solid ${COLORS.cardBorder}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: COLORS.purple, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>⚛</div>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: COLORS.white }}>QuantumGuard</div>
            <div style={{ fontSize: 10, color: COLORS.muted }}>Security Platform</div>
          </div>
        </div>
      </div>
      <nav style={{ flex: 1, padding: "16px 12px" }}>
        {navItems.map(item => (
          <div key={item.id} onClick={() => setActive(item.id)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", borderRadius: 8, marginBottom: 4, cursor: "pointer", background: active === item.id ? `${COLORS.purple}22` : "transparent", border: active === item.id ? `1px solid ${COLORS.purple}44` : "1px solid transparent" }}>
            <span style={{ fontSize: 16 }}>{item.icon}</span>
            <span style={{ fontSize: 13, color: active === item.id ? COLORS.purpleLight : COLORS.muted, fontWeight: active === item.id ? 600 : 400 }}>{item.label}</span>
            {active === item.id && <div style={{ marginLeft: "auto", width: 4, height: 4, borderRadius: "50%", background: COLORS.purple }}></div>}
          </div>
        ))}
      </nav>
      <div style={{ padding: "12px 16px", margin: "0 12px 12px", borderRadius: 8, background: `${COLORS.green}11`, border: `1px solid ${COLORS.green}33` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: COLORS.green }}></div>
          <span style={{ fontSize: 11, color: COLORS.green }}>API Online</span>
        </div>
        <div style={{ fontSize: 10, color: COLORS.muted, marginTop: 2 }}>railway.app</div>
      </div>
      <div style={{ padding: "16px 20px", borderTop: `1px solid ${COLORS.cardBorder}` }}>
        {user ? (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
              <img src={user.photoURL} alt="avatar" style={{ width: 28, height: 28, borderRadius: "50%" }} />
              <div>
                <div style={{ fontSize: 12, color: COLORS.text, fontWeight: 500 }}>{user.displayName?.split(" ")[0]}</div>
                <div style={{ fontSize: 10, color: COLORS.muted }}>Free Plan</div>
              </div>
            </div>
            <button onClick={onLogout} style={{ width: "100%", padding: "6px", borderRadius: 6, background: "transparent", border: `1px solid ${COLORS.cardBorder}`, color: COLORS.muted, cursor: "pointer", fontSize: 11 }}>Sign Out</button>
          </div>
        ) : (
          <button onClick={onLogin} style={{ width: "100%", padding: "8px", borderRadius: 8, background: COLORS.purple, border: "none", color: COLORS.white, cursor: "pointer", fontSize: 12, fontWeight: 600 }}>Sign in with Google</button>
        )}
        <button onClick={() => setDarkMode(!darkMode)} style={{ width: "100%", marginTop: 8, padding: "6px", borderRadius: 6, background: "transparent", border: `1px solid ${COLORS.cardBorder}`, color: COLORS.muted, cursor: "pointer", fontSize: 11 }}>
          {darkMode ? "☀️ Light Mode" : "🌙 Dark Mode"}
        </button>
      </div>
    </div>
  );
}

function TopBar({ title, subtitle }) {
  return (
    <div style={{ borderBottom: `1px solid ${COLORS.cardBorder}`, padding: "20px 32px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 700, color: COLORS.white, margin: 0 }}>{title}</h1>
        {subtitle && <p style={{ fontSize: 12, color: COLORS.muted, margin: "4px 0 0" }}>{subtitle}</p>}
      </div>
      <span style={{ fontSize: 11, color: COLORS.muted }}>{new Date().toLocaleDateString("en-US", { weekday: "long", year: "numeric", month: "long", day: "numeric" })}</span>
    </div>
  );
}

function ScannerPage({ user }) {
  const [mode, setMode] = useState("github");
  const [input, setInput] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [stepIndex, setStepIndex] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [copied, setCopied] = useState(false);
  const [checklist, setChecklist] = useState({});
  const [saved, setSaved] = useState(false);
  const [emailInput, setEmailInput] = useState("");
  const [emailSent, setEmailSent] = useState(false);
  const [sendingEmail, setSendingEmail] = useState(false);
  const intervalRef = useRef(null);

  const startProgress = () => {
    setProgress(0); setStepIndex(0);
    let p = 0;
    intervalRef.current = setInterval(() => {
      p += Math.random() * 8 + 2;
      if (p > 92) p = 92;
      setProgress(Math.round(p));
      setStepIndex(Math.min(SCAN_STEPS.length - 1, Math.floor(p / (100 / SCAN_STEPS.length))));
    }, 400);
  };

  const stopProgress = () => {
    clearInterval(intervalRef.current);
    setProgress(100);
    setStepIndex(SCAN_STEPS.length - 1);
  };

  const handleScan = async () => {
    setLoading(true); setError(null); setResult(null); setChecklist({}); setSaved(false);
    startProgress();
    try {
      let res;
      if (mode === "zip") {
        if (!file) throw new Error("Please select a ZIP file");
        const formData = new FormData();
        formData.append("file", file);
        res = await fetch(`${API}/public-scan-zip`, { method: "POST", body: formData });
      } else if (mode === "github") {
        if (!input) throw new Error("Please enter a GitHub URL");
        res = await fetch(`${API}/scan-github`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ github_url: input, github_token: githubToken || null }) });
      } else {
        if (!input) throw new Error("Please enter a path");
        res = await fetch(`${API}/scan`, { method: "POST", headers: { "Content-Type": "application/json", "x-api-key": "quantumguard-secret-2026" }, body: JSON.stringify({ directory: input }) });
      }
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Scan failed");
      stopProgress();
      setResult(data);
      if (user) {
        await addDoc(collection(db, "scans"), { userId: user.uid, userEmail: user.email, filename: file?.name || input || "scan", score: data.quantum_readiness_score, findings: data.total_findings, createdAt: new Date() });
        await incrementScanCount(user.uid);
        setSaved(true);
      }
    } catch (e) {
      stopProgress();
      setError(e.message);
    }
    setLoading(false);
  };

  const handleEmail = async () => {
    if (!emailInput || !result) return;
    setSendingEmail(true);
    try {
      await emailjs.send("service_vy8yxbq", "template_mgydwpx", { to_email: emailInput, score: result.quantum_readiness_score, total: result.total_findings, filename: file?.name || input || "scan" }, "vATUvI1IlAtH0ooKaQlY9");
      setEmailSent(true);
      setTimeout(() => setEmailSent(false), 3000);
    } catch (e) { alert("Email failed. Please try again."); }
    setSendingEmail(false);
  };

  const getScoreColor = (s) => s >= 70 ? COLORS.green : s >= 40 ? COLORS.amber : COLORS.red;

  const severityCounts = result ? {
    CRITICAL: result.findings.filter(f => f.severity === "CRITICAL").length,
    HIGH: result.findings.filter(f => f.severity === "HIGH").length,
    MEDIUM: result.findings.filter(f => f.severity === "MEDIUM").length,
  } : null;

  const fileBreakdown = result ? result.findings.reduce((acc, f) => { const n = f.file.split("/").pop(); acc[n] = (acc[n] || 0) + 1; return acc; }, {}) : null;

  const handleCSV = () => {
    if (!result) return;
    const header = "Severity,File,Line,Code,Fix\n";
    const rows = result.findings.map(f => `"${f.severity}","${f.file}","${f.line}","${f.code.replace(/"/g, "'")}","${f.replacement}"`).join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "quantumguard-report.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  const handlePDF = () => {
    if (!result) return;
    const win = window.open("", "_blank");
    win.document.write(`<html><head><title>QuantumGuard Threat Report</title><style>body{font-family:'Segoe UI',sans-serif;padding:40px;background:#0a0a0f;color:#E8E8F0;}h1{color:#6C63FF;border-bottom:2px solid #6C63FF;padding-bottom:16px;}.score{font-size:72px;font-weight:800;color:${getScoreColor(result.quantum_readiness_score)};}.meta{background:#111127;padding:20px;border-radius:8px;margin:20px 0;border:1px solid #1e1e3a;}.finding{border-left:3px solid #FF3B3B;padding:12px 16px;margin:12px 0;background:#111127;border-radius:0 8px 8px 0;}.high{border-color:#FFB800;}.medium{border-color:#00D4AA;}code{background:#0a0a0f;padding:4px 8px;border-radius:4px;font-size:12px;color:#8B85FF;font-family:monospace;}.badge{display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;}.CRITICAL{background:#FF3B3B22;color:#FF3B3B;}.HIGH{background:#FFB80022;color:#FFB800;}.MEDIUM{background:#00D4AA22;color:#00D4AA;}</style></head><body><h1>⚛ QuantumGuard Threat Intelligence Report</h1><div class="meta"><p>Generated: ${new Date().toLocaleString()}</p><p>Target: ${result.github_url || "ZIP Upload"}</p></div><div class="score">${result.quantum_readiness_score}<span style="font-size:24px;color:#6B6B8A">/100</span></div><p style="color:#6B6B8A">Quantum Readiness Score</p><div class="meta"><p>Total Threats: <strong style="color:#FF3B3B">${result.total_findings}</strong></p><p>Critical: ${severityCounts?.CRITICAL} | High: ${severityCounts?.HIGH} | Medium: ${severityCounts?.MEDIUM}</p></div><h2>Threat Findings</h2>${result.findings.map(f => `<div class="finding ${f.severity}"><span class="badge ${f.severity}">${f.severity}</span> <strong>${f.file.split("/").pop()}:${f.line}</strong><br/><code>${f.code}</code><br/><span style="color:#6B6B8A">Remediation: </span><strong style="color:#6C63FF">${f.replacement}</strong></div>`).join("")}</body></html>`);
    win.document.close(); win.print();
  };

  const filteredFindings = result ? result.findings.filter(f => (filter === "ALL" || f.severity === filter) && (search === "" || f.file.toLowerCase().includes(search.toLowerCase()) || f.code.toLowerCase().includes(search.toLowerCase()))) : [];
  const grouped = filteredFindings.reduce((acc, f) => { if (!acc[f.file]) acc[f.file] = []; acc[f.file].push(f); return acc; }, {});

  return (
    <div>
      <TopBar title="Threat Scanner" subtitle="Quantum vulnerability analysis engine" />
      <div style={{ padding: "24px 32px" }}>
        <div style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 24, marginBottom: 24 }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
            {[{ id: "github", icon: "🔗", label: "GitHub URL" }, { id: "zip", icon: "📁", label: "Upload ZIP" }, { id: "path", icon: "🖥️", label: "Server Path" }].map(m => (
              <button key={m.id} onClick={() => setMode(m.id)} style={{ padding: "8px 16px", borderRadius: 6, border: `1px solid ${mode === m.id ? COLORS.purple : COLORS.cardBorder}`, background: mode === m.id ? `${COLORS.purple}22` : "transparent", color: mode === m.id ? COLORS.purpleLight : COLORS.muted, cursor: "pointer", fontSize: 12, fontWeight: mode === m.id ? 600 : 400 }}>
                {m.icon} {m.label}
              </button>
            ))}
          </div>
          {mode === "zip" ? (
            <div style={{ display: "flex", gap: 12 }}>
              <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files[0])} style={{ flex: 1, padding: "10px 14px", borderRadius: 8, border: `1px solid ${COLORS.cardBorder}`, background: COLORS.bg, color: COLORS.text, fontSize: 13 }} />
              <button onClick={handleScan} disabled={loading} style={{ padding: "10px 24px", borderRadius: 8, background: COLORS.purple, color: COLORS.white, border: "none", cursor: "pointer", fontSize: 13, fontWeight: 600 }}>{loading ? "Scanning..." : "▶ Run Scan"}</button>
            </div>
          ) : mode === "github" ? (
            <div>
              <div style={{ display: "flex", gap: 12, marginBottom: 8 }}>
                <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="https://github.com/username/repo" style={{ flex: 1, padding: "10px 14px", borderRadius: 8, border: `1px solid ${COLORS.cardBorder}`, background: COLORS.bg, color: COLORS.text, fontSize: 13 }} />
                <button onClick={handleScan} disabled={loading} style={{ padding: "10px 24px", borderRadius: 8, background: loading ? `${COLORS.purple}88` : COLORS.purple, color: COLORS.white, border: "none", cursor: loading ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600 }}>{loading ? "Scanning..." : "▶ Run Scan"}</button>
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <button onClick={() => setShowToken(!showToken)} style={{ background: "transparent", border: `1px solid ${COLORS.cardBorder}`, borderRadius: 6, padding: "4px 12px", cursor: "pointer", color: COLORS.muted, fontSize: 11 }}>{showToken ? "Hide Token" : "🔒 Private Repo"}</button>
                {showToken && <input value={githubToken} onChange={(e) => setGithubToken(e.target.value)} placeholder="GitHub Personal Access Token" type="password" style={{ flex: 1, padding: "4px 12px", borderRadius: 6, border: `1px solid ${COLORS.cardBorder}`, background: COLORS.bg, color: COLORS.text, fontSize: 11 }} />}
              </div>
            </div>
          ) : (
            <div style={{ display: "flex", gap: 12 }}>
              <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="/app/src" style={{ flex: 1, padding: "10px 14px", borderRadius: 8, border: `1px solid ${COLORS.cardBorder}`, background: COLORS.bg, color: COLORS.text, fontSize: 13 }} />
              <button onClick={handleScan} disabled={loading} style={{ padding: "10px 24px", borderRadius: 8, background: COLORS.purple, color: COLORS.white, border: "none", cursor: "pointer", fontSize: 13, fontWeight: 600 }}>{loading ? "Scanning..." : "▶ Run Scan"}</button>
            </div>
          )}
          {loading && (
            <div style={{ marginTop: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: COLORS.muted, marginBottom: 6 }}>
                <span style={{ color: COLORS.purpleLight }}>⚡ {SCAN_STEPS[stepIndex]}</span>
                <span>{progress}%</span>
              </div>
              <div style={{ background: COLORS.bg, borderRadius: 4, height: 4 }}>
                <div style={{ background: `linear-gradient(90deg, ${COLORS.purple}, ${COLORS.purpleLight})`, height: 4, borderRadius: 4, width: `${progress}%`, transition: "width 0.4s ease" }}></div>
              </div>
            </div>
          )}
          {error && (
            <div style={{ marginTop: 16, background: `${COLORS.red}11`, border: `1px solid ${COLORS.red}44`, borderRadius: 8, padding: 12 }}>
              <div style={{ color: COLORS.red, fontSize: 13 }}>⚠ {error}</div>
            </div>
          )}
        </div>

        {result && (
          <div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, marginBottom: 24 }}>
              {[
                { label: "Risk Score", value: result.quantum_readiness_score, suffix: "/100", color: getScoreColor(result.quantum_readiness_score), desc: result.quantum_readiness_score >= 70 ? "✓ Quantum Safe" : result.quantum_readiness_score >= 40 ? "⚠ At Risk" : "✗ Critical" },
                { label: "Total Threats", value: result.total_findings, color: COLORS.red, desc: "vulnerabilities found" },
                { label: "Critical", value: severityCounts.CRITICAL, color: COLORS.red, desc: "immediate action needed" },
                { label: "High Risk", value: severityCounts.HIGH, color: COLORS.amber, desc: "requires attention" },
              ].map((m, i) => (
                <div key={i} style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 20 }}>
                  <div style={{ fontSize: 11, color: COLORS.muted, marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>{m.label}</div>
                  <div style={{ fontSize: 36, fontWeight: 800, color: m.color, lineHeight: 1 }}>{m.value}<span style={{ fontSize: 14, color: COLORS.muted }}>{m.suffix}</span></div>
                  <div style={{ fontSize: 11, color: COLORS.muted, marginTop: 6 }}>{m.desc}</div>
                </div>
              ))}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 24 }}>
              <div style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 20 }}>
                <div style={{ fontSize: 12, color: COLORS.muted, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>Severity Distribution</div>
                {[
                  { key: "CRITICAL", color: COLORS.red, count: severityCounts.CRITICAL },
                  { key: "HIGH", color: COLORS.amber, count: severityCounts.HIGH },
                  { key: "MEDIUM", color: COLORS.green, count: severityCounts.MEDIUM },
                ].map(b => (
                  <div key={b.key} style={{ marginBottom: 12 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
                      <span style={{ color: b.color, fontWeight: 600 }}>{b.key}</span>
                      <span style={{ color: COLORS.muted }}>{b.count} ({Math.round(b.count / result.total_findings * 100)}%)</span>
                    </div>
                    <div style={{ background: COLORS.bg, borderRadius: 4, height: 6 }}>
                      <div style={{ background: b.color, height: 6, borderRadius: 4, width: `${(b.count / result.total_findings) * 100}%`, transition: "width 0.6s" }}></div>
                    </div>
                  </div>
                ))}
              </div>
              <div style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 20 }}>
                <div style={{ fontSize: 12, color: COLORS.muted, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>Score Breakdown</div>
                {[
                  { label: "Crypto Issues", desc: "RSA, ECC, RC4, DES", color: COLORS.red, pct: Math.round((severityCounts.CRITICAL / result.total_findings) * 100) },
                  { label: "TLS / Protocol", desc: "Weak TLS, SSL", color: COLORS.amber, pct: Math.round((severityCounts.HIGH / result.total_findings) * 100) },
                  { label: "Hash / Secrets", desc: "MD5, SHA-1, Keys", color: COLORS.green, pct: Math.round((severityCounts.MEDIUM / result.total_findings) * 100) },
                ].map((b, i) => (
                  <div key={i} style={{ marginBottom: 12 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
                      <div><span style={{ color: b.color, fontWeight: 600 }}>{b.label}</span><span style={{ color: COLORS.muted, marginLeft: 8, fontSize: 10 }}>{b.desc}</span></div>
                      <span style={{ color: b.color, fontWeight: 600 }}>{b.pct}%</span>
                    </div>
                    <div style={{ background: COLORS.bg, borderRadius: 4, height: 6 }}>
                      <div style={{ background: b.color, height: 6, borderRadius: 4, width: `${b.pct}%`, transition: "width 0.6s" }}></div>
                    </div>
                  </div>
                ))}
                <div style={{ fontSize: 10, color: COLORS.muted, marginTop: 8, padding: "6px 10px", background: COLORS.bg, borderRadius: 4 }}>Score = 100 − (CRITICAL×10) − (HIGH×6) − (MEDIUM×3)</div>
              </div>
            </div>

            {fileBreakdown && (
              <div style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 20, marginBottom: 24 }}>
                <div style={{ fontSize: 12, color: COLORS.muted, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>Top Affected Files</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 8 }}>
                  {Object.entries(fileBreakdown).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([fname, count], i) => (
                    <div key={i} style={{ background: COLORS.bg, borderRadius: 8, padding: "10px 14px", border: `1px solid ${COLORS.cardBorder}` }}>
                      <div style={{ fontSize: 12, color: COLORS.text, fontFamily: "monospace", marginBottom: 4 }}>{fname}</div>
                      <div style={{ fontSize: 11, color: COLORS.red }}>{count} threats</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 20, marginBottom: 24 }}>
              <div style={{ fontSize: 12, color: COLORS.muted, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>Export & Share</div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
                <button onClick={handlePDF} style={{ padding: "8px 16px", borderRadius: 6, background: COLORS.purple, color: COLORS.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📄 PDF Report</button>
                <button onClick={handleCSV} style={{ padding: "8px 16px", borderRadius: 6, background: COLORS.green, color: "#000", border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📊 CSV Export</button>
                <button onClick={() => { navigator.clipboard.writeText(result.findings.map(f => `[${f.severity}] ${f.file}:${f.line} — ${f.code} → Fix: ${f.replacement}`).join("\n")); setCopied(true); setTimeout(() => setCopied(false), 2000); }} style={{ padding: "8px 16px", borderRadius: 6, background: copied ? COLORS.green : "transparent", color: copied ? "#000" : COLORS.muted, border: `1px solid ${COLORS.cardBorder}`, cursor: "pointer", fontSize: 12 }}>{copied ? "✓ Copied!" : "📋 Copy"}</button>
                <button onClick={() => window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(`QuantumGuard Scan: ${result.quantum_readiness_score}/100 — ${result.total_findings} vulnerabilities found\nquantumguard-one.vercel.app\n#QuantumSecurity`)}`, "_blank")} style={{ padding: "8px 16px", borderRadius: 6, background: "#1DA1F2", color: COLORS.white, border: "none", cursor: "pointer", fontSize: 12 }}>🐦 Share</button>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <input value={emailInput} onChange={(e) => setEmailInput(e.target.value)} placeholder="Email report to..." type="email" style={{ flex: 1, padding: "8px 14px", borderRadius: 6, border: `1px solid ${COLORS.cardBorder}`, background: COLORS.bg, color: COLORS.text, fontSize: 12 }} />
                <button onClick={handleEmail} disabled={sendingEmail || !emailInput} style={{ padding: "8px 16px", borderRadius: 6, background: emailSent ? COLORS.green : COLORS.purple, color: emailSent ? "#000" : COLORS.white, border: "none", cursor: "pointer", fontSize: 12 }}>{emailSent ? "✓ Sent!" : sendingEmail ? "Sending..." : "📧 Email"}</button>
              </div>
            </div>

            <div style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 20 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 8 }}>
                <div style={{ fontSize: 12, color: COLORS.muted, textTransform: "uppercase", letterSpacing: 1 }}>Threat Intelligence — {result.total_findings} findings</div>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map(f => (
                    <button key={f} onClick={() => setFilter(f)} style={{ padding: "4px 12px", borderRadius: 20, border: `1px solid ${filter === f ? COLORS.purple : COLORS.cardBorder}`, background: filter === f ? `${COLORS.purple}22` : "transparent", color: filter === f ? COLORS.purpleLight : COLORS.muted, cursor: "pointer", fontSize: 11 }}>
                      {f} {f !== "ALL" && severityCounts ? `(${severityCounts[f]})` : ""}
                    </button>
                  ))}
                  <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search..." style={{ padding: "4px 12px", borderRadius: 20, border: `1px solid ${COLORS.cardBorder}`, background: COLORS.bg, color: COLORS.text, fontSize: 11, width: 120 }} />
                </div>
              </div>
              {Object.entries(grouped).map(([file, filefindings], gi) => (
                <div key={gi} style={{ marginBottom: 12, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 8, overflow: "hidden" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 16px", background: COLORS.bg, borderBottom: `1px solid ${COLORS.cardBorder}` }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontSize: 11, color: COLORS.purple }}>📄</span>
                      <span style={{ fontFamily: "monospace", fontSize: 12, color: COLORS.text }}>{file.split("/").pop()}</span>
                      <span style={{ fontSize: 10, color: COLORS.muted }}>{file}</span>
                    </div>
                    <span style={{ background: `${COLORS.red}22`, color: COLORS.red, fontSize: 11, padding: "2px 8px", borderRadius: 20 }}>{filefindings.length} threats</span>
                  </div>
                  <div style={{ padding: 16 }}>
                    {filefindings.map((f, i) => {
                      const key = `${f.file}:${f.line}`;
                      return (
                        <div key={i} style={{ borderLeft: `3px solid ${f.severity === "CRITICAL" ? COLORS.red : f.severity === "HIGH" ? COLORS.amber : COLORS.green}`, paddingLeft: 14, marginBottom: i < filefindings.length - 1 ? 16 : 0, opacity: checklist[key] ? 0.4 : 1 }}>
                          <div style={{ display: "flex", gap: 8, marginBottom: 6, alignItems: "center", flexWrap: "wrap" }}>
                            <input type="checkbox" checked={!!checklist[key]} onChange={() => setChecklist(p => ({ ...p, [key]: !p[key] }))} style={{ cursor: "pointer" }} />
                            <span style={{ background: f.severity === "CRITICAL" ? `${COLORS.red}22` : f.severity === "HIGH" ? `${COLORS.amber}22` : `${COLORS.green}22`, color: f.severity === "CRITICAL" ? COLORS.red : f.severity === "HIGH" ? COLORS.amber : COLORS.green, padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700 }}>{f.severity}</span>
                            <span style={{ color: COLORS.muted, fontSize: 11 }}>Line {f.line}</span>
                            {checklist[key] && <span style={{ fontSize: 10, color: COLORS.green }}>✓ Remediated</span>}
                          </div>
                          <div style={{ fontFamily: "monospace", background: COLORS.bg, padding: "8px 12px", borderRadius: 6, fontSize: 11, marginBottom: 6, color: COLORS.purpleLight, overflowX: "auto" }}>{f.code}</div>
                          <div style={{ fontSize: 11, color: COLORS.muted }}>Remediation: <span style={{ color: COLORS.green }}>{f.replacement}</span></div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
            {saved && <div style={{ marginTop: 12, background: `${COLORS.green}11`, border: `1px solid ${COLORS.green}44`, borderRadius: 8, padding: "10px 16px", color: COLORS.green, fontSize: 12 }}>✓ Scan saved to history</div>}
          </div>
        )}
      </div>
    </div>
  );
}

function HistoryPage({ user }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) return;
    const fetchHistory = async () => {
      try {
        const q = query(collection(db, "scans"), where("userId", "==", user.uid), orderBy("createdAt", "desc"));
        const snapshot = await getDocs(q);
        setHistory(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })));
      } catch (e) { console.error(e); }
      setLoading(false);
    };
    fetchHistory();
  }, [user]);

  if (!user) return (
    <div>
      <TopBar title="Scan History" subtitle="Your previous scans" />
      <div style={{ padding: 32, textAlign: "center" }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>🔒</div>
        <div style={{ color: COLORS.muted, fontSize: 14 }}>Sign in to view your scan history</div>
      </div>
    </div>
  );

  return (
    <div>
      <TopBar title="Scan History" subtitle={`${history.length} total scans`} />
      <div style={{ padding: "24px 32px" }}>
        {loading ? (
          <div style={{ color: COLORS.muted }}>Loading...</div>
        ) : history.length === 0 ? (
          <div style={{ color: COLORS.muted, fontSize: 14 }}>No scans yet!</div>
        ) : (
          <div style={{ display: "grid", gap: 8 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 120px 100px 100px", gap: 16, padding: "8px 16px" }}>
              {["Target", "Date", "Score", "Threats"].map(h => (
                <div key={h} style={{ fontSize: 11, color: COLORS.muted, textTransform: "uppercase", letterSpacing: 1 }}>{h}</div>
              ))}
            </div>
            {history.map((scan, i) => (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 120px 100px 100px", gap: 16, padding: "14px 16px", background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 8, alignItems: "center" }}>
                <div style={{ fontFamily: "monospace", fontSize: 12, color: COLORS.text }}>{scan.filename || "scan"}</div>
                <div style={{ fontSize: 11, color: COLORS.muted }}>{scan.createdAt?.toDate?.()?.toLocaleDateString() || "—"}</div>
                <div style={{ fontSize: 18, fontWeight: 700, color: scan.score >= 70 ? COLORS.green : scan.score >= 40 ? COLORS.amber : COLORS.red }}>{scan.score}</div>
                <div style={{ fontSize: 14, fontWeight: 600, color: COLORS.red }}>{scan.findings}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function AnalyticsPage({ user }) {
  return (
    <div>
      <TopBar title="Analytics" subtitle="Security posture overview" />
      <div style={{ padding: "24px 32px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 16, marginBottom: 24 }}>
          {[
            { label: "Languages Supported", value: "6", desc: "Python, JS, Java, TS, Go, Rust", color: COLORS.purple },
            { label: "Vulnerability Types", value: "15+", desc: "RSA, ECC, DH, DSA, MD5 & more", color: COLORS.red },
            { label: "NIST Compliance", value: "2024", desc: "FIPS 203, 204, 205 aligned", color: COLORS.green },
          ].map((s, i) => (
            <div key={i} style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 24 }}>
              <div style={{ fontSize: 11, color: COLORS.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 8 }}>{s.label}</div>
              <div style={{ fontSize: 40, fontWeight: 800, color: s.color }}>{s.value}</div>
              <div style={{ fontSize: 11, color: COLORS.muted, marginTop: 6 }}>{s.desc}</div>
            </div>
          ))}
        </div>
        <div style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 24 }}>
          <div style={{ fontSize: 12, color: COLORS.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>Quantum Timeline</div>
          {[
            { year: "2024", event: "NIST finalizes PQC standards — FIPS 203, 204, 205", color: COLORS.green },
            { year: "2026", event: "QuantumGuard launches — first focused scanner", color: COLORS.purple },
            { year: "2027", event: "Regulatory pressure increases for compliance", color: COLORS.amber },
            { year: "2030", event: "Cryptographically Relevant Quantum Computers arrive", color: COLORS.red },
          ].map((t, i) => (
            <div key={i} style={{ display: "flex", gap: 16, marginBottom: 16, alignItems: "flex-start" }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: t.color, marginTop: 4, flexShrink: 0 }}></div>
              <div>
                <span style={{ fontSize: 12, fontWeight: 700, color: t.color, marginRight: 12 }}>{t.year}</span>
                <span style={{ fontSize: 12, color: COLORS.muted }}>{t.event}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function MigrationPage({ user }) {
  const [scans, setScans] = useState([]);
  const [migrationStatus, setMigrationStatus] = useState({});

  useEffect(() => {
    if (!user) return;
    const fetchScans = async () => {
      try {
        const q = query(collection(db, "scans"), where("userId", "==", user.uid), orderBy("createdAt", "desc"));
        const snapshot = await getDocs(q);
        setScans(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })));
      } catch (e) { console.error(e); }
    };
    fetchScans();
  }, [user]);

  const vulnTypes = ["RSA", "ECC", "DH", "DSA", "MD5", "SHA1", "RC4", "DES", "ECB_MODE", "WEAK_TLS", "HARDCODED_SECRET"];
  const getStatus = (vuln) => migrationStatus[vuln] || "pending";
  const setStatus = (vuln, status) => setMigrationStatus(p => ({ ...p, [vuln]: status }));
  const totalFixed = Object.values(migrationStatus).filter(s => s === "fixed").length;
  const totalInProgress = Object.values(migrationStatus).filter(s => s === "in_progress").length;
  const overallProgress = Math.round((totalFixed / vulnTypes.length) * 100);
  const statusColors = { pending: COLORS.muted, in_progress: COLORS.amber, fixed: COLORS.green };
  const fixes = {
    RSA: "CRYSTALS-Kyber (ML-KEM FIPS 203)",
    ECC: "CRYSTALS-Dilithium (ML-DSA FIPS 204)",
    DH: "CRYSTALS-Kyber (ML-KEM FIPS 203)",
    DSA: "CRYSTALS-Dilithium (ML-DSA FIPS 204)",
    MD5: "SHA-3-256 or BLAKE3",
    SHA1: "SHA-3-256 or BLAKE3",
    RC4: "AES-256-GCM",
    DES: "AES-256-GCM",
    ECB_MODE: "AES-256-GCM",
    WEAK_TLS: "TLS 1.3",
    HARDCODED_SECRET: "AWS Secrets Manager / Vault",
  };

  if (!user) return (
    <div>
      <TopBar title="Migration Tracker" subtitle="Track your quantum migration progress" />
      <div style={{ padding: 32, textAlign: "center" }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>🔒</div>
        <div style={{ color: COLORS.muted, fontSize: 14 }}>Sign in to track your migration progress</div>
      </div>
    </div>
  );

  return (
    <div>
      <TopBar title="Crypto Migration Tracker" subtitle="Track your quantum-safe migration progress" />
      <div style={{ padding: "24px 32px" }}>
        <div style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 24, marginBottom: 24 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 8 }}>
            <div>
              <div style={{ fontSize: 12, color: COLORS.muted, textTransform: "uppercase", letterSpacing: 1 }}>Overall Migration Progress</div>
              <div style={{ fontSize: 36, fontWeight: 800, color: overallProgress >= 70 ? COLORS.green : overallProgress >= 40 ? COLORS.amber : COLORS.red, marginTop: 4 }}>{overallProgress}%</div>
            </div>
            <div style={{ display: "flex", gap: 16 }}>
              {[
                { label: "Fixed", value: totalFixed, color: COLORS.green },
                { label: "In Progress", value: totalInProgress, color: COLORS.amber },
                { label: "Pending", value: vulnTypes.length - totalFixed - totalInProgress, color: COLORS.muted },
              ].map((s, i) => (
                <div key={i} style={{ textAlign: "center" }}>
                  <div style={{ fontSize: 24, fontWeight: 700, color: s.color }}>{s.value}</div>
                  <div style={{ fontSize: 11, color: COLORS.muted }}>{s.label}</div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ background: COLORS.bg, borderRadius: 8, height: 12 }}>
            <div style={{ background: `linear-gradient(90deg, ${COLORS.purple}, ${COLORS.green})`, height: 12, borderRadius: 8, width: `${overallProgress}%`, transition: "width 0.6s ease" }}></div>
          </div>
        </div>

        <div style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 24, marginBottom: 24 }}>
          <div style={{ fontSize: 12, color: COLORS.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>Vulnerability Migration Status</div>
          {vulnTypes.map((vuln, i) => {
            const status = getStatus(vuln);
            const severity = ["RSA", "ECC", "RC4", "DES"].includes(vuln) ? "CRITICAL" : ["DH", "DSA", "ECB_MODE", "WEAK_TLS", "HARDCODED_SECRET"].includes(vuln) ? "HIGH" : "MEDIUM";
            return (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 2fr 120px 140px", gap: 16, padding: "12px 16px", background: status === "fixed" ? `${COLORS.green}08` : COLORS.bg, borderRadius: 8, marginBottom: 6, border: `1px solid ${status === "fixed" ? COLORS.green + "33" : status === "in_progress" ? COLORS.amber + "33" : COLORS.cardBorder}`, alignItems: "center" }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: status === "fixed" ? COLORS.muted : COLORS.white, textDecoration: status === "fixed" ? "line-through" : "none" }}>{vuln}</div>
                <div style={{ fontSize: 11, color: COLORS.muted, fontFamily: "monospace" }}>{fixes[vuln]}</div>
                <div style={{ fontSize: 10, fontWeight: 700, color: severity === "CRITICAL" ? COLORS.red : severity === "HIGH" ? COLORS.amber : COLORS.green, background: severity === "CRITICAL" ? `${COLORS.red}22` : severity === "HIGH" ? `${COLORS.amber}22` : `${COLORS.green}22`, padding: "2px 8px", borderRadius: 4, textAlign: "center" }}>{severity}</div>
                <div style={{ display: "flex", gap: 4 }}>
                  {["pending", "in_progress", "fixed"].map(s => (
                    <button key={s} onClick={() => setStatus(vuln, s)} style={{ flex: 1, padding: "4px 6px", borderRadius: 4, border: `1px solid ${status === s ? statusColors[s] : COLORS.cardBorder}`, background: status === s ? `${statusColors[s]}22` : "transparent", color: status === s ? statusColors[s] : COLORS.muted, cursor: "pointer", fontSize: 9 }}>
                      {s === "pending" ? "⬜" : s === "in_progress" ? "🔄" : "✅"}
                    </button>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        {scans.length > 0 && (
          <div style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 24, marginBottom: 16 }}>
            <div style={{ fontSize: 12, color: COLORS.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 16 }}>Recent Scans</div>
            {scans.slice(0, 5).map((scan, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: COLORS.bg, borderRadius: 8, marginBottom: 8, border: `1px solid ${COLORS.cardBorder}` }}>
                <div>
                  <div style={{ fontSize: 12, color: COLORS.text, fontFamily: "monospace" }}>{scan.filename || "scan"}</div>
                  <div style={{ fontSize: 10, color: COLORS.muted }}>{scan.createdAt?.toDate?.()?.toLocaleDateString() || "—"}</div>
                </div>
                <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
                  <div style={{ textAlign: "center" }}>
                    <div style={{ fontSize: 18, fontWeight: 700, color: scan.score >= 70 ? COLORS.green : scan.score >= 40 ? COLORS.amber : COLORS.red }}>{scan.score}</div>
                    <div style={{ fontSize: 10, color: COLORS.muted }}>Score</div>
                  </div>
                  <div style={{ textAlign: "center" }}>
                    <div style={{ fontSize: 18, fontWeight: 700, color: COLORS.red }}>{scan.findings}</div>
                    <div style={{ fontSize: 10, color: COLORS.muted }}>Threats</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={() => {
            const report = vulnTypes.map(v => `${v},${getStatus(v)},${fixes[v]}`).join("\n");
            const blob = new Blob([`Vulnerability,Status,Fix\n${report}`], { type: "text/csv" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a"); a.href = url; a.download = "migration-status.csv"; a.click();
          }} style={{ padding: "8px 20px", borderRadius: 8, background: COLORS.green, color: "#000", border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📊 Export Migration Report</button>
          <button onClick={() => setMigrationStatus({})} style={{ padding: "8px 20px", borderRadius: 8, background: "transparent", color: COLORS.muted, border: `1px solid ${COLORS.cardBorder}`, cursor: "pointer", fontSize: 12 }}>Reset</button>
        </div>
      </div>
    </div>
  );
}

function DocsPage() {
  return (
    <div>
      <TopBar title="Documentation" subtitle="Integration guides and API reference" />
      <div style={{ padding: "24px 32px" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          {[
            { title: "Quick Start", icon: "⚡", desc: "Scan your first repo in 30 seconds", steps: ["Go to Scanner tab", "Paste GitHub URL", "Click Run Scan", "Download PDF report"] },
            { title: "GitHub Actions", icon: "🔄", desc: "Automate scans in CI/CD pipeline", steps: ["Copy workflow YAML", "Add to .github/workflows/", "Push to trigger scan", "View results in Actions"] },
            { title: "Private Repos", icon: "🔒", desc: "Scan private repositories securely", steps: ["Generate GitHub PAT", "Click Private Repo button", "Paste your token", "Token never stored"] },
            { title: "API Reference", icon: "🔌", desc: "Integrate QuantumGuard in your stack", steps: ["POST /public-scan-zip", "POST /scan-github", "POST /scan (API key)", "GET /health"] },
          ].map((d, i) => (
            <div key={i} style={{ background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 24 }}>
              <div style={{ fontSize: 24, marginBottom: 8 }}>{d.icon}</div>
              <div style={{ fontSize: 15, fontWeight: 600, color: COLORS.white, marginBottom: 4 }}>{d.title}</div>
              <div style={{ fontSize: 12, color: COLORS.muted, marginBottom: 16 }}>{d.desc}</div>
              {d.steps.map((s, j) => (
                <div key={j} style={{ display: "flex", gap: 8, marginBottom: 6, alignItems: "center" }}>
                  <span style={{ fontSize: 10, color: COLORS.purple, fontWeight: 700 }}>{j + 1}</span>
                  <span style={{ fontSize: 12, color: COLORS.muted }}>{s}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
        <div style={{ marginTop: 16, background: COLORS.card, border: `1px solid ${COLORS.cardBorder}`, borderRadius: 12, padding: 24 }}>
          <div style={{ fontSize: 12, color: COLORS.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 12 }}>API Endpoints</div>
          {[
            { method: "POST", path: "/public-scan-zip", desc: "Upload ZIP file for scanning" },
            { method: "POST", path: "/scan-github", desc: "Scan GitHub repository by URL" },
            { method: "POST", path: "/scan", desc: "Scan server path (requires API key)" },
            { method: "GET", path: "/health", desc: "Check API health status" },
          ].map((e, i) => (
            <div key={i} style={{ display: "flex", gap: 12, alignItems: "center", padding: "8px 0", borderBottom: i < 3 ? `1px solid ${COLORS.cardBorder}` : "none" }}>
              <span style={{ background: `${COLORS.purple}22`, color: COLORS.purple, padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 700, minWidth: 50, textAlign: "center" }}>{e.method}</span>
              <span style={{ fontFamily: "monospace", fontSize: 12, color: COLORS.purpleLight }}>{e.path}</span>
              <span style={{ fontSize: 12, color: COLORS.muted }}>{e.desc}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Homepage({ onGetStarted }) {
  return (
    <div style={{ minHeight: "100vh", background: COLORS.bg, color: COLORS.text, fontFamily: "sans-serif" }}>
      <div style={{ textAlign: "center", padding: "100px 20px 60px" }}>
        <div style={{ display: "inline-flex", gap: 8, marginBottom: 32, flexWrap: "wrap", justifyContent: "center" }}>
          {[
            { text: "NIST PQC 2024", color: COLORS.purple },
            { text: "Open Source", color: COLORS.green },
            { text: "Free Forever", color: COLORS.red },
          ].map((b, i) => (
            <span key={i} style={{ background: `${b.color}22`, border: `1px solid ${b.color}44`, borderRadius: 20, padding: "4px 14px", fontSize: 11, color: b.color, fontWeight: 600 }}>{b.text}</span>
          ))}
        </div>
        <h1 style={{ fontSize: "clamp(36px, 6vw, 64px)", fontWeight: 800, lineHeight: 1.1, maxWidth: 900, margin: "0 auto 24px", color: COLORS.white }}>
          Quantum Threat Intelligence<br />
          <span style={{ color: COLORS.purple }}>for Your Codebase</span>
        </h1>
        <p style={{ fontSize: "clamp(15px, 2vw, 20px)", color: COLORS.muted, maxWidth: 600, margin: "0 auto 48px", lineHeight: 1.7 }}>
          Enterprise-grade quantum vulnerability scanner. Detect RSA, ECC, and 15+ cryptographic weaknesses before quantum computers break them.
        </p>
        <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
          <button onClick={onGetStarted} style={{ background: COLORS.purple, color: COLORS.white, padding: "16px 40px", borderRadius: 10, border: "none", cursor: "pointer", fontSize: 16, fontWeight: 700 }}>▶ Launch Scanner</button>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ background: "transparent", color: COLORS.text, padding: "16px 40px", borderRadius: 10, textDecoration: "none", fontSize: 16, border: `1px solid ${COLORS.cardBorder}` }}>GitHub →</a>
        </div>
        <p style={{ color: COLORS.muted, fontSize: 12, marginTop: 16 }}>No credit card. No signup required. Scan instantly.</p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 1, maxWidth: 860, margin: "0 auto 80px", background: COLORS.cardBorder, borderRadius: 12, overflow: "hidden" }}>
        {[{ num: "15+", label: "Vulnerabilities" }, { num: "6", label: "Languages" }, { num: "2030", label: "Quantum Deadline" }, { num: "100%", label: "Open Source" }].map((s, i) => (
          <div key={i} style={{ background: COLORS.card, padding: 24, textAlign: "center" }}>
            <div style={{ fontSize: 32, fontWeight: 800, color: COLORS.purple }}>{s.num}</div>
            <div style={{ color: COLORS.muted, fontSize: 12, marginTop: 4 }}>{s.label}</div>
          </div>
        ))}
      </div>

      <div style={{ maxWidth: 900, margin: "0 auto 80px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: 32, fontWeight: 700, marginBottom: 48, color: COLORS.white }}>Enterprise Security Platform</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 16 }}>
          {[
            { icon: "🔍", title: "Deep Code Analysis", desc: "Line-by-line scanning across 6 languages — Python, JS, Java, TypeScript, Go, Rust" },
            { icon: "📊", title: "Quantum Readiness Score", desc: "0-100 risk score with full breakdown — Crypto, TLS, Hash, Secrets" },
            { icon: "🎯", title: "NIST 2024 Remediation", desc: "Every finding includes CRYSTALS-Kyber or Dilithium migration path" },
            { icon: "🔒", title: "Private Repo Support", desc: "Scan private GitHub repos securely with Personal Access Token" },
            { icon: "📄", title: "Threat Reports", desc: "Professional PDF reports, CSV export, email delivery for board presentations" },
            { icon: "🔄", title: "Migration Tracker", desc: "Track your quantum migration progress — vulnerability by vulnerability" },
          ].map((f, i) => (
            <div key={i} style={{ background: COLORS.card, borderRadius: 12, padding: 24, border: `1px solid ${COLORS.cardBorder}` }}>
              <div style={{ fontSize: 24, marginBottom: 12 }}>{f.icon}</div>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 8, color: COLORS.white }}>{f.title}</div>
              <div style={{ fontSize: 12, color: COLORS.muted, lineHeight: 1.6 }}>{f.desc}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ maxWidth: 900, margin: "0 auto 80px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: 32, fontWeight: 700, marginBottom: 48, color: COLORS.white }}>Simple Pricing</h2>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 16 }}>
          {[
            { name: "Free", price: "$0", period: "forever", features: ["Web scanner", "ZIP + GitHub scan", "Private repo support", "PDF & CSV reports", "Migration tracker", "10 scans/day"] },
            { name: "Pro", price: "$29", period: "/month", features: ["Everything in Free", "Unlimited scans", "AI-powered reports", "Team members", "API access", "Priority support"], highlight: true },
            { name: "Enterprise", price: "Custom", features: ["Everything in Pro", "CI/CD integration", "SSO login", "SOC2 compliance", "Dedicated support"] },
          ].map((p, i) => (
            <div key={i} style={{ background: COLORS.card, borderRadius: 12, padding: 28, border: p.highlight ? `2px solid ${COLORS.purple}` : `1px solid ${COLORS.cardBorder}`, position: "relative" }}>
              {p.highlight && <div style={{ position: "absolute", top: -12, left: "50%", transform: "translateX(-50%)", background: COLORS.purple, color: COLORS.white, padding: "3px 16px", borderRadius: 20, fontSize: 11, fontWeight: 600 }}>Most Popular</div>}
              <div style={{ fontSize: 16, fontWeight: 600, color: COLORS.white, marginBottom: 4 }}>{p.name}</div>
              <div style={{ fontSize: 32, fontWeight: 800, color: COLORS.purple, marginBottom: 16 }}>{p.price}<span style={{ fontSize: 14, color: COLORS.muted }}>{p.period}</span></div>
              {p.features.map((f, j) => <div key={j} style={{ fontSize: 12, color: COLORS.muted, marginBottom: 8 }}>✓ {f}</div>)}
              <button style={{ width: "100%", marginTop: 16, padding: "10px", borderRadius: 8, background: p.highlight ? COLORS.purple : "transparent", color: p.highlight ? COLORS.white : COLORS.purple, border: `1px solid ${COLORS.purple}`, cursor: "pointer", fontSize: 13, fontWeight: 600 }}>
                {p.name === "Free" ? "Get Started Free" : p.name === "Pro" ? "Coming Soon" : "Contact Us"}
              </button>
            </div>
          ))}
        </div>
      </div>

      <div style={{ textAlign: "center", padding: "60px 20px", background: COLORS.card, borderTop: `1px solid ${COLORS.cardBorder}` }}>
        <h2 style={{ fontSize: 32, fontWeight: 700, color: COLORS.white, marginBottom: 16 }}>Ready to secure your code?</h2>
        <p style={{ color: COLORS.muted, marginBottom: 32, fontSize: 15 }}>Scan your codebase in 30 seconds. Free forever.</p>
        <button onClick={onGetStarted} style={{ background: COLORS.purple, color: COLORS.white, padding: "16px 48px", borderRadius: 10, border: "none", cursor: "pointer", fontSize: 16, fontWeight: 700 }}>▶ Launch Scanner</button>
      </div>
      <div style={{ textAlign: "center", padding: "24px 20px", color: COLORS.muted, fontSize: 12 }}>
        QuantumGuard by MANGSRI — Open Source Quantum Security Platform — 2026
      </div>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(null);
  const [active, setActive] = useState("home");
  const [darkMode, setDarkMode] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(false);
const isMobile = window.innerWidth <= 768;

  useEffect(() => {
    onAuthStateChanged(auth, (u) => setUser(u));
  }, []);

  const handleLogin = async () => {
    try { await signInWithGoogle(); } catch (e) { console.error(e); }
  };

  const handleLogout = async () => {
    try { await signOut(auth); setUser(null); } catch (e) { console.error(e); }
  };

  if (active === "home") {
    return <Homepage onGetStarted={() => setActive("scan")} />;
  }

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: COLORS.bg, color: COLORS.text, fontFamily: "'Segoe UI', sans-serif" }}>
      <Sidebar active={active} setActive={setActive} user={user} onLogin={handleLogin} onLogout={handleLogout} darkMode={darkMode} setDarkMode={setDarkMode} />
      <div style={{ marginLeft: 220, flex: 1, minHeight: "100vh" }}>
        {active === "scan" && <ScannerPage user={user} />}
        {active === "history" && <HistoryPage user={user} />}
        {active === "migration" && <MigrationPage user={user} />}
        {active === "dashboard" && <AnalyticsPage user={user} />}
        {active === "docs" && <DocsPage />}
      </div>
    </div>
  );
}