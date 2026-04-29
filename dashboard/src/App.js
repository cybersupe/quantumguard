import { useState, useEffect, useRef } from "react";
import "./App.css";
import emailjs from "@emailjs/browser";
import { auth, db, signInWithGoogle, canUserScan, incrementScanCount } from "./firebase";
import { onAuthStateChanged, signOut } from "firebase/auth";
import { collection, addDoc, getDocs, query, where, orderBy } from "firebase/firestore";

const API = "https://quantumguard-api.onrender.com";

const C = {
  bg: "#f8faf8",
  sidebar: "#ffffff",
  sidebarBorder: "#e2f0e2",
  topbar: "#ffffff",
  panel: "#ffffff",
  panelBorder: "#e2f0e2",
  input: "#f0f7f0",
  green: "#16a34a",
  greenDark: "#15803d",
  greenLight: "#dcfce7",
  greenLighter: "#f0fdf4",
  greenMid: "#86efac",
  red: "#dc2626",
  redLight: "#fee2e2",
  amber: "#d97706",
  amberLight: "#fef3c7",
  blue: "#2563eb",
  blueLight: "#dbeafe",
  text: "#1a1a1a",
  textMid: "#374151",
  muted: "#6b7280",
  white: "#ffffff",
  critical: "#dc2626",
  high: "#d97706",
  medium: "#ca8a04",
};

const SCAN_STEPS = [
  "Initializing scan engine...", "Connecting to target...", "Analyzing file structure...",
  "Running vulnerability checks...", "Calculating risk score...", "Generating threat report...",
];

// ── Sidebar ──────────────────────────────────────────────────
function Sidebar({ active, setActive, user, onLogin, onLogout, open, onClose }) {
  const navItems = [
    { id: "scan", icon: "⚡", label: "Scanner" },
    { id: "agility", icon: "🔬", label: "Agility Checker" },
    { id: "tls", icon: "🔐", label: "TLS Analyzer" },
    { id: "history", icon: "🗂", label: "Scan History" },
    { id: "migration", icon: "🔄", label: "Migration" },
    { id: "dashboard", icon: "📊", label: "Analytics" },
    { id: "docs", icon: "📖", label: "Docs" },
  ];
  return (
    <>
      {open && <div className="sidebar-overlay open" onClick={onClose} />}
      <div className={`sidebar${open ? " open" : ""}`} style={{
        width: 240, minHeight: "100vh", background: C.sidebar,
        borderRight: `1px solid ${C.panelBorder}`, display: "flex",
        flexDirection: "column", position: "fixed", left: 0, top: 0, zIndex: 100,
        boxShadow: "2px 0 8px rgba(0,0,0,0.06)",
      }}>
        {/* Logo */}
        <div style={{ padding: "20px 20px", borderBottom: `1px solid ${C.panelBorder}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 36, height: 36, borderRadius: 10, background: C.green, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18 }}>⚛</div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}>
                <span style={{ color: C.green }}>Quantum</span>Guard
              </div>
              <div style={{ fontSize: 10, color: C.muted }}>Security Platform</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: "12px 12px" }}>
          {navItems.map(item => (
            <div key={item.id} onClick={() => { setActive(item.id); onClose(); }} style={{
              display: "flex", alignItems: "center", gap: 10, padding: "10px 12px",
              borderRadius: 10, marginBottom: 2, cursor: "pointer",
              background: active === item.id ? C.greenLight : "transparent",
              color: active === item.id ? C.green : C.muted,
              fontWeight: active === item.id ? 600 : 400,
              transition: "all 0.15s",
            }}>
              <span style={{ fontSize: 16 }}>{item.icon}</span>
              <span style={{ fontSize: 13 }}>{item.label}</span>
              {active === item.id && <div style={{ marginLeft: "auto", width: 6, height: 6, borderRadius: "50%", background: C.green }}></div>}
            </div>
          ))}
        </nav>

        {/* API Status */}
        <div style={{ padding: "10px 16px", margin: "0 12px 12px", borderRadius: 10, background: C.greenLighter, border: `1px solid ${C.greenMid}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: C.green }}></div>
            <span style={{ fontSize: 11, color: C.green, fontWeight: 600 }}>API Online</span>
          </div>
          <div style={{ fontSize: 9, color: C.muted, marginTop: 2 }}>quantumguard-api.onrender.com</div>
        </div>

        {/* User */}
        <div style={{ padding: "14px 16px", borderTop: `1px solid ${C.panelBorder}` }}>
          {user ? (
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <img src={user.photoURL} alt="avatar" style={{ width: 30, height: 30, borderRadius: "50%", border: `2px solid ${C.greenMid}` }} />
                <div>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 600 }}>{user.displayName?.split(" ")[0]}</div>
                  <div style={{ fontSize: 10, color: C.muted }}>Free Plan</div>
                </div>
              </div>
              <button onClick={onLogout} style={{ width: "100%", padding: "6px", borderRadius: 8, background: "transparent", border: `1px solid ${C.panelBorder}`, color: C.muted, cursor: "pointer", fontSize: 11 }}>Sign Out</button>
            </div>
          ) : (
            <button onClick={onLogin} style={{ width: "100%", padding: "9px", borderRadius: 10, background: C.green, border: "none", color: C.white, cursor: "pointer", fontSize: 12, fontWeight: 600 }}>
              Sign in with Google
            </button>
          )}
        </div>
      </div>
    </>
  );
}

// ── TopBar ────────────────────────────────────────────────────
function TopBar({ title, user, onLogin, onLogout, onHamburger }) {
  return (
    <div style={{
      height: 56, background: C.white, borderBottom: `1px solid ${C.panelBorder}`,
      display: "flex", alignItems: "center", padding: "0 20px", gap: 12,
      boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
    }}>
      <button onClick={onHamburger} style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", fontSize: 20, padding: "0 4px" }} className="hamburger-top">☰</button>
      <span style={{ color: C.muted, fontSize: 13 }}>QuantumGuard</span>
      <span style={{ color: C.greenMid, fontSize: 13 }}>›</span>
      <span style={{ color: C.text, fontSize: 14, fontWeight: 600 }}>{title}</span>
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, background: C.greenLighter, padding: "4px 10px", borderRadius: 20, border: `1px solid ${C.greenMid}` }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: C.green }}></div>
          <span style={{ fontSize: 11, color: C.green, fontWeight: 600 }}>API Online</span>
        </div>
        <span style={{ fontSize: 11, color: C.muted }}>{new Date().toLocaleDateString("en-US", { weekday: "short", month: "short", day: "numeric" })}</span>
        {user ? (
          <button onClick={onLogout} style={{ background: "transparent", border: `1px solid ${C.panelBorder}`, borderRadius: 8, padding: "4px 12px", cursor: "pointer", color: C.muted, fontSize: 11 }}>
            {user.displayName?.split(" ")[0]} · Sign Out
          </button>
        ) : (
          <button onClick={onLogin} style={{ background: C.green, border: "none", borderRadius: 8, padding: "6px 16px", cursor: "pointer", color: C.white, fontSize: 12, fontWeight: 600 }}>
            Sign In
          </button>
        )}
      </div>
    </div>
  );
}

// ── Panel ─────────────────────────────────────────────────────
function Panel({ title, children, style = {}, accent = false }) {
  return (
    <div style={{ background: C.white, border: `1px solid ${C.panelBorder}`, borderRadius: 12, marginBottom: 16, overflow: "hidden", boxShadow: "0 1px 4px rgba(0,0,0,0.04)", ...style }}>
      {title && (
        <div style={{ padding: "12px 18px", borderBottom: `1px solid ${C.panelBorder}`, background: accent ? C.greenLighter : C.white, display: "flex", alignItems: "center", gap: 8 }}>
          {accent && <div style={{ width: 3, height: 16, background: C.green, borderRadius: 2 }}></div>}
          <span style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{title}</span>
        </div>
      )}
      <div style={{ padding: 18 }}>{children}</div>
    </div>
  );
}

// ── Metric ────────────────────────────────────────────────────
function Metric({ label, value, suffix = "", color, desc, icon }) {
  return (
    <div style={{ background: C.white, border: `1px solid ${C.panelBorder}`, borderRadius: 12, padding: "18px 20px", boxShadow: "0 1px 4px rgba(0,0,0,0.04)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
        <div style={{ fontSize: 12, color: C.muted, fontWeight: 500 }}>{label}</div>
        {icon && <div style={{ fontSize: 20 }}>{icon}</div>}
      </div>
      <div style={{ fontSize: 38, fontWeight: 800, color: color || C.text, lineHeight: 1 }}>
        {value}<span style={{ fontSize: 14, color: C.muted, fontWeight: 400 }}>{suffix}</span>
      </div>
      {desc && <div style={{ fontSize: 11, color: C.muted, marginTop: 6 }}>{desc}</div>}
    </div>
  );
}

// ── SevBar ────────────────────────────────────────────────────
function SevBar({ label, count, total, color }) {
  const pct = total > 0 ? Math.round(count / total * 100) : 0;
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
        <span style={{ color, fontWeight: 600 }}>{label}</span>
        <span style={{ color: C.muted }}>{count} ({pct}%)</span>
      </div>
      <div style={{ background: C.input, borderRadius: 4, height: 8 }}>
        <div style={{ background: color, height: 8, borderRadius: 4, width: `${pct}%`, transition: "width 0.6s" }}></div>
      </div>
    </div>
  );
}

// ── Badge ─────────────────────────────────────────────────────
function Badge({ text, color, bg }) {
  return (
    <span style={{ background: bg, color, padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700 }}>{text}</span>
  );
}

// ══════════════════════════════════════════════════════════════
// SCANNER PAGE
// ══════════════════════════════════════════════════════════════
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
  const [checklist, setChecklist] = useState({});
  const [saved, setSaved] = useState(false);
  const [emailInput, setEmailInput] = useState("");
  const [emailSent, setEmailSent] = useState(false);
  const [sendingEmail, setSendingEmail] = useState(false);
  const [aiModal, setAiModal] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiResult, setAiResult] = useState(null);
  const intervalRef = useRef(null);

  const startProgress = () => {
    setProgress(0); setStepIndex(0); let p = 0;
    intervalRef.current = setInterval(() => {
      p += Math.random() * 8 + 2; if (p > 92) p = 92;
      setProgress(Math.round(p));
      setStepIndex(Math.min(SCAN_STEPS.length - 1, Math.floor(p / (100 / SCAN_STEPS.length))));
    }, 400);
  };
  const stopProgress = () => { clearInterval(intervalRef.current); setProgress(100); setStepIndex(SCAN_STEPS.length - 1); };

  const handleScan = async () => {
    setLoading(true); setError(null); setResult(null); setChecklist({}); setSaved(false);
    startProgress();
    try {
      let res;
      if (mode === "zip") {
        if (!file) throw new Error("Please select a ZIP file");
        const fd = new FormData(); fd.append("file", file);
        res = await fetch(`${API}/public-scan-zip`, { method: "POST", body: fd });
      } else if (mode === "github") {
        if (!input) throw new Error("Please enter a GitHub URL");
        res = await fetch(`${API}/scan-github`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ github_url: input, ...(githubToken ? { github_token: githubToken } : {}) }) });
      } else {
        if (!input) throw new Error("Please enter a path");
        res = await fetch(`${API}/scan`, { method: "POST", headers: { "Content-Type": "application/json", "x-api-key": "quantumguard-secret-2026" }, body: JSON.stringify({ directory: input }) });
      }
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Scan failed");
      stopProgress(); setResult(data);
      if (user) {
        await addDoc(collection(db, "scans"), { userId: user.uid, userEmail: user.email, filename: file?.name || input || "scan", score: data.quantum_readiness_score, findings: data.total_findings, createdAt: new Date() });
        await incrementScanCount(user.uid); setSaved(true);
      }
    } catch (e) { stopProgress(); setError(typeof e.message === "string" ? e.message : "Scan failed."); }
    setLoading(false);
  };

  const handleEmail = async () => {
    if (!emailInput || !result) return; setSendingEmail(true);
    try {
      await emailjs.send("service_vy8yxbq", "template_mgydwpx", { to_email: emailInput, score: result.quantum_readiness_score, total: result.total_findings, filename: file?.name || input || "scan" }, "vATUvI1IlAtH0ooKaQlY9");
      setEmailSent(true); setTimeout(() => setEmailSent(false), 3000);
    } catch (e) { alert("Email failed."); }
    setSendingEmail(false);
  };

  const handleAiFix = async (finding) => {
    setAiModal(finding); setAiLoading(true); setAiResult(null);
    try {
      const res = await fetch(`${API}/ai-fix`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ finding }) });
      const data = await res.json();
      setAiResult(data.fix || "Could not generate fix.");
    } catch (e) { setAiResult("Error calling AI. Please try again."); }
    setAiLoading(false);
  };

  const scoreColor = result ? (result.quantum_readiness_score >= 70 ? C.green : result.quantum_readiness_score >= 40 ? C.amber : C.red) : C.muted;
  const sev = result ? { CRITICAL: result.findings.filter(f => f.severity === "CRITICAL").length, HIGH: result.findings.filter(f => f.severity === "HIGH").length, MEDIUM: result.findings.filter(f => f.severity === "MEDIUM").length } : null;
  const filtered = result ? result.findings.filter(f => (filter === "ALL" || f.severity === filter) && (search === "" || f.file.toLowerCase().includes(search.toLowerCase()) || f.code.toLowerCase().includes(search.toLowerCase()))) : [];
  const grouped = filtered.reduce((a, f) => { if (!a[f.file]) a[f.file] = []; a[f.file].push(f); return a; }, {});

  const handleNIST = () => {
    if (!result) return;
    const NIST_MAP = {
      RSA: { id: "NIST SP 800-131A", fix: "CRYSTALS-Kyber (ML-KEM) — FIPS 203", level: "CRITICAL" },
      ECC: { id: "NIST SP 800-186", fix: "CRYSTALS-Dilithium (ML-DSA) — FIPS 204", level: "CRITICAL" },
      DH: { id: "NIST SP 800-56A", fix: "CRYSTALS-Kyber (ML-KEM) — FIPS 203", level: "HIGH" },
      DSA: { id: "NIST SP 800-186", fix: "CRYSTALS-Dilithium (ML-DSA) — FIPS 204", level: "HIGH" },
      MD5: { id: "NIST SP 800-107", fix: "SHA-3-256 — FIPS 202", level: "MEDIUM" },
      SHA1: { id: "NIST SP 800-107", fix: "SHA-3-256 — FIPS 202", level: "MEDIUM" },
      RC4: { id: "NIST SP 800-175B", fix: "AES-256-GCM — FIPS 197", level: "CRITICAL" },
      DES: { id: "NIST SP 800-131A", fix: "AES-256-GCM — FIPS 197", level: "CRITICAL" },
      ECB: { id: "NIST SP 800-38A", fix: "AES-256-GCM — FIPS 197", level: "HIGH" },
      TLS: { id: "NIST SP 800-52 Rev 2", fix: "TLS 1.3 — RFC 8446", level: "HIGH" },
      JWT: { id: "NIST SP 800-131A", fix: "RS256 with post-quantum keys", level: "CRITICAL" },
      WEAK_RANDOM: { id: "NIST SP 800-90A", fix: "DRBG / secrets module", level: "MEDIUM" },
    };
    const getNIST = (vuln) => {
      const key = Object.keys(NIST_MAP).find(k => vuln.toUpperCase().includes(k));
      return key ? NIST_MAP[key] : { id: "NIST SP 800-175B", fix: "See NIST PQC standards", level: vuln };
    };
    const win = window.open("", "_blank");
    const critCount = result.findings.filter(f => f.severity === "CRITICAL").length;
    const highCount = result.findings.filter(f => f.severity === "HIGH").length;
    const medCount = result.findings.filter(f => f.severity === "MEDIUM").length;
    const complianceStatus = result.quantum_readiness_score >= 70 ? "COMPLIANT" : result.quantum_readiness_score >= 40 ? "PARTIALLY COMPLIANT" : "NON-COMPLIANT";
    const statusColor = result.quantum_readiness_score >= 70 ? "#16a34a" : result.quantum_readiness_score >= 40 ? "#d97706" : "#dc2626";
    win.document.write(`<!DOCTYPE html>
<html>
<head>
<title>QuantumGuard NIST Compliance Report</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; margin: 0; padding: 0; background: #f8faf8; color: #1a1a1a; }
  .header { background: #16a34a; padding: 32px 48px; }
  .header-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
  .logo { display: flex; align-items: center; gap: 12px; }
  .logo-icon { width: 44px; height: 44px; background: rgba(255,255,255,0.2); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 22px; }
  .logo-text { font-size: 22px; font-weight: 800; color: white; }
  .report-badge { background: rgba(255,255,255,0.2); padding: 6px 16px; border-radius: 20px; color: white; font-size: 12px; font-weight: 600; }
  h1 { font-size: 28px; font-weight: 800; color: white; margin: 0 0 6px; }
  .header-sub { font-size: 13px; color: rgba(255,255,255,0.8); }
  .container { max-width: 960px; margin: 0 auto; padding: 32px 48px; }
  .meta-grid { display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 28px; }
  .meta-card { background: white; border: 1px solid #e2f0e2; border-radius: 12px; padding: 16px; text-align: center; }
  .meta-label { font-size: 11px; color: #6b7280; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }
  .meta-value { font-size: 28px; font-weight: 800; }
  .meta-desc { font-size: 11px; color: #6b7280; margin-top: 4px; }
  .status-box { background: white; border: 2px solid ${statusColor}; border-radius: 12px; padding: 20px 24px; margin-bottom: 28px; display: flex; justify-content: space-between; align-items: center; }
  .status-label { font-size: 13px; color: #6b7280; margin-bottom: 4px; }
  .status-value { font-size: 22px; font-weight: 800; color: ${statusColor}; }
  .section { background: white; border: 1px solid #e2f0e2; border-radius: 12px; margin-bottom: 20px; overflow: hidden; }
  .section-header { background: #f0fdf4; padding: 14px 20px; border-bottom: 1px solid #e2f0e2; display: flex; justify-content: space-between; align-items: center; }
  .section-title { font-size: 14px; font-weight: 700; color: #15803d; }
  .section-body { padding: 20px; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { background: #16a34a; color: white; padding: 10px 12px; text-align: left; font-size: 11px; font-weight: 600; }
  td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
  tr:nth-child(even) td { background: #f9fafb; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; }
  .CRITICAL { background: #fee2e2; color: #dc2626; }
  .HIGH { background: #fef3c7; color: #d97706; }
  .MEDIUM { background: #fef9c3; color: #ca8a04; }
  .nist-ref { font-family: monospace; font-size: 10px; color: #2563eb; background: #dbeafe; padding: 2px 6px; border-radius: 4px; }
  .fix { color: #16a34a; font-weight: 500; }
  .footer { background: #16a34a; padding: 20px 48px; margin-top: 32px; display: flex; justify-content: space-between; align-items: center; }
  .footer-text { color: rgba(255,255,255,0.8); font-size: 11px; }
  .footer-logo { color: white; font-weight: 700; font-size: 13px; }
  .exec-row { display: flex; gap: 32px; }
  .exec-item { flex: 1; }
  .exec-label { font-size: 11px; color: #6b7280; margin-bottom: 4px; }
  .exec-value { font-size: 14px; font-weight: 600; color: #1a1a1a; }
  @media print { body { background: white; } }
</style>
</head>
<body>
<div class="header">
  <div class="header-top">
    <div class="logo">
      <div class="logo-icon">⚛</div>
      <div class="logo-text">QuantumGuard</div>
    </div>
    <div class="report-badge">NIST PQC Compliance Report</div>
  </div>
  <h1>Quantum Cryptography Compliance Assessment</h1>
  <div class="header-sub">Generated: ${new Date().toLocaleString()} &nbsp;·&nbsp; Framework: NIST Post-Quantum Cryptography Standards 2024 &nbsp;·&nbsp; quantumguard.site</div>
</div>

<div class="container">

  <div class="meta-grid">
    <div class="meta-card">
      <div class="meta-label">Quantum Readiness Score</div>
      <div class="meta-value" style="color:${scoreColor}">${result.quantum_readiness_score}</div>
      <div class="meta-desc">out of 100</div>
    </div>
    <div class="meta-card">
      <div class="meta-label">Total Findings</div>
      <div class="meta-value" style="color:#dc2626">${result.total_findings}</div>
      <div class="meta-desc">vulnerabilities detected</div>
    </div>
    <div class="meta-card">
      <div class="meta-label">Critical</div>
      <div class="meta-value" style="color:#dc2626">${critCount}</div>
      <div class="meta-desc">immediate action required</div>
    </div>
    <div class="meta-card">
      <div class="meta-label">High Risk</div>
      <div class="meta-value" style="color:#d97706">${highCount}</div>
      <div class="meta-desc">requires attention</div>
    </div>
  </div>

  <div class="status-box">
    <div>
      <div class="status-label">Overall NIST PQC Compliance Status</div>
      <div class="status-value">${complianceStatus}</div>
    </div>
    <div class="exec-row">
      <div class="exec-item">
        <div class="exec-label">Target</div>
        <div class="exec-value">${result.github_url || "Uploaded ZIP"}</div>
      </div>
      <div class="exec-item">
        <div class="exec-label">Assessment Date</div>
        <div class="exec-value">${new Date().toLocaleDateString()}</div>
      </div>
      <div class="exec-item">
        <div class="exec-label">Framework</div>
        <div class="exec-value">NIST FIPS 203/204/205</div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-title">📋 Executive Summary</div>
    </div>
    <div class="section-body">
      <p style="font-size:13px;color:#374151;line-height:1.7;margin-bottom:12px;">
        This report presents the findings of a quantum cryptography vulnerability assessment conducted using QuantumGuard. The assessment evaluated the target codebase against NIST post-quantum cryptography standards published in 2024, including FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).
      </p>
      <p style="font-size:13px;color:#374151;line-height:1.7;margin-bottom:12px;">
        The assessment identified <strong>${result.total_findings} quantum-vulnerable cryptographic implementations</strong> across the codebase, resulting in a Quantum Readiness Score of <strong style="color:${statusColor}">${result.quantum_readiness_score}/100</strong>. Immediate remediation is recommended for all CRITICAL findings to ensure compliance with emerging post-quantum cryptography mandates.
      </p>
      <p style="font-size:13px;color:#374151;line-height:1.7;">
        Organizations must migrate from vulnerable algorithms to NIST-approved post-quantum alternatives before the Year-to-Quantum (Y2Q) deadline, estimated at approximately 2030.
      </p>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-title">🏛 NIST Framework Reference</div>
    </div>
    <div class="section-body">
      <table>
        <tr><th>NIST Standard</th><th>Algorithm</th><th>Purpose</th><th>Status</th></tr>
        <tr><td><span class="nist-ref">FIPS 203</span></td><td>ML-KEM (CRYSTALS-Kyber)</td><td>Key Encapsulation Mechanism</td><td style="color:#16a34a;font-weight:600">✓ Recommended</td></tr>
        <tr><td><span class="nist-ref">FIPS 204</span></td><td>ML-DSA (CRYSTALS-Dilithium)</td><td>Digital Signature</td><td style="color:#16a34a;font-weight:600">✓ Recommended</td></tr>
        <tr><td><span class="nist-ref">FIPS 205</span></td><td>SLH-DSA (SPHINCS+)</td><td>Hash-based Signature</td><td style="color:#16a34a;font-weight:600">✓ Recommended</td></tr>
        <tr><td><span class="nist-ref">FIPS 202</span></td><td>SHA-3 / SHAKE</td><td>Hash Function</td><td style="color:#16a34a;font-weight:600">✓ Quantum Safe</td></tr>
        <tr><td><span class="nist-ref">NIST SP 800-131A</span></td><td>RSA, DSA, DH, ECC</td><td>Legacy Algorithms</td><td style="color:#dc2626;font-weight:600">✗ Deprecated for PQC</td></tr>
        <tr><td><span class="nist-ref">NIST SP 800-107</span></td><td>SHA-1, MD5</td><td>Legacy Hash Functions</td><td style="color:#dc2626;font-weight:600">✗ Deprecated</td></tr>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-title">🔍 Detailed Findings — ${result.total_findings} Vulnerabilities</div>
      <div style="font-size:11px;color:#6b7280">Sorted by severity · NIST references included</div>
    </div>
    <div class="section-body">
      <table>
        <tr><th>Severity</th><th>File</th><th>Line</th><th>Vulnerable Code</th><th>NIST Reference</th><th>Recommended Fix</th></tr>
        ${result.findings.map(f => {
          const nist = getNIST(f.vulnerability || f.replacement || "");
          const sevClass = f.severity;
          return `<tr>
            <td><span class="badge ${sevClass}">${f.severity}</span></td>
            <td style="font-family:monospace;font-size:10px;color:#2563eb">${f.file.split("/").pop()}</td>
            <td style="font-family:monospace;font-size:10px">${f.line}</td>
            <td style="font-family:monospace;font-size:10px;max-width:200px;word-break:break-all">${f.code.substring(0,60)}${f.code.length>60?"...":""}</td>
            <td><span class="nist-ref">${nist.id}</span></td>
            <td class="fix" style="font-size:10px">${f.replacement}</td>
          </tr>`;
        }).join("")}
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-title">📊 Severity Distribution</div>
    </div>
    <div class="section-body">
      <table>
        <tr><th>Severity Level</th><th>Count</th><th>Percentage</th><th>Priority</th><th>Recommended Timeline</th></tr>
        <tr><td><span class="badge CRITICAL">CRITICAL</span></td><td>${critCount}</td><td>${result.total_findings > 0 ? Math.round(critCount/result.total_findings*100) : 0}%</td><td>Immediate</td><td>Fix within 7 days</td></tr>
        <tr><td><span class="badge HIGH">HIGH</span></td><td>${highCount}</td><td>${result.total_findings > 0 ? Math.round(highCount/result.total_findings*100) : 0}%</td><td>Urgent</td><td>Fix within 30 days</td></tr>
        <tr><td><span class="badge MEDIUM">MEDIUM</span></td><td>${medCount}</td><td>${result.total_findings > 0 ? Math.round(medCount/result.total_findings*100) : 0}%</td><td>Important</td><td>Fix within 90 days</td></tr>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-header">
      <div class="section-title">✅ Remediation Recommendations</div>
    </div>
    <div class="section-body">
      <p style="font-size:13px;color:#374151;line-height:1.7;margin-bottom:16px;">Based on the findings, the following remediation steps are recommended in priority order:</p>
      <table>
        <tr><th>#</th><th>Action</th><th>Algorithm</th><th>NIST Standard</th><th>Priority</th></tr>
        <tr><td>1</td><td>Replace all RSA implementations</td><td>CRYSTALS-Kyber (ML-KEM)</td><td><span class="nist-ref">FIPS 203</span></td><td><span class="badge CRITICAL">CRITICAL</span></td></tr>
        <tr><td>2</td><td>Replace all ECC/ECDSA implementations</td><td>CRYSTALS-Dilithium (ML-DSA)</td><td><span class="nist-ref">FIPS 204</span></td><td><span class="badge CRITICAL">CRITICAL</span></td></tr>
        <tr><td>3</td><td>Replace RC4, DES, 3DES ciphers</td><td>AES-256-GCM</td><td><span class="nist-ref">FIPS 197</span></td><td><span class="badge CRITICAL">CRITICAL</span></td></tr>
        <tr><td>4</td><td>Upgrade TLS to version 1.3 minimum</td><td>TLS 1.3 with PQC cipher suites</td><td><span class="nist-ref">NIST SP 800-52 Rev 2</span></td><td><span class="badge HIGH">HIGH</span></td></tr>
        <tr><td>5</td><td>Replace MD5 and SHA-1 hash functions</td><td>SHA-3-256 or BLAKE3</td><td><span class="nist-ref">FIPS 202</span></td><td><span class="badge MEDIUM">MEDIUM</span></td></tr>
      </table>
    </div>
  </div>

</div>

<div class="footer">
  <div class="footer-logo">⚛ QuantumGuard</div>
  <div class="footer-text">Generated by QuantumGuard · quantumguard.site · NIST PQC Framework 2024 · ${new Date().toLocaleDateString()}</div>
  <div class="footer-text">This report is for informational purposes. Consult a qualified security professional before implementation.</div>
</div>

<script>window.print();</script>
</body>
</html>`);
    win.document.close();
  };

  const handleCSV = () => {
    if (!result) return;
    const blob = new Blob(["Severity,File,Line,Code,Fix\n" + result.findings.map(f => `"${f.severity}","${f.file}","${f.line}","${f.code.replace(/"/g, "'")}","${f.replacement}"`).join("\n")], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "quantumguard.csv"; a.click();
  };

  const handlePDF = () => {
    if (!result) return;
    const win = window.open("", "_blank");
    win.document.write(`<html><head><title>QuantumGuard Report</title><style>body{font-family:'Segoe UI',sans-serif;padding:40px;background:#f8faf8;color:#1a1a1a;}h1{color:#16a34a;border-bottom:3px solid #16a34a;padding-bottom:12px;}.score{font-size:64px;font-weight:800;color:${scoreColor};}.finding{border-left:4px solid #dc2626;padding:10px 16px;margin:8px 0;background:#fff;border-radius:0 8px 8px 0;box-shadow:0 1px 4px rgba(0,0,0,0.06);}.HIGH{border-color:#d97706;}.MEDIUM{border-color:#ca8a04;}code{background:#f0fdf4;padding:3px 8px;border-radius:4px;font-size:12px;color:#15803d;}</style></head><body><h1>⚛ QuantumGuard Threat Report</h1><p>Generated: ${new Date().toLocaleString()}</p><p>Target: ${result.github_url || "ZIP Upload"}</p><div class="score">${result.quantum_readiness_score}/100</div><p>Total: ${result.total_findings} | Critical: ${sev?.CRITICAL} | High: ${sev?.HIGH} | Medium: ${sev?.MEDIUM}</p><hr/>${result.findings.map(f => `<div class="finding ${f.severity}"><b>[${f.severity}]</b> ${f.file.split("/").pop()}:${f.line}<br/><code>${f.code}</code><br/>Fix: ${f.replacement}</div>`).join("")}</body></html>`);
    win.document.close(); win.print();
  };

  const btnStyle = (active) => ({
    padding: "8px 16px", borderRadius: 8, border: `1.5px solid ${active ? C.green : C.panelBorder}`,
    background: active ? C.greenLight : C.white, color: active ? C.green : C.muted,
    cursor: "pointer", fontSize: 12, fontWeight: active ? 600 : 400, transition: "all 0.15s",
  });

  return (
    <div style={{ padding: 20 }}>
      <Panel title="Scan Target" accent>
        <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
          {[{ id: "github", label: "🔗 GitHub URL" }, { id: "zip", label: "📁 Upload ZIP" }, { id: "path", label: "🖥️ Server Path" }].map(m => (
            <button key={m.id} onClick={() => setMode(m.id)} style={btnStyle(mode === m.id)}>{m.label}</button>
          ))}
        </div>
        {mode === "zip" ? (
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <input type="file" accept=".zip" onChange={e => setFile(e.target.files[0])} style={{ flex: 1, minWidth: 200, padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
            <button onClick={handleScan} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: C.green, color: C.white, border: "none", cursor: "pointer", fontSize: 13, fontWeight: 600 }}>{loading ? "Scanning..." : "▶ Run Scan"}</button>
          </div>
        ) : mode === "github" ? (
          <div>
            <div style={{ display: "flex", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
              <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && handleScan()} placeholder="https://github.com/username/repo" style={{ flex: 1, minWidth: 200, padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
              <button onClick={handleScan} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: loading ? "#86efac" : C.green, color: C.white, border: "none", cursor: loading ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600 }}>{loading ? "Scanning..." : "▶ Run Scan"}</button>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <button onClick={() => setShowToken(!showToken)} style={{ background: "transparent", border: `1px solid ${C.panelBorder}`, borderRadius: 6, padding: "4px 12px", cursor: "pointer", color: C.muted, fontSize: 11 }}>🔒 {showToken ? "Hide Token" : "Private Repo"}</button>
              {showToken && <input value={githubToken} onChange={e => setGithubToken(e.target.value)} placeholder="GitHub Personal Access Token" type="password" style={{ flex: 1, padding: "4px 12px", borderRadius: 6, border: `1px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 11 }} />}
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <input value={input} onChange={e => setInput(e.target.value)} placeholder="/app/src" style={{ flex: 1, minWidth: 200, padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
            <button onClick={handleScan} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: C.green, color: C.white, border: "none", cursor: "pointer", fontSize: 13, fontWeight: 600 }}>{loading ? "Scanning..." : "▶ Run Scan"}</button>
          </div>
        )}
        {loading && (
          <div style={{ marginTop: 14, background: C.greenLighter, borderRadius: 8, padding: "12px 16px", border: `1px solid ${C.greenMid}` }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: C.green, marginBottom: 6, fontWeight: 500 }}>
              <span>✦ {SCAN_STEPS[stepIndex]}</span><span>{progress}%</span>
            </div>
            <div style={{ background: C.greenMid, borderRadius: 4, height: 6 }}>
              <div style={{ background: C.green, height: 6, borderRadius: 4, width: `${progress}%`, transition: "width 0.4s ease" }}></div>
            </div>
          </div>
        )}
        {error && <div style={{ marginTop: 12, background: C.redLight, border: `1px solid #fca5a5`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 13 }}>⚠ {error}</div>}
        {saved && <div style={{ marginTop: 10, background: C.greenLighter, border: `1px solid ${C.greenMid}`, borderRadius: 8, padding: "8px 14px", color: C.green, fontSize: 12, fontWeight: 500 }}>✓ Scan saved to history</div>}
      </Panel>

      {result && (
        <>
          <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
            <Metric label="Quantum Readiness Score" value={result.quantum_readiness_score} suffix="/100" color={scoreColor} icon={result.quantum_readiness_score >= 70 ? "✅" : result.quantum_readiness_score >= 40 ? "⚠️" : "🚨"} desc={result.quantum_readiness_score >= 70 ? "Quantum Safe" : result.quantum_readiness_score >= 40 ? "At Risk" : "Critical Risk"} />
            <Metric label="Total Threats" value={result.total_findings} color={C.red} icon="🔍" desc="vulnerabilities detected" />
            <Metric label="Critical" value={sev.CRITICAL} color={C.critical} icon="🔴" desc="immediate action required" />
            <Metric label="High Risk" value={sev.HIGH} color={C.amber} icon="🟡" desc="requires attention" />
          </div>

          <div className="charts-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
            <Panel title="Severity Distribution" accent>
              <SevBar label="Critical" count={sev.CRITICAL} total={result.total_findings} color={C.critical} />
              <SevBar label="High" count={sev.HIGH} total={result.total_findings} color={C.amber} />
              <SevBar label="Medium" count={sev.MEDIUM} total={result.total_findings} color={C.medium} />
            </Panel>
            <Panel title="Score Breakdown" accent>
              <SevBar label="Crypto Issues (RSA/ECC/RC4/DES)" count={sev.CRITICAL} total={result.total_findings} color={C.critical} />
              <SevBar label="TLS / Protocol" count={sev.HIGH} total={result.total_findings} color={C.amber} />
              <SevBar label="Hash / Secrets" count={sev.MEDIUM} total={result.total_findings} color={C.medium} />
              <div style={{ fontSize: 11, color: C.muted, marginTop: 10, background: C.input, padding: "6px 10px", borderRadius: 6 }}>
                Score = 100 − (CRITICAL×10) − (HIGH×6) − (MEDIUM×3)
              </div>
            </Panel>
          </div>

          <Panel title="Export & Share" accent>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
              <button onClick={handlePDF} style={{ padding: "8px 16px", borderRadius: 8, background: C.green, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📄 PDF Report</button>
              <button onClick={handleNIST} style={{ padding: "8px 16px", borderRadius: 8, background: C.blue, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>🏛 NIST Report</button>
              <button onClick={handleCSV} style={{ padding: "8px 16px", borderRadius: 8, background: C.greenLight, color: C.green, border: `1px solid ${C.greenMid}`, cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📊 CSV Export</button>
              <button onClick={() => navigator.clipboard.writeText(result.findings.map(f => `[${f.severity}] ${f.file}:${f.line} — ${f.code} → ${f.replacement}`).join("\n"))} style={{ padding: "8px 16px", borderRadius: 8, background: C.white, color: C.muted, border: `1px solid ${C.panelBorder}`, cursor: "pointer", fontSize: 12 }}>📋 Copy All</button>
              <button onClick={() => { const t = encodeURIComponent("QuantumGuard: " + result.quantum_readiness_score + "/100 — " + result.total_findings + " vulnerabilities\nquantumguard.site #QuantumSecurity"); window.open("https://twitter.com/intent/tweet?text=" + t, "_blank"); }} style={{ padding: "8px 16px", borderRadius: 8, background: "#1DA1F2", color: C.white, border: "none", cursor: "pointer", fontSize: 12 }}>🐦 Share</button>
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <input value={emailInput} onChange={e => setEmailInput(e.target.value)} placeholder="Email report to..." type="email" style={{ flex: 1, minWidth: 200, padding: "8px 14px", borderRadius: 8, border: `1px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 12 }} />
              <button onClick={handleEmail} disabled={sendingEmail || !emailInput} style={{ padding: "8px 16px", borderRadius: 8, background: emailSent ? C.green : C.green, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>{emailSent ? "✓ Sent!" : sendingEmail ? "Sending..." : "📧 Send Email"}</button>
            </div>
          </Panel>

          <Panel title={`Threat Intelligence — ${result.total_findings} findings`} accent>
            <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
              {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map(f => (
                <button key={f} onClick={() => setFilter(f)} style={{ padding: "5px 14px", borderRadius: 20, border: `1.5px solid ${filter === f ? C.green : C.panelBorder}`, background: filter === f ? C.greenLight : C.white, color: filter === f ? C.green : C.muted, cursor: "pointer", fontSize: 11, fontWeight: filter === f ? 600 : 400 }}>
                  {f} {f !== "ALL" && sev ? `(${sev[f]})` : ""}
                </button>
              ))}
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search..." style={{ padding: "5px 12px", borderRadius: 20, border: `1px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 11, width: 120, marginLeft: "auto" }} />
            </div>

            {Object.entries(grouped).map(([file, findings], gi) => (
              <div key={gi} style={{ marginBottom: 12, border: `1px solid ${C.panelBorder}`, borderRadius: 10, overflow: "hidden" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 16px", background: C.greenLighter, borderBottom: `1px solid ${C.panelBorder}`, flexWrap: "wrap", gap: 4 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <span style={{ color: C.green }}>📄</span>
                    <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{file.split("/").pop()}</span>
                    <span style={{ fontSize: 10, color: C.muted }}>{file}</span>
                  </div>
                  <Badge text={`${findings.length} threats`} color={C.red} bg={C.redLight} />
                </div>
                <div style={{ padding: 14 }}>
                  {findings.map((f, i) => {
                    const key = `${f.file}:${f.line}`;
                    const sevColor = f.severity === "CRITICAL" ? C.critical : f.severity === "HIGH" ? C.amber : C.medium;
                    const sevBg = f.severity === "CRITICAL" ? C.redLight : f.severity === "HIGH" ? C.amberLight : "#fef9c3";
                    return (
                      <div key={i} style={{ borderLeft: `3px solid ${sevColor}`, paddingLeft: 14, marginBottom: i < findings.length - 1 ? 16 : 0, opacity: checklist[key] ? 0.4 : 1 }}>
                        <div style={{ display: "flex", gap: 8, marginBottom: 6, alignItems: "center", flexWrap: "wrap" }}>
                          <input type="checkbox" checked={!!checklist[key]} onChange={() => setChecklist(p => ({ ...p, [key]: !p[key] }))} style={{ cursor: "pointer" }} />
                          <Badge text={f.severity} color={sevColor} bg={sevBg} />
                          <span style={{ color: C.muted, fontSize: 11 }}>Line {f.line}</span>
                          {checklist[key] && <Badge text="✓ Remediated" color={C.green} bg={C.greenLight} />}
                          <button onClick={() => handleAiFix(f)} style={{ marginLeft: "auto", padding: "2px 10px", borderRadius: 6, background: C.greenLight, border: `1px solid ${C.greenMid}`, color: C.green, cursor: "pointer", fontSize: 10, fontWeight: 600 }}>⚡ AI Fix</button>
                        </div>
                        <div style={{ fontFamily: "monospace", background: C.input, padding: "8px 12px", borderRadius: 6, fontSize: 11, marginBottom: 6, color: C.greenDark, overflowX: "auto" }}>{f.code}</div>
                        <div style={{ fontSize: 11, color: C.muted }}>Fix: <span style={{ color: C.green, fontWeight: 500 }}>{f.replacement}</span></div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
            {filtered.length === 0 && <div style={{ textAlign: "center", padding: 24, color: C.muted }}>No findings match filter.</div>}
          </Panel>
        </>
      )}

      {aiModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 999, display: "flex", alignItems: "center", justifyContent: "center", padding: 16 }}>
          <div style={{ background: C.white, borderRadius: 16, width: "100%", maxWidth: 640, maxHeight: "80vh", display: "flex", flexDirection: "column", boxShadow: "0 20px 60px rgba(0,0,0,0.2)" }}>
            <div style={{ padding: "14px 18px", borderBottom: `1px solid ${C.panelBorder}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{ width: 32, height: 32, borderRadius: 8, background: C.green, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>⚡</div>
                <span style={{ fontSize: 14, fontWeight: 700, color: C.text }}>AI Migration Assistant</span>
              </div>
              <button onClick={() => { setAiModal(null); setAiResult(null); }} style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", fontSize: 20 }}>✕</button>
            </div>
            <div style={{ padding: 16, borderBottom: `1px solid ${C.panelBorder}`, background: C.greenLighter }}>
              <div style={{ fontSize: 11, color: C.muted, marginBottom: 4 }}>Vulnerable Code</div>
              <div style={{ fontFamily: "monospace", fontSize: 12, color: C.red, background: C.white, padding: "8px 12px", borderRadius: 8, border: `1px solid #fca5a5` }}>{aiModal.code}</div>
              <div style={{ fontSize: 11, color: C.muted, marginTop: 8 }}>{aiModal.file.split("/").pop()}:{aiModal.line} · <Badge text={aiModal.severity} color={C.critical} bg={C.redLight} /></div>
            </div>
            <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
              {aiLoading ? (
                <div style={{ textAlign: "center", padding: 32 }}>
                  <div style={{ fontSize: 32, marginBottom: 12 }}>⚡</div>
                  <div style={{ fontSize: 13, color: C.green, fontWeight: 600 }}>Generating AI fix...</div>
                </div>
              ) : aiResult ? (
                <div>
                  <div style={{ fontSize: 12, color: C.muted, marginBottom: 8, fontWeight: 500 }}>AI Recommendation</div>
                  <div style={{ fontFamily: "monospace", fontSize: 12, color: C.text, lineHeight: 1.8, whiteSpace: "pre-wrap", background: C.input, padding: 14, borderRadius: 8, border: `1px solid ${C.panelBorder}` }}>{aiResult}</div>
                  <button onClick={() => navigator.clipboard.writeText(aiResult)} style={{ marginTop: 12, padding: "7px 16px", borderRadius: 8, background: C.green, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>Copy Fix</button>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// AGILITY PAGE
// ══════════════════════════════════════════════════════════════
function AgilityPage() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleCheck = async () => {
    if (!input) return; setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`${API}/check-agility`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ github_url: input }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Check failed");
      setResult(data);
    } catch (e) { setError(typeof e.message === "string" ? e.message : "Check failed."); }
    setLoading(false);
  };

  const agilityColor = result ? (result.agility_score >= 70 ? C.green : result.agility_score >= 40 ? C.amber : C.red) : C.muted;

  return (
    <div style={{ padding: 20 }}>
      <Panel title="Crypto Agility Analysis" accent>
        <div style={{ fontSize: 13, color: C.muted, marginBottom: 14, lineHeight: 1.7, background: C.greenLighter, padding: "10px 14px", borderRadius: 8 }}>
          <strong style={{ color: C.green }}>Crypto Agility</strong> = ability to swap encryption algorithms without major code changes.
          Hardcoded algorithms score <strong style={{ color: C.red }}>zero agility</strong>. Configurable algorithms score <strong style={{ color: C.green }}>high agility</strong>.
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && handleCheck()} placeholder="https://github.com/username/repo" style={{ flex: 1, minWidth: 200, padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
          <button onClick={handleCheck} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: loading ? "#86efac" : C.green, color: C.white, border: "none", cursor: loading ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600 }}>{loading ? "Analyzing..." : "🔬 Check Agility"}</button>
        </div>
        {error && <div style={{ marginTop: 12, background: C.redLight, border: `1px solid #fca5a5`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 13 }}>⚠ {error}</div>}
      </Panel>

      {result && (
        <>
          <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12, marginBottom: 16 }}>
            <Metric label="Agility Score" value={result.agility_score} suffix="/100" color={agilityColor} icon="🔬" desc={result.agility_score >= 70 ? "High Agility" : result.agility_score >= 40 ? "Partial Agility" : "Low Agility"} />
            <Metric label="Hardcoded Crypto" value={result.hardcoded_count} color={C.red} icon="🔴" desc="needs to be configurable" />
            <Metric label="Configurable Crypto" value={result.configurable_count} color={C.green} icon="✅" desc="already agile" />
          </div>
          <Panel title="Agility Breakdown" accent>
            <SevBar label="Hardcoded Crypto" count={result.hardcoded_count} total={result.hardcoded_count + result.configurable_count} color={C.red} />
            <SevBar label="Configurable Crypto" count={result.configurable_count} total={result.hardcoded_count + result.configurable_count} color={C.green} />
          </Panel>
          {result.findings && result.findings.length > 0 && (
            <Panel title={`Findings — ${result.findings.length} items`} accent>
              {result.findings.map((f, i) => (
                <div key={i} style={{ borderLeft: `3px solid ${f.type === "hardcoded" ? C.red : C.green}`, paddingLeft: 14, marginBottom: 14 }}>
                  <div style={{ display: "flex", gap: 8, marginBottom: 6, alignItems: "center", flexWrap: "wrap" }}>
                    <Badge text={f.type.toUpperCase()} color={f.type === "hardcoded" ? C.red : C.green} bg={f.type === "hardcoded" ? C.redLight : C.greenLight} />
                    <span style={{ color: C.muted, fontSize: 11 }}>{f.file.split("/").pop()}:{f.line}</span>
                    <span style={{ color: C.muted, fontSize: 11 }}>— {f.description}</span>
                  </div>
                  <div style={{ fontFamily: "monospace", background: C.input, padding: "8px 12px", borderRadius: 6, fontSize: 11, marginBottom: 6, color: C.greenDark }}>{f.code}</div>
                  <div style={{ fontSize: 11, color: C.muted }}>{f.type === "hardcoded" ? "⚠ " : "✓ "}<span style={{ color: f.type === "hardcoded" ? C.amber : C.green }}>{f.recommendation}</span></div>
                </div>
              ))}
            </Panel>
          )}
        </>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// TLS PAGE
// ══════════════════════════════════════════════════════════════
function TLSPage() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async () => {
    if (!domain) return; setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`${API}/analyze-tls`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ domain: domain.replace("https://", "").replace("http://", "").split("/")[0] }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Analysis failed");
      setResult(data);
    } catch (e) { setError(typeof e.message === "string" ? e.message : "Analysis failed."); }
    setLoading(false);
  };

  const scoreColor = result ? (result.tls_score >= 70 ? C.green : result.tls_score >= 40 ? C.amber : C.red) : C.muted;

  return (
    <div style={{ padding: 20 }}>
      <Panel title="TLS / SSL Quantum Readiness Analyzer" accent>
        <div style={{ fontSize: 13, color: C.muted, marginBottom: 14, background: C.greenLighter, padding: "10px 14px", borderRadius: 8, lineHeight: 1.7 }}>
          Checks any domain for TLS version, cipher suite, and quantum vulnerability.
          <strong style={{ color: C.green }}> TLS 1.3 + forward secrecy</strong> = best protection.
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <input value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === "Enter" && handleAnalyze()} placeholder="google.com or https://github.com" style={{ flex: 1, minWidth: 200, padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
          <button onClick={handleAnalyze} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: loading ? "#86efac" : C.green, color: C.white, border: "none", cursor: loading ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600 }}>{loading ? "Analyzing..." : "🔐 Analyze TLS"}</button>
        </div>
        {error && <div style={{ marginTop: 12, background: C.redLight, border: `1px solid #fca5a5`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 13 }}>⚠ {error}</div>}
      </Panel>

      {result && (
        <>
          <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
            <Metric label="TLS Score" value={result.tls_score} suffix="/100" color={scoreColor} icon="🎯" desc={result.tls_score >= 70 ? "Quantum Ready" : "Needs Improvement"} />
            <Metric label="TLS Version" value={result.tls_version} color={result.tls_version === "TLSv1.3" ? C.green : C.amber} icon="🔒" desc={result.tls_version === "TLSv1.3" ? "Latest" : "Upgrade Needed"} />
            <Metric label="Quantum Safe" value={result.quantum_safe ? "YES" : "NO"} color={result.quantum_safe ? C.green : C.red} icon={result.quantum_safe ? "✅" : "❌"} desc={result.quantum_safe ? "Forward secrecy active" : "RSA key exchange"} />
            <Metric label="Key Size" value={result.cipher_bits} suffix=" bit" color={result.cipher_bits >= 256 ? C.green : C.amber} icon="🔑" desc={result.cipher_bits >= 256 ? "Strong" : "Upgrade Needed"} />
          </div>

          <Panel title="Cipher Suite Details" accent>
            <div className="tls-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {[["Domain", result.domain, C.green], ["Cipher Suite", result.cipher_suite, C.text], ["Certificate Expires", result.cert_expires, C.amber], ["Recommendation", result.recommendation, C.green]].map(([label, value, color], i) => (
                <div key={i} style={{ background: C.input, borderRadius: 8, padding: "12px 14px" }}>
                  <div style={{ fontSize: 11, color: C.muted, marginBottom: 4, fontWeight: 500 }}>{label}</div>
                  <div style={{ fontSize: 12, color, fontWeight: 500, wordBreak: "break-all" }}>{value}</div>
                </div>
              ))}
            </div>
          </Panel>

          {result.issues && result.issues.length > 0 && (
            <Panel title={`Issues Found — ${result.issues.length}`} accent>
              {result.issues.map((issue, i) => (
                <div key={i} style={{ display: "flex", gap: 10, padding: "10px 0", borderBottom: i < result.issues.length - 1 ? `1px solid ${C.panelBorder}` : "none" }}>
                  <span style={{ color: C.red, fontSize: 16 }}>⚠</span>
                  <span style={{ fontSize: 13, color: C.textMid }}>{issue}</span>
                </div>
              ))}
            </Panel>
          )}

          {result.issues && result.issues.length === 0 && (
            <div style={{ textAlign: "center", padding: 32, background: C.white, borderRadius: 12, border: `1px solid ${C.panelBorder}` }}>
              <div style={{ fontSize: 40, marginBottom: 12 }}>✅</div>
              <div style={{ fontSize: 16, color: C.green, fontWeight: 700 }}>No Issues Found</div>
              <div style={{ fontSize: 13, color: C.muted, marginTop: 4 }}>{result.domain} is using strong TLS configuration</div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// HISTORY PAGE
// ══════════════════════════════════════════════════════════════
function HistoryPage({ user }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user) return;
    const fetch_ = async () => {
      try {
        const q = query(collection(db, "scans"), where("userId", "==", user.uid), orderBy("createdAt", "desc"));
        const snap = await getDocs(q);
        setHistory(snap.docs.map(d => ({ id: d.id, ...d.data() })));
      } catch (e) { console.error(e); }
      setLoading(false);
    };
    fetch_();
  }, [user]);

  if (!user) return (
    <div style={{ padding: 20 }}>
      <div style={{ textAlign: "center", padding: 48, background: C.white, borderRadius: 12, border: `1px solid ${C.panelBorder}` }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>🔒</div>
        <div style={{ fontSize: 16, color: C.text, fontWeight: 600, marginBottom: 8 }}>Sign in to view history</div>
        <div style={{ fontSize: 13, color: C.muted }}>Your scan history is saved securely to your account</div>
      </div>
    </div>
  );

  return (
    <div style={{ padding: 20 }}>
      <Panel title={`Scan History — ${history.length} records`} accent>
        {loading ? <div style={{ color: C.muted, fontSize: 13 }}>Loading...</div> :
          history.length === 0 ? <div style={{ color: C.muted, fontSize: 13 }}>No scans yet!</div> : (
            <>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 160px 80px 80px", gap: 12, padding: "8px 12px", borderBottom: `1px solid ${C.panelBorder}`, marginBottom: 4 }}>
                {["Target", "Date", "Score", "Threats"].map((h, i) => <div key={i} style={{ fontSize: 11, color: C.muted, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5 }}>{h}</div>)}
              </div>
              {history.map((scan, i) => (
                <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 160px 80px 80px", gap: 12, padding: "12px", borderBottom: i < history.length - 1 ? `1px solid ${C.panelBorder}` : "none", alignItems: "center", background: i % 2 === 0 ? C.white : C.greenLighter, borderRadius: 6 }}>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 500, wordBreak: "break-all" }}>{scan.filename || "scan"}</div>
                  <div style={{ fontSize: 11, color: C.muted }}>{scan.createdAt?.toDate?.()?.toLocaleDateString() || "—"}</div>
                  <div style={{ fontSize: 20, fontWeight: 700, color: scan.score >= 70 ? C.green : scan.score >= 40 ? C.amber : C.red }}>{scan.score}</div>
                  <div style={{ fontSize: 16, fontWeight: 600, color: C.red }}>{scan.findings}</div>
                </div>
              ))}
            </>
          )}
      </Panel>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// MIGRATION PAGE
// ══════════════════════════════════════════════════════════════
function MigrationPage({ user }) {
  const [migrationStatus, setMigrationStatus] = useState({});
  const vulnTypes = ["RSA", "ECC", "DH", "DSA", "MD5", "SHA1", "RC4", "DES", "ECB_MODE", "WEAK_TLS", "HARDCODED_SECRET"];
  const getStatus = v => migrationStatus[v] || "pending";
  const setStatus = (v, s) => setMigrationStatus(p => ({ ...p, [v]: s }));
  const totalFixed = Object.values(migrationStatus).filter(s => s === "fixed").length;
  const totalIP = Object.values(migrationStatus).filter(s => s === "in_progress").length;
  const progress = Math.round((totalFixed / vulnTypes.length) * 100);
  const fixes = { RSA: "CRYSTALS-Kyber (ML-KEM FIPS 203)", ECC: "CRYSTALS-Dilithium (ML-DSA FIPS 204)", DH: "CRYSTALS-Kyber (ML-KEM FIPS 203)", DSA: "CRYSTALS-Dilithium (ML-DSA FIPS 204)", MD5: "SHA-3-256 or BLAKE3", SHA1: "SHA-3-256 or BLAKE3", RC4: "AES-256-GCM", DES: "AES-256-GCM", ECB_MODE: "AES-256-GCM", WEAK_TLS: "TLS 1.3", HARDCODED_SECRET: "AWS Secrets Manager" };
  const sevOf = v => ["RSA", "ECC", "RC4", "DES"].includes(v) ? "CRITICAL" : ["DH", "DSA", "ECB_MODE", "WEAK_TLS", "HARDCODED_SECRET"].includes(v) ? "HIGH" : "MEDIUM";

  if (!user) return (
    <div style={{ padding: 20 }}>
      <div style={{ textAlign: "center", padding: 48, background: C.white, borderRadius: 12, border: `1px solid ${C.panelBorder}` }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>🔒</div>
        <div style={{ fontSize: 16, color: C.text, fontWeight: 600 }}>Sign in to track migration</div>
      </div>
    </div>
  );

  return (
    <div style={{ padding: 20 }}>
      <Panel title="Migration Progress" accent>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 8 }}>
          <div>
            <div style={{ fontSize: 11, color: C.muted, fontWeight: 500, marginBottom: 4 }}>Overall Progress</div>
            <div style={{ fontSize: 40, fontWeight: 800, color: progress >= 70 ? C.green : progress >= 40 ? C.amber : C.red }}>{progress}%</div>
          </div>
          <div style={{ display: "flex", gap: 20 }}>
            {[["Fixed", totalFixed, C.green], ["In Progress", totalIP, C.amber], ["Pending", vulnTypes.length - totalFixed - totalIP, C.muted]].map(([l, v, c], i) => (
              <div key={i} style={{ textAlign: "center" }}>
                <div style={{ fontSize: 24, fontWeight: 700, color: c }}>{v}</div>
                <div style={{ fontSize: 11, color: C.muted }}>{l}</div>
              </div>
            ))}
          </div>
        </div>
        <div style={{ background: C.input, borderRadius: 8, height: 12 }}>
          <div style={{ background: `linear-gradient(90deg, ${C.green}, #4ade80)`, height: 12, borderRadius: 8, width: `${progress}%`, transition: "width 0.6s" }}></div>
        </div>
      </Panel>

      <Panel title="Vulnerability Migration Status" accent>
        {vulnTypes.map((v, i) => {
          const status = getStatus(v);
          const sev = sevOf(v);
          const sevColor = sev === "CRITICAL" ? C.critical : sev === "HIGH" ? C.amber : C.medium;
          const sevBg = sev === "CRITICAL" ? C.redLight : sev === "HIGH" ? C.amberLight : "#fef9c3";
          return (
            <div key={i} style={{ display: "flex", gap: 10, padding: "10px 12px", background: status === "fixed" ? C.greenLighter : i % 2 === 0 ? C.white : C.input, borderRadius: 8, marginBottom: 4, border: `1px solid ${status === "fixed" ? C.greenMid : C.panelBorder}`, alignItems: "center", flexWrap: "wrap" }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: status === "fixed" ? C.muted : C.text, textDecoration: status === "fixed" ? "line-through" : "none", minWidth: 120 }}>{v}</div>
              <div style={{ fontSize: 11, color: C.muted, flex: 1, minWidth: 150 }}>{fixes[v]}</div>
              <Badge text={sev} color={sevColor} bg={sevBg} />
              <div style={{ display: "flex", gap: 4 }}>
                {[["pending", "⬜"], ["in_progress", "🔄"], ["fixed", "✅"]].map(([st, icon]) => (
                  <button key={st} onClick={() => setStatus(v, st)} style={{ padding: "4px 8px", borderRadius: 6, border: `1.5px solid ${status === st ? (st === "fixed" ? C.green : st === "in_progress" ? C.amber : C.muted) : C.panelBorder}`, background: status === st ? (st === "fixed" ? C.greenLight : st === "in_progress" ? C.amberLight : C.input) : C.white, cursor: "pointer", fontSize: 14 }}>{icon}</button>
                ))}
              </div>
            </div>
          );
        })}
        <div style={{ padding: "12px 0 4px", display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button onClick={() => { const blob = new Blob([`Vulnerability,Status,Fix\n${vulnTypes.map(v => `${v},${getStatus(v)},${fixes[v]}`).join("\n")}`], { type: "text/csv" }); const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "migration-status.csv"; a.click(); }} style={{ padding: "8px 18px", borderRadius: 8, background: C.green, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📊 Export CSV</button>
          <button onClick={() => setMigrationStatus({})} style={{ padding: "8px 18px", borderRadius: 8, background: C.white, color: C.muted, border: `1px solid ${C.panelBorder}`, cursor: "pointer", fontSize: 12 }}>Reset</button>
        </div>
      </Panel>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// ANALYTICS PAGE
// ══════════════════════════════════════════════════════════════
function AnalyticsPage() {
  return (
    <div style={{ padding: 20 }}>
      <div className="analytics-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12, marginBottom: 16 }}>
        <Metric label="Languages Supported" value="8" color={C.green} icon="💻" desc="Python, JS, Java, TS, Go, Rust, C, C++" />
        <Metric label="Vulnerability Types" value="15+" color={C.red} icon="🔍" desc="RSA, ECC, DH, DSA, MD5 & more" />
        <Metric label="NIST Compliance" value="2024" color={C.blue} icon="📋" desc="FIPS 203, 204, 205 aligned" />
      </div>
      <Panel title="Quantum Timeline" accent>
        {[
          { year: "2024", event: "NIST finalizes PQC standards — FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)", color: C.green },
          { year: "2026", event: "QuantumGuard launches — first developer-focused quantum vulnerability scanner", color: C.blue },
          { year: "2027", event: "Regulatory pressure increases — organizations must show PQC compliance", color: C.amber },
          { year: "2030", event: "Y2Q — Cryptographically Relevant Quantum Computers expected to arrive", color: C.red },
        ].map((t, i) => (
          <div key={i} style={{ display: "flex", gap: 16, marginBottom: 16, alignItems: "flex-start", padding: "10px 0", borderBottom: i < 3 ? `1px solid ${C.panelBorder}` : "none" }}>
            <div style={{ background: t.color, color: C.white, padding: "4px 10px", borderRadius: 8, fontSize: 13, fontWeight: 700, flexShrink: 0 }}>{t.year}</div>
            <div style={{ fontSize: 13, color: C.textMid, lineHeight: 1.6, paddingTop: 4 }}>{t.event}</div>
          </div>
        ))}
      </Panel>
      <Panel title="Vulnerability Reference" accent>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(160px,1fr))", gap: 8 }}>
          {[["RSA", "CRITICAL"], ["ECC", "CRITICAL"], ["RC4", "CRITICAL"], ["DES/3DES", "CRITICAL"], ["MD5", "MEDIUM"], ["SHA-1", "MEDIUM"], ["DH", "HIGH"], ["DSA", "HIGH"], ["ECB Mode", "HIGH"], ["Weak TLS", "HIGH"], ["JWT None", "CRITICAL"], ["Hardcoded Keys", "HIGH"]].map(([v, s], i) => {
            const c = s === "CRITICAL" ? C.critical : s === "HIGH" ? C.amber : C.medium;
            const bg = s === "CRITICAL" ? C.redLight : s === "HIGH" ? C.amberLight : "#fef9c3";
            return (
              <div key={i} style={{ background: C.input, borderRadius: 8, padding: "10px 12px", border: `1px solid ${C.panelBorder}` }}>
                <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 4 }}>{v}</div>
                <Badge text={s} color={c} bg={bg} />
              </div>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// DOCS PAGE
// ══════════════════════════════════════════════════════════════
function DocsPage() {
  return (
    <div style={{ padding: 20 }}>
      <Panel title="API Endpoints" accent>
        {[
          { method: "POST", path: "/scan-github", auth: "None", desc: "Scan any public GitHub repo. Body: {github_url, github_token?}" },
          { method: "POST", path: "/public-scan-zip", auth: "None", desc: "Upload ZIP file (max 10MB). multipart/form-data" },
          { method: "POST", path: "/check-agility", auth: "None", desc: "Check crypto agility. Body: {github_url}" },
          { method: "POST", path: "/analyze-tls", auth: "None", desc: "Analyze TLS. Body: {domain}" },
          { method: "POST", path: "/scan", auth: "x-api-key header", desc: "Scan server path. Body: {directory}" },
          { method: "GET", path: "/health", auth: "None", desc: "Returns {status: healthy}" },
        ].map((e, i) => (
          <div key={i} style={{ display: "flex", gap: 12, padding: "10px 0", borderBottom: i < 5 ? `1px solid ${C.panelBorder}` : "none", flexWrap: "wrap", alignItems: "center" }}>
            <Badge text={e.method} color={C.green} bg={C.greenLight} />
            <span style={{ fontFamily: "monospace", fontSize: 12, color: C.green, fontWeight: 600, minWidth: 160 }}>{e.path}</span>
            <span style={{ fontSize: 11, color: C.amber, minWidth: 100 }}>{e.auth}</span>
            <span style={{ fontSize: 12, color: C.muted }}>{e.desc}</span>
          </div>
        ))}
      </Panel>
      <div className="docs-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        {[
          { title: "Quick Start", icon: "⚡", steps: ["Go to Scanner tab", "Paste GitHub repo URL", "Click Run Scan", "Download PDF report"] },
          { title: "Crypto Agility", icon: "🔬", steps: ["Go to Agility Checker", "Paste GitHub repo URL", "Click Check Agility", "Review hardcoded vs configurable"] },
          { title: "Private Repos", icon: "🔒", steps: ["Click Private Repo button", "Generate GitHub PAT", "Paste your token", "Token never stored"] },
          { title: "Rate Limits", icon: "⏱", steps: ["/scan-github: 20/min", "/public-scan-zip: 3/min", "/check-agility: 10/min", "/analyze-tls: 10/min"] },
        ].map((d, i) => (
          <Panel key={i} title={`${d.icon} ${d.title}`}>
            {d.steps.map((step, j) => (
              <div key={j} style={{ display: "flex", gap: 10, marginBottom: 8, alignItems: "flex-start" }}>
                <div style={{ width: 20, height: 20, borderRadius: "50%", background: C.green, color: C.white, fontSize: 10, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{j + 1}</div>
                <span style={{ fontSize: 12, color: C.textMid, paddingTop: 2 }}>{step}</span>
              </div>
            ))}
          </Panel>
        ))}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// HOMEPAGE
// ══════════════════════════════════════════════════════════════
// NEW HOMEPAGE — Replace existing Homepage function in App.js

function Homepage({ onGetStarted }) {
  return (
    <div style={{ minHeight: "100vh", background: C.bg, fontFamily: "'Segoe UI', sans-serif", overflowX: "hidden" }}>

      {/* ── NAVBAR ── */}
      <nav style={{ background: "rgba(255,255,255,0.95)", backdropFilter: "blur(12px)", borderBottom: `1px solid ${C.panelBorder}`, padding: "0 40px", height: 66, display: "flex", alignItems: "center", justifyContent: "space-between", boxShadow: "0 1px 6px rgba(0,0,0,0.06)", position: "sticky", top: 0, zIndex: 100 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 38, height: 38, borderRadius: 10, background: C.green, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, boxShadow: "0 2px 8px rgba(22,163,74,0.3)" }}>⚛</div>
          <span style={{ fontSize: 19, fontWeight: 800, letterSpacing: -0.5 }}><span style={{ color: C.green }}>Quantum</span>Guard</span>
          <span style={{ background: C.greenLighter, color: C.green, fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 20, border: `1px solid ${C.greenMid}`, marginLeft: 4 }}>BETA</span>
        </div>
        <div className="nav-links" style={{ display: "flex", alignItems: "center", gap: 32 }}>
          {[{ label: "Features", id: "features" }, { label: "How It Works", id: "howitworks" }, { label: "Pricing", id: "pricing" }, { label: "Documentation", id: "docs" }].map(item => (
            <span key={item.id} onClick={() => document.getElementById(item.id)?.scrollIntoView({ behavior: "smooth" })} style={{ fontSize: 14, color: C.muted, cursor: "pointer", fontWeight: 500, transition: "color 0.15s" }} onMouseEnter={e => e.target.style.color = C.green} onMouseLeave={e => e.target.style.color = C.muted}>{item.label}</span>
          ))}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, background: C.greenLighter, padding: "5px 12px", borderRadius: 20, border: `1px solid ${C.greenMid}` }}>
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: C.green, animation: "pulse 2s infinite" }}></div>
            <span style={{ fontSize: 11, color: C.green, fontWeight: 700 }}>API ONLINE</span>
          </div>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ fontSize: 13, color: C.muted, textDecoration: "none", fontWeight: 500, display: "flex", alignItems: "center", gap: 4 }}>★ GitHub</a>
          <button onClick={onGetStarted} style={{ background: C.green, color: C.white, padding: "9px 22px", borderRadius: 10, border: "none", cursor: "pointer", fontSize: 14, fontWeight: 700, boxShadow: "0 2px 8px rgba(22,163,74,0.35)", transition: "all 0.15s" }} onMouseEnter={e => { e.target.style.background = C.greenDark; e.target.style.transform = "translateY(-1px)"; }} onMouseLeave={e => { e.target.style.background = C.green; e.target.style.transform = "translateY(0)"; }}>Get Started Free →</button>
        </div>
      </nav>

      {/* ── HERO ── */}
      <div style={{ background: "linear-gradient(135deg, #f0fdf4 0%, #f8faf8 50%, #f0f9ff 100%)", borderBottom: `1px solid ${C.panelBorder}`, padding: "0 40px" }}>
        <div className="hero-grid" style={{ maxWidth: 1200, margin: "0 auto", padding: "70px 0 60px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 70, alignItems: "center" }}>
          {/* Left */}
          <div>
            <div style={{ display: "inline-flex", alignItems: "center", gap: 8, background: C.white, border: `1px solid ${C.greenMid}`, borderRadius: 30, padding: "6px 14px", marginBottom: 28, boxShadow: "0 1px 4px rgba(22,163,74,0.1)" }}>
              <span style={{ fontSize: 14 }}>🏛</span>
              <span style={{ fontSize: 12, color: C.green, fontWeight: 700 }}>Submitted to NIST NCCoE & NIST PQC Team</span>
            </div>
            <h1 style={{ fontSize: "clamp(34px,4.5vw,58px)", fontWeight: 900, lineHeight: 1.1, marginBottom: 22, color: C.text, letterSpacing: -1 }}>
              Is Your Code<br />
              <span style={{ color: C.green, position: "relative" }}>Quantum Safe?</span>
            </h1>
            <p style={{ fontSize: 17, color: C.muted, lineHeight: 1.75, marginBottom: 36, maxWidth: 500 }}>
              Quantum computers will break RSA and ECC encryption by 2030. QuantumGuard scans your codebase in <strong style={{ color: C.text }}>30 seconds</strong> and gives you exact NIST-approved fixes — completely free.
            </p>
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginBottom: 36 }}>
              <button onClick={onGetStarted} style={{ background: C.green, color: C.white, padding: "14px 30px", borderRadius: 12, border: "none", cursor: "pointer", fontSize: 16, fontWeight: 700, boxShadow: "0 4px 16px rgba(22,163,74,0.35)", display: "flex", alignItems: "center", gap: 8, transition: "all 0.15s" }} onMouseEnter={e => e.target.style.transform = "translateY(-2px)"} onMouseLeave={e => e.target.style.transform = "translateY(0)"}>
                🛡 Scan My Code Now
              </button>
              <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ background: C.white, color: C.text, padding: "14px 30px", borderRadius: 12, border: `1.5px solid ${C.panelBorder}`, cursor: "pointer", fontSize: 15, fontWeight: 600, textDecoration: "none", display: "flex", alignItems: "center", gap: 8, boxShadow: "0 1px 4px rgba(0,0,0,0.06)" }}>
                ★ Star on GitHub
              </a>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 20 }}>
              {[["✓ Free Forever", C.green], ["✓ No Signup Required", C.green], ["✓ NIST FIPS 203/204/205", C.green], ["✓ Open Source", C.green]].map(([text, color], i) => (
                <span key={i} style={{ fontSize: 13, color, fontWeight: 600 }}>{text}</span>
              ))}
            </div>
          </div>

          {/* Right — Dashboard Preview */}
          <div className="hero-preview" style={{ background: C.white, borderRadius: 20, boxShadow: "0 24px 80px rgba(0,0,0,0.12)", border: `1px solid ${C.panelBorder}`, overflow: "hidden" }}>
            <div style={{ background: C.green, padding: "12px 18px", display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ display: "flex", gap: 6 }}>
                {["#ff5f57", "#febc2e", "#28c840"].map((c, i) => <div key={i} style={{ width: 12, height: 12, borderRadius: "50%", background: c }}></div>)}
              </div>
              <span style={{ color: "rgba(255,255,255,0.8)", fontSize: 12, marginLeft: 8, fontFamily: "monospace" }}>quantumguard.site — Scanner</span>
              <div style={{ marginLeft: "auto", background: "rgba(255,255,255,0.2)", borderRadius: 20, padding: "2px 10px" }}>
                <span style={{ color: C.white, fontSize: 10, fontWeight: 700 }}>● LIVE</span>
              </div>
            </div>
            <div style={{ padding: 20 }}>
              {/* Input bar */}
              <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                <div style={{ flex: 1, background: C.input, borderRadius: 8, padding: "10px 14px", fontSize: 12, color: C.muted, fontFamily: "monospace", border: `1px solid ${C.panelBorder}` }}>
                  https://github.com/fastapi/fastapi
                </div>
                <div style={{ background: C.green, borderRadius: 8, padding: "10px 14px", color: C.white, fontSize: 12, fontWeight: 700, cursor: "pointer" }}>▶ Scan</div>
              </div>
              {/* Score cards */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10, marginBottom: 14 }}>
                {[["58", "Score", C.amber, C.amberLight], ["8", "Threats", C.red, C.redLight], ["0", "Critical", C.green, C.greenLighter], ["6", "High", C.amber, C.amberLight]].map(([n, l, c, bg], i) => (
                  <div key={i} style={{ background: bg, borderRadius: 10, padding: 12, textAlign: "center", border: `1px solid ${c}22` }}>
                    <div style={{ fontSize: 22, fontWeight: 800, color: c }}>{n}</div>
                    <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{l}</div>
                  </div>
                ))}
              </div>
              {/* Findings */}
              <div style={{ background: C.input, borderRadius: 10, padding: 12, marginBottom: 10 }}>
                <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, marginBottom: 8 }}>TOP FINDINGS</div>
                {[["HIGH", "TLS cipher suite — quantum vulnerable", "ssl/config.py:45"], ["HIGH", "RSA key exchange detected", "auth/keys.py:12"], ["MEDIUM", "SHA-1 hash function usage", "utils/hash.py:8"]].map(([sev, issue, file], i) => {
                  const sevColor = sev === "CRITICAL" ? C.red : sev === "HIGH" ? C.amber : "#ca8a04";
                  const sevBg = sev === "CRITICAL" ? C.redLight : sev === "HIGH" ? C.amberLight : "#fef9c3";
                  return (
                    <div key={i} style={{ display: "flex", gap: 8, alignItems: "center", padding: "6px 0", borderBottom: i < 2 ? `1px solid ${C.panelBorder}` : "none" }}>
                      <span style={{ background: sevBg, color: sevColor, fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 4, flexShrink: 0 }}>{sev}</span>
                      <span style={{ fontSize: 11, color: C.text, flex: 1 }}>{issue}</span>
                      <span style={{ fontSize: 9, color: C.muted, fontFamily: "monospace" }}>{file}</span>
                    </div>
                  );
                })}
              </div>
              {/* Action buttons */}
              <div style={{ display: "flex", gap: 8 }}>
                {["📄 PDF Report", "🏛 NIST Report", "📊 CSV"].map((btn, i) => (
                  <div key={i} style={{ flex: 1, background: i === 1 ? C.green : C.white, color: i === 1 ? C.white : C.text, borderRadius: 8, padding: "8px 4px", textAlign: "center", fontSize: 10, fontWeight: 600, border: `1px solid ${i === 1 ? C.green : C.panelBorder}`, cursor: "pointer" }}>{btn}</div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── TRUST BAR ── */}
      <div style={{ background: C.white, borderBottom: `1px solid ${C.panelBorder}`, padding: "28px 40px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", textAlign: "center" }}>
          <p style={{ fontSize: 12, color: C.muted, fontWeight: 600, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>Trusted by developers scanning real repositories</p>
          <div className="stats-bar-grid" style={{ maxWidth: 900, margin: "0 auto", display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 20 }}>
            {[["50+", "Vulnerability Checks"], ["8", "Languages"], ["99.9%", "Uptime"], ["< 30s", "Scan Time"], ["100%", "Private"]].map(([num, label], i) => (
              <div key={i} style={{ textAlign: "center" }}>
                <div style={{ fontSize: 26, fontWeight: 900, color: C.green, letterSpacing: -1 }}>{num}</div>
                <div style={{ fontSize: 11, color: C.muted, marginTop: 3 }}>{label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── FEATURES ── */}
      <div id="features" style={{ maxWidth: 1200, margin: "0 auto", padding: "80px 40px" }}>
        <div style={{ textAlign: "center", marginBottom: 56 }}>
          <div style={{ display: "inline-block", background: C.greenLighter, color: C.green, fontSize: 12, fontWeight: 700, padding: "5px 16px", borderRadius: 20, marginBottom: 16, border: `1px solid ${C.greenMid}` }}>FEATURES</div>
          <h2 style={{ fontSize: 38, fontWeight: 900, color: C.text, marginBottom: 14, letterSpacing: -0.5 }}>Everything to go quantum-safe</h2>
          <p style={{ color: C.muted, fontSize: 16, maxWidth: 560, margin: "0 auto", lineHeight: 1.7 }}>Comprehensive quantum vulnerability detection and NIST-approved migration tools — all free</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px,1fr))", gap: 22 }}>
          {[
            { icon: "🔍", title: "Threat Scanner", desc: "Scan GitHub repos, ZIP files, or server paths. Detects 15+ quantum-vulnerable algorithms in 30 seconds.", badge: "Core", badgeColor: C.green },
            { icon: "🏛", title: "NIST Compliance Report", desc: "Generate professional FIPS 203/204/205 compliance reports with NIST references per finding.", badge: "Enterprise", badgeColor: C.blue },
            { icon: "🔐", title: "TLS Analyzer", desc: "Check any domain's TLS version, cipher suite, and quantum safety rating instantly.", badge: "Free", badgeColor: C.green },
            { icon: "🔬", title: "Agility Checker", desc: "Detect hardcoded vs configurable crypto. Score 0-100 for migration readiness.", badge: "Free", badgeColor: C.green },
            { icon: "🤖", title: "AI Fix Assistant", desc: "Claude-powered exact replacement code for every vulnerability found in your codebase.", badge: "Pro", badgeColor: "#7c3aed" },
            { icon: "🔄", title: "Migration Tracker", desc: "Track 11 vulnerability types from Pending to Fixed across your entire organization.", badge: "Free", badgeColor: C.green },
            { icon: "⚙", title: "GitHub CI/CD", desc: "Auto-scan your repo on every push. Automatically fails build if critical vulnerabilities found.", badge: "Free", badgeColor: C.green },
            { icon: "📊", title: "PDF & CSV Reports", desc: "Export professional vulnerability reports as PDF or CSV. Share with your team instantly.", badge: "Free", badgeColor: C.green },
          ].map((f, i) => (
            <div key={i} style={{ background: C.white, borderRadius: 16, padding: 26, border: `1px solid ${C.panelBorder}`, boxShadow: "0 1px 6px rgba(0,0,0,0.04)", transition: "all 0.2s", cursor: "default" }} onMouseEnter={e => { e.currentTarget.style.boxShadow = "0 8px 24px rgba(22,163,74,0.12)"; e.currentTarget.style.borderColor = C.greenMid; e.currentTarget.style.transform = "translateY(-2px)"; }} onMouseLeave={e => { e.currentTarget.style.boxShadow = "0 1px 6px rgba(0,0,0,0.04)"; e.currentTarget.style.borderColor = C.panelBorder; e.currentTarget.style.transform = "translateY(0)"; }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
                <div style={{ width: 50, height: 50, borderRadius: 14, background: C.greenLighter, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24 }}>{f.icon}</div>
                <span style={{ background: f.badgeColor + "18", color: f.badgeColor, fontSize: 10, fontWeight: 700, padding: "3px 10px", borderRadius: 20, border: `1px solid ${f.badgeColor}33` }}>{f.badge}</span>
              </div>
              <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 8, color: C.text }}>{f.title}</div>
              <div style={{ fontSize: 13, color: C.muted, lineHeight: 1.65 }}>{f.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── HOW IT WORKS ── */}
      <div id="howitworks" style={{ background: C.white, borderTop: `1px solid ${C.panelBorder}`, borderBottom: `1px solid ${C.panelBorder}`, padding: "80px 40px" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <div style={{ textAlign: "center", marginBottom: 56 }}>
            <div style={{ display: "inline-block", background: C.greenLighter, color: C.green, fontSize: 12, fontWeight: 700, padding: "5px 16px", borderRadius: 20, marginBottom: 16, border: `1px solid ${C.greenMid}` }}>HOW IT WORKS</div>
            <h2 style={{ fontSize: 38, fontWeight: 900, color: C.text, marginBottom: 14, letterSpacing: -0.5 }}>From URL to report in 30 seconds</h2>
            <p style={{ color: C.muted, fontSize: 16, lineHeight: 1.7 }}>No installation. No signup. Just paste and scan.</p>
          </div>
          <div className="how-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 40 }}>
            {[
              { step: "1", icon: "🔗", title: "Paste GitHub URL", desc: "Enter any public or private GitHub repository URL. Works with ZIP files and server paths too." },
              { step: "2", icon: "🔍", title: "We Scan Your Code", desc: "Our engine checks every line against 15+ NIST-aligned vulnerability patterns across 8 languages." },
              { step: "3", icon: "📊", title: "Get Full Report", desc: "Receive Quantum Readiness Score 0-100, NIST compliance report, PDF export, and AI-powered fixes." },
            ].map((s, i) => (
              <div key={i} style={{ textAlign: "center", position: "relative" }}>
                {i < 2 && <div style={{ position: "absolute", top: 32, left: "60%", width: "80%", height: 2, background: `linear-gradient(90deg, ${C.green}, ${C.greenMid})`, zIndex: 0 }}></div>}
                <div style={{ position: "relative", zIndex: 1 }}>
                  <div style={{ width: 66, height: 66, borderRadius: "50%", background: C.green, color: C.white, fontSize: 26, fontWeight: 900, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px", boxShadow: "0 4px 14px rgba(22,163,74,0.3)" }}>{s.step}</div>
                  <div style={{ fontSize: 38, marginBottom: 14 }}>{s.icon}</div>
                  <div style={{ fontSize: 18, fontWeight: 800, marginBottom: 10, color: C.text }}>{s.title}</div>
                  <div style={{ fontSize: 14, color: C.muted, lineHeight: 1.75, maxWidth: 280, margin: "0 auto" }}>{s.desc}</div>
                </div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 48, background: C.greenLighter, borderRadius: 14, padding: "20px 28px", border: `1px solid ${C.greenMid}`, display: "flex", alignItems: "center", gap: 16, maxWidth: 700, margin: "48px auto 0" }}>
            <span style={{ fontSize: 24 }}>🔒</span>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: C.text, marginBottom: 2 }}>Your code is always private</div>
              <div style={{ fontSize: 13, color: C.muted }}>Source code is scanned in memory and permanently deleted immediately. We store only your score. Open source — verify it yourself.</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── NIST SECTION ── */}
      <div style={{ background: "linear-gradient(135deg, #0f172a 0%, #1e3a2e 100%)", padding: "70px 40px" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto", textAlign: "center" }}>
          <div style={{ display: "inline-block", background: "rgba(134,239,172,0.15)", color: C.greenMid, fontSize: 12, fontWeight: 700, padding: "5px 16px", borderRadius: 20, marginBottom: 20, border: "1px solid rgba(134,239,172,0.3)" }}>NIST ALIGNED</div>
          <h2 style={{ fontSize: 36, fontWeight: 900, color: C.white, marginBottom: 14, letterSpacing: -0.5 }}>Built on Official NIST Standards</h2>
          <p style={{ color: "#94a3b8", fontSize: 15, marginBottom: 44, lineHeight: 1.7, maxWidth: 600, margin: "0 auto 44px" }}>Every recommendation is backed by NIST's official post-quantum cryptography standards published in 2024</p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px,1fr))", gap: 16, maxWidth: 900, margin: "0 auto 44px" }}>
            {[
              { code: "FIPS 203", name: "ML-KEM", desc: "Replaces RSA and ECDH key exchange", color: "#86efac" },
              { code: "FIPS 204", name: "ML-DSA", desc: "Replaces ECDSA and DSA signatures", color: "#86efac" },
              { code: "FIPS 205", name: "SLH-DSA", desc: "Hash-based signature scheme", color: "#86efac" },
              { code: "FIPS 202", name: "SHA-3", desc: "Replaces SHA-1 and MD5 hashing", color: "#86efac" },
            ].map((n, i) => (
              <div key={i} style={{ background: "rgba(255,255,255,0.06)", borderRadius: 14, padding: 22, border: "1px solid rgba(134,239,172,0.2)", textAlign: "center" }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: n.color, marginBottom: 6, fontFamily: "monospace", letterSpacing: 1 }}>{n.code}</div>
                <div style={{ fontSize: 22, fontWeight: 900, color: C.white, marginBottom: 6 }}>{n.name}</div>
                <div style={{ fontSize: 12, color: "#94a3b8", lineHeight: 1.5 }}>{n.desc}</div>
              </div>
            ))}
          </div>
          <div style={{ background: "rgba(134,239,172,0.1)", borderRadius: 14, padding: "16px 28px", border: "1px solid rgba(134,239,172,0.2)", display: "inline-flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 20 }}>🏛</span>
            <span style={{ color: "#94a3b8", fontSize: 13 }}>Submitted to <strong style={{ color: C.white }}>NIST NCCoE</strong> and <strong style={{ color: C.white }}>NIST PQC Team</strong> for review</span>
          </div>
        </div>
      </div>

      {/* ── PRICING ── */}
      <div id="pricing" style={{ maxWidth: 1200, margin: "0 auto", padding: "80px 40px" }}>
        <div style={{ textAlign: "center", marginBottom: 56 }}>
          <div style={{ display: "inline-block", background: C.greenLighter, color: C.green, fontSize: 12, fontWeight: 700, padding: "5px 16px", borderRadius: 20, marginBottom: 16, border: `1px solid ${C.greenMid}` }}>PRICING</div>
          <h2 style={{ fontSize: 38, fontWeight: 900, color: C.text, marginBottom: 14, letterSpacing: -0.5 }}>Simple, transparent pricing</h2>
          <p style={{ color: C.muted, fontSize: 16 }}>Start free. Upgrade when your team needs more.</p>
        </div>
        <div className="pricing-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 24, maxWidth: 1000, margin: "0 auto" }}>
          {[
            { name: "Free", price: "$0", period: "forever", color: C.text, highlight: false, badge: null, features: ["Web scanner", "GitHub URL + ZIP scan", "15+ vulnerability types", "PDF & NIST reports", "TLS Analyzer", "Agility Checker", "10 scans/day", "Community support"], cta: "Get Started Free", ctaAction: onGetStarted },
            { name: "Pro", price: "$29", period: "/month", color: C.green, highlight: true, badge: "Most Popular", features: ["Everything in Free", "Unlimited scans", "AI-powered fix suggestions", "5 team members", "Full API access", "Priority email support", "Migration tracker", "Advanced analytics"], cta: "Coming Soon", ctaAction: null },
            { name: "Enterprise", price: "Custom", period: "", color: "#7c3aed", highlight: false, badge: null, features: ["Everything in Pro", "Unlimited team members", "Self-hosted deployment", "SSO / SAML login", "Audit logs", "SOC2 compliance", "Dedicated support", "Custom integrations"], cta: "Contact Us", ctaAction: () => window.open("mailto:thisispayyavula@gmail.com?subject=QuantumGuard Enterprise Inquiry") },
          ].map((p, i) => (
            <div key={i} style={{ background: C.white, borderRadius: 20, padding: 30, border: p.highlight ? `2px solid ${C.green}` : `1px solid ${C.panelBorder}`, boxShadow: p.highlight ? "0 12px 32px rgba(22,163,74,0.15)" : "0 2px 8px rgba(0,0,0,0.04)", position: "relative", transition: "transform 0.2s" }} onMouseEnter={e => e.currentTarget.style.transform = "translateY(-4px)"} onMouseLeave={e => e.currentTarget.style.transform = "translateY(0)"}>
              {p.badge && <div style={{ position: "absolute", top: -14, left: "50%", transform: "translateX(-50%)", background: C.green, color: C.white, padding: "5px 18px", borderRadius: 20, fontSize: 11, fontWeight: 700, whiteSpace: "nowrap" }}>{p.badge}</div>}
              <div style={{ fontSize: 16, fontWeight: 700, color: C.text, marginBottom: 8 }}>{p.name}</div>
              <div style={{ marginBottom: 4 }}>
                <span style={{ fontSize: 42, fontWeight: 900, color: p.color, letterSpacing: -1 }}>{p.price}</span>
                <span style={{ fontSize: 14, color: C.muted, fontWeight: 400 }}>{p.period}</span>
              </div>
              <div style={{ height: 1, background: C.panelBorder, margin: "20px 0" }}></div>
              {p.features.map((f, j) => (
                <div key={j} style={{ display: "flex", gap: 10, marginBottom: 10, alignItems: "flex-start" }}>
                  <span style={{ color: C.green, fontWeight: 700, fontSize: 14, flexShrink: 0, marginTop: 1 }}>✓</span>
                  <span style={{ fontSize: 13, color: C.muted, lineHeight: 1.5 }}>{f}</span>
                </div>
              ))}
              <button onClick={p.ctaAction} style={{ width: "100%", marginTop: 24, padding: "12px", borderRadius: 12, background: p.highlight ? C.green : "transparent", color: p.highlight ? C.white : p.color, border: `2px solid ${p.color}`, cursor: p.ctaAction ? "pointer" : "default", fontSize: 14, fontWeight: 700, transition: "all 0.15s" }}>{p.cta}</button>
            </div>
          ))}
        </div>
      </div>

      {/* ── DOCS ── */}
      <div id="docs" style={{ background: C.white, borderTop: `1px solid ${C.panelBorder}`, padding: "80px 40px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <div style={{ textAlign: "center", marginBottom: 56 }}>
            <div style={{ display: "inline-block", background: C.greenLighter, color: C.green, fontSize: 12, fontWeight: 700, padding: "5px 16px", borderRadius: 20, marginBottom: 16, border: `1px solid ${C.greenMid}` }}>DOCUMENTATION</div>
            <h2 style={{ fontSize: 38, fontWeight: 900, color: C.text, marginBottom: 14, letterSpacing: -0.5 }}>Integrate in minutes</h2>
            <p style={{ color: C.muted, fontSize: 16 }}>Everything you need to add quantum security to your workflow</p>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))", gap: 20 }}>
            {[
              { icon: "⚡", title: "Quick Start", desc: "Scan your first repo in 30 seconds. No installation required.", steps: ["Paste GitHub URL", "Click Run Scan", "Download report"] },
              { icon: "🔌", title: "REST API", desc: "Integrate QuantumGuard into your stack with our documented REST API.", steps: ["POST /scan-github", "POST /check-agility", "POST /analyze-tls"] },
              { icon: "🔄", title: "GitHub Actions", desc: "Auto-scan on every push with our CI/CD workflow integration.", steps: ["Copy workflow YAML", "Add to .github/workflows/", "Push to trigger"] },
              { icon: "🖥", title: "Self-Hosting", desc: "Run QuantumGuard inside your own network. Complete Docker guide included.", steps: ["Clone the repo", "Run Docker container", "Code never leaves you"] },
            ].map((d, i) => (
              <div key={i} style={{ background: C.greenLighter, borderRadius: 16, padding: 26, border: `1px solid ${C.greenMid}`, transition: "all 0.2s" }} onMouseEnter={e => { e.currentTarget.style.background = C.white; e.currentTarget.style.boxShadow = "0 8px 24px rgba(22,163,74,0.12)"; }} onMouseLeave={e => { e.currentTarget.style.background = C.greenLighter; e.currentTarget.style.boxShadow = "none"; }}>
                <div style={{ fontSize: 30, marginBottom: 12 }}>{d.icon}</div>
                <div style={{ fontSize: 16, fontWeight: 800, color: C.text, marginBottom: 8 }}>{d.title}</div>
                <div style={{ fontSize: 13, color: C.muted, marginBottom: 16, lineHeight: 1.65 }}>{d.desc}</div>
                {d.steps.map((step, j) => (
                  <div key={j} style={{ display: "flex", gap: 10, marginBottom: 7, alignItems: "center" }}>
                    <div style={{ width: 20, height: 20, borderRadius: "50%", background: C.green, color: C.white, fontSize: 10, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{j + 1}</div>
                    <span style={{ fontSize: 12, color: C.textMid, fontWeight: 500 }}>{step}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── CTA ── */}
      <div style={{ background: "linear-gradient(135deg, #16a34a 0%, #15803d 100%)", padding: "80px 40px", textAlign: "center", position: "relative", overflow: "hidden" }}>
        <div style={{ position: "absolute", top: -40, right: -40, width: 200, height: 200, borderRadius: "50%", background: "rgba(255,255,255,0.05)" }}></div>
        <div style={{ position: "absolute", bottom: -60, left: -60, width: 240, height: 240, borderRadius: "50%", background: "rgba(255,255,255,0.05)" }}></div>
        <div style={{ position: "relative", zIndex: 1 }}>
          <div style={{ fontSize: 14, color: "rgba(255,255,255,0.8)", fontWeight: 600, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>Get Started Today</div>
          <h2 style={{ fontSize: 42, fontWeight: 900, color: C.white, marginBottom: 16, letterSpacing: -0.5 }}>Ready to secure your code?</h2>
          <p style={{ color: "rgba(255,255,255,0.8)", marginBottom: 36, fontSize: 16, maxWidth: 480, margin: "0 auto 36px", lineHeight: 1.7 }}>Join developers who are scanning their codebases for quantum vulnerabilities before the 2030 deadline.</p>
          <div style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap" }}>
            <button onClick={onGetStarted} style={{ background: C.white, color: C.green, padding: "15px 34px", borderRadius: 12, border: "none", cursor: "pointer", fontSize: 16, fontWeight: 800, boxShadow: "0 4px 16px rgba(0,0,0,0.15)", display: "inline-flex", alignItems: "center", gap: 8, transition: "all 0.15s" }} onMouseEnter={e => e.target.style.transform = "translateY(-2px)"} onMouseLeave={e => e.target.style.transform = "translateY(0)"}>
              🛡 Start Scanning Now — Free
            </button>
            <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ background: "rgba(255,255,255,0.15)", color: C.white, padding: "15px 34px", borderRadius: 12, border: "2px solid rgba(255,255,255,0.3)", cursor: "pointer", fontSize: 16, fontWeight: 700, textDecoration: "none", display: "inline-flex", alignItems: "center", gap: 8 }}>
              ★ Star on GitHub
            </a>
          </div>
          <p style={{ color: "rgba(255,255,255,0.6)", fontSize: 13, marginTop: 20 }}>Free forever · No credit card · Open source · NIST aligned</p>
        </div>
      </div>

      {/* ── FOOTER ── */}
      <div style={{ background: C.white, borderTop: `1px solid ${C.panelBorder}`, padding: "28px 40px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 30, height: 30, borderRadius: 8, background: C.green, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15 }}>⚛</div>
            <span style={{ fontSize: 14, fontWeight: 700 }}><span style={{ color: C.green }}>Quantum</span>Guard</span>
            <span style={{ fontSize: 12, color: C.muted }}>by MANGSRI · Open Source · Free Forever</span>
          </div>
          <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "center" }}>
            {[["About", "/about.html"], ["Privacy Policy", "/privacy.html"], ["Terms", "/terms.html"], ["SLA", "/sla.html"]].map(([label, href], i) => (
              <a key={i} href={href} style={{ color: C.muted, fontSize: 13, textDecoration: "none", fontWeight: 500 }} onMouseEnter={e => e.target.style.color = C.green} onMouseLeave={e => e.target.style.color = C.muted}>{label}</a>
            ))}
            <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ color: C.green, fontSize: 13, textDecoration: "none", fontWeight: 600 }}>GitHub ↗</a>
          </div>
        </div>
      </div>

    </div>
  );
}


// ══════════════════════════════════════════════════════════════
// APP ROOT
// ══════════════════════════════════════════════════════════════
export default function App() {
  const [user, setUser] = useState(null);
  const [active, setActive] = useState("home");
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => { onAuthStateChanged(auth, u => setUser(u)); }, []);

  const handleLogin = async () => { try { await signInWithGoogle(); } catch (e) { console.error(e); } };
  const handleLogout = async () => { try { await signOut(auth); setUser(null); } catch (e) { console.error(e); } };

  if (active === "home") return <Homepage onGetStarted={() => setActive("scan")} />;

  const pageTitle = { scan: "Threat Scanner", agility: "Agility Checker", tls: "TLS Analyzer", history: "Scan History", migration: "Migration Tracker", dashboard: "Analytics", docs: "Documentation" };

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: C.bg }}>
      <button className="hamburger" onClick={() => setSidebarOpen(!sidebarOpen)}>☰</button>
      {sidebarOpen && <div className="sidebar-overlay open" onClick={() => setSidebarOpen(false)} />}

      <Sidebar active={active} setActive={setActive} user={user} onLogin={handleLogin} onLogout={handleLogout} open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div className="main-content" style={{ flex: 1, minHeight: "100vh", display: "flex", flexDirection: "column" }}>
        <TopBar title={pageTitle[active] || active} user={user} onLogin={handleLogin} onLogout={handleLogout} onHamburger={() => setSidebarOpen(!sidebarOpen)} />
        <div style={{ flex: 1, overflowY: "auto" }}>
          {active === "scan" && <ScannerPage user={user} />}
          {active === "agility" && <AgilityPage />}
          {active === "tls" && <TLSPage />}
          {active === "history" && <HistoryPage user={user} />}
          {active === "migration" && <MigrationPage user={user} />}
          {active === "dashboard" && <AnalyticsPage />}
          {active === "docs" && <DocsPage />}
        </div>
      </div>
    </div>
  );
}
