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

// ── Days to 2030 counter ─────────────────────────────────────
function daysTo2030() {
  const now = new Date();
  const y2q = new Date("2030-01-01");
  return Math.ceil((y2q - now) / (1000 * 60 * 60 * 24));
}

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
        {/* Y2Q countdown in sidebar */}
        <div style={{ margin: "10px 12px 0", padding: "8px 12px", background: "#fff5f5", border: "1px solid #fca5a5", borderRadius: 8 }}>
          <div style={{ fontSize: 9, color: C.red, fontWeight: 700, letterSpacing: 1, textTransform: "uppercase" }}>⚠ Quantum Deadline</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: C.red }}>{daysTo2030()}</div>
          <div style={{ fontSize: 9, color: C.muted }}>days until Y2Q (2030)</div>
        </div>
        <nav style={{ flex: 1, padding: "12px 12px" }}>
          {navItems.map(item => (
            <div key={item.id} onClick={() => { setActive(item.id); onClose(); }} style={{
              display: "flex", alignItems: "center", gap: 10, padding: "10px 12px",
              borderRadius: 10, marginBottom: 2, cursor: "pointer",
              background: active === item.id ? C.greenLight : "transparent",
              color: active === item.id ? C.green : C.muted,
              fontWeight: active === item.id ? 600 : 400, transition: "all 0.15s",
            }}>
              <span style={{ fontSize: 16 }}>{item.icon}</span>
              <span style={{ fontSize: 13 }}>{item.label}</span>
              {active === item.id && <div style={{ marginLeft: "auto", width: 6, height: 6, borderRadius: "50%", background: C.green }}></div>}
            </div>
          ))}
        </nav>
        <div style={{ padding: "10px 16px", margin: "0 12px 12px", borderRadius: 10, background: C.greenLighter, border: `1px solid ${C.greenMid}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: C.green }}></div>
            <span style={{ fontSize: 11, color: C.green, fontWeight: 600 }}>API Online</span>
          </div>
          <div style={{ fontSize: 9, color: C.muted, marginTop: 2 }}>quantumguard-api.onrender.com</div>
        </div>
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
      <button onClick={onHamburger} style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", fontSize: 20, padding: "0 4px", display: "none" }} className="hamburger-top">☰</button>
      <span style={{ color: C.muted, fontSize: 13 }}>QuantumGuard</span>
      <span style={{ color: C.greenMid, fontSize: 13 }}>›</span>
      <span style={{ color: C.text, fontSize: 14, fontWeight: 600 }}>{title}</span>
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
        {/* Y2Q badge in topbar */}
        <div style={{ display: "flex", alignItems: "center", gap: 6, background: "#fff5f5", padding: "4px 10px", borderRadius: 20, border: "1px solid #fca5a5" }}>
          <span style={{ fontSize: 11, color: C.red, fontWeight: 700 }}>⚠ {daysTo2030()}d to Y2Q</span>
        </div>
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

// ── ConfidenceBadge ───────────────────────────────────────────
function ConfidenceBadge({ confidence }) {
  const map = {
    HIGH: { color: C.red, bg: C.redLight },
    MEDIUM: { color: C.amber, bg: C.amberLight },
    LOW: { color: C.muted, bg: C.input },
  };
  const style = map[confidence] || map.LOW;
  return <Badge text={`${confidence} CONF`} color={style.color} bg={style.bg} />;
}

// ── TLS Label Badge ───────────────────────────────────────────
function TLSLabelBadge({ label }) {
  const map = {
    "Post-Quantum Safe": { color: C.green, bg: C.greenLight },
    "Modern TLS Secure": { color: C.blue, bg: C.blueLight },
    "Not Post-Quantum Safe Yet": { color: C.amber, bg: C.amberLight },
    "PQC Upgrade Recommended": { color: C.amber, bg: C.amberLight },
    "Insecure TLS Configuration": { color: C.red, bg: C.redLight },
    "PQC Upgrade Required": { color: C.red, bg: C.redLight },
  };
  const style = map[label] || { color: C.muted, bg: C.input };
  return <Badge text={label} color={style.color} bg={style.bg} />;
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
  const [sevFilter, setSevFilter] = useState("ALL");
  const [confFilter, setConfFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [checklist, setChecklist] = useState({});
  const [saved, setSaved] = useState(false);
  const [emailInput, setEmailInput] = useState("");
  const [emailSent, setEmailSent] = useState(false);
  const [sendingEmail, setSendingEmail] = useState(false);
  const [aiModal, setAiModal] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiResult, setAiResult] = useState(null);
  const [expandedSnippets, setExpandedSnippets] = useState({});
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
  const sev = result ? {
    CRITICAL: result.findings.filter(f => f.severity === "CRITICAL").length,
    HIGH: result.findings.filter(f => f.severity === "HIGH").length,
    MEDIUM: result.findings.filter(f => f.severity === "MEDIUM").length,
  } : null;
  const conf = result ? {
    HIGH: result.findings.filter(f => f.confidence === "HIGH").length,
    MEDIUM: result.findings.filter(f => f.confidence === "MEDIUM").length,
    LOW: result.findings.filter(f => f.confidence === "LOW").length,
  } : null;

  const filtered = result ? result.findings.filter(f =>
    (sevFilter === "ALL" || f.severity === sevFilter) &&
    (confFilter === "ALL" || f.confidence === confFilter) &&
    (search === "" || f.file?.toLowerCase().includes(search.toLowerCase()) || f.code?.toLowerCase().includes(search.toLowerCase()))
  ) : [];
  const grouped = filtered.reduce((a, f) => { if (!a[f.file]) a[f.file] = []; a[f.file].push(f); return a; }, {});

  const handleNIST = () => {
    if (!result) return;
    const NIST_MAP = {
      RSA: { id: "NIST SP 800-131A / FIPS 203", fix: "CRYSTALS-Kyber (ML-KEM) — FIPS 203" },
      ECC: { id: "NIST SP 800-186 / FIPS 204", fix: "CRYSTALS-Dilithium (ML-DSA) — FIPS 204" },
      DH: { id: "NIST SP 800-56A / FIPS 203", fix: "CRYSTALS-Kyber (ML-KEM) — FIPS 203" },
      DSA: { id: "NIST SP 800-186 / FIPS 204", fix: "CRYSTALS-Dilithium (ML-DSA) — FIPS 204" },
      MD5: { id: "NIST SP 800-107 / FIPS 202", fix: "SHA-3-256 — FIPS 202" },
      SHA1: { id: "NIST SP 800-107 / FIPS 202", fix: "SHA-3-256 — FIPS 202" },
      RC4: { id: "NIST SP 800-175B", fix: "AES-256-GCM — FIPS 197" },
      DES: { id: "NIST SP 800-131A", fix: "AES-256-GCM — FIPS 197" },
      ECB: { id: "NIST SP 800-38A", fix: "AES-256-GCM — FIPS 197" },
      TLS: { id: "NIST SP 800-52 Rev 2", fix: "TLS 1.3 — RFC 8446" },
      JWT: { id: "NIST SP 800-131A", fix: "RS256 with post-quantum keys" },
      WEAK_RANDOM: { id: "NIST SP 800-90A", fix: "DRBG / secrets module" },
    };
    const getNIST = (vuln) => {
      const key = Object.keys(NIST_MAP).find(k => (vuln || "").toUpperCase().includes(k));
      return key ? NIST_MAP[key] : { id: "NIST SP 800-175B", fix: "See NIST PQC standards" };
    };
    const win = window.open("", "_blank");
    const critCount = sev?.CRITICAL || 0;
    const highCount = sev?.HIGH || 0;
    const medCount = sev?.MEDIUM || 0;
    const confSummary = result.confidence_summary || {};
    const complianceStatus = result.quantum_readiness_score >= 70 ? "COMPLIANT" : result.quantum_readiness_score >= 40 ? "PARTIALLY COMPLIANT" : "NON-COMPLIANT";
    const statusColor = result.quantum_readiness_score >= 70 ? "#16a34a" : result.quantum_readiness_score >= 40 ? "#d97706" : "#dc2626";
    win.document.write(`<!DOCTYPE html>
<html><head><title>QuantumGuard NIST Compliance Report</title>
<style>
body{font-family:'Segoe UI',sans-serif;margin:0;padding:0;background:#f8faf8;color:#1a1a1a;}
.header{background:#16a34a;padding:32px 48px;}
h1{font-size:28px;font-weight:800;color:white;margin:0 0 6px;}
.header-sub{font-size:13px;color:rgba(255,255,255,0.8);}
.container{max-width:960px;margin:0 auto;padding:32px 48px;}
.meta-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px;}
.meta-card{background:white;border:1px solid #e2f0e2;border-radius:12px;padding:16px;text-align:center;}
.meta-label{font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;}
.meta-value{font-size:28px;font-weight:800;}
.section{background:white;border:1px solid #e2f0e2;border-radius:12px;margin-bottom:20px;overflow:hidden;}
.section-header{background:#f0fdf4;padding:14px 20px;border-bottom:1px solid #e2f0e2;}
.section-title{font-size:14px;font-weight:700;color:#15803d;}
.section-body{padding:20px;}
table{width:100%;border-collapse:collapse;font-size:12px;}
th{background:#16a34a;color:white;padding:10px 12px;text-align:left;font-size:11px;font-weight:600;}
td{padding:10px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top;}
tr:nth-child(even) td{background:#f9fafb;}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;}
.CRITICAL{background:#fee2e2;color:#dc2626;}.HIGH{background:#fef3c7;color:#d97706;}.MEDIUM{background:#fef9c3;color:#ca8a04;}
.nist-ref{font-family:monospace;font-size:10px;color:#2563eb;background:#dbeafe;padding:2px 6px;border-radius:4px;}
.fix{color:#16a34a;font-weight:500;}
.footer{background:#16a34a;padding:20px 48px;margin-top:32px;display:flex;justify-content:space-between;align-items:center;}
.footer-text{color:rgba(255,255,255,0.8);font-size:11px;}
.status-box{background:white;border:2px solid ${statusColor};border-radius:12px;padding:20px 24px;margin-bottom:28px;display:flex;justify-content:space-between;align-items:center;}
.status-value{font-size:22px;font-weight:800;color:${statusColor};}
@media print{body{background:white;}}
</style></head><body>
<div class="header">
  <h1>⚛ QuantumGuard — NIST PQC Compliance Report</h1>
  <div class="header-sub">Generated: ${new Date().toLocaleString()} · NIST FIPS 203/204/205 · quantumguard.site · Mangsri QuantumGuard LLC</div>
</div>
<div class="container">
  <div class="meta-grid">
    <div class="meta-card"><div class="meta-label">Readiness Score</div><div class="meta-value" style="color:${statusColor}">${result.quantum_readiness_score}/100</div></div>
    <div class="meta-card"><div class="meta-label">Total Findings</div><div class="meta-value" style="color:#dc2626">${result.total_findings}</div></div>
    <div class="meta-card"><div class="meta-label">Critical</div><div class="meta-value" style="color:#dc2626">${critCount}</div></div>
    <div class="meta-card"><div class="meta-label">High Confidence</div><div class="meta-value" style="color:#d97706">${confSummary.HIGH || 0}</div></div>
  </div>
  <div class="status-box">
    <div><div style="font-size:13px;color:#6b7280;margin-bottom:4px">NIST PQC Compliance Status</div><div class="status-value">${complianceStatus}</div></div>
    <div style="font-size:13px;color:#374151">Target: ${result.github_url || "Uploaded ZIP"}<br/>Date: ${new Date().toLocaleDateString()}<br/>Framework: NIST FIPS 203/204/205</div>
  </div>
  <div class="section">
    <div class="section-header"><div class="section-title">📋 Executive Summary</div></div>
    <div class="section-body">
      <p style="font-size:13px;color:#374151;line-height:1.7">This assessment identified <strong>${result.total_findings} quantum-vulnerable cryptographic implementations</strong> resulting in a Quantum Readiness Score of <strong style="color:${statusColor}">${result.quantum_readiness_score}/100</strong>. High-confidence findings: ${confSummary.HIGH || 0}. Medium-confidence: ${confSummary.MEDIUM || 0}. Low-confidence (docs/tests): ${confSummary.LOW || 0}. Migrate all CRITICAL findings before the Y2Q deadline (~2030).</p>
    </div>
  </div>
  <div class="section">
    <div class="section-header"><div class="section-title">🔍 Detailed Findings — ${result.total_findings} Vulnerabilities</div></div>
    <div class="section-body">
      <table>
        <tr><th>Severity</th><th>Confidence</th><th>File</th><th>Line</th><th>Vulnerable Code</th><th>NIST Reference</th><th>Fix</th></tr>
        ${result.findings.map(f => {
          const nist = getNIST(f.vulnerability || "");
          return `<tr>
            <td><span class="badge ${f.severity}">${f.severity}</span></td>
            <td style="font-size:10px;color:#6b7280">${f.confidence || "MEDIUM"}</td>
            <td style="font-family:monospace;font-size:10px;color:#2563eb">${(f.file || "").split("/").pop()}</td>
            <td style="font-family:monospace;font-size:10px">${f.line}</td>
            <td style="font-family:monospace;font-size:10px;max-width:180px;word-break:break-all">${(f.code || "").substring(0,50)}${(f.code || "").length > 50 ? "..." : ""}</td>
            <td><span class="nist-ref">${nist.id}</span></td>
            <td class="fix" style="font-size:10px">${f.replacement || f.recommended_fix || ""}</td>
          </tr>`;
        }).join("")}
      </table>
    </div>
  </div>
  <div class="section">
    <div class="section-header"><div class="section-title">✅ Remediation Priority</div></div>
    <div class="section-body">
      <table>
        <tr><th>#</th><th>Action</th><th>Algorithm</th><th>NIST Standard</th><th>Priority</th></tr>
        <tr><td>1</td><td>Replace RSA</td><td>CRYSTALS-Kyber (ML-KEM)</td><td><span class="nist-ref">FIPS 203</span></td><td><span class="badge CRITICAL">CRITICAL</span></td></tr>
        <tr><td>2</td><td>Replace ECC/ECDSA</td><td>CRYSTALS-Dilithium (ML-DSA)</td><td><span class="nist-ref">FIPS 204</span></td><td><span class="badge CRITICAL">CRITICAL</span></td></tr>
        <tr><td>3</td><td>Replace RC4/DES/3DES</td><td>AES-256-GCM</td><td><span class="nist-ref">FIPS 197</span></td><td><span class="badge CRITICAL">CRITICAL</span></td></tr>
        <tr><td>4</td><td>Upgrade TLS to 1.3</td><td>TLS 1.3 + PQC cipher suites</td><td><span class="nist-ref">NIST SP 800-52 Rev 2</span></td><td><span class="badge HIGH">HIGH</span></td></tr>
        <tr><td>5</td><td>Replace MD5/SHA-1</td><td>SHA-3-256 / BLAKE3</td><td><span class="nist-ref">FIPS 202</span></td><td><span class="badge MEDIUM">MEDIUM</span></td></tr>
      </table>
    </div>
  </div>
</div>
<div class="footer">
  <div style="color:white;font-weight:700">⚛ QuantumGuard v2.0</div>
  <div class="footer-text">Mangsri QuantumGuard LLC · quantumguard.site · NIST PQC Framework 2024</div>
  <div class="footer-text">${new Date().toLocaleDateString()}</div>
</div>
<script>window.print();</script>
</body></html>`);
    win.document.close();
  };

  const handleCSV = () => {
    if (!result) return;
    const blob = new Blob([
      "Severity,Confidence,File,Line,Vulnerability,Code,Risk,Fix,Migration Priority\n" +
      result.findings.map(f => `"${f.severity}","${f.confidence || "MEDIUM"}","${f.file}","${f.line}","${f.vulnerability}","${(f.code || "").replace(/"/g, "'")}","${(f.risk_explanation || "").replace(/"/g, "'")}","${(f.recommended_fix || f.replacement || "").replace(/"/g, "'")}","${f.migration_priority || ""}"`).join("\n")
    ], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "quantumguard-v2.csv"; a.click();
  };

  const handlePDF = () => {
    if (!result) return;
    const win = window.open("", "_blank");
    win.document.write(`<html><head><title>QuantumGuard Report</title><style>body{font-family:'Segoe UI',sans-serif;padding:40px;background:#f8faf8;color:#1a1a1a;}h1{color:#16a34a;border-bottom:3px solid #16a34a;padding-bottom:12px;}.score{font-size:64px;font-weight:800;color:${scoreColor};}.finding{border-left:4px solid #dc2626;padding:10px 16px;margin:8px 0;background:#fff;border-radius:0 8px 8px 0;box-shadow:0 1px 4px rgba(0,0,0,0.06);}.HIGH{border-color:#d97706;}.MEDIUM{border-color:#ca8a04;}code{background:#f0fdf4;padding:3px 8px;border-radius:4px;font-size:12px;color:#15803d;}.risk{font-size:11px;color:#6b7280;margin-top:4px;}.conf{font-size:10px;color:#2563eb;background:#dbeafe;padding:1px 6px;border-radius:4px;margin-left:6px;}</style></head><body>
    <h1>⚛ QuantumGuard Threat Report v2.0</h1>
    <p>Generated: ${new Date().toLocaleString()} · Mangsri QuantumGuard LLC · quantumguard.site</p>
    <p>Target: ${result.github_url || "ZIP Upload"}</p>
    <div class="score">${result.quantum_readiness_score}/100</div>
    <p>Total: ${result.total_findings} | Critical: ${sev?.CRITICAL} | High: ${sev?.HIGH} | Medium: ${sev?.MEDIUM}</p>
    <p>Confidence — HIGH: ${conf?.HIGH} | MEDIUM: ${conf?.MEDIUM} | LOW: ${conf?.LOW}</p>
    <hr/>
    ${result.findings.filter(f => f.confidence !== "LOW").map(f => `<div class="finding ${f.severity}">
      <b>[${f.severity}]</b> ${(f.file || "").split("/").pop()}:${f.line}<span class="conf">${f.confidence || "MEDIUM"}</span><br/>
      <code>${f.code || ""}</code><br/>
      <div class="risk">${f.risk_explanation || ""}</div>
      Fix: ${f.recommended_fix || f.replacement || ""}
    </div>`).join("")}
    </body></html>`);
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
          {/* Score + Severity metrics */}
          <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
            <Metric label="Quantum Readiness Score" value={result.quantum_readiness_score} suffix="/100" color={scoreColor} icon={result.quantum_readiness_score >= 70 ? "✅" : result.quantum_readiness_score >= 40 ? "⚠️" : "🚨"} desc={result.quantum_readiness_score >= 70 ? "Quantum Safe" : result.quantum_readiness_score >= 40 ? "At Risk" : "Critical Risk"} />
            <Metric label="Total Threats" value={result.total_findings} color={C.red} icon="🔍" desc="vulnerabilities detected" />
            <Metric label="Critical" value={sev.CRITICAL} color={C.critical} icon="🔴" desc="immediate action required" />
            <Metric label="High Risk" value={sev.HIGH} color={C.amber} icon="🟡" desc="requires attention" />
          </div>

          {/* Confidence summary — NEW v2.0 */}
          <Panel title="Confidence Summary — v2.0" accent>
            <div style={{ fontSize: 12, color: C.muted, marginBottom: 12, background: C.greenLighter, padding: "8px 12px", borderRadius: 6 }}>
              Score only counts HIGH and MEDIUM confidence findings. LOW confidence findings (docs/test files) are shown but do not affect your score.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 12 }}>
              {[
                ["HIGH Confidence", conf.HIGH, C.red, "Real API/function calls — fix these"],
                ["MEDIUM Confidence", conf.MEDIUM, C.amber, "Clear pattern matches — review these"],
                ["LOW Confidence", conf.LOW, C.muted, "Docs/test files — no score impact"],
              ].map(([label, val, color, desc], i) => (
                <div key={i} style={{ background: C.input, borderRadius: 10, padding: "14px 16px", textAlign: "center" }}>
                  <div style={{ fontSize: 11, color: C.muted, marginBottom: 4 }}>{label}</div>
                  <div style={{ fontSize: 28, fontWeight: 800, color }}>{val}</div>
                  <div style={{ fontSize: 11, color: C.muted, marginTop: 4 }}>{desc}</div>
                </div>
              ))}
            </div>
          </Panel>

          <div className="charts-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
            <Panel title="Severity Distribution" accent>
              <SevBar label="Critical" count={sev.CRITICAL} total={result.total_findings} color={C.critical} />
              <SevBar label="High" count={sev.HIGH} total={result.total_findings} color={C.amber} />
              <SevBar label="Medium" count={sev.MEDIUM} total={result.total_findings} color={C.medium} />
            </Panel>
            <Panel title="Score Breakdown" accent>
              <SevBar label="HIGH Confidence (full penalty)" count={conf.HIGH} total={result.total_findings} color={C.critical} />
              <SevBar label="MEDIUM Confidence (50% penalty)" count={conf.MEDIUM} total={result.total_findings} color={C.amber} />
              <SevBar label="LOW Confidence (no penalty)" count={conf.LOW} total={result.total_findings} color={C.muted} />
              <div style={{ fontSize: 11, color: C.muted, marginTop: 10, background: C.input, padding: "6px 10px", borderRadius: 6 }}>
                Score = 100 − (CRITICAL×10×conf_mult) − (HIGH×6×conf_mult) − (MEDIUM×3×conf_mult)
              </div>
            </Panel>
          </div>

          <Panel title="Export & Share" accent>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
              <button onClick={handlePDF} style={{ padding: "8px 16px", borderRadius: 8, background: C.green, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📄 PDF Report</button>
              <button onClick={handleNIST} style={{ padding: "8px 16px", borderRadius: 8, background: C.blue, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>🏛 NIST Report</button>
              <button onClick={handleCSV} style={{ padding: "8px 16px", borderRadius: 8, background: C.greenLight, color: C.green, border: `1px solid ${C.greenMid}`, cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📊 CSV Export</button>
              <button onClick={() => navigator.clipboard.writeText(result.findings.map(f => `[${f.severity}][${f.confidence}] ${f.file}:${f.line} — ${f.code} → ${f.recommended_fix || f.replacement}`).join("\n"))} style={{ padding: "8px 16px", borderRadius: 8, background: C.white, color: C.muted, border: `1px solid ${C.panelBorder}`, cursor: "pointer", fontSize: 12 }}>📋 Copy All</button>
              <button onClick={() => { const t = encodeURIComponent("QuantumGuard: " + result.quantum_readiness_score + "/100 — " + result.total_findings + " vulnerabilities\nquantumguard.site #QuantumSecurity"); window.open("https://twitter.com/intent/tweet?text=" + t, "_blank"); }} style={{ padding: "8px 16px", borderRadius: 8, background: "#1DA1F2", color: C.white, border: "none", cursor: "pointer", fontSize: 12 }}>🐦 Share</button>
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <input value={emailInput} onChange={e => setEmailInput(e.target.value)} placeholder="Email report to..." type="email" style={{ flex: 1, minWidth: 200, padding: "8px 14px", borderRadius: 8, border: `1px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 12 }} />
              <button onClick={handleEmail} disabled={sendingEmail || !emailInput} style={{ padding: "8px 16px", borderRadius: 8, background: C.green, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>{emailSent ? "✓ Sent!" : sendingEmail ? "Sending..." : "📧 Send Email"}</button>
            </div>
          </Panel>

          {/* Threat Intelligence — with confidence + severity filters */}
          <Panel title={`Threat Intelligence — ${result.total_findings} findings`} accent>
            <div style={{ display: "flex", gap: 8, marginBottom: 10, flexWrap: "wrap", alignItems: "center" }}>
              <span style={{ fontSize: 11, color: C.muted, fontWeight: 600 }}>SEVERITY:</span>
              {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map(f => (
                <button key={f} onClick={() => setSevFilter(f)} style={{ padding: "4px 12px", borderRadius: 20, border: `1.5px solid ${sevFilter === f ? C.green : C.panelBorder}`, background: sevFilter === f ? C.greenLight : C.white, color: sevFilter === f ? C.green : C.muted, cursor: "pointer", fontSize: 11, fontWeight: sevFilter === f ? 600 : 400 }}>
                  {f} {f !== "ALL" && sev ? `(${sev[f]})` : ""}
                </button>
              ))}
            </div>
            <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
              <span style={{ fontSize: 11, color: C.muted, fontWeight: 600 }}>CONFIDENCE:</span>
              {["ALL", "HIGH", "MEDIUM", "LOW"].map(f => (
                <button key={f} onClick={() => setConfFilter(f)} style={{ padding: "4px 12px", borderRadius: 20, border: `1.5px solid ${confFilter === f ? C.blue : C.panelBorder}`, background: confFilter === f ? C.blueLight : C.white, color: confFilter === f ? C.blue : C.muted, cursor: "pointer", fontSize: 11, fontWeight: confFilter === f ? 600 : 400 }}>
                  {f} {f !== "ALL" && conf ? `(${conf[f]})` : ""}
                </button>
              ))}
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search files..." style={{ padding: "4px 12px", borderRadius: 20, border: `1px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 11, width: 130, marginLeft: "auto" }} />
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
                    const showSnippet = expandedSnippets[key];
                    return (
                      <div key={i} style={{ borderLeft: `3px solid ${sevColor}`, paddingLeft: 14, marginBottom: i < findings.length - 1 ? 18 : 0, opacity: checklist[key] ? 0.4 : 1 }}>
                        {/* Header row */}
                        <div style={{ display: "flex", gap: 8, marginBottom: 6, alignItems: "center", flexWrap: "wrap" }}>
                          <input type="checkbox" checked={!!checklist[key]} onChange={() => setChecklist(p => ({ ...p, [key]: !p[key] }))} style={{ cursor: "pointer" }} />
                          <Badge text={f.severity} color={sevColor} bg={sevBg} />
                          <ConfidenceBadge confidence={f.confidence || "MEDIUM"} />
                          <span style={{ color: C.muted, fontSize: 11 }}>Line {f.line}</span>
                          {f.detection_method && <span style={{ fontSize: 10, color: C.blue, background: C.blueLight, padding: "1px 6px", borderRadius: 4 }}>{f.detection_method}</span>}
                          {f.is_test_file && <span style={{ fontSize: 10, color: C.muted, background: C.input, padding: "1px 6px", borderRadius: 4 }}>TEST FILE</span>}
                          {checklist[key] && <Badge text="✓ Remediated" color={C.green} bg={C.greenLight} />}
                          <button onClick={() => handleAiFix(f)} style={{ marginLeft: "auto", padding: "2px 10px", borderRadius: 6, background: C.greenLight, border: `1px solid ${C.greenMid}`, color: C.green, cursor: "pointer", fontSize: 10, fontWeight: 600 }}>⚡ AI Fix</button>
                        </div>
                        {/* Code */}
                        <div style={{ fontFamily: "monospace", background: C.input, padding: "8px 12px", borderRadius: 6, fontSize: 11, marginBottom: 6, color: C.greenDark, overflowX: "auto" }}>{f.code}</div>
                        {/* Snippet toggle */}
                        {f.snippet && (
                          <div style={{ marginBottom: 6 }}>
                            <button onClick={() => setExpandedSnippets(p => ({ ...p, [key]: !showSnippet }))} style={{ background: "transparent", border: "none", color: C.blue, cursor: "pointer", fontSize: 10, padding: 0 }}>
                              {showSnippet ? "▲ Hide context" : "▼ Show code context"}
                            </button>
                            {showSnippet && (
                              <div style={{ fontFamily: "monospace", background: "#f8f9ff", border: `1px solid ${C.blueLight}`, padding: "8px 12px", borderRadius: 6, fontSize: 11, marginTop: 4, whiteSpace: "pre", overflowX: "auto", color: C.textMid }}>{f.snippet}</div>
                            )}
                          </div>
                        )}
                        {/* Risk explanation — NEW */}
                        {f.risk_explanation && (
                          <div style={{ fontSize: 11, color: C.textMid, background: "#fff8f0", border: `1px solid ${C.amberLight}`, padding: "6px 10px", borderRadius: 6, marginBottom: 6 }}>
                            ⚠ <strong>Risk:</strong> {f.risk_explanation}
                          </div>
                        )}
                        {/* Fix */}
                        <div style={{ fontSize: 11, color: C.muted }}>
                          Fix: <span style={{ color: C.green, fontWeight: 500 }}>{f.recommended_fix || f.replacement}</span>
                        </div>
                        {/* Migration priority — NEW */}
                        {f.migration_priority && (
                          <div style={{ fontSize: 10, color: C.muted, marginTop: 3 }}>
                            Priority: <span style={{ color: f.severity === "CRITICAL" ? C.red : C.amber, fontWeight: 600 }}>{f.migration_priority}</span>
                          </div>
                        )}
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

      {/* AI Fix Modal */}
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
              <div style={{ fontSize: 11, color: C.muted, marginTop: 8 }}>{(aiModal.file || "").split("/").pop()}:{aiModal.line} · <Badge text={aiModal.severity} color={C.critical} bg={C.redLight} /> <ConfidenceBadge confidence={aiModal.confidence || "MEDIUM"} /></div>
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
// AGILITY PAGE — Updated for v2.0 response fields
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
          Score formula: <strong style={{ color: C.text }}>max(0, 100 − hardcoded×5 + configurable×3)</strong>
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && handleCheck()} placeholder="https://github.com/username/repo" style={{ flex: 1, minWidth: 200, padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
          <button onClick={handleCheck} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: loading ? "#86efac" : C.green, color: C.white, border: "none", cursor: loading ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600 }}>{loading ? "Analyzing..." : "🔬 Check Agility"}</button>
        </div>
        {error && <div style={{ marginTop: 12, background: C.redLight, border: `1px solid #fca5a5`, borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 13 }}>⚠ {error}</div>}
      </Panel>

      {result && (
        <>
          <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
            <Metric label="Agility Score" value={result.agility_score} suffix="/100" color={agilityColor} icon="🔬" desc={result.status || (result.agility_score >= 70 ? "High Agility" : "Low Agility")} />
            <Metric label="Hardcoded Crypto" value={result.hardcoded_count} color={C.red} icon="🔴" desc="needs to be configurable" />
            <Metric label="Configurable Crypto" value={result.configurable_count} color={C.green} icon="✅" desc="already agile" />
            <Metric label="Migration Ease" value={result.migration_ease || "—"} color={result.migration_ease === "Very Easy" ? C.green : result.migration_ease === "Hard" ? C.red : C.amber} icon="🚀" desc="to PQC migration" />
          </div>

          {/* Status + Summary box — NEW v2.0 */}
          {result.summary && (
            <Panel title="Agility Summary" accent>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                <div style={{ background: C.input, borderRadius: 8, padding: "12px 14px" }}>
                  <div style={{ fontSize: 11, color: C.muted, marginBottom: 4 }}>Status</div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: agilityColor }}>{result.status}</div>
                </div>
                <div style={{ background: C.input, borderRadius: 8, padding: "12px 14px" }}>
                  <div style={{ fontSize: 11, color: C.muted, marginBottom: 4 }}>Files With Issues</div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}>{result.summary.total_files_with_issues}</div>
                </div>
                <div style={{ background: C.greenLighter, border: `1px solid ${C.greenMid}`, borderRadius: 8, padding: "12px 14px", gridColumn: "span 2" }}>
                  <div style={{ fontSize: 11, color: C.muted, marginBottom: 4 }}>Recommendation</div>
                  <div style={{ fontSize: 13, color: C.green, fontWeight: 500 }}>{result.summary.recommendation}</div>
                </div>
              </div>
            </Panel>
          )}

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
                    <span style={{ color: C.muted, fontSize: 11 }}>{(f.file || "").split("/").pop()}:{f.line}</span>
                    <span style={{ color: C.muted, fontSize: 11 }}>— {f.description}</span>
                  </div>
                  <div style={{ fontFamily: "monospace", background: C.input, padding: "8px 12px", borderRadius: 6, fontSize: 11, marginBottom: 6, color: C.greenDark }}>{f.code}</div>
                  {/* Fix field — NEW v2.0 */}
                  <div style={{ fontSize: 11, marginBottom: 4 }}>
                    <span style={{ color: C.muted }}>Fix: </span>
                    <span style={{ color: f.type === "hardcoded" ? C.amber : C.green, fontWeight: 500 }}>{f.fix || f.recommendation}</span>
                  </div>
                  {f.impact && (
                    <div style={{ fontSize: 11, color: C.muted, fontStyle: "italic" }}>{f.impact}</div>
                  )}
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
// TLS PAGE — Updated for v2.0 response fields
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
          <strong style={{ color: C.red }}> quantum_safe=true ONLY when actual PQC/hybrid KEM is detected.</strong>
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
            <Metric label="TLS Score" value={result.tls_score} suffix="/100" color={scoreColor} icon="🎯" desc={result.tls_score >= 70 ? "Strong Config" : "Needs Improvement"} />
            <Metric label="TLS Version" value={result.tls_version} color={result.tls_version === "TLSv1.3" ? C.green : C.amber} icon="🔒" desc={result.tls_version === "TLSv1.3" ? "Latest standard" : "Upgrade recommended"} />
            <Metric label="Quantum Safe" value={result.quantum_safe ? "YES" : "NO"} color={result.quantum_safe ? C.green : C.red} icon={result.quantum_safe ? "✅" : "❌"} desc={result.quantum_safe ? "PQC KEM detected!" : "No PQC key exchange"} />
            <Metric label="Key Size" value={result.cipher_bits} suffix=" bit" color={result.cipher_bits >= 256 ? C.green : C.amber} icon="🔑" desc={result.cipher_bits >= 256 ? "Quantum-resilient" : "Upgrade to 256-bit"} />
          </div>

          {/* Labels — NEW v2.0 */}
          {result.labels && result.labels.length > 0 && (
            <Panel title="Security Classification" accent>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
                {result.labels.map((label, i) => (
                  <TLSLabelBadge key={i} label={label} />
                ))}
              </div>
              {result.nist_recommendation && (
                <div style={{ background: C.blueLight, border: `1px solid #93c5fd`, borderRadius: 8, padding: "10px 14px" }}>
                  <div style={{ fontSize: 11, color: C.blue, fontWeight: 600, marginBottom: 4 }}>NIST Recommendation ({result.nist_standard})</div>
                  <div style={{ fontSize: 12, color: C.textMid, lineHeight: 1.7 }}>{result.nist_recommendation}</div>
                </div>
              )}
            </Panel>
          )}

          {/* Strengths + Crypto Issues (separate from cert) — NEW v2.0 */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
            {result.strengths && result.strengths.length > 0 && (
              <Panel title="✅ Strengths" accent>
                {result.strengths.map((s, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, padding: "8px 0", borderBottom: i < result.strengths.length - 1 ? `1px solid ${C.panelBorder}` : "none" }}>
                    <span style={{ color: C.green }}>✓</span>
                    <span style={{ fontSize: 13, color: C.textMid }}>{s}</span>
                  </div>
                ))}
              </Panel>
            )}

            {result.crypto_issues && result.crypto_issues.length > 0 && (
              <Panel title="⚠ Crypto Issues" accent>
                {result.crypto_issues.map((issue, i) => (
                  <div key={i} style={{ display: "flex", gap: 8, padding: "8px 0", borderBottom: i < result.crypto_issues.length - 1 ? `1px solid ${C.panelBorder}` : "none" }}>
                    <span style={{ color: C.red }}>⚠</span>
                    <span style={{ fontSize: 12, color: C.textMid, lineHeight: 1.5 }}>{issue}</span>
                  </div>
                ))}
              </Panel>
            )}
          </div>

          {/* Certificate Issues — SEPARATE from crypto score */}
          {result.cert_issues && result.cert_issues.length > 0 && (
            <Panel title="🔒 Certificate Issues (separate from score)" accent>
              <div style={{ fontSize: 11, color: C.muted, marginBottom: 10, background: C.amberLight, padding: "6px 10px", borderRadius: 6 }}>
                Certificate issues do not affect the TLS crypto score. They are operational risks shown separately.
              </div>
              {result.cert_issues.map((issue, i) => (
                <div key={i} style={{ display: "flex", gap: 10, padding: "10px 0", borderBottom: i < result.cert_issues.length - 1 ? `1px solid ${C.panelBorder}` : "none" }}>
                  <span style={{ color: C.amber, fontSize: 16 }}>⏰</span>
                  <span style={{ fontSize: 13, color: C.textMid }}>{issue}</span>
                </div>
              ))}
            </Panel>
          )}

          {/* Certificate details */}
          {result.certificate && (
            <Panel title="Certificate Details" accent>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                {[
                  ["Domain", result.domain],
                  ["Cipher Suite", result.cipher_suite],
                  ["Certificate CN", result.certificate.subject_cn || "—"],
                  ["Issuer", result.certificate.issuer_cn || "—"],
                  ["Expires", result.certificate.cert_expires || "—"],
                  ["Days Remaining", result.certificate.days_until_expiry != null ? `${result.certificate.days_until_expiry} days` : "—"],
                  ["Forward Secrecy", result.has_forward_secrecy ? "Yes" : "No"],
                  ["PQC Key Exchange", result.has_pqc_key_exchange ? "Yes (Detected!)" : "Not yet"],
                ].map(([label, value], i) => (
                  <div key={i} style={{ background: C.input, borderRadius: 8, padding: "10px 12px" }}>
                    <div style={{ fontSize: 11, color: C.muted, marginBottom: 3 }}>{label}</div>
                    <div style={{ fontSize: 12, color: C.text, fontWeight: 500, wordBreak: "break-all" }}>{value}</div>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {result.crypto_issues && result.crypto_issues.length === 0 && result.cert_issues && result.cert_issues.length === 0 && (
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
          { year: "2026", event: "QuantumGuard v2.0 launches — confidence levels, accurate TLS analysis, false positive reduction", color: C.blue },
          { year: "2027", event: "Regulatory pressure increases — organizations must show PQC compliance", color: C.amber },
          { year: "2030", event: `Y2Q — Quantum computers break RSA/ECC. ${daysTo2030()} days remaining.`, color: C.red },
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
          { method: "GET", path: "/health", auth: "None", desc: "Returns {status: healthy, version: 2.0}" },
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
// HOMEPAGE — Updated with Y2Q counter + trust signals
// ══════════════════════════════════════════════════════════════
function Homepage({ onGetStarted }) {
  const days = daysTo2030();
  return (
    <div style={{ minHeight: "100vh", background: C.bg, fontFamily: "'Segoe UI', sans-serif" }}>
      {/* Navbar */}
      <nav style={{ background: C.white, borderBottom: `1px solid ${C.panelBorder}`, padding: "0 16px", height: 64, display: "flex", alignItems: "center", justifyContent: "space-between", boxShadow: "0 1px 4px rgba(0,0,0,0.06)", position: "sticky", top: 0, zIndex: 50 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 36, height: 36, borderRadius: 10, background: C.green, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18 }}>⚛</div>
          <span style={{ fontSize: 18, fontWeight: 700 }}><span style={{ color: C.green }}>Quantum</span>Guard</span>
        </div>
        <div className="nav-links" style={{ display: "flex", alignItems: "center", gap: 32 }}>
          {[{ label: "Features", id: "features" }, { label: "How It Works", id: "howitworks" }, { label: "Pricing", id: "pricing" }, { label: "Documentation", id: "docs" }].map(item => (
            <span key={item.id} onClick={() => document.getElementById(item.id)?.scrollIntoView({ behavior: "smooth" })} style={{ fontSize: 14, color: C.muted, cursor: "pointer" }} onMouseEnter={e => e.target.style.color = C.green} onMouseLeave={e => e.target.style.color = C.muted}>{item.label}</span>
          ))}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, background: "#fff5f5", padding: "6px 12px", borderRadius: 20, border: "1px solid #fca5a5" }}>
            <span style={{ fontSize: 11, color: C.red, fontWeight: 700 }}>⚠ {days} days to Y2Q</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, background: C.greenLighter, padding: "6px 12px", borderRadius: 20, border: `1px solid ${C.greenMid}` }}>
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: C.green }}></div>
            <span style={{ fontSize: 11, color: C.green, fontWeight: 600 }}>API ONLINE</span>
          </div>
          <button onClick={onGetStarted} style={{ background: C.green, color: C.white, padding: "9px 22px", borderRadius: 10, border: "none", cursor: "pointer", fontSize: 14, fontWeight: 600, boxShadow: "0 2px 8px rgba(22,163,74,0.3)" }}>Get Started Free</button>
        </div>
      </nav>

      {/* Urgency bar */}
      <div style={{ background: "#fff5f5", borderBottom: "1px solid #fca5a5", padding: "10px 40px", display: "flex", alignItems: "center", justifyContent: "center", gap: 16, flexWrap: "wrap" }}>
        <span style={{ fontSize: 13, color: C.red, fontWeight: 700 }}>⚠ QUANTUM DEADLINE 2030</span>
        <span style={{ fontSize: 13, color: C.textMid }}>{days} days remaining · RSA and ECC encryption will be broken by quantum computers · Start your migration now</span>
        <button onClick={onGetStarted} style={{ background: C.red, color: C.white, padding: "5px 16px", borderRadius: 8, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>Scan My Code Free →</button>
      </div>

      {/* Hero */}
      <div className="hero-grid" style={{ maxWidth: 1200, margin: "0 auto", padding: "40px 20px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 60, alignItems: "center" }}>
        <div>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 6, background: C.greenLighter, border: `1px solid ${C.greenMid}`, borderRadius: 20, padding: "5px 14px", marginBottom: 24 }}>
            <span style={{ fontSize: 12, color: C.green, fontWeight: 600 }}>🛡 World's First Free Quantum Vulnerability Scanner</span>
          </div>
          <h1 style={{ fontSize: "clamp(32px,4vw,52px)", fontWeight: 800, lineHeight: 1.15, marginBottom: 20, color: C.text }}>
            Find Quantum<br /><span style={{ color: C.green }}>Vulnerabilities.</span><br />Secure Tomorrow.
          </h1>
          <p style={{ fontSize: 16, color: C.muted, lineHeight: 1.7, marginBottom: 32, maxWidth: 480 }}>
            QuantumGuard scans your codebase for RSA, ECC, MD5, DES and other cryptographic vulnerabilities that will be broken by quantum computers by 2030. Free forever.
          </p>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 28 }}>
            <button onClick={onGetStarted} style={{ background: C.green, color: C.white, padding: "13px 28px", borderRadius: 10, border: "none", cursor: "pointer", fontSize: 15, fontWeight: 700, boxShadow: "0 4px 12px rgba(22,163,74,0.3)", display: "flex", alignItems: "center", gap: 8 }}>
              🛡 Run a Free Scan Now
            </button>
            <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ background: C.white, color: C.text, padding: "13px 28px", borderRadius: 10, border: `1.5px solid ${C.panelBorder}`, cursor: "pointer", fontSize: 15, fontWeight: 600, textDecoration: "none", display: "flex", alignItems: "center", gap: 8 }}>
              ⭐ Star on GitHub
            </a>
          </div>
          {/* Trust signals */}
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 20 }}>
            {[["✓ No signup required", C.green], ["✓ Scans in 30 seconds", C.green], ["✓ NIST FIPS 203/204/205", C.green], ["✓ Open Source (AGPL v3)", C.green]].map(([text, color], i) => (
              <span key={i} style={{ fontSize: 12, color, fontWeight: 500 }}>{text}</span>
            ))}
          </div>
          {/* Submitted to NIST badge */}
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, background: C.blueLight, border: `1px solid #93c5fd`, borderRadius: 8, padding: "8px 14px" }}>
            <span style={{ fontSize: 18 }}>🏛</span>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: C.blue }}>Submitted to NIST NCCoE</div>
              <div style={{ fontSize: 10, color: C.muted }}>nccoe@nist.gov · pqc-comments@nist.gov</div>
            </div>
          </div>
        </div>

        {/* Dashboard preview */}
        <div className="hero-preview" style={{ background: C.white, borderRadius: 16, boxShadow: "0 20px 60px rgba(0,0,0,0.12)", border: `1px solid ${C.panelBorder}`, overflow: "hidden" }}>
          <div style={{ background: C.green, padding: "10px 16px", display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 28, height: 28, borderRadius: 6, background: "rgba(255,255,255,0.2)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 14 }}>⚛</div>
            <span style={{ color: C.white, fontSize: 13, fontWeight: 600 }}>QuantumGuard v2.0</span>
            <span style={{ color: "rgba(255,255,255,0.7)", fontSize: 12, marginLeft: "auto" }}>Live Dashboard</span>
          </div>
          <div style={{ padding: 16 }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 12 }}>
              <div style={{ background: C.greenLighter, borderRadius: 10, padding: 14, border: `1px solid ${C.greenMid}` }}>
                <div style={{ fontSize: 11, color: C.muted, marginBottom: 4 }}>Security Score</div>
                <div style={{ fontSize: 32, fontWeight: 800, color: C.amber }}>72<span style={{ fontSize: 14, color: C.muted }}>/100</span></div>
                <div style={{ fontSize: 11, color: C.amber, fontWeight: 600 }}>At Risk</div>
              </div>
              <div style={{ background: C.input, borderRadius: 10, padding: 14 }}>
                <div style={{ fontSize: 11, color: C.muted, marginBottom: 6 }}>Confidence Breakdown</div>
                {[["HIGH", "12", C.red], ["MEDIUM", "8", C.amber], ["LOW", "4", C.muted]].map(([l, n, c], i) => (
                  <div key={i} style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <span style={{ fontSize: 10, color: C.muted }}>{l}</span>
                    <span style={{ fontSize: 12, fontWeight: 700, color: c }}>{n}</span>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ background: C.input, borderRadius: 8, padding: 10, marginBottom: 10 }}>
              <div style={{ fontSize: 11, color: C.muted, marginBottom: 6, fontWeight: 500 }}>TLS Analysis — google.com</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                <span style={{ background: C.blueLight, color: C.blue, padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700 }}>Modern TLS Secure</span>
                <span style={{ background: C.amberLight, color: C.amber, padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700 }}>Not Post-Quantum Safe Yet</span>
                <span style={{ background: C.amberLight, color: C.amber, padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700 }}>PQC Upgrade Recommended</span>
              </div>
            </div>
            <div style={{ background: C.input, borderRadius: 8, padding: 10 }}>
              <div style={{ fontSize: 11, color: C.muted, marginBottom: 6, fontWeight: 500 }}>Top HIGH Confidence Findings</div>
              {[["CRITICAL", "RSA key generation", "HIGH CONF"], ["HIGH", "Hardcoded IV", "HIGH CONF"], ["MEDIUM", "SHA-1 hash usage", "MED CONF"]].map(([sev, issue, conf], i) => {
                const sevColor = sev === "CRITICAL" ? C.critical : sev === "HIGH" ? C.amber : C.medium;
                const sevBg = sev === "CRITICAL" ? C.redLight : sev === "HIGH" ? C.amberLight : "#fef9c3";
                return (
                  <div key={i} style={{ display: "flex", gap: 6, alignItems: "center", padding: "4px 0", borderBottom: i < 2 ? `1px solid ${C.panelBorder}` : "none" }}>
                    <span style={{ background: sevBg, color: sevColor, padding: "1px 6px", borderRadius: 4, fontSize: 9, fontWeight: 700 }}>{sev}</span>
                    <span style={{ fontSize: 10, color: C.text, flex: 1 }}>{issue}</span>
                    <span style={{ fontSize: 9, color: C.red, fontWeight: 600 }}>{conf}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Stats bar */}
      <div style={{ background: C.white, borderTop: `1px solid ${C.panelBorder}`, borderBottom: `1px solid ${C.panelBorder}`, padding: "24px 16px" }}>
        <div className="stats-bar-grid" style={{ maxWidth: 1200, margin: "0 auto", display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 20, textAlign: "center" }}>
          {[["50+", "Vulnerability Checks"], ["8", "Supported Languages"], [`${days}d`, "Until Y2Q (2030)"], ["< 30s", "Average Scan Time"], ["$0", "Cost Forever"]].map(([num, label], i) => (
            <div key={i}>
              <div style={{ fontSize: 28, fontWeight: 800, color: i === 2 ? C.red : C.green }}>{num}</div>
              <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>{label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Features */}
      <div id="features" style={{ maxWidth: 1200, margin: "0 auto", padding: "60px 40px" }}>
        <h2 style={{ fontSize: 36, fontWeight: 800, textAlign: "center", marginBottom: 12, color: C.text }}>Everything you need to go quantum-safe</h2>
        <p style={{ textAlign: "center", color: C.muted, fontSize: 16, marginBottom: 40 }}>Comprehensive quantum vulnerability detection and migration tools</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px,1fr))", gap: 20 }}>
          {[
            { icon: "🔍", title: "Quantum Vulnerability Scanner", desc: "Detects cryptographic algorithms vulnerable to quantum attacks across 8 languages. Confidence-weighted scoring — no false positive inflation." },
            { icon: "🎯", title: "Confidence Levels", desc: "Every finding rated HIGH/MEDIUM/LOW confidence. HIGH = real API calls. LOW = docs/tests. Score only counts real threats." },
            { icon: "🔬", title: "Crypto Agility Checker", desc: "Checks if your encryption is hardcoded or configurable. Score formula: max(0, 100 − hardcoded×5 + configurable×3)." },
            { icon: "🔐", title: "TLS Analyzer", desc: "Accurate TLS scoring. quantum_safe=true ONLY when actual PQC/hybrid KEM detected. Cert expiry separated from crypto score." },
            { icon: "🏛", title: "NIST Compliance Reports", desc: "Full PDF reports aligned with NIST FIPS 203, 204, 205. Export CSV for your security team." },
            { icon: "🔄", title: "GitHub Actions CI/CD", desc: "Auto-scan on every push. Fail builds below your threshold. Posts results as PR comments." },
          ].map((f, i) => (
            <div key={i} style={{ background: C.white, borderRadius: 12, padding: 24, border: `1px solid ${C.panelBorder}`, boxShadow: "0 1px 4px rgba(0,0,0,0.04)" }}>
              <div style={{ width: 48, height: 48, borderRadius: 12, background: C.greenLighter, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22, marginBottom: 14 }}>{f.icon}</div>
              <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 8, color: C.text }}>{f.title}</div>
              <div style={{ fontSize: 13, color: C.muted, lineHeight: 1.6 }}>{f.desc}</div>
            </div>
          ))}
        </div>
      </div>

      {/* HOW IT WORKS */}
      <div id="howitworks" style={{ background: C.white, borderTop: `1px solid ${C.panelBorder}`, padding: "60px 40px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <h2 style={{ fontSize: 36, fontWeight: 800, textAlign: "center", marginBottom: 12, color: C.text }}>How It Works</h2>
          <p style={{ textAlign: "center", color: C.muted, fontSize: 16, marginBottom: 48 }}>Scan your codebase in 30 seconds — no installation needed</p>
          <div className="how-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 32, maxWidth: 900, margin: "0 auto" }}>
            {[
              { step: "1", title: "Paste GitHub URL", desc: "Enter any public or private GitHub repository URL. No git installation needed.", icon: "🔗" },
              { step: "2", title: "We Scan Your Code", desc: "Our AST + regex engine checks every line against 15+ vulnerability patterns with confidence scoring.", icon: "🔍" },
              { step: "3", title: "Get Your Report", desc: "Receive a Quantum Readiness Score with exact fixes, NIST references, PDF export, and confidence levels.", icon: "📊" },
            ].map((s, i) => (
              <div key={i} style={{ textAlign: "center" }}>
                <div style={{ width: 64, height: 64, borderRadius: "50%", background: C.green, color: C.white, fontSize: 28, fontWeight: 800, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 16px" }}>{s.step}</div>
                <div style={{ fontSize: 36, marginBottom: 12 }}>{s.icon}</div>
                <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8, color: C.text }}>{s.title}</div>
                <div style={{ fontSize: 14, color: C.muted, lineHeight: 1.7 }}>{s.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* PRICING */}
      <div id="pricing" style={{ maxWidth: 1200, margin: "0 auto", padding: "60px 40px" }}>
        <h2 style={{ fontSize: 36, fontWeight: 800, textAlign: "center", marginBottom: 12, color: C.text }}>Simple Pricing</h2>
        <p style={{ textAlign: "center", color: C.muted, fontSize: 16, marginBottom: 40 }}>Start free. Upgrade when you need more.</p>
        <div className="pricing-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 24, maxWidth: 1000, margin: "0 auto" }}>
          {[
            { name: "Free", price: "$0", period: "forever", color: C.text, features: ["Web scanner", "GitHub URL + ZIP scan", "15+ vulnerability types", "PDF & CSV reports", "TLS Analyzer", "Agility Checker", "Confidence scoring", "NIST compliance reports"], highlight: false, cta: "Get Started Free" },
            { name: "Pro", price: "$29", period: "/month", color: C.green, features: ["Everything in Free", "Unlimited scans", "AI-powered fix suggestions", "Team members (5 seats)", "API access", "Priority support", "Migration tracker"], highlight: true, cta: "Coming Soon" },
            { name: "Enterprise", price: "Custom", period: "", color: C.text, features: ["Everything in Pro", "Unlimited team members", "CI/CD integration", "SSO login", "SOC2 compliance", "Dedicated support", "Custom reports"], highlight: false, cta: "Contact Us" },
          ].map((p, i) => (
            <div key={i} style={{ background: C.white, borderRadius: 16, padding: 28, border: p.highlight ? `2px solid ${C.green}` : `1px solid ${C.panelBorder}`, boxShadow: p.highlight ? "0 8px 24px rgba(22,163,74,0.15)" : "0 1px 4px rgba(0,0,0,0.04)", position: "relative" }}>
              {p.highlight && <div style={{ position: "absolute", top: -14, left: "50%", transform: "translateX(-50%)", background: C.green, color: C.white, padding: "4px 16px", borderRadius: 20, fontSize: 12, fontWeight: 600 }}>Most Popular</div>}
              <div style={{ fontSize: 18, fontWeight: 700, color: C.text, marginBottom: 6 }}>{p.name}</div>
              <div style={{ fontSize: 36, fontWeight: 800, color: p.color, marginBottom: 4 }}>{p.price}<span style={{ fontSize: 14, color: C.muted, fontWeight: 400 }}>{p.period}</span></div>
              <div style={{ height: 1, background: C.panelBorder, margin: "16px 0" }}></div>
              {p.features.map((f, j) => (
                <div key={j} style={{ display: "flex", gap: 8, marginBottom: 8, alignItems: "flex-start" }}>
                  <span style={{ color: C.green, fontWeight: 700, fontSize: 13 }}>✓</span>
                  <span style={{ fontSize: 13, color: C.muted }}>{f}</span>
                </div>
              ))}
              <button style={{ width: "100%", marginTop: 20, padding: "11px", borderRadius: 10, background: p.highlight ? C.green : C.white, color: p.highlight ? C.white : C.green, border: `1.5px solid ${C.green}`, cursor: "pointer", fontSize: 14, fontWeight: 600 }}>{p.cta}</button>
            </div>
          ))}
        </div>
      </div>

      {/* DOCS SECTION */}
      <div id="docs" style={{ background: C.white, borderTop: `1px solid ${C.panelBorder}`, padding: "60px 40px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <h2 style={{ fontSize: 36, fontWeight: 800, textAlign: "center", marginBottom: 12, color: C.text }}>Documentation</h2>
          <p style={{ textAlign: "center", color: C.muted, fontSize: 16, marginBottom: 40 }}>Everything you need to integrate QuantumGuard</p>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(240px,1fr))", gap: 20 }}>
            {[
              { icon: "⚡", title: "Quick Start", desc: "Scan your first repo in 30 seconds. No installation required.", steps: ["Paste GitHub URL", "Click Run Scan", "Download report"] },
              { icon: "🔌", title: "REST API", desc: "Integrate QuantumGuard into your stack with our simple REST API.", steps: ["POST /scan-github", "POST /check-agility", "POST /analyze-tls"] },
              { icon: "🔄", title: "GitHub Actions", desc: "Auto-scan your repo on every push with our CI/CD workflow.", steps: ["Copy workflow YAML", "Add to .github/workflows/", "Push to trigger scan"] },
              { icon: "🔒", title: "Private Repos", desc: "Scan private repositories securely using GitHub PAT.", steps: ["Generate GitHub PAT", "Click Private Repo", "Token never stored"] },
            ].map((d, i) => (
              <div key={i} style={{ background: C.greenLighter, borderRadius: 12, padding: 24, border: `1px solid ${C.greenMid}` }}>
                <div style={{ fontSize: 28, marginBottom: 10 }}>{d.icon}</div>
                <div style={{ fontSize: 15, fontWeight: 700, color: C.text, marginBottom: 6 }}>{d.title}</div>
                <div style={{ fontSize: 13, color: C.muted, marginBottom: 14, lineHeight: 1.6 }}>{d.desc}</div>
                {d.steps.map((step, j) => (
                  <div key={j} style={{ display: "flex", gap: 8, marginBottom: 6, alignItems: "center" }}>
                    <div style={{ width: 18, height: 18, borderRadius: "50%", background: C.green, color: C.white, fontSize: 10, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{j + 1}</div>
                    <span style={{ fontSize: 12, color: C.textMid }}>{step}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* CTA */}
      <div style={{ background: C.greenLighter, borderTop: `1px solid ${C.greenMid}`, padding: "60px 40px", textAlign: "center" }}>
        <h2 style={{ fontSize: 32, fontWeight: 800, color: C.text, marginBottom: 12 }}>Ready to secure your code for the quantum future?</h2>
        <p style={{ color: C.muted, marginBottom: 12, fontSize: 15 }}>The quantum deadline is {days} days away. Start your migration today — it's free.</p>
        <p style={{ color: C.muted, marginBottom: 28, fontSize: 13 }}>Submitted to NIST NCCoE · Open Source (AGPL v3) · Built by Mangsri QuantumGuard LLC</p>
        <button onClick={onGetStarted} style={{ background: C.green, color: C.white, padding: "14px 36px", borderRadius: 10, border: "none", cursor: "pointer", fontSize: 16, fontWeight: 700, boxShadow: "0 4px 12px rgba(22,163,74,0.3)", display: "inline-flex", alignItems: "center", gap: 8 }}>
          🛡 Start Scanning Now — Free
        </button>
      </div>

      <div style={{ background: C.white, borderTop: `1px solid ${C.panelBorder}`, padding: "20px 40px", textAlign: "center" }}>
        <div style={{ color: C.muted, fontSize: 12, marginBottom: 8 }}>
          QuantumGuard v2.0 · Mangsri QuantumGuard LLC · EIN: 42-2185776 · Montgomery, AL · Open Source · Free Forever · quantumguard.site
        </div>
        <div style={{ display: "flex", justifyContent: "center", gap: 20, flexWrap: "wrap" }}>
          {[["About", "/about.html"], ["Privacy Policy", "/privacy.html"], ["Terms of Service", "/terms.html"], ["SLA", "/sla.html"]].map(([label, href], i) => (
            <a key={i} href={href} style={{ color: C.green, fontSize: 12, textDecoration: "none" }}>{label}</a>
          ))}
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ color: C.green, fontSize: 12, textDecoration: "none" }}>GitHub ↗</a>
          <a href="https://quantumguard-api.onrender.com/docs" target="_blank" rel="noreferrer" style={{ color: C.green, fontSize: 12, textDecoration: "none" }}>API Docs ↗</a>
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
      <div className="main-content" style={{ marginLeft: 240, flex: 1, minHeight: "100vh", display: "flex", flexDirection: "column" }}>
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
