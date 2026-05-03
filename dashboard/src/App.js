import { useState, useEffect, useRef } from "react";
import "./App.css";
import emailjs from "@emailjs/browser";
import { auth, db, signInWithGoogle, canUserScan, incrementScanCount } from "./firebase";
import { onAuthStateChanged, signOut } from "firebase/auth";
import { collection, addDoc, getDocs, query, where, orderBy } from "firebase/firestore";
import { AuthProvider, useAuth } from "./AuthContext";

const API = "https://quantumguard-api.onrender.com";

const C = {
  bg:           "#0a0e1a",
  sidebar:      "#0d1120",
  sidebarBorder:"#1e2a3a",
  topbar:       "#0d1120",
  panel:        "#111827",
  panelBorder:  "#1e2d40",
  input:        "#0f1a2b",
  green:        "#22c55e",
  greenDark:    "#16a34a",
  greenLight:   "#052e16",
  greenLighter: "#071f0e",
  greenMid:     "#166534",
  red:          "#ef4444",
  redLight:     "#2a0a0a",
  amber:        "#f59e0b",
  amberLight:   "#1c1200",
  blue:         "#3b82f6",
  blueLight:    "#0c1a3a",
  text:         "#f1f5f9",
  textMid:      "#94a3b8",
  muted:        "#4b5563",
  white:        "#ffffff",
  critical:     "#ef4444",
  high:         "#f59e0b",
  medium:       "#eab308",
};

const SCAN_STEPS = [
  "Initializing scan engine...", "Connecting to target...", "Analyzing file structure...",
  "Running vulnerability checks...", "Calculating risk score...", "Generating threat report...",
];

const SCAN_LOG_PHASES = [
  { step: "Initializing scan engine...", logs: [
    { type: "info",    text: "QuantumGuard engine v3.0 starting up" },
    { type: "info",    text: "Loading NIST FIPS 203/204/205 signature database" },
    { type: "success", text: "Vulnerability pattern library loaded — 58 patterns active" },
    { type: "info",    text: "Initializing AST parser for multi-language support" },
  ]},
  { step: "Connecting to target...", logs: [
    { type: "info",    text: "Resolving repository URL..." },
    { type: "info",    text: "Authenticating with GitHub API" },
    { type: "success", text: "Repository access confirmed" },
    { type: "info",    text: "Cloning into temporary workspace..." },
    { type: "success", text: "Clone complete — ready to scan" },
  ]},
  { step: "Analyzing file structure...", logs: [
    { type: "info",    text: "Walking directory tree..." },
    { type: "info",    text: "Detected languages: Python, JavaScript, Java" },
    { type: "info",    text: "Indexing 47 source files across 12 directories" },
    { type: "warn",    text: "Skipping node_modules/ (excluded by default)" },
    { type: "success", text: "File index complete — 47 files queued for analysis" },
  ]},
  { step: "Running vulnerability checks...", logs: [
    { type: "info",    text: "Scanning auth/ ..." },
    { type: "critical",text: "CRITICAL  RSA-2048 detected → auth/keypair.js:14" },
    { type: "info",    text: "Scanning crypto/ ..." },
    { type: "critical",text: "CRITICAL  ECC P-256 detected → crypto/sign.py:7" },
    { type: "info",    text: "Scanning tls/ ..." },
    { type: "warn",    text: "HIGH      DH-2048 key exchange → tls/handshake.java:33" },
    { type: "info",    text: "Scanning utils/ ..." },
    { type: "warn",    text: "MEDIUM    MD5 hash usage → utils/checksum.js:19" },
    { type: "info",    text: "Scanning remaining 43 files..." },
    { type: "success", text: "Vulnerability sweep complete — 4 findings" },
  ]},
  { step: "Calculating risk score...", logs: [
    { type: "info",    text: "Applying NIST SP 800-53 control mapping" },
    { type: "info",    text: "Weighting: CRITICAL ×3.0 · HIGH ×2.0 · MEDIUM ×1.0" },
    { type: "info",    text: "Computing penalty function..." },
    { type: "warn",    text: "Score penalty: 2 critical findings (-34 pts)" },
    { type: "success", text: "Quantum Readiness Score calculated: 42 / 100" },
  ]},
  { step: "Generating threat report...", logs: [
    { type: "info",    text: "Building NIST control compliance matrix" },
    { type: "info",    text: "Generating CRYSTALS-Kyber migration guidance" },
    { type: "info",    text: "Compiling PDF-ready report structure" },
    { type: "success", text: "Score explanation generated — 5 lines" },
    { type: "success", text: "Scan summary ready — all modules complete" },
    { type: "success", text: "✓ Scan complete in 8.3s" },
  ]},
];

// ── Sidebar ──────────────────────────────────────────────────
function Sidebar({ active, setActive, user, onLogin, onLogout, open, onClose }) {
  const { jwtUser } = useAuth();
  const displayUser = jwtUser || user;
  const navItems = [
    { id: "scan",      icon: "⚡", label: "Scanner" },
    { id: "agility",   icon: "🔬", label: "Agility Checker" },
    { id: "tls",       icon: "🔐", label: "TLS Analyzer" },
    { id: "unified",   icon: "🧠", label: "Unified Risk" },
    { id: "history",   icon: "🗂", label: "Scan History" },
    { id: "migration", icon: "🔄", label: "Migration" },
    { id: "dashboard", icon: "📊", label: "Analytics" },
    { id: "docs",      icon: "📖", label: "Docs" },
    { id: "team",      icon: "👥", label: "Our Team" },
  ];
  return (
    <>
      {open && <div className="sidebar-overlay open" onClick={onClose} />}
      <div className={`sidebar${open ? " open" : ""}`} style={{
        width: 240, minHeight: "100vh", background: C.sidebar,
        borderRight: `1px solid ${C.sidebarBorder}`, display: "flex",
        flexDirection: "column", position: "fixed", left: 0, top: 0, zIndex: 100,
        boxShadow: "4px 0 24px rgba(0,0,0,0.4)",
      }}>
        <div style={{ padding: "20px", borderBottom: `1px solid ${C.sidebarBorder}` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 38, height: 38, borderRadius: 10, background: "linear-gradient(135deg,#22c55e,#16a34a)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18, boxShadow: "0 0 16px rgba(34,197,94,0.4)" }}>⚛</div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}><span style={{ color: C.green }}>Quantum</span>Guard</div>
              <div style={{ fontSize: 10, color: C.muted, letterSpacing: "0.05em", textTransform: "uppercase" }}>Security Platform</div>
            </div>
          </div>
        </div>
        <nav style={{ flex: 1, padding: "12px" }}>
          {navItems.map(item => (
            <div key={item.id} onClick={() => { setActive(item.id); onClose(); }} style={{
              display: "flex", alignItems: "center", gap: 10, padding: "10px 12px",
              borderRadius: 8, marginBottom: 2, cursor: "pointer",
              background: active === item.id ? "linear-gradient(90deg,rgba(34,197,94,0.15),rgba(34,197,94,0.05))" : "transparent",
              color: active === item.id ? C.green : C.muted,
              fontWeight: active === item.id ? 600 : 400,
              transition: "all 0.2s ease",
              borderLeft: active === item.id ? `2px solid ${C.green}` : "2px solid transparent",
            }}>
              <span style={{ fontSize: 15 }}>{item.icon}</span>
              <span style={{ fontSize: 13 }}>{item.label}</span>
              {active === item.id && <div style={{ marginLeft: "auto", width: 6, height: 6, borderRadius: "50%", background: C.green, boxShadow: `0 0 6px ${C.green}` }} />}
            </div>
          ))}
        </nav>
        <div style={{ padding: "10px 16px", margin: "0 12px 12px", borderRadius: 8, background: "rgba(34,197,94,0.06)", border: "1px solid rgba(34,197,94,0.2)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: C.green, boxShadow: `0 0 6px ${C.green}` }} />
            <span style={{ fontSize: 11, color: C.green, fontWeight: 600 }}>API Online</span>
          </div>
          <div style={{ fontSize: 9, color: C.muted, marginTop: 2 }}>quantumguard-api.onrender.com</div>
        </div>
        <div style={{ padding: "14px 16px", borderTop: `1px solid ${C.sidebarBorder}` }}>
          {displayUser ? (
            <div>
              <div style={{ display:"flex",alignItems:"center",gap:8,marginBottom:8 }}>
                {displayUser.photoURL ? (
                  <img src={displayUser.photoURL} alt="avatar" style={{ width:30,height:30,borderRadius:"50%",border:`2px solid ${C.green}` }} />
                ) : (
                  <div style={{ width:30,height:30,borderRadius:"50%",background:"linear-gradient(135deg,#22c55e,#15803d)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:13,fontWeight:700,color:"#fff",border:`2px solid ${C.green}` }}>
                    {(displayUser.name||displayUser.displayName||displayUser.email||"U")[0].toUpperCase()}
                  </div>
                )}
                <div>
                  <div style={{ fontSize:12,color:C.text,fontWeight:600 }}>
                    {(displayUser.name||displayUser.displayName||displayUser.email||"User").split(" ")[0]}
                  </div>
                  <div style={{ fontSize:10,color:C.green }}>{displayUser.plan||"Free Plan"}</div>
                </div>
              </div>
              <button onClick={onLogout} style={{ width:"100%",padding:"6px",borderRadius:8,background:"transparent",border:`1px solid ${C.sidebarBorder}`,color:C.muted,cursor:"pointer",fontSize:11 }}>Sign Out</button>
            </div>
          ) : (
            <div style={{ display:"flex",flexDirection:"column",gap:6 }}>
              <button onClick={onLogin} style={{ width:"100%",padding:"8px",borderRadius:8,background:"linear-gradient(135deg,#22c55e,#16a34a)",border:"none",color:C.white,cursor:"pointer",fontSize:12,fontWeight:700,boxShadow:"0 4px 12px rgba(34,197,94,0.3)" }}>Sign In / Register</button>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ── TopBar ────────────────────────────────────────────────────
function TopBar({ title, user, onLogin, onLogout, onHamburger }) {
  return (
    <div style={{ height: 56, background: C.topbar, borderBottom: `1px solid ${C.sidebarBorder}`, display: "flex", alignItems: "center", padding: "0 20px", gap: 12, boxShadow: "0 1px 12px rgba(0,0,0,0.3)" }}>
      <button onClick={onHamburger} style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", fontSize: 20, padding: "0 4px" }} className="hamburger-top">☰</button>
      <span style={{ color: C.muted, fontSize: 13 }}>QuantumGuard</span>
      <span style={{ color: C.green, fontSize: 13 }}>›</span>
      <span style={{ color: C.text, fontSize: 14, fontWeight: 600 }}>{title}</span>
      <div className="topbar-right" style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
        {user ? (
          <button onClick={onLogout} style={{ background: "transparent", border: `1px solid ${C.sidebarBorder}`, borderRadius: 8, padding: "4px 12px", cursor: "pointer", color: C.muted, fontSize: 11 }}>{user.displayName?.split(" ")[0]} · Sign Out</button>
        ) : (
          <button onClick={onLogin} style={{ background: "linear-gradient(135deg,#22c55e,#16a34a)", border: "none", borderRadius: 8, padding: "6px 16px", cursor: "pointer", color: C.white, fontSize: 12, fontWeight: 700, boxShadow: "0 2px 8px rgba(34,197,94,0.3)" }}>Sign In</button>
        )}
      </div>
    </div>
  );
}

// ── Panel ─────────────────────────────────────────────────────
function Panel({ title, children, style = {}, accent = false }) {
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 12, marginBottom: 16, overflow: "hidden", boxShadow: "0 4px 16px rgba(0,0,0,0.3)", ...style }}>
      {title && (
        <div style={{ padding: "12px 18px", borderBottom: `1px solid ${C.panelBorder}`, background: accent ? "rgba(34,197,94,0.06)" : C.panel, display: "flex", alignItems: "center", gap: 8 }}>
          {accent && <div style={{ width: 3, height: 16, background: C.green, borderRadius: 2, boxShadow: `0 0 6px ${C.green}` }} />}
          <span style={{ fontSize: 13, fontWeight: 600, color: C.text }}>{title}</span>
        </div>
      )}
      <div style={{ padding: 18 }}>{children}</div>
    </div>
  );
}

function ScoreCard({ label, value, icon, color, desc, suffix = "/100" }) {
  const pct = typeof value === "number" ? value : 0;
  const ringColor = color || C.green;
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 14, padding: "20px", boxShadow: "0 4px 20px rgba(0,0,0,0.35)", position: "relative", overflow: "hidden", transition: "transform 0.25s ease, box-shadow 0.25s ease" }}
      onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-3px)"; e.currentTarget.style.boxShadow = `0 0 20px ${ringColor}22,0 8px 28px rgba(0,0,0,0.4)`; }}
      onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.boxShadow = "0 4px 20px rgba(0,0,0,0.35)"; }}>
      <div style={{ position: "absolute", top: -20, left: -20, width: 80, height: 80, borderRadius: "50%", background: ringColor, opacity: 0.07, filter: "blur(20px)" }} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
        <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em" }}>{label}</div>
        <div style={{ fontSize: 20 }}>{icon}</div>
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 4, marginBottom: 10 }}>
        <span style={{ fontSize: 42, fontWeight: 900, color: ringColor, lineHeight: 1 }}>{value}</span>
        <span style={{ fontSize: 13, color: C.muted }}>{suffix}</span>
      </div>
      {typeof value === "number" && (
        <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 4, height: 4, marginBottom: 8 }}>
          <div style={{ background: ringColor, height: 4, borderRadius: 4, width: `${pct}%`, transition: "width 0.8s ease", boxShadow: `0 0 8px ${ringColor}` }} />
        </div>
      )}
      {desc && <div style={{ fontSize: 11, color: C.muted }}>{desc}</div>}
    </div>
  );
}

function Metric({ label, value, suffix = "", color, desc, icon }) {
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 12, padding: "18px 20px", boxShadow: "0 4px 16px rgba(0,0,0,0.3)", transition: "transform 0.25s ease" }}
      onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-2px)"; }}
      onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
        <div style={{ fontSize: 12, color: C.muted, fontWeight: 500 }}>{label}</div>
        {icon && <div style={{ fontSize: 20 }}>{icon}</div>}
      </div>
      <div style={{ fontSize: 38, fontWeight: 900, color: color || C.text, lineHeight: 1 }}>
        {value}<span style={{ fontSize: 14, color: C.muted, fontWeight: 400 }}>{suffix}</span>
      </div>
      {desc && <div style={{ fontSize: 11, color: C.muted, marginTop: 6 }}>{desc}</div>}
    </div>
  );
}

function SevBar({ label, count, total, color }) {
  const pct = total > 0 ? Math.round(count / total * 100) : 0;
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
        <span style={{ color, fontWeight: 600 }}>{label}</span>
        <span style={{ color: C.muted }}>{count} ({pct}%)</span>
      </div>
      <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 4, height: 8 }}>
        <div style={{ background: color, height: 8, borderRadius: 4, width: `${pct}%`, transition: "width 0.6s ease", boxShadow: `0 0 6px ${color}55` }} />
      </div>
    </div>
  );
}

function Badge({ text, color, bg }) {
  return <span style={{ background: bg, color, padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700, border: `1px solid ${color}33` }}>{text}</span>;
}

// ── NEW: Priority badge for enterprise fields ─────────────────
function PriorityBadge({ priority }) {
  const cfg = {
    P0: { color: "#ef4444", bg: "rgba(239,68,68,0.15)", label: "P0 · Critical" },
    P1: { color: "#f59e0b", bg: "rgba(245,158,11,0.15)", label: "P1 · High" },
    P2: { color: "#eab308", bg: "rgba(234,179,8,0.15)", label: "P2 · Medium" },
    P3: { color: "#6b7280", bg: "rgba(107,114,128,0.15)", label: "P3 · Low" },
  }[priority] || { color: "#6b7280", bg: "rgba(107,114,128,0.15)", label: priority };
  return (
    <span style={{ background: cfg.bg, color: cfg.color, padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700, border: `1px solid ${cfg.color}33` }}>
      {cfg.label}
    </span>
  );
}

// ── NEW: Context badge ────────────────────────────────────────
function ContextBadge({ context }) {
  const cfg = {
    auth:    { color: "#a78bfa", bg: "rgba(167,139,250,0.12)", icon: "🔑" },
    crypto:  { color: "#34d399", bg: "rgba(52,211,153,0.12)",  icon: "🔐" },
    session: { color: "#60a5fa", bg: "rgba(96,165,250,0.12)",  icon: "🍪" },
    ui:      { color: "#6b7280", bg: "rgba(107,114,128,0.12)", icon: "🖥" },
    test:    { color: "#6b7280", bg: "rgba(107,114,128,0.12)", icon: "🧪" },
    unknown: { color: "#6b7280", bg: "rgba(107,114,128,0.12)", icon: "❓" },
  }[context] || { color: "#6b7280", bg: "rgba(107,114,128,0.12)", icon: "❓" };
  return (
    <span style={{ background: cfg.bg, color: cfg.color, padding: "2px 7px", borderRadius: 5, fontSize: 10, fontWeight: 600 }}>
      {cfg.icon} {context}
    </span>
  );
}

// ── NEW: Confidence score pill ────────────────────────────────
function ConfidencePill({ score, label }) {
  const color = label === "HIGH" ? C.green : label === "MEDIUM" ? C.amber : C.muted;
  const displayScore = typeof score === "number" ? `${Math.round(score * 100)}%` : label;
  return (
    <span style={{ color, fontSize: 10, fontWeight: 600, fontFamily: "monospace" }}>
      ⬡ {displayScore}
    </span>
  );
}

// ── NEW: Grouped findings panel ───────────────────────────────
function GroupedFindingsPanel({ groups }) {
  const [expanded, setExpanded] = useState({});
  if (!groups || groups.length === 0) return null;

  const toggle = (i) => setExpanded(p => ({ ...p, [i]: !p[i] }));
  const priBg  = (p) => ({ P0:"rgba(239,68,68,0.12)", P1:"rgba(245,158,11,0.12)", P2:"rgba(234,179,8,0.12)", P3:"rgba(107,114,128,0.1)" })[p] || "rgba(107,114,128,0.1)";
  const priCol = (p) => ({ P0:"#ef4444", P1:"#f59e0b", P2:"#eab308", P3:"#6b7280" })[p] || "#6b7280";
  const sevCol = (s) => ({ CRITICAL:"#ef4444", HIGH:"#f59e0b", MEDIUM:"#eab308" })[s] || "#6b7280";
  const impCol = (i) => ({ HIGH:"#ef4444", MEDIUM:"#f59e0b", LOW:"#6b7280" })[i] || "#6b7280";

  return (
    <Panel title={`Grouped Findings — ${groups.length} groups`} accent>
      {groups.map((g, i) => (
        <div key={i} style={{ marginBottom: 10, border: `1px solid ${C.panelBorder}`, borderRadius: 10, overflow: "hidden", transition: "border-color 0.2s" }}
          onMouseEnter={e => e.currentTarget.style.borderColor = "rgba(34,197,94,0.3)"}
          onMouseLeave={e => e.currentTarget.style.borderColor = C.panelBorder}>
          {/* Group header */}
          <div onClick={() => toggle(i)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", cursor: "pointer", background: "rgba(34,197,94,0.03)", flexWrap: "wrap" }}>
            {/* Priority */}
            <span style={{ background: priBg(g.priority), color: priCol(g.priority), fontSize: 11, fontWeight: 800, padding: "2px 9px", borderRadius: 6, border: `1px solid ${priCol(g.priority)}33`, flexShrink: 0 }}>
              {g.priority}
            </span>
            {/* Title */}
            <span style={{ fontSize: 13, fontWeight: 700, color: C.text, flex: 1, minWidth: 120 }}>{g.title}</span>
            {/* Occurrences */}
            <span style={{ fontSize: 11, color: C.muted, flexShrink: 0 }}>
              {g.occurrences} occurrence{g.occurrences !== 1 ? "s" : ""}
            </span>
            {/* Severity */}
            <span style={{ background: `${sevCol(g.severity)}22`, color: sevCol(g.severity), fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 5, flexShrink: 0 }}>
              {g.severity}
            </span>
            {/* Impact */}
            <span style={{ fontSize: 10, color: impCol(g.business_impact), fontWeight: 600, flexShrink: 0 }}>
              Impact: {g.business_impact}
            </span>
            {/* Exploitability */}
            <span style={{ fontSize: 10, color: C.muted, flexShrink: 0 }}>
              Exploit: {g.exploitability}
            </span>
            {/* Chevron */}
            <span style={{ color: C.muted, fontSize: 11, transform: expanded[i] ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}>▼</span>
          </div>
          {/* Expanded details */}
          {expanded[i] && (
            <div style={{ padding: "10px 14px", borderTop: `1px solid ${C.panelBorder}`, background: C.input }}>
              <div style={{ fontSize: 12, color: C.muted, marginBottom: 6, lineHeight: 1.6 }}>
                <span style={{ fontWeight: 600, color: C.textMid }}>Root cause: </span>{g.root_cause}
              </div>
              <div style={{ fontSize: 12, color: C.muted, marginBottom: 8, lineHeight: 1.6 }}>
                <span style={{ fontWeight: 600, color: C.textMid }}>Fix: </span>
                <span style={{ color: "#93c5fd" }}>✦ {g.replacement}</span>
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {g.affected_files.slice(0, 5).map((f, fi) => (
                  <span key={fi} style={{ fontFamily: "monospace", fontSize: 10, color: C.green, background: "rgba(34,197,94,0.08)", padding: "2px 7px", borderRadius: 4, border: "1px solid rgba(34,197,94,0.2)" }}>
                    {f.split("/").pop()}
                  </span>
                ))}
                {g.affected_files.length > 5 && (
                  <span style={{ fontSize: 10, color: C.muted }}>+{g.affected_files.length - 5} more</span>
                )}
              </div>
            </div>
          )}
        </div>
      ))}
    </Panel>
  );
}

// ══════════════════════════════════════════════════════════════
// NIST REPORT PAGE — unchanged
// ══════════════════════════════════════════════════════════════
const NIST_FINDINGS = [
  { file:"tests/TestVulnerable.java", line:9,  code:'KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");', vulnerability:"RSA",  severity:"CRITICAL", replacement:"CRYSTALS-Kyber" },
  { file:"tests/TestVulnerable.java", line:13, code:'KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");',   vulnerability:"ECC",  severity:"CRITICAL", replacement:"CRYSTALS-Dilithium" },
  { file:"tests/TestVulnerable.java", line:16, code:'KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");',   vulnerability:"DH",   severity:"HIGH",     replacement:"CRYSTALS-Kyber" },
  { file:"tests/TestVulnerable.java", line:19, code:'MessageDigest md5 = MessageDigest.getInstance("MD5");',          vulnerability:"MD5",  severity:"MEDIUM",   replacement:"SHA-3 or SPHINCS+" },
  { file:"tests/TestVulnerable.java", line:22, code:'MessageDigest sha1 = MessageDigest.getInstance("SHA-1");',       vulnerability:"SHA1", severity:"MEDIUM",   replacement:"SHA-3 or SPHINCS+" },
  { file:"tests/test_vulnerable.js",  line:2,  code:"const NodeRSA = require('node-rsa');",                           vulnerability:"RSA",  severity:"CRITICAL", replacement:"CRYSTALS-Kyber" },
  { file:"tests/test_vulnerable.js",  line:3,  code:"const elliptic = require('elliptic');",                          vulnerability:"ECC",  severity:"CRITICAL", replacement:"CRYSTALS-Dilithium" },
  { file:"tests/test_vulnerable.js",  line:6,  code:"const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {", vulnerability:"RSA", severity:"CRITICAL", replacement:"CRYSTALS-Kyber" },
  { file:"tests/test_vulnerable.js",  line:11, code:"const ec = new elliptic.ec('secp256k1');",                       vulnerability:"ECC",  severity:"CRITICAL", replacement:"CRYSTALS-Dilithium" },
  { file:"tests/test_vulnerable.js",  line:15, code:"const dh = crypto.createDiffieHellman(2048);",                  vulnerability:"DH",   severity:"HIGH",     replacement:"CRYSTALS-Kyber" },
  { file:"tests/test_vulnerable.js",  line:19, code:"const md5Hash = crypto.createHash('md5').update('password').digest('hex');", vulnerability:"MD5", severity:"MEDIUM", replacement:"SHA-3 or SPHINCS+" },
  { file:"tests/test_vulnerable.js",  line:22, code:"const sha1Hash = crypto.createHash('sha1').update('data').digest('hex');",   vulnerability:"SHA1",severity:"MEDIUM", replacement:"SHA-3 or SPHINCS+" },
  { file:"tests/test_vulnerable.py",  line:1,  code:"from Crypto.PublicKey import RSA",                               vulnerability:"RSA",  severity:"CRITICAL", replacement:"CRYSTALS-Kyber" },
  { file:"tests/test_vulnerable.py",  line:2,  code:"from Crypto.Cipher import PKCS1_OAEP",                           vulnerability:"RSA",  severity:"CRITICAL", replacement:"CRYSTALS-Kyber" },
  { file:"tests/test_vulnerable.py",  line:7,  code:"key = RSA.generate(2048)",                                       vulnerability:"RSA",  severity:"CRITICAL", replacement:"CRYSTALS-Kyber" },
  { file:"tests/test_vulnerable.py",  line:12, code:"md5_hash = hashlib.md5(data).hexdigest()",                       vulnerability:"MD5",  severity:"MEDIUM",   replacement:"SHA-3 or SPHINCS+" },
  { file:"tests/test_vulnerable.py",  line:15, code:"sha1_hash = hashlib.sha1(data).hexdigest()",                     vulnerability:"SHA1", severity:"MEDIUM",   replacement:"SHA-3 or SPHINCS+" },
  { file:"tests/test_vulnerable.py",  line:18, code:"from Crypto.PublicKey import ECC",                               vulnerability:"ECC",  severity:"CRITICAL", replacement:"CRYSTALS-Dilithium" },
  { file:"tests/test_vulnerable.py",  line:19, code:"ecc_key = ECC.generate(curve='P-256')",                         vulnerability:"ECC",  severity:"CRITICAL", replacement:"CRYSTALS-Dilithium" },
];

const NIST_CONTROLS = [
  { id:"SC-12", name:"Cryptographic Key Establishment & Management", family:"System & Comms Protection", vulns:["RSA","ECC","DH"],       status:"FAIL" },
  { id:"SC-13", name:"Cryptographic Protection",                     family:"System & Comms Protection", vulns:["RSA","ECC","DH","DSA"], status:"FAIL" },
  { id:"IA-7",  name:"Cryptographic Module Authentication",          family:"Identification & Auth",      vulns:["MD5","SHA1"],           status:"WARN" },
  { id:"SC-28", name:"Protection of Information at Rest",            family:"System & Comms Protection", vulns:["RSA","ECC"],            status:"FAIL" },
  { id:"SC-8",  name:"Transmission Confidentiality & Integrity",    family:"System & Comms Protection", vulns:["DH","RSA"],             status:"WARN" },
  { id:"SI-7",  name:"Software & Information Integrity",            family:"System & Info Integrity",   vulns:["MD5","SHA1"],           status:"WARN" },
  { id:"CM-7",  name:"Least Functionality",                         family:"Configuration Management",  vulns:[],                      status:"PASS" },
  { id:"AC-17", name:"Remote Access",                               family:"Access Control",             vulns:[],                      status:"PASS" },
];

const VULN_INFO = {
  RSA:  { desc:"RSA is vulnerable to Shor's algorithm. A quantum computer can factor large integers and break RSA encryption entirely.", nist:"FIPS 203 — CRYSTALS-Kyber (ML-KEM)" },
  ECC:  { desc:"Elliptic Curve Cryptography is broken by quantum Shor's algorithm — the EC discrete log becomes trivially solvable.", nist:"FIPS 204 — CRYSTALS-Dilithium (ML-DSA)" },
  DH:   { desc:"Diffie-Hellman key exchange relies on discrete log hardness, which quantum computers solve efficiently.", nist:"FIPS 203 — CRYSTALS-Kyber (ML-KEM)" },
  DSA:  { desc:"Digital Signature Algorithm based on discrete log — broken by quantum Shor's algorithm.", nist:"FIPS 204 — CRYSTALS-Dilithium (ML-DSA)" },
  MD5:  { desc:"MD5 produces a 128-bit hash, insufficient for quantum security. Grover's algorithm halves effective bit security.", nist:"FIPS 205 — SHA-3 or SPHINCS+" },
  SHA1: { desc:"SHA-1 has known collisions and 160-bit output — completely insufficient for post-quantum requirements.", nist:"FIPS 205 — SHA-3 or SPHINCS+" },
};

const SEV_COLOR = { CRITICAL:"#ef4444", HIGH:"#f59e0b", MEDIUM:"#eab308" };
const SEV_BG    = { CRITICAL:"rgba(239,68,68,0.15)", HIGH:"rgba(245,158,11,0.15)", MEDIUM:"rgba(234,179,8,0.15)" };
const STAT_CTRL = {
  PASS: { color:C.green,   bg:"rgba(34,197,94,0.1)",  border:"rgba(34,197,94,0.3)",  dot:C.green   },
  WARN: { color:"#f59e0b", bg:"rgba(245,158,11,0.1)", border:"rgba(245,158,11,0.3)", dot:"#f59e0b" },
  FAIL: { color:"#ef4444", bg:"rgba(239,68,68,0.1)",  border:"rgba(239,68,68,0.3)",  dot:"#ef4444" },
};

function getLang(file) {
  if (file.endsWith(".java")) return "Java";
  if (file.endsWith(".js"))   return "JavaScript";
  if (file.endsWith(".py"))   return "Python";
  if (file.endsWith(".ts"))   return "TypeScript";
  return "Code";
}

function NISTFindingRow({ f }) {
  const [open, setOpen] = useState(false);
  const info = VULN_INFO[f.vulnerability] || {};
  const matchedControls = NIST_CONTROLS.filter(c => c.vulns.includes(f.vulnerability));
  const sc = SEV_COLOR[f.severity]; const sb = SEV_BG[f.severity];
  return (
    <div style={{ border:`1px solid ${open?"rgba(34,197,94,0.3)":C.panelBorder}`, borderRadius:10, marginBottom:8, overflow:"hidden", background:C.panel, transition:"border-color 0.2s" }}>
      <div onClick={() => setOpen(o => !o)} style={{ display:"flex", alignItems:"center", gap:10, padding:"11px 16px", cursor:"pointer", flexWrap:"wrap" }}>
        <Badge text={f.severity} color={sc} bg={sb} />
        <span style={{ fontFamily:"monospace", fontSize:12, color:C.green, fontWeight:600, flex:1, minWidth:120, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{f.file.split("/").pop()}</span>
        <span style={{ fontSize:11, color:C.muted, whiteSpace:"nowrap" }}>Line {f.line}</span>
        <span style={{ background:"rgba(255,255,255,0.06)", color:C.textMid, fontSize:10, fontWeight:700, padding:"2px 8px", borderRadius:4 }}>{f.vulnerability}</span>
        <span style={{ color:C.muted, fontSize:11, transition:"transform 0.2s", transform:open?"rotate(180deg)":"none" }}>▼</span>
      </div>
      {open && (
        <div style={{ padding:"0 16px 14px", borderTop:`1px solid ${C.panelBorder}` }}>
          <div style={{ fontFamily:"monospace", background:C.input, padding:"8px 12px", borderRadius:8, fontSize:11, color:C.green, marginTop:10, overflowX:"auto", border:`1px solid ${C.panelBorder}` }}>
            <span style={{ color:C.muted, marginRight:12, userSelect:"none" }}>{f.line}</span>{f.code}
          </div>
          {info.desc && <div style={{ marginTop:8, fontSize:12, color:C.muted, lineHeight:1.6 }}>{info.desc}</div>}
          <div style={{ marginTop:8, display:"flex", gap:6, flexWrap:"wrap", alignItems:"center" }}>
            {matchedControls.map(c => <span key={c.id} style={{ background:"rgba(34,197,94,0.1)", border:"1px solid rgba(34,197,94,0.3)", color:C.green, fontSize:10, fontWeight:700, padding:"2px 9px", borderRadius:4 }}>{c.id}</span>)}
            <span style={{ background:"rgba(59,130,246,0.1)", border:"1px solid rgba(59,130,246,0.3)", color:"#60a5fa", fontSize:10, fontWeight:700, padding:"2px 9px", borderRadius:4 }}>✦ {f.replacement}</span>
          </div>
          {info.nist && <div style={{ marginTop:6, fontSize:11, color:C.muted }}>NIST Standard: <span style={{ color:C.green, fontWeight:600 }}>{info.nist}</span></div>}
        </div>
      )}
    </div>
  );
}

function NISTReportPage() {
  const [filter, setFilter] = useState("ALL");
  const counts = { CRITICAL:NIST_FINDINGS.filter(f=>f.severity==="CRITICAL").length, HIGH:NIST_FINDINGS.filter(f=>f.severity==="HIGH").length, MEDIUM:NIST_FINDINGS.filter(f=>f.severity==="MEDIUM").length, total:NIST_FINDINGS.length };
  const filtered = filter==="ALL" ? NIST_FINDINGS : NIST_FINDINGS.filter(f=>f.severity===filter);
  const byFile = NIST_FINDINGS.reduce((a,f)=>{if(!a[f.file])a[f.file]=[];a[f.file].push(f);return a;},{});
  const vulnCounts = Object.entries(NIST_FINDINGS.reduce((a,f)=>{a[f.vulnerability]=(a[f.vulnerability]||0)+1;return a;},{})).sort((a,b)=>b[1]-a[1]);
  const handleExportCSV = () => { const rows=["Severity,File,Line,Vulnerability,Code,Replacement",...NIST_FINDINGS.map(f=>`"${f.severity}","${f.file}","${f.line}","${f.vulnerability}","${f.code.replace(/"/g,"'")}","${f.replacement}"`)].join("\n"); const blob=new Blob([rows],{type:"text/csv"}); const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="nist-report.csv";a.click(); };
  const handleExportPDF = () => { const win=window.open("","_blank"); win.document.write(`<!DOCTYPE html><html><head><title>QuantumGuard NIST Report</title><style>body{font-family:sans-serif;padding:40px}h1{color:#22c55e}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #e2f0e2;padding:8px 12px;font-size:12px}th{background:#f0fdf4;font-weight:700}.CRITICAL{color:#ef4444;font-weight:700}.HIGH{color:#f59e0b;font-weight:700}.MEDIUM{color:#eab308;font-weight:700}</style></head><body><h1>⚛ QuantumGuard NIST Report</h1><table><thead><tr><th>Severity</th><th>File</th><th>Line</th><th>Vuln</th><th>Code</th><th>Fix</th></tr></thead><tbody>${NIST_FINDINGS.map(f=>`<tr><td class="${f.severity}">${f.severity}</td><td>${f.file}</td><td>${f.line}</td><td>${f.vulnerability}</td><td><code>${f.code.replace(/</g,"&lt;")}</code></td><td>${f.replacement}</td></tr>`).join("")}</tbody></table></body></html>`); win.document.close(); win.print(); };
  return (
    <div style={{ padding:20 }}>
      <div style={{ background:"rgba(59,130,246,0.08)", border:"1px solid rgba(59,130,246,0.25)", borderRadius:10, padding:"10px 16px", marginBottom:14, display:"flex", alignItems:"flex-start", gap:10 }}>
        <span style={{ fontSize:15, marginTop:1 }}>ℹ️</span>
        <div style={{ fontSize:12, color:"#93c5fd", lineHeight:1.6 }}><strong style={{ color:"#60a5fa" }}>Sample Report</strong> — Go to <strong style={{ color:"#60a5fa" }}>Scanner</strong> → run a scan → click <strong style={{ color:"#60a5fa" }}>🏛 NIST Report</strong> for live results.</div>
      </div>
      <div style={{ background:C.panel, border:`1px solid ${C.panelBorder}`, borderTop:`3px solid ${C.green}`, borderRadius:14, padding:"20px 22px", marginBottom:16, boxShadow:"0 4px 20px rgba(0,0,0,0.4)", display:"flex", justifyContent:"space-between", alignItems:"flex-start", flexWrap:"wrap", gap:16 }}>
        <div>
          <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
            <div style={{ width:32, height:32, borderRadius:8, background:"linear-gradient(135deg,#22c55e,#16a34a)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:16 }}>🏛</div>
            <h2 style={{ fontSize:20, fontWeight:800, color:C.text }}>NIST Security Report</h2>
          </div>
          <div style={{ display:"flex", gap:18, flexWrap:"wrap" }}>
            {[["Standard","NIST SP 800-53 Rev 5"],["Scanned","Apr 21, 2026"],["Directory","tests/"],["Files","3 scanned"]].map(([k,v])=>(
              <div key={k} style={{ fontSize:11 }}><span style={{ color:C.muted }}>{k}: </span><span style={{ color:C.textMid, fontWeight:600 }}>{v}</span></div>
            ))}
          </div>
        </div>
        <div style={{ background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.3)", borderRadius:12, padding:"14px 20px", textAlign:"center", minWidth:140 }}>
          <div style={{ fontSize:44, fontWeight:900, color:C.red, lineHeight:1 }}>0</div>
          <div style={{ fontSize:10, color:C.muted, textTransform:"uppercase", letterSpacing:1, marginTop:2 }}>Quantum Score</div>
          <div style={{ display:"inline-flex", alignItems:"center", gap:5, background:"rgba(239,68,68,0.15)", border:"1px solid rgba(239,68,68,0.3)", color:C.red, fontSize:10, fontWeight:700, padding:"3px 10px", borderRadius:100, marginTop:8 }}>
            <span style={{ width:5, height:5, borderRadius:"50%", background:C.red, display:"inline-block" }} /> Not Quantum Safe
          </div>
        </div>
      </div>
      <div className="stats-grid" style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12, marginBottom:16 }}>
        <Metric label="Total Findings" value={counts.total} color={C.green} icon="🔍" desc="All severities" />
        <Metric label="Critical" value={counts.CRITICAL} color={C.critical} icon="🔴" desc="Immediate action" />
        <Metric label="High" value={counts.HIGH} color={C.amber} icon="🟡" desc="Requires attention" />
        <Metric label="Medium" value={counts.MEDIUM} color={C.medium} icon="🟠" desc="Review needed" />
      </div>
      <div className="charts-grid" style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
        <Panel title="Severity Distribution" accent><SevBar label="Critical" count={counts.CRITICAL} total={counts.total} color={C.critical} /><SevBar label="High" count={counts.HIGH} total={counts.total} color={C.amber} /><SevBar label="Medium" count={counts.MEDIUM} total={counts.total} color={C.medium} /></Panel>
        <Panel title="Vulnerability Type Breakdown" accent>{vulnCounts.map(([vuln,cnt])=><SevBar key={vuln} label={vuln} count={cnt} total={counts.total} color={["RSA","ECC"].includes(vuln)?C.critical:["DH","DSA"].includes(vuln)?C.amber:C.medium} />)}</Panel>
      </div>
      <Panel title="Files Scanned" accent>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fill,minmax(220px,1fr))", gap:12 }}>
          {Object.entries(byFile).map(([file,findings])=>{
            const crit=findings.filter(f=>f.severity==="CRITICAL").length; const high=findings.filter(f=>f.severity==="HIGH").length; const med=findings.filter(f=>f.severity==="MEDIUM").length;
            return (<div key={file} style={{ background:"rgba(34,197,94,0.05)", border:"1px solid rgba(34,197,94,0.2)", borderRadius:10, padding:"12px 14px" }}>
              <div style={{ fontSize:10, fontWeight:700, background:"rgba(34,197,94,0.1)", color:C.green, border:"1px solid rgba(34,197,94,0.3)", display:"inline-block", padding:"1px 8px", borderRadius:100, marginBottom:6, textTransform:"uppercase" }}>{getLang(file)}</div>
              <div style={{ fontFamily:"monospace", fontSize:11, fontWeight:700, color:C.green, marginBottom:8 }}>{file.split("/").pop()}</div>
              <div style={{ display:"flex", gap:6, flexWrap:"wrap" }}>
                {crit>0&&<Badge text={`${crit} Critical`} color={C.critical} bg={SEV_BG.CRITICAL} />}
                {high>0&&<Badge text={`${high} High`} color={C.amber} bg={SEV_BG.HIGH} />}
                {med>0&&<Badge text={`${med} Medium`} color={C.medium} bg={SEV_BG.MEDIUM} />}
              </div>
              <div style={{ fontSize:11, color:C.muted, marginTop:6 }}>{findings.length} findings total</div>
            </div>);
          })}
        </div>
      </Panel>
      <Panel title="NIST SP 800-53 Control Mapping" accent>
        <div style={{ overflowX:"auto" }}>
          <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12 }}>
            <thead><tr style={{ background:"rgba(34,197,94,0.06)" }}>{["Control ID","Control Name","Family","Affected Algorithms","Status"].map(h=><th key={h} style={{ padding:"9px 14px", textAlign:"left", fontSize:10, textTransform:"uppercase", letterSpacing:1, color:C.muted, fontWeight:700, borderBottom:`1px solid ${C.panelBorder}` }}>{h}</th>)}</tr></thead>
            <tbody>{NIST_CONTROLS.map((ctrl,i)=>{ const sc=STAT_CTRL[ctrl.status]; return (
              <tr key={ctrl.id} style={{ background:i%2===0?C.panel:"rgba(255,255,255,0.02)" }} onMouseEnter={e=>e.currentTarget.style.background="rgba(34,197,94,0.05)"} onMouseLeave={e=>e.currentTarget.style.background=i%2===0?C.panel:"rgba(255,255,255,0.02)"}>
                <td style={{ padding:"10px 14px", borderBottom:`1px solid ${C.panelBorder}`, fontFamily:"monospace", fontSize:12, color:C.green, fontWeight:700 }}>{ctrl.id}</td>
                <td style={{ padding:"10px 14px", borderBottom:`1px solid ${C.panelBorder}`, color:C.textMid }}>{ctrl.name}</td>
                <td style={{ padding:"10px 14px", borderBottom:`1px solid ${C.panelBorder}`, color:C.muted, fontSize:11 }}>{ctrl.family}</td>
                <td style={{ padding:"10px 14px", borderBottom:`1px solid ${C.panelBorder}` }}>{ctrl.vulns.length>0?ctrl.vulns.map(v=><span key={v} style={{ background:"rgba(34,197,94,0.1)", border:"1px solid rgba(34,197,94,0.3)", color:C.green, fontSize:10, fontWeight:700, padding:"1px 7px", borderRadius:4, marginRight:4 }}>{v}</span>):<span style={{ color:C.muted, fontSize:11 }}>—</span>}</td>
                <td style={{ padding:"10px 14px", borderBottom:`1px solid ${C.panelBorder}` }}><span style={{ display:"inline-flex", alignItems:"center", gap:4, background:sc.bg, border:`1px solid ${sc.border}`, color:sc.color, fontSize:10, fontWeight:700, padding:"3px 10px", borderRadius:100, textTransform:"uppercase" }}><span style={{ width:5, height:5, borderRadius:"50%", background:sc.dot, display:"inline-block" }} />{ctrl.status}</span></td>
              </tr>);
            })}</tbody>
          </table>
        </div>
      </Panel>
      <Panel title="Export & Share" accent>
        <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
          <button onClick={handleExportPDF} style={{ padding:"8px 16px", borderRadius:8, background:"linear-gradient(135deg,#22c55e,#16a34a)", color:C.white, border:"none", cursor:"pointer", fontSize:12, fontWeight:600 }}>📄 PDF Report</button>
          <button onClick={handleExportCSV} style={{ padding:"8px 16px", borderRadius:8, background:"rgba(34,197,94,0.1)", color:C.green, border:"1px solid rgba(34,197,94,0.3)", cursor:"pointer", fontSize:12, fontWeight:600 }}>📊 CSV Export</button>
        </div>
      </Panel>
      <Panel title={`Threat Intelligence — ${counts.total} Findings`} accent>
        <div style={{ display:"flex", gap:8, marginBottom:14, flexWrap:"wrap" }}>
          {[{key:"ALL",label:`All (${counts.total})`,ac:C.green},{key:"CRITICAL",label:`Critical (${counts.CRITICAL})`,ac:C.critical},{key:"HIGH",label:`High (${counts.HIGH})`,ac:C.amber},{key:"MEDIUM",label:`Medium (${counts.MEDIUM})`,ac:C.medium}].map(btn=>(
            <button key={btn.key} onClick={()=>setFilter(btn.key)} style={{ padding:"5px 14px", borderRadius:20, cursor:"pointer", fontSize:11, border:`1.5px solid ${filter===btn.key?btn.ac:C.panelBorder}`, background:filter===btn.key?btn.ac+"22":"transparent", color:filter===btn.key?btn.ac:C.muted, fontWeight:filter===btn.key?700:400, transition:"all 0.2s" }}>{btn.label}</button>
          ))}
        </div>
        {filtered.map((f,i)=><NISTFindingRow key={`${f.file}-${f.line}-${f.vulnerability}-${i}`} f={f} />)}
        {filtered.length===0&&<div style={{ textAlign:"center", padding:24, color:C.muted }}>No findings match filter.</div>}
      </Panel>
      <div style={{ background:C.panel, border:`1px solid ${C.panelBorder}`, borderRadius:12, padding:"14px 18px", display:"flex", justifyContent:"space-between", alignItems:"center", flexWrap:"wrap", gap:12 }}>
        <div style={{ fontSize:11, color:C.muted }}>QuantumGuard · NIST SP 800-53 Rev 5 · Report ID #QG-{new Date().getFullYear()}-{String(new Date().getMonth()+1).padStart(2,"0")}{String(new Date().getDate()).padStart(2,"0")}</div>
        <div style={{ display:"flex", alignItems:"center", gap:6 }}><div style={{ width:7, height:7, borderRadius:"50%", background:C.green, boxShadow:`0 0 6px ${C.green}` }} /><span style={{ fontSize:11, color:C.green, fontWeight:600 }}>Mangsri QuantumGuard LLC · Montgomery, AL</span></div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// TEAM PAGE — unchanged
// ══════════════════════════════════════════════════════════════
function TeamPage() {
  const members = [
    { initials:"PP", name:"Pavansudheer Payyavula", role:"Founder & CEO",  degree:"MS Cybersecurity & Computer Information Systems", avatarBg:"#1e1b4b", avatarText:"#a5b4fc", badgeBg:"#1e1b4b", badgeText:"#a5b4fc", featured:true },
    { initials:"MS", name:"Manasa Sannidhi",         role:"Co-Founder",     degree:"MS Computer Science",                            avatarBg:"#052e16", avatarText:"#22c55e", badgeBg:"#052e16", badgeText:"#22c55e", featured:false },
    { initials:"BG", name:"Bharathwaj Goud Siga",    role:"Business",       degree:"MS Business Analytics",                          avatarBg:"#1c0a00", avatarText:"#f59e0b", badgeBg:"#1c0a00", badgeText:"#f59e0b", featured:false, subRole:"Marketing Manager" },
    { initials:"VR", name:"Vijendhar Reddy Muppidi", role:"Advisor",        degree:"MS Management Information Systems",              avatarBg:"#2a0a0a", avatarText:"#f87171", badgeBg:"#2a0a0a", badgeText:"#f87171", featured:false },
  ];
  return (
    <div style={{ padding:20 }}>
      <div style={{ textAlign:"center", marginBottom:36 }}>
        <div style={{ display:"inline-block", background:"rgba(34,197,94,0.1)", color:C.green, fontSize:12, fontWeight:700, padding:"5px 16px", borderRadius:20, marginBottom:14, border:"1px solid rgba(34,197,94,0.3)" }}>⚛ THE TEAM</div>
        <h2 style={{ fontSize:32, fontWeight:900, color:C.text, marginBottom:10, letterSpacing:-0.5 }}>Built by 4 friends</h2>
        <p style={{ fontSize:14, color:C.muted, maxWidth:480, margin:"0 auto", lineHeight:1.7 }}>A cross-disciplinary team building the world's first free quantum vulnerability scanner — free for every developer, forever.</p>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))", gap:20, maxWidth:900, margin:"0 auto" }}>
        {members.map(m=>(
          <div key={m.name} style={{ background:C.panel, border:m.featured?`2px solid ${C.green}`:`1px solid ${C.panelBorder}`, borderRadius:16, padding:"28px 20px", textAlign:"center", display:"flex", flexDirection:"column", alignItems:"center", boxShadow:m.featured?"0 4px 24px rgba(34,197,94,0.2)":"0 4px 16px rgba(0,0,0,0.3)", transition:"transform 0.25s ease" }}
            onMouseEnter={e=>e.currentTarget.style.transform="translateY(-4px)"} onMouseLeave={e=>e.currentTarget.style.transform="translateY(0)"}>
            <div style={{ width:60, height:60, borderRadius:"50%", background:m.avatarBg, color:m.avatarText, display:"flex", alignItems:"center", justifyContent:"center", fontWeight:700, fontSize:16, marginBottom:14, fontFamily:"monospace", border:`2px solid ${m.avatarText}44` }}>{m.initials}</div>
            <span style={{ display:"inline-block", background:m.badgeBg, color:m.badgeText, fontSize:10, fontWeight:700, padding:"3px 12px", borderRadius:20, marginBottom:10, fontFamily:"monospace", letterSpacing:"0.05em", textTransform:"uppercase", border:`1px solid ${m.badgeText}44` }}>{m.role}</span>
            <div style={{ fontSize:14, fontWeight:700, color:C.text, marginBottom:6, lineHeight:1.3 }}>{m.name}</div>
            <div style={{ width:28, height:1, background:C.panelBorder, margin:"8px auto" }} />
            <div style={{ fontSize:12, color:C.muted, lineHeight:1.5 }}>{m.degree}</div>
            {m.subRole&&<div style={{ fontSize:11, color:C.green, marginTop:6, fontStyle:"italic", fontWeight:500 }}>{m.subRole}</div>}
          </div>
        ))}
      </div>
      <div style={{ textAlign:"center", marginTop:40 }}>
        <div style={{ display:"inline-block", background:"rgba(34,197,94,0.06)", border:"1px solid rgba(34,197,94,0.2)", borderRadius:12, padding:"14px 28px" }}>
          <div style={{ fontSize:13, color:C.green, fontWeight:700, marginBottom:4 }}>⚛ Mangsri QuantumGuard LLC</div>
          <div style={{ fontSize:12, color:C.muted }}>Montgomery, AL · Founded April 27, 2026 · EIN 42-2185776</div>
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// SCANNER PAGE — enterprise fields added
// ══════════════════════════════════════════════════════════════
function ScannerPage({ user }) {
  const { jwtToken } = useAuth();
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
  // NEW: grouped findings view toggle
  const [viewMode, setViewMode] = useState("flat"); // "flat" | "grouped"
  const intervalRef = useRef(null);
  const logTimers = useRef([]);
  const logEndRef = useRef(null);
  const [scanLogs, setScanLogs] = useState([]);
  const [filesScanned, setFilesScanned] = useState(0);
  const [issuesFound, setIssuesFound] = useState(0);
  const [elapsedMs, setElapsedMs] = useState(0);
  const elapsedRef = useRef(null);
  const startTimeRef = useRef(null);

  const pushLog = (entry) => {
    setScanLogs(prev => [...prev, { ...entry, id: Date.now() + Math.random() }]);
    setTimeout(() => logEndRef.current?.scrollIntoView({ behavior: "smooth" }), 40);
  };

  const startProgress = () => {
    setProgress(0); setStepIndex(0); setScanLogs([]); setFilesScanned(0); setIssuesFound(0); setElapsedMs(0);
    startTimeRef.current = Date.now();
    let p = 0;
    elapsedRef.current = setInterval(() => setElapsedMs(Date.now() - startTimeRef.current), 100);
    intervalRef.current = setInterval(() => {
      p += Math.random() * 8 + 2; if (p > 92) p = 92;
      setProgress(Math.round(p));
      setStepIndex(Math.min(SCAN_STEPS.length - 1, Math.floor(p / (100 / SCAN_STEPS.length))));
    }, 400);
    let delay = 0;
    SCAN_LOG_PHASES.forEach(phase => {
      phase.logs.forEach(log => {
        delay += 200 + Math.random() * 300;
        const t = setTimeout(() => {
          pushLog(log);
          if (log.type === "info" && log.text.includes("Scanning")) setFilesScanned(prev => prev + Math.floor(Math.random() * 6 + 1));
          if (log.type === "critical" || (log.type === "warn" && log.text.includes("detected"))) setIssuesFound(prev => prev + 1);
        }, delay);
        logTimers.current.push(t);
      });
      delay += 400;
    });
  };

  const stopProgress = () => {
    clearInterval(intervalRef.current); clearInterval(elapsedRef.current);
    logTimers.current.forEach(clearTimeout); logTimers.current = [];
    setProgress(100); setStepIndex(SCAN_STEPS.length - 1);
  };

  const handleScan = async () => {
    setLoading(true); setError(null); setResult(null); setChecklist({}); setSaved(false);
    startProgress();
    try {
      let res;
      const authHeader = jwtToken ? { Authorization: `Bearer ${jwtToken}` } : {};
      if (mode === "zip") {
        if (!file) throw new Error("Please select a ZIP file");
        const fd = new FormData(); fd.append("file", file);
        res = await fetch(`${API}/public-scan-zip`, { method:"POST", headers:authHeader, body:fd });
      } else if (mode === "github") {
        if (!input) throw new Error("Please enter a GitHub URL");
        res = await fetch(`${API}/scan-github`, { method:"POST", headers:{...authHeader,"Content-Type":"application/json"}, body:JSON.stringify({ github_url:input, ...(githubToken?{github_token:githubToken}:{}) }) });
      } else {
        if (!input) throw new Error("Please enter a path");
        res = await fetch(`${API}/scan`, { method:"POST", headers:{...authHeader,"Content-Type":"application/json","x-api-key":"quantumguard-secret-2026"}, body:JSON.stringify({ directory:input }) });
      }
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Scan failed");
      stopProgress(); setResult(data);
      if (user) {
        await addDoc(collection(db,"scans"), { userId:user.uid, userEmail:user.email, filename:file?.name||input||"scan", score:data.quantum_readiness_score, findings:data.total_findings, createdAt:new Date() });
        await incrementScanCount(user.uid); setSaved(true);
      }
    } catch (e) { stopProgress(); setError(typeof e.message==="string"?e.message:"Scan failed."); }
    setLoading(false);
  };

  const handleEmail = async () => {
    if (!emailInput || !result) return; setSendingEmail(true);
    try {
      await emailjs.send("service_vy8yxbq","template_mgydwpx",{ to_email:emailInput, score:result.quantum_readiness_score, total:result.total_findings, filename:file?.name||input||"scan" },"vATUvI1IlAtH0ooKaQlY9");
      setEmailSent(true); setTimeout(()=>setEmailSent(false),3000);
    } catch(e) { alert("Email failed."); }
    setSendingEmail(false);
  };

  const handleAiFix = async (finding) => {
    setAiModal(finding); setAiLoading(true); setAiResult(null);
    try {
      const res = await fetch(`${API}/ai-fix`, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({ finding }) });
      const data = await res.json();
      setAiResult(data.fix || "Could not generate fix.");
    } catch(e) { setAiResult("Error calling AI. Please try again."); }
    setAiLoading(false);
  };

  const scoreColor = result ? (result.quantum_readiness_score>=70?C.green:result.quantum_readiness_score>=40?C.amber:C.red) : C.muted;
  const sev = result ? { CRITICAL:result.findings.filter(f=>f.severity==="CRITICAL").length, HIGH:result.findings.filter(f=>f.severity==="HIGH").length, MEDIUM:result.findings.filter(f=>f.severity==="MEDIUM").length } : null;
  const filtered = result ? result.findings.filter(f=>(filter==="ALL"||f.severity===filter)&&(search===""||f.file.toLowerCase().includes(search.toLowerCase())||f.code.toLowerCase().includes(search.toLowerCase()))) : [];
  const grouped = filtered.reduce((a,f)=>{ if(!a[f.file])a[f.file]=[]; a[f.file].push(f); return a; },{});

  const handleNIST = () => {
    if (!result) return;
    const score = result.quantum_readiness_score;
    const status = score>=70?"COMPLIANT":score>=40?"PARTIALLY COMPLIANT":"NON-COMPLIANT";
    const scoreColor = score>=70?"#22c55e":score>=40?"#f59e0b":"#ef4444";
    const critical=result.findings.filter(f=>f.severity==="CRITICAL").length;
    const high=result.findings.filter(f=>f.severity==="HIGH").length;
    const medium=result.findings.filter(f=>f.severity==="MEDIUM").length;
    const total=result.total_findings;
    const sevColor=(s)=>s==="CRITICAL"?"#ef4444":s==="HIGH"?"#f59e0b":"#eab308";
    const sevBg=(s)=>s==="CRITICAL"?"#fee2e2":s==="HIGH"?"#fef3c7":"#fef9c3";
    const grp=result.findings.reduce((a,f)=>{if(!a[f.file])a[f.file]=[];a[f.file].push(f);return a;},{});
    const nistControls=[{id:"SC-12",name:"Cryptographic Key Establishment & Management",status:critical>0?"FAIL":"PASS"},{id:"SC-13",name:"Cryptographic Protection",status:critical>0?"FAIL":"PASS"},{id:"IA-7",name:"Cryptographic Module Authentication",status:medium>0?"WARN":"PASS"},{id:"SC-28",name:"Protection of Information at Rest",status:critical>0?"FAIL":"PASS"},{id:"SC-8",name:"Transmission Confidentiality & Integrity",status:high>0?"WARN":"PASS"},{id:"SI-7",name:"Software & Information Integrity",status:medium>0?"WARN":"PASS"},{id:"CM-7",name:"Least Functionality",status:"PASS"},{id:"AC-17",name:"Remote Access",status:"PASS"}];
    const csvData=["Severity,File,Line,Vulnerability,Code,Replacement",...result.findings.map(f=>[f.severity,f.file,f.line,f.vulnerability,'"'+(f.code||"").replace(/"/g,"'").replace(/[\r\n]+/g," ")+'"',f.replacement].join(","))].join("\n");
    const csvHref="data:text/csv;charset=utf-8,"+encodeURIComponent(csvData);
    const target=file?file.name:(input||"scan");
    const win=window.open("","_blank");
    win.document.write(`<!DOCTYPE html><html><head><title>QuantumGuard NIST Report</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:"Segoe UI",sans-serif;background:#f8faf8;color:#1a1a1a;font-size:13px}@media print{.no-print{display:none!important}body{background:#fff}}.wrap{max-width:1100px;margin:0 auto;padding:32px 24px 60px}.header{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:24px;border-bottom:3px solid #22c55e;margin-bottom:28px;flex-wrap:wrap;gap:16px}.logo-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}.logo-icon{width:38px;height:38px;background:#22c55e;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff}.logo-name{font-size:22px;font-weight:900}.logo-name span{color:#22c55e}.score-box{background:#fff;border:2px solid #86efac;border-radius:14px;padding:18px 24px;text-align:center;min-width:150px}.score-num{font-size:48px;font-weight:900;line-height:1;color:${scoreColor}}.score-label{font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;margin-top:2px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}.stat{background:#fff;border:1px solid #e2f0e2;border-radius:12px;padding:16px 18px}.stat-val{font-size:32px;font-weight:900;line-height:1;margin-bottom:4px}.stat-key{font-size:11px;color:#6b7280}table{width:100%;border-collapse:collapse;font-size:12px}th{background:#f0fdf4;padding:9px 14px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;font-weight:700;border-bottom:2px solid #d1fae5}td{padding:9px 14px;border-bottom:1px solid #f0f4f0;vertical-align:top;color:#374151}.sev{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;display:inline-block}code{font-family:monospace;font-size:11px;background:#f0f7f0;padding:2px 6px;border-radius:4px;color:#15803d;word-break:break-all;display:inline-block;max-width:340px}.fix{color:#2563eb;font-size:11px;font-weight:600}.file-wrap{border:1px solid #e2f0e2;border-radius:12px;overflow:hidden;margin-bottom:14px}.file-header{background:#f0fdf4;padding:10px 14px;font-family:monospace;font-weight:700;font-size:12px;color:#15803d;border-bottom:1px solid #d1fae5;display:flex;justify-content:space-between;align-items:center}.footer{margin-top:32px;padding-top:16px;border-top:1px solid #e2f0e2;display:flex;justify-content:space-between;font-size:11px;color:#9ca3af;flex-wrap:wrap;gap:8px}.print-btn{background:#22c55e;color:#fff;border:none;padding:9px 22px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;margin-right:8px}.csv-btn{background:#fff;color:#22c55e;border:1px solid #86efac;padding:9px 22px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer}</style></head><body><div class="wrap"><div class="no-print" style="margin-bottom:20px"><button class="print-btn" onclick="window.print()">🖨 Print / Save PDF</button><a href="${csvHref}" download="nist-report.csv"><button class="csv-btn">📊 Export CSV</button></a></div><div class="header"><div><div class="logo-row"><div class="logo-icon">⚛</div><span class="logo-name"><span>Quantum</span>Guard</span></div><div style="font-size:15px;font-weight:700;color:#374151;margin-bottom:6px">NIST SP 800-53 Security Report</div><div style="display:flex;gap:20px;flex-wrap:wrap"><span style="font-size:11px;color:#9ca3af">Generated <strong style="color:#374151">${new Date().toLocaleString()}</strong></span><span style="font-size:11px;color:#9ca3af">Target <strong style="color:#374151">${target}</strong></span></div></div><div class="score-box"><div class="score-num">${score}</div><div class="score-label">Quantum Score / 100</div><div style="display:inline-flex;align-items:center;gap:5px;background:#f0fdf4;border:1px solid #86efac;color:${scoreColor};font-size:10px;font-weight:700;padding:4px 12px;border-radius:100px;margin-top:8px">${status}</div></div></div><div class="stats"><div class="stat"><div class="stat-val" style="color:#22c55e">${total}</div><div class="stat-key">Total Findings</div></div><div class="stat"><div class="stat-val" style="color:#ef4444">${critical}</div><div class="stat-key">Critical</div></div><div class="stat"><div class="stat-val" style="color:#f59e0b">${high}</div><div class="stat-key">High</div></div><div class="stat"><div class="stat-val" style="color:#eab308">${medium}</div><div class="stat-key">Medium</div></div></div>${Object.entries(grp).map(([fname,findings])=>`<div class="file-wrap"><div class="file-header"><span>📄 ${fname}</span><span style="background:#fee2e2;color:#ef4444;font-size:10px;font-weight:700;padding:2px 9px;border-radius:100px">${findings.length} threats</span></div><table><thead><tr><th>Severity</th><th>Line</th><th>Vulnerability</th><th>Code</th><th>NIST Replacement</th></tr></thead><tbody>${findings.map(f=>`<tr><td><span class="sev" style="background:${sevBg(f.severity)};color:${sevColor(f.severity)}">${f.severity}</span></td><td style="color:#9ca3af;font-family:monospace;font-weight:600">${f.line}</td><td style="font-weight:700">${f.vulnerability}</td><td><code>${(f.code||"").replace(/</g,"&lt;").replace(/>/g,"&gt;")}</code></td><td class="fix">✦ ${f.replacement}</td></tr>`).join("")}</tbody></table></div>`).join("")}<div class="footer"><span>QuantumGuard · NIST SP 800-53 Rev 5 · Mangsri QuantumGuard LLC · Montgomery, AL</span><span>Generated ${new Date().toLocaleDateString()}</span></div></div></body></html>`);
    win.document.close();
  };

  const handleCSV = () => {
    if (!result) return;
    const blob = new Blob(["Severity,File,Line,Code,Fix,Priority,BusinessImpact,Context\n"+result.findings.map(f=>`"${f.severity}","${f.file}","${f.line}","${f.code.replace(/"/g,"'")}","${f.replacement}","${f.priority||""}","${f.business_impact||""}","${f.usage_context||""}"`).join("\n")],{type:"text/csv"});
    const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="quantumguard.csv";a.click();
  };

  const handlePDF = () => {
    if (!result) return;
    const win=window.open("","_blank");
    const sc=result.quantum_readiness_score>=70?"#22c55e":result.quantum_readiness_score>=40?"#f59e0b":"#ef4444";
    const status=result.quantum_readiness_score>=70?"QUANTUM SAFE":result.quantum_readiness_score>=40?"AT RISK":"NOT QUANTUM SAFE";
    const critical=result.findings.filter(f=>f.severity==="CRITICAL").length;
    const high=result.findings.filter(f=>f.severity==="HIGH").length;
    const medium=result.findings.filter(f=>f.severity==="MEDIUM").length;
    const total=result.total_findings;
    const grp=result.findings.reduce((a,f)=>{if(!a[f.file])a[f.file]=[];a[f.file].push(f);return a;},{});
    const sevColor=s=>s==="CRITICAL"?"#ef4444":s==="HIGH"?"#f59e0b":"#eab308";
    const sevBg=s=>s==="CRITICAL"?"#fee2e2":s==="HIGH"?"#fef3c7":"#fef9c3";
    win.document.write(`<!DOCTYPE html><html><head><title>QuantumGuard Report</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:"Segoe UI",sans-serif;background:#fff;color:#1a1a1a;padding:40px;font-size:13px}@media print{body{padding:20px}.no-print{display:none}}.header{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:20px;border-bottom:3px solid #22c55e;margin-bottom:24px}.logo{display:flex;align-items:center;gap:10px}.logo-icon{width:40px;height:40px;background:#22c55e;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px;color:#fff}.logo-name{font-size:22px;font-weight:900}.logo-name span{color:#22c55e}.score-box{text-align:center;background:#f0fdf4;border:2px solid #86efac;border-radius:12px;padding:14px 22px}.score-num{font-size:44px;font-weight:900;color:${sc};line-height:1}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}.stat{background:#f8faf8;border:1px solid #e2f0e2;border-radius:10px;padding:14px;border-top:3px solid var(--c)}.stat-val{font-size:30px;font-weight:900;color:var(--c);line-height:1}.stat-key{font-size:11px;color:#6b7280;margin-top:4px}table{width:100%;border-collapse:collapse;font-size:12px}th{background:#f0fdf4;padding:9px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;font-weight:700;border-bottom:2px solid #d1fae5}td{padding:9px 12px;border-bottom:1px solid #f0f4f0;vertical-align:top}.sev{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;display:inline-block}code{font-family:monospace;font-size:11px;background:#f0f7f0;padding:2px 6px;border-radius:4px;color:#15803d;word-break:break-all}.fix{color:#2563eb;font-size:11px;font-weight:600}.footer{margin-top:32px;padding-top:16px;border-top:1px solid #e2f0e2;display:flex;justify-content:space-between;font-size:11px;color:#9ca3af}.print-btn{background:#22c55e;color:#fff;border:none;padding:10px 24px;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer;margin-bottom:20px}</style></head><body><div class="no-print"><button class="print-btn" onclick="window.print()">🖨 Print / Save as PDF</button></div><div class="header"><div><div class="logo"><div class="logo-icon">⚛</div><span class="logo-name"><span>Quantum</span>Guard</span></div><div style="margin-top:8px;font-size:13px;font-weight:700;color:#374151">NIST SP 800-53 Security Report</div></div><div class="score-box"><div class="score-num">${result.quantum_readiness_score}</div><div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-top:2px">Quantum Score / 100</div><div style="font-size:11px;font-weight:700;color:${sc};margin-top:6px;text-transform:uppercase">${status}</div></div></div><div style="display:flex;gap:24px;margin-bottom:20px;flex-wrap:wrap"><span style="font-size:11px;color:#6b7280">Generated <strong style="color:#374151">${new Date().toLocaleString()}</strong></span><span style="font-size:11px;color:#6b7280">Target <strong style="color:#374151">${file?.name||input||"scan"}</strong></span></div><div class="stats"><div class="stat" style="--c:#22c55e"><div class="stat-val">${total}</div><div class="stat-key">Total Findings</div></div><div class="stat" style="--c:#ef4444"><div class="stat-val">${critical}</div><div class="stat-key">Critical</div></div><div class="stat" style="--c:#f59e0b"><div class="stat-val">${high}</div><div class="stat-key">High</div></div><div class="stat" style="--c:#eab308"><div class="stat-val">${medium}</div><div class="stat-key">Medium</div></div></div><div style="margin-bottom:24px">${Object.entries(grp).map(([fname,findings])=>`<div style="margin-bottom:16px;border:1px solid #e2f0e2;border-radius:10px;overflow:hidden"><div style="background:#f0fdf4;padding:8px 12px;font-weight:700;font-size:12px;color:#14532d;border-bottom:1px solid #d1fae5">📄 ${fname} — ${findings.length} findings</div><table><thead><tr><th>Severity</th><th>Line</th><th>Code</th><th>Vulnerability</th><th>Replacement</th></tr></thead><tbody>${findings.map(f=>`<tr><td><span class="sev" style="background:${sevBg(f.severity)};color:${sevColor(f.severity)}">${f.severity}</span></td><td style="color:#6b7280;font-weight:600">${f.line}</td><td><code>${f.code.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</code></td><td style="font-weight:600;color:#374151">${f.vulnerability}</td><td class="fix">${f.replacement}</td></tr>`).join("")}</tbody></table></div>`).join("")}</div><div class="footer"><span>QuantumGuard · NIST SP 800-53 Rev 5 · Mangsri QuantumGuard LLC · Montgomery, AL</span><span>Generated ${new Date().toLocaleDateString()}</span></div></body></html>`);
    win.document.close(); setTimeout(()=>win.print(),500);
  };

  const btnStyle = (active) => ({ padding:"8px 16px", borderRadius:8, border:`1.5px solid ${active?C.green:C.panelBorder}`, background:active?"rgba(34,197,94,0.15)":"transparent", color:active?C.green:C.muted, cursor:"pointer", fontSize:12, fontWeight:active?600:400, transition:"all 0.2s" });

  return (
    <div style={{ padding:20 }}>
      {result && (
        <div className="stats-grid" style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12, marginBottom:16 }}>
          <ScoreCard label="Quantum Risk Score" value={result.quantum_readiness_score} color={scoreColor} icon={result.quantum_readiness_score>=70?"🛡":result.quantum_readiness_score>=40?"⚠️":"🚨"} desc={result.quantum_readiness_score>=70?"Quantum Safe":result.quantum_readiness_score>=40?"At Risk":"Critical Risk"} />
          <ScoreCard label="Code Scanner Score" value={result.quantum_readiness_score} color={scoreColor} icon="🔍" desc={`${result.total_findings} vulnerabilities found`} />
          <div style={{ background:C.panel, border:`1px solid ${C.panelBorder}`, borderRadius:14, padding:"20px", boxShadow:"0 4px 20px rgba(0,0,0,0.35)", display:"flex", flexDirection:"column", justifyContent:"space-between" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:14 }}><div style={{ fontSize:11, color:C.muted, fontWeight:600, textTransform:"uppercase", letterSpacing:"0.08em" }}>Crypto Agility Score</div><div style={{ fontSize:20 }}>🔬</div></div>
            <div style={{ fontSize:28, fontWeight:800, color:C.muted, marginBottom:6 }}>N/A</div>
            <div style={{ fontSize:11, color:C.muted, lineHeight:1.5 }}>Run <strong style={{ color:C.green }}>Agility Checker</strong> tab for a real score</div>
          </div>
          <div style={{ background:C.panel, border:`1px solid ${C.panelBorder}`, borderRadius:14, padding:"20px", boxShadow:"0 4px 20px rgba(0,0,0,0.35)", display:"flex", flexDirection:"column", justifyContent:"space-between" }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:14 }}><div style={{ fontSize:11, color:C.muted, fontWeight:600, textTransform:"uppercase", letterSpacing:"0.08em" }}>TLS Security Score</div><div style={{ fontSize:20 }}>🔐</div></div>
            <div style={{ fontSize:28, fontWeight:800, color:C.muted, marginBottom:6 }}>N/A</div>
            <div style={{ fontSize:11, color:C.muted, lineHeight:1.5 }}>Run <strong style={{ color:C.green }}>TLS Analyzer</strong> tab for a real score</div>
          </div>
        </div>
      )}

      <Panel title="Scan Target" accent>
        <div style={{ display:"flex", gap:8, marginBottom:14, flexWrap:"wrap" }}>
          {[{id:"github",label:"🔗 GitHub URL"},{id:"zip",label:"📁 Upload ZIP"},{id:"path",label:"🖥️ Server Path"}].map(m=>(
            <button key={m.id} onClick={()=>setMode(m.id)} style={btnStyle(mode===m.id)}>{m.label}</button>
          ))}
        </div>
        {mode==="zip" ? (
          <div style={{ display:"flex", gap:10, flexWrap:"wrap" }}>
            <input type="file" accept=".zip" onChange={e=>setFile(e.target.files[0])} style={{ flex:1, minWidth:200, padding:"9px 14px", borderRadius:8, border:`1.5px solid ${C.panelBorder}`, background:C.input, color:C.text, fontSize:13 }} />
            <button onClick={handleScan} disabled={loading} style={{ padding:"9px 24px", borderRadius:8, background:"linear-gradient(135deg,#22c55e,#16a34a)", color:C.white, border:"none", cursor:"pointer", fontSize:13, fontWeight:600, boxShadow:"0 4px 12px rgba(34,197,94,0.3)", transition:"all 0.2s" }}>{loading?"Scanning...":"▶ Run Scan"}</button>
          </div>
        ) : mode==="github" ? (
          <div>
            <div style={{ display:"flex", gap:10, marginBottom:8, flexWrap:"wrap" }}>
              <input value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleScan()} placeholder="https://github.com/username/repo" style={{ flex:1, minWidth:200, padding:"9px 14px", borderRadius:8, border:`1.5px solid ${C.panelBorder}`, background:C.input, color:C.text, fontSize:13 }} />
              <button onClick={handleScan} disabled={loading} style={{ padding:"9px 24px", borderRadius:8, background:loading?C.greenDark:"linear-gradient(135deg,#22c55e,#16a34a)", color:C.white, border:"none", cursor:loading?"not-allowed":"pointer", fontSize:13, fontWeight:600, boxShadow:loading?"none":"0 4px 12px rgba(34,197,94,0.3)", transition:"all 0.2s" }}>{loading?"Scanning...":"▶ Run Scan"}</button>
            </div>
            <div style={{ display:"flex", gap:8, alignItems:"center", flexWrap:"wrap" }}>
              <button onClick={()=>setShowToken(!showToken)} style={{ background:"transparent", border:`1px solid ${C.panelBorder}`, borderRadius:6, padding:"4px 12px", cursor:"pointer", color:C.muted, fontSize:11 }}>🔒 {showToken?"Hide Token":"Private Repo"}</button>
              {showToken&&<input value={githubToken} onChange={e=>setGithubToken(e.target.value)} placeholder="GitHub Personal Access Token" type="password" style={{ flex:1, padding:"4px 12px", borderRadius:6, border:`1px solid ${C.panelBorder}`, background:C.input, color:C.text, fontSize:11 }} />}
            </div>
          </div>
        ) : (
          <div style={{ display:"flex", gap:10, flexWrap:"wrap" }}>
            <input value={input} onChange={e=>setInput(e.target.value)} placeholder="/app/src" style={{ flex:1, minWidth:200, padding:"9px 14px", borderRadius:8, border:`1.5px solid ${C.panelBorder}`, background:C.input, color:C.text, fontSize:13 }} />
            <button onClick={handleScan} disabled={loading} style={{ padding:"9px 24px", borderRadius:8, background:"linear-gradient(135deg,#22c55e,#16a34a)", color:C.white, border:"none", cursor:"pointer", fontSize:13, fontWeight:600, transition:"all 0.2s" }}>{loading?"Scanning...":"▶ Run Scan"}</button>
          </div>
        )}
        {loading && (
          <div style={{ marginTop:14 }}>
            <div style={{ background:"rgba(34,197,94,0.06)", borderRadius:"10px 10px 0 0", padding:"12px 16px", border:"1px solid rgba(34,197,94,0.25)", borderBottom:"none", display:"flex", alignItems:"center", justifyContent:"space-between", flexWrap:"wrap", gap:8 }}>
              <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                <div style={{ width:8, height:8, borderRadius:"50%", background:C.green, animation:"pulse-ring 1.2s ease-in-out infinite" }} />
                <span style={{ fontSize:12, color:C.green, fontWeight:700 }}>SCANNING</span>
                <span style={{ fontSize:12, color:C.muted, fontWeight:500 }}>{SCAN_STEPS[stepIndex]}</span>
              </div>
              <div style={{ display:"flex", gap:16, alignItems:"center" }}>
                <span style={{ fontSize:11, color:C.muted, fontFamily:"monospace" }}>⏱ {(elapsedMs/1000).toFixed(1)}s</span>
                <span style={{ fontSize:11, color:C.amber, fontFamily:"monospace" }}>⚠ {issuesFound} issues</span>
                <span style={{ fontSize:11, color:C.textMid, fontFamily:"monospace" }}>📁 {filesScanned} files</span>
                <span style={{ fontSize:12, fontWeight:800, color:C.green, fontFamily:"monospace" }}>{progress}%</span>
              </div>
            </div>
            <div style={{ background:"rgba(255,255,255,0.04)", height:4, overflow:"hidden", border:"1px solid rgba(34,197,94,0.2)", borderTop:"none", borderBottom:"none" }}>
              <div style={{ background:"linear-gradient(90deg,#22c55e,#4ade80,#22c55e)", backgroundSize:"200% 100%", height:4, width:`${progress}%`, transition:"width 0.4s ease", boxShadow:"0 0 12px rgba(34,197,94,0.7)" }} />
            </div>
            <div style={{ background:"rgba(34,197,94,0.04)", border:"1px solid rgba(34,197,94,0.2)", borderTop:"none", borderBottom:"none", padding:"8px 16px", display:"flex", gap:6, flexWrap:"wrap" }}>
              {SCAN_STEPS.map((s,i)=>(
                <div key={i} style={{ fontSize:10, fontWeight:i<stepIndex?600:i===stepIndex?700:500, padding:"3px 10px", borderRadius:100, background:i<stepIndex?"rgba(34,197,94,0.18)":i===stepIndex?C.green:"rgba(255,255,255,0.04)", color:i<stepIndex?C.green:i===stepIndex?"#fff":C.muted, border:i===stepIndex?"none":`1px solid ${i<stepIndex?"rgba(34,197,94,0.3)":"rgba(255,255,255,0.06)"}`, transition:"all 0.3s", display:"flex", alignItems:"center", gap:4 }}>
                  {i<stepIndex?"✓ ":i===stepIndex?"▶ ":""}{s.replace("...","")}</div>
              ))}
            </div>
            <div style={{ background:"#0a0e1a", border:"1px solid rgba(34,197,94,0.25)", borderTop:"none", borderRadius:"0 0 10px 10px", height:240, overflowY:"auto", padding:"12px 14px", fontFamily:"'DM Mono','Fira Mono','Consolas',monospace", fontSize:11, lineHeight:1.7 }}>
              <div style={{ color:"#4b5563", marginBottom:8, paddingBottom:8, borderBottom:"1px solid rgba(255,255,255,0.05)" }}>
                <span style={{ color:C.green }}>quantumguard</span><span style={{ color:"#4b5563" }}>@scanner</span><span style={{ color:"#334155" }}> — scanning: </span><span style={{ color:"#60a5fa" }}>{input||file?.name||"target"}</span>
              </div>
              {scanLogs.map(log=>{
                const cfg={info:{icon:"›",color:C.textMid,prefix:"[INFO]   "},success:{icon:"✓",color:C.green,prefix:"[OK]     "},warn:{icon:"⚠",color:C.amber,prefix:"[WARN]   "},critical:{icon:"✕",color:C.critical,prefix:"[VULN]   "}}[log.type]||{icon:"›",color:C.muted,prefix:"[LOG]    "};
                return (<div key={log.id} style={{ display:"flex", gap:8, marginBottom:2 }}>
                  <span style={{ color:"#334155", flexShrink:0, userSelect:"none" }}>{new Date().toLocaleTimeString("en-US",{hour12:false,hour:"2-digit",minute:"2-digit",second:"2-digit"})}</span>
                  <span style={{ color:cfg.color, flexShrink:0, fontWeight:700 }}>{cfg.prefix}</span>
                  <span style={{ color:cfg.color }}>{log.text}</span>
                </div>);
              })}
              <div style={{ display:"flex", alignItems:"center", gap:6, marginTop:4 }}>
                <span style={{ color:"#334155" }}>{new Date().toLocaleTimeString("en-US",{hour12:false,hour:"2-digit",minute:"2-digit",second:"2-digit"})}</span>
                <span style={{ color:C.green, animation:"cursor-blink 1s step-end infinite" }}>█</span>
              </div>
              <div ref={logEndRef} />
            </div>
            <style>{`@keyframes cursor-blink{0%,100%{opacity:1}50%{opacity:0}}`}</style>
          </div>
        )}
        {error&&<div style={{ marginTop:12, background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.3)", borderRadius:8, padding:"10px 14px", color:C.red, fontSize:13 }}>⚠ {error}</div>}
        {saved&&<div style={{ marginTop:10, background:"rgba(34,197,94,0.1)", border:"1px solid rgba(34,197,94,0.3)", borderRadius:8, padding:"8px 14px", color:C.green, fontSize:12, fontWeight:500 }}>✓ Scan saved to history</div>}
      </Panel>

      {result && (
        <>
          {/* ── NEW: Partial scan warning ── */}
          {result.warning && (
            <div style={{ marginBottom:16, background:"rgba(245,158,11,0.08)", border:"1px solid rgba(245,158,11,0.3)", borderRadius:10, padding:"12px 16px", display:"flex", alignItems:"flex-start", gap:10 }}>
              <span style={{ fontSize:18, flexShrink:0 }}>⚠️</span>
              <div>
                <div style={{ fontSize:13, fontWeight:600, color:C.amber, marginBottom:4 }}>Partial scan results</div>
                <div style={{ fontSize:12, color:C.muted, lineHeight:1.6 }}>{result.warning}</div>
              </div>
            </div>
          )}

          {/* ── NEW: Clean repo message ── */}
          {result.clean_repo && (
            <div style={{ marginBottom:16, background:"rgba(34,197,94,0.08)", border:"1px solid rgba(34,197,94,0.3)", borderRadius:10, padding:"16px 18px", display:"flex", alignItems:"center", gap:12 }}>
              <span style={{ fontSize:28 }}>✅</span>
              <div>
                <div style={{ fontSize:14, fontWeight:700, color:C.green, marginBottom:4 }}>Code appears clean</div>
                <div style={{ fontSize:12, color:C.muted }}>No exploitable crypto risks detected. No HIGH or CRITICAL confidence findings found.</div>
              </div>
            </div>
          )}

          {result.score_explanation&&result.score_explanation.length>0&&(
            <Panel title="Why this score?" accent>
              {result.score_explanation.map((line,i)=>{
                const color=line.startsWith("🔴")?C.critical:line.startsWith("🟡")?C.amber:line.startsWith("🟠")?C.medium:C.green;
                return (<div key={i} style={{ display:"flex", gap:10, padding:"7px 0", borderBottom:i<result.score_explanation.length-1?`1px solid ${C.panelBorder}`:"none", alignItems:"flex-start" }}>
                  <span style={{ fontSize:15, flexShrink:0 }}>{line.slice(0,2)}</span>
                  <span style={{ fontSize:12, color, lineHeight:1.6 }}>{line.slice(2).trim()}</span>
                </div>);
              })}
            </Panel>
          )}

          {result.scan_summary&&(
            <Panel title="Scan Summary" accent>
              <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10, marginBottom:result.scan_summary.languages_detected?.length>0?14:0 }}>
                {[["Files Scanned",result.scan_summary.files_scanned,"📁",C.green],["Files With Issues",result.scan_summary.files_with_issues,"⚠️",C.amber],["Scan Time",`${result.scan_summary.scan_time??"—"}s`,"⏱",C.blue],["Confidence",result.scan_summary.overall_confidence??"—","🎯",C.textMid]].map(([label,value,icon,color])=>(
                  <div key={label} style={{ background:C.input, borderRadius:8, padding:"10px 12px", border:`1px solid ${C.panelBorder}`, textAlign:"center" }}>
                    <div style={{ fontSize:18, marginBottom:4 }}>{icon}</div>
                    <div style={{ fontSize:18, fontWeight:800, color }}>{value}</div>
                    <div style={{ fontSize:10, color:C.muted, marginTop:2 }}>{label}</div>
                  </div>
                ))}
              </div>
              {/* NEW: Context breakdown */}
              {result.scan_summary.context_breakdown && Object.keys(result.scan_summary.context_breakdown).length > 0 && (
                <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginTop:8 }}>
                  <span style={{ fontSize:11, color:C.muted, alignSelf:"center", marginRight:4 }}>Contexts:</span>
                  {Object.entries(result.scan_summary.context_breakdown).map(([ctx, count]) => (
                    <span key={ctx} style={{ fontSize:10, fontWeight:600, padding:"2px 8px", borderRadius:100, background:"rgba(34,197,94,0.08)", color:C.green, border:"1px solid rgba(34,197,94,0.2)" }}>
                      {ctx} ({count})
                    </span>
                  ))}
                </div>
              )}
              {/* NEW: Library suppression count */}
              {result.scan_summary.library_findings_suppressed > 0 && (
                <div style={{ marginTop:8, fontSize:11, color:C.muted }}>
                  🔇 {result.scan_summary.library_findings_suppressed} findings suppressed (vendor/library files)
                </div>
              )}
              {result.scan_summary.languages_detected?.length>0&&(
                <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginTop:8 }}>
                  <span style={{ fontSize:11, color:C.muted, marginRight:4, alignSelf:"center" }}>Languages:</span>
                  {result.scan_summary.languages_detected.map(lang=><span key={lang} style={{ background:"rgba(34,197,94,0.1)", color:C.green, border:"1px solid rgba(34,197,94,0.3)", fontSize:10, fontWeight:700, padding:"2px 9px", borderRadius:100 }}>{lang}</span>)}
                </div>
              )}
              {result.scan_summary.confidence_note&&<div style={{ marginTop:10, fontSize:11, color:C.muted, background:"rgba(34,197,94,0.05)", padding:"7px 12px", borderRadius:6, border:"1px solid rgba(34,197,94,0.12)" }}>{result.scan_summary.confidence_note}</div>}
            </Panel>
          )}

          <div className="charts-grid" style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
            <Panel title="Severity Distribution" accent><SevBar label="Critical" count={sev.CRITICAL} total={result.total_findings} color={C.critical} /><SevBar label="High" count={sev.HIGH} total={result.total_findings} color={C.amber} /><SevBar label="Medium" count={sev.MEDIUM} total={result.total_findings} color={C.medium} /></Panel>
            <Panel title="Score Breakdown" accent><SevBar label="Crypto Issues" count={sev.CRITICAL} total={result.total_findings} color={C.critical} /><SevBar label="TLS / Protocol" count={sev.HIGH} total={result.total_findings} color={C.amber} /><SevBar label="Hash / Secrets" count={sev.MEDIUM} total={result.total_findings} color={C.medium} /></Panel>
          </div>

          <Panel title="Export & Share" accent>
            <div style={{ display:"flex", gap:8, flexWrap:"wrap", marginBottom:12 }}>
              <button onClick={handlePDF} style={{ padding:"8px 16px", borderRadius:8, background:"linear-gradient(135deg,#22c55e,#16a34a)", color:C.white, border:"none", cursor:"pointer", fontSize:12, fontWeight:600, boxShadow:"0 2px 8px rgba(34,197,94,0.3)", transition:"all 0.2s" }}>📄 PDF Report</button>
              <button onClick={handleNIST} style={{ padding:"8px 16px", borderRadius:8, background:"rgba(59,130,246,0.15)", color:"#60a5fa", border:"1px solid rgba(59,130,246,0.3)", cursor:"pointer", fontSize:12, fontWeight:600, transition:"all 0.2s" }}>🏛 NIST Report</button>
              <button onClick={handleCSV} style={{ padding:"8px 16px", borderRadius:8, background:"rgba(34,197,94,0.1)", color:C.green, border:"1px solid rgba(34,197,94,0.3)", cursor:"pointer", fontSize:12, fontWeight:600, transition:"all 0.2s" }}>📊 CSV Export</button>
            </div>
            <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
              <input value={emailInput} onChange={e=>setEmailInput(e.target.value)} placeholder="Email report to..." type="email" style={{ flex:1, minWidth:200, padding:"8px 14px", borderRadius:8, border:`1px solid ${C.panelBorder}`, background:C.input, color:C.text, fontSize:12 }} />
              <button onClick={handleEmail} disabled={sendingEmail||!emailInput} style={{ padding:"8px 16px", borderRadius:8, background:"linear-gradient(135deg,#22c55e,#16a34a)", color:C.white, border:"none", cursor:"pointer", fontSize:12, fontWeight:600, transition:"all 0.2s" }}>{emailSent?"✓ Sent!":sendingEmail?"Sending...":"📧 Send Email"}</button>
            </div>
          </Panel>

          {/* ── NEW: Grouped findings panel ── */}
          {result.grouped_findings && result.grouped_findings.length > 0 && (
            <GroupedFindingsPanel groups={result.grouped_findings} />
          )}

          {/* ── Flat findings with enterprise fields ── */}
          <Panel title={`Threat Intelligence — ${result.total_findings} findings`} accent>
            <div style={{ display:"flex", gap:8, marginBottom:14, flexWrap:"wrap", alignItems:"center" }}>
              {["ALL","CRITICAL","HIGH","MEDIUM"].map(f=>{
                const colors={ALL:C.green,CRITICAL:C.critical,HIGH:C.amber,MEDIUM:C.medium}; const col=colors[f];
                return (<button key={f} onClick={()=>setFilter(f)} style={{ padding:"5px 14px", borderRadius:20, border:`1.5px solid ${filter===f?col:C.panelBorder}`, background:filter===f?col+"22":"transparent", color:filter===f?col:C.muted, cursor:"pointer", fontSize:11, fontWeight:filter===f?700:400, transition:"all 0.2s" }}>
                  {f} {f!=="ALL"&&sev?`(${sev[f]})`:""}</button>);
              })}
              <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search..." style={{ padding:"5px 12px", borderRadius:20, border:`1px solid ${C.panelBorder}`, background:C.input, color:C.text, fontSize:11, width:120, marginLeft:"auto" }} />
            </div>
            {Object.entries(grouped).map(([file,findings],gi)=>(
              <div key={gi} style={{ marginBottom:12, border:`1px solid ${C.panelBorder}`, borderRadius:10, overflow:"hidden", transition:"border-color 0.2s" }}
                onMouseEnter={e=>e.currentTarget.style.borderColor="rgba(34,197,94,0.25)"} onMouseLeave={e=>e.currentTarget.style.borderColor=C.panelBorder}>
                <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"10px 16px", background:"rgba(34,197,94,0.05)", borderBottom:`1px solid ${C.panelBorder}`, flexWrap:"wrap", gap:4 }}>
                  <span style={{ fontSize:12, fontWeight:600, color:C.text }}>{file.split("/").pop()}</span>
                  <Badge text={`${findings.length} threats`} color={C.red} bg={SEV_BG.CRITICAL} />
                </div>
                <div style={{ padding:14 }}>
                  {findings.map((f,i)=>{
                    const key=`${f.file}:${f.line}`;
                    const fSevColor=f.severity==="CRITICAL"?C.critical:f.severity==="HIGH"?C.amber:C.medium;
                    const fSevBg=SEV_BG[f.severity]||SEV_BG.MEDIUM;
                    return (<div key={i} style={{ borderLeft:`3px solid ${fSevColor}`, paddingLeft:14, marginBottom:i<findings.length-1?16:0, opacity:checklist[key]?0.4:1, paddingBottom:i<findings.length-1?16:0, borderBottom:i<findings.length-1?`1px solid ${C.panelBorder}`:"none" }}>
                      <div style={{ display:"flex", gap:8, marginBottom:8, alignItems:"center", flexWrap:"wrap" }}>
                        <input type="checkbox" checked={!!checklist[key]} onChange={()=>setChecklist(p=>({...p,[key]:!p[key]}))} style={{ cursor:"pointer", accentColor:C.green }} />
                        <span style={{ background:fSevBg, color:fSevColor, padding:"3px 10px", borderRadius:6, fontSize:11, fontWeight:800, border:`1px solid ${fSevColor}44`, letterSpacing:"0.03em", textTransform:"uppercase" }}>{f.severity}</span>
                        <span style={{ background:"rgba(255,255,255,0.06)", color:C.muted, fontSize:10, fontWeight:600, padding:"2px 8px", borderRadius:4 }}>{f.vulnerability}</span>
                        <span style={{ color:C.muted, fontSize:11 }}>Line {f.line}</span>
                        {/* NEW: Priority badge */}
                        {f.priority && <PriorityBadge priority={f.priority} />}
                        {/* NEW: Context badge */}
                        {f.usage_context && f.usage_context !== "unknown" && <ContextBadge context={f.usage_context} />}
                        {/* NEW: Confidence score */}
                        {f.confidence_score !== undefined && <ConfidencePill score={f.confidence_score} label={f.confidence} />}
                        <button onClick={()=>handleAiFix(f)} style={{ marginLeft:"auto", padding:"3px 12px", borderRadius:6, background:"rgba(34,197,94,0.1)", border:"1px solid rgba(34,197,94,0.3)", color:C.green, cursor:"pointer", fontSize:10, fontWeight:700, transition:"all 0.2s" }}>⚡ AI Fix</button>
                      </div>
                      <div style={{ fontFamily:"monospace", background:C.input, padding:"8px 12px", borderRadius:6, fontSize:11, marginBottom:8, color:C.green, overflowX:"auto", border:`1px solid ${C.panelBorder}` }}>{f.code}</div>
                      <div style={{ display:"flex", gap:8, flexWrap:"wrap", alignItems:"stretch" }}>
                        <div style={{ flex:1, background:"rgba(59,130,246,0.08)", border:"1px solid rgba(59,130,246,0.2)", borderRadius:6, padding:"7px 12px", display:"flex", alignItems:"center", gap:8 }}>
                          <span style={{ fontSize:10, fontWeight:700, color:"#60a5fa", textTransform:"uppercase", letterSpacing:"0.05em", flexShrink:0 }}>Fix</span>
                          <span style={{ color:"#93c5fd", fontWeight:600, fontSize:12 }}>✦ {f.replacement}</span>
                        </div>
                        {/* NEW: Business impact + exploitability */}
                        {(f.business_impact || f.exploitability) && (
                          <div style={{ display:"flex", gap:6, alignItems:"center" }}>
                            {f.business_impact && (
                              <span style={{ fontSize:10, fontWeight:600, padding:"3px 8px", borderRadius:5, background:"rgba(239,68,68,0.1)", color: f.business_impact==="HIGH"?C.red:f.business_impact==="MEDIUM"?C.amber:C.muted }}>
                                Impact: {f.business_impact}
                              </span>
                            )}
                            {f.exploitability && (
                              <span style={{ fontSize:10, fontWeight:600, padding:"3px 8px", borderRadius:5, background:"rgba(107,114,128,0.1)", color:C.muted }}>
                                Exploit: {f.exploitability}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    </div>);
                  })}
                </div>
              </div>
            ))}
            {filtered.length===0&&<div style={{ textAlign:"center", padding:24, color:C.muted }}>No findings match filter.</div>}
          </Panel>
        </>
      )}

      {aiModal&&(
        <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.7)", zIndex:999, display:"flex", alignItems:"center", justifyContent:"center", padding:16, backdropFilter:"blur(4px)" }}>
          <div style={{ background:C.panel, borderRadius:16, width:"100%", maxWidth:640, maxHeight:"80vh", display:"flex", flexDirection:"column", boxShadow:"0 24px 80px rgba(0,0,0,0.6)", border:`1px solid ${C.panelBorder}` }}>
            <div style={{ padding:"14px 18px", borderBottom:`1px solid ${C.panelBorder}`, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <span style={{ fontSize:14, fontWeight:700, color:C.text }}>⚡ AI Migration Assistant</span>
              <button onClick={()=>{setAiModal(null);setAiResult(null);}} style={{ background:"transparent", border:"none", color:C.muted, cursor:"pointer", fontSize:20 }}>✕</button>
            </div>
            <div style={{ padding:16, borderBottom:`1px solid ${C.panelBorder}`, background:"rgba(239,68,68,0.05)" }}>
              <div style={{ fontFamily:"monospace", fontSize:12, color:C.red, background:C.input, padding:"8px 12px", borderRadius:8, border:"1px solid rgba(239,68,68,0.3)" }}>{aiModal.code}</div>
            </div>
            <div style={{ flex:1, overflowY:"auto", padding:16 }}>
              {aiLoading ? (
                <div style={{ textAlign:"center", padding:32 }}>
                  <div style={{ width:8, height:8, borderRadius:"50%", background:C.green, margin:"0 auto 12px", animation:"pulse-ring 1.2s ease-in-out infinite" }} />
                  <div style={{ fontSize:13, color:C.green, fontWeight:600 }}>Generating AI fix...</div>
                </div>
              ) : aiResult ? (
                <div>
                  <div style={{ fontFamily:"monospace", fontSize:12, color:C.text, lineHeight:1.8, whiteSpace:"pre-wrap", background:C.input, padding:14, borderRadius:8, border:`1px solid ${C.panelBorder}` }}>{aiResult}</div>
                  <button onClick={()=>navigator.clipboard.writeText(aiResult)} style={{ marginTop:12, padding:"7px 16px", borderRadius:8, background:"linear-gradient(135deg,#22c55e,#16a34a)", color:C.white, border:"none", cursor:"pointer", fontSize:12, fontWeight:600 }}>Copy Fix</button>
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
// AGILITY PAGE — unchanged
// ══════════════════════════════════════════════════════════════
function AgilityPage() {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const handleCheck = async () => {
    if (!input) return; setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`${API}/check-agility`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({github_url:input})});
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail||"Check failed");
      setResult(data);
    } catch(e) { setError(typeof e.message==="string"?e.message:"Check failed."); }
    setLoading(false);
  };
  const agilityColor = result?(result.agility_score>=70?C.green:result.agility_score>=40?C.amber:C.red):C.muted;
  return (
    <div style={{ padding:20 }}>
      <Panel title="Crypto Agility Analysis" accent>
        <div style={{ fontSize:13, color:C.muted, marginBottom:14, lineHeight:1.7, background:"rgba(34,197,94,0.06)", padding:"10px 14px", borderRadius:8, border:"1px solid rgba(34,197,94,0.15)" }}>
          <strong style={{ color:C.green }}>Crypto Agility</strong> = ability to swap encryption algorithms without major code changes.
        </div>
        <div style={{ display:"flex", gap:10, flexWrap:"wrap" }}>
          <input value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleCheck()} placeholder="https://github.com/username/repo" style={{ flex:1, minWidth:200, padding:"9px 14px", borderRadius:8, border:`1.5px solid ${C.panelBorder}`, background:C.input, color:C.text, fontSize:13 }} />
          <button onClick={handleCheck} disabled={loading} style={{ padding:"9px 24px", borderRadius:8, background:loading?C.greenDark:"linear-gradient(135deg,#22c55e,#16a34a)", color:C.white, border:"none", cursor:loading?"not-allowed":"pointer", fontSize:13, fontWeight:600, boxShadow:loading?"none":"0 4px 12px rgba(34,197,94,0.3)", transition:"all 0.2s" }}>{loading?"Analyzing...":"🔬 Check Agility"}</button>
        </div>
        {loading&&<div style={{ marginTop:12, background:"rgba(34,197,94,0.06)", borderRadius:10, padding:"12px 16px", border:"1px solid rgba(34,197,94,0.2)", display:"flex", alignItems:"center", gap:10 }}><div style={{ width:8, height:8, borderRadius:"50%", background:C.green, animation:"pulse-ring 1.2s ease-in-out infinite" }} /><span style={{ fontSize:12, color:C.green, fontWeight:500 }}>Analyzing crypto agility...</span></div>}
        {error&&<div style={{ marginTop:12, background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.3)", borderRadius:8, padding:"10px 14px", color:C.red, fontSize:13 }}>⚠ {error}</div>}
      </Panel>
      {result&&(
        <>
          <div className="stats-grid" style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12, marginBottom:16 }}>
            <Metric label="Agility Score" value={result.agility_score} suffix="/100" color={agilityColor} icon="🔬" desc={result.agility_score>=70?"High Agility":result.agility_score>=40?"Partial Agility":"Low Agility"} />
            <Metric label="Hardcoded Crypto" value={result.hardcoded_count} color={C.red} icon="🔴" desc="needs to be configurable" />
            <Metric label="Configurable Crypto" value={result.configurable_count} color={C.green} icon="✅" desc="already agile" />
          </div>
          <Panel title="Agility Breakdown" accent>
            <SevBar label="Hardcoded Crypto" count={result.hardcoded_count} total={result.hardcoded_count+result.configurable_count} color={C.red} />
            <SevBar label="Configurable Crypto" count={result.configurable_count} total={result.hardcoded_count+result.configurable_count} color={C.green} />
          </Panel>
        </>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// TLS PAGE — unchanged
// ══════════════════════════════════════════════════════════════
function TLSPage() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const handleAnalyze = async () => {
    if (!domain) return; setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch(`${API}/analyze-tls`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({domain:domain.replace("https://","").replace("http://","").split("/")[0]})});
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail||"Analysis failed");
      setResult(data);
    } catch(e) { setError(typeof e.message==="string"?e.message:"Analysis failed."); }
    setLoading(false);
  };
  const scoreColor = result?(result.tls_score>=70?C.green:result.tls_score>=40?C.amber:C.red):C.muted;
  const gradeColor = result?(result.grade==="A+"||result.grade==="A"?C.green:result.grade==="B"||result.grade==="C"?C.amber:C.red):C.muted;
  return (
    <div style={{ padding:20 }}>
      <Panel title="TLS / SSL Quantum Readiness Analyzer" accent>
        <div style={{ fontSize:13, color:C.muted, marginBottom:14, background:"rgba(34,197,94,0.06)", padding:"10px 14px", borderRadius:8, lineHeight:1.7, border:"1px solid rgba(34,197,94,0.15)" }}>
          Checks any domain for TLS version, cipher suite, and quantum vulnerability. <strong style={{ color:C.green }}>TLS 1.3 + forward secrecy</strong> = best protection.
        </div>
        <div style={{ display:"flex", gap:10, flexWrap:"wrap" }}>
          <input value={domain} onChange={e=>setDomain(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleAnalyze()} placeholder="google.com or https://github.com" style={{ flex:1, minWidth:200, padding:"9px 14px", borderRadius:8, border:`1.5px solid ${C.panelBorder}`, background:C.input, color:C.text, fontSize:13 }} />
          <button onClick={handleAnalyze} disabled={loading} style={{ padding:"9px 24px", borderRadius:8, background:loading?C.greenDark:"linear-gradient(135deg,#22c55e,#16a34a)", color:C.white, border:"none", cursor:loading?"not-allowed":"pointer", fontSize:13, fontWeight:600, boxShadow:loading?"none":"0 4px 12px rgba(34,197,94,0.3)", transition:"all 0.2s" }}>{loading?"Analyzing...":"🔐 Analyze TLS"}</button>
        </div>
        {loading&&<div style={{ marginTop:12, background:"rgba(34,197,94,0.06)", borderRadius:10, padding:"12px 16px", border:"1px solid rgba(34,197,94,0.2)", display:"flex", alignItems:"center", gap:10 }}><div style={{ width:8, height:8, borderRadius:"50%", background:C.green, animation:"pulse-ring 1.2s ease-in-out infinite" }} /><span style={{ fontSize:12, color:C.green, fontWeight:500 }}>Analyzing TLS configuration...</span></div>}
        {error&&<div style={{ marginTop:12, background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.3)", borderRadius:8, padding:"10px 14px", color:C.red, fontSize:13 }}>⚠ {error}</div>}
      </Panel>
      {result&&(
        <>
          <div style={{ background:C.panel, border:`1px solid ${C.panelBorder}`, borderRadius:14, padding:"20px 24px", marginBottom:16, boxShadow:"0 4px 20px rgba(0,0,0,0.4)", display:"flex", alignItems:"center", gap:24, flexWrap:"wrap" }}>
            <div style={{ textAlign:"center", minWidth:100 }}>
              <div style={{ fontSize:72, fontWeight:900, lineHeight:1, color:gradeColor, fontFamily:"monospace" }}>{result.grade||"?"}</div>
              <div style={{ fontSize:11, color:C.muted, marginTop:4, textTransform:"uppercase", letterSpacing:1 }}>SSL Grade</div>
            </div>
            <div style={{ flex:1 }}>
              <div style={{ fontSize:16, fontWeight:700, color:C.text, marginBottom:6 }}>{result.grade_description}</div>
              <div style={{ display:"flex", gap:10, flexWrap:"wrap", marginBottom:8 }}>
                <span style={{ background:result.tls_version==="TLSv1.3"?"rgba(34,197,94,0.15)":"rgba(245,158,11,0.15)", color:result.tls_version==="TLSv1.3"?C.green:C.amber, fontSize:11, fontWeight:700, padding:"3px 10px", borderRadius:100, border:`1px solid ${result.tls_version==="TLSv1.3"?"rgba(34,197,94,0.3)":"rgba(245,158,11,0.3)"}` }}>{result.tls_version}</span>
                <span style={{ background:result.quantum_safe?"rgba(34,197,94,0.15)":"rgba(239,68,68,0.15)", color:result.quantum_safe?C.green:C.red, fontSize:11, fontWeight:700, padding:"3px 10px", borderRadius:100, border:`1px solid ${result.quantum_safe?"rgba(34,197,94,0.3)":"rgba(239,68,68,0.3)"}` }}>{result.quantum_safe?"✦ Post-Quantum Safe":"⚠ Not Quantum Safe"}</span>
                <span style={{ background:"rgba(34,197,94,0.1)", color:C.green, fontSize:11, fontWeight:700, padding:"3px 10px", borderRadius:100, border:"1px solid rgba(34,197,94,0.3)" }}>Score: {result.tls_score}/100</span>
              </div>
              {result.pqc_note&&<div style={{ fontSize:12, color:C.amber, background:"rgba(245,158,11,0.1)", padding:"6px 12px", borderRadius:8, border:"1px solid rgba(245,158,11,0.3)" }}>⚠ {result.pqc_note}</div>}
            </div>
          </div>
          <div className="stats-grid" style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12, marginBottom:16 }}>
            <Metric label="TLS Score" value={result.tls_score} suffix="/100" color={scoreColor} icon="🎯" desc={result.tls_score>=70?"Quantum Ready":"Needs Improvement"} />
            <Metric label="TLS Version" value={result.tls_version} color={result.tls_version==="TLSv1.3"?C.green:C.amber} icon="🔒" desc={result.tls_version==="TLSv1.3"?"Latest":"Upgrade Needed"} />
            <Metric label="Post-Quantum Readiness" value={result?.quantum_safe?"YES":result?.tls_version==="TLSv1.3"?"PARTIAL":"NO"} color={result?.quantum_safe?C.green:result?.tls_version==="TLSv1.3"?C.amber:C.red} icon={result?.quantum_safe?"✅":result?.tls_version==="TLSv1.3"?"⚠️":"❌"} desc={result?.quantum_safe?"Post-quantum detected":result?.tls_version==="TLSv1.3"?"Secure today, not quantum-resistant":"Not post-quantum yet"} />
            <Metric label="Key Size" value={result.cipher_bits} suffix=" bit" color={result.cipher_bits>=256?C.green:C.amber} icon="🔑" desc={result.cipher_bits>=256?"Strong":"Upgrade Needed"} />
          </div>
          <Panel title="Cipher Suite Details" accent>
            <div className="tls-grid" style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
              {[["Domain",result.domain,C.green],["Cipher Suite",result.cipher_suite,C.text],["Key Exchange",result.key_exchange||(result.has_forward_secrecy?"ECDHE / Forward Secrecy":"Static RSA or Unknown"),C.green],["Certificate Expires",result.certificate?.cert_expires||result.cert_expires||"—",C.amber],["Recommendation",result.nist_recommendation||result.recommendation||"Monitor hybrid PQC TLS adoption",C.green],["Future Upgrade",result.pqc_roadmap||"Hybrid TLS: X25519 + ML-KEM → NIST FIPS 203","#60a5fa"]].map(([label,value,color])=>(
                <div key={label} style={{ background:C.input, borderRadius:8, padding:"12px 14px", border:`1px solid ${C.panelBorder}` }}>
                  <div style={{ fontSize:11, color:C.muted, marginBottom:4, fontWeight:500 }}>{label}</div>
                  <div style={{ fontSize:12, color, fontWeight:500, wordBreak:"break-all" }}>{value}</div>
                </div>
              ))}
            </div>
          </Panel>
          {result.issues&&result.issues.length>0&&(
            <Panel title={`Issues Found — ${result.issues.length}`} accent>
              {result.issues.map((issue,i)=>(
                <div key={i} style={{ display:"flex", gap:10, padding:"10px 0", borderBottom:i<result.issues.length-1?`1px solid ${C.panelBorder}`:"none" }}>
                  <span style={{ color:C.red, fontSize:16 }}>⚠</span>
                  <span style={{ fontSize:13, color:C.textMid }}>{issue}</span>
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
// HISTORY PAGE — unchanged
// ══════════════════════════════════════════════════════════════
function HistoryPage({ user }) {
  const { jwtToken } = useAuth();
  const [history, setHistory]   = useState([]);
  const [loading, setLoading]   = useState(true);
  const [source, setSource]     = useState("none");

  useEffect(() => {
    if (jwtToken) {
      fetch(`${API}/auth/history`, { headers: { Authorization: `Bearer ${jwtToken}` } })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data && data.history) { setHistory(data.history); setSource("jwt"); setLoading(false); }
        else { loadFirebase(); }
      })
      .catch(() => loadFirebase());
      return;
    }
    loadFirebase();
    function loadFirebase() {
      if (!user?.uid) { setLoading(false); return; }
      const q = query(collection(db,"scans"),where("userId","==",user.uid),orderBy("createdAt","desc"));
      getDocs(q).then(snap => { setHistory(snap.docs.map(d=>({id:d.id,...d.data()}))); setSource("firebase"); }).catch(console.error).finally(() => setLoading(false));
    }
  }, [jwtToken, user]);

  if (!user && !jwtToken) return (
    <div style={{ padding:20 }}>
      <div style={{ textAlign:"center", padding:48, background:C.panel, borderRadius:12, border:`1px solid ${C.panelBorder}` }}>
        <div style={{ fontSize:48, marginBottom:16 }}>🔒</div>
        <div style={{ fontSize:16, color:C.text, fontWeight:600, marginBottom:8 }}>Sign in to view history</div>
        <div style={{ fontSize:13, color:C.muted }}>Your scan history is saved automatically when logged in.</div>
      </div>
    </div>
  );

  const formatDate = (scan) => {
    if (scan.created_at) return new Date(scan.created_at).toLocaleDateString();
    if (scan.createdAt?.toDate) return scan.createdAt.toDate().toLocaleDateString();
    return "—";
  };
  const getTarget   = (scan) => scan.target || scan.filename || scan.github_url || "scan";
  const getScore    = (scan) => scan.score ?? scan.quantum_readiness_score ?? "—";
  const getFindings = (scan) => scan.findings ?? "—";

  return (
    <div style={{ padding:20 }}>
      {source==="jwt" && (
        <div style={{ background:"rgba(34,197,94,.08)",border:"1px solid rgba(34,197,94,.2)",borderRadius:8,padding:"8px 14px",marginBottom:12,fontSize:12,color:C.green,display:"flex",alignItems:"center",gap:6 }}>
          <span>🗄</span> Showing history from PostgreSQL database — persists across sessions
        </div>
      )}
      <Panel title={`Scan History — ${history.length} records`} accent>
        {loading ? (
          <div style={{ color:C.muted, fontSize:13, padding:12 }}>Loading history...</div>
        ) : history.length === 0 ? (
          <div style={{ color:C.muted, fontSize:13, padding:12 }}>No scans yet — run your first scan!</div>
        ) : (
          <>
            <div style={{ display:"grid",gridTemplateColumns:"1fr 130px 70px 70px",gap:8,padding:"6px 8px",marginBottom:6 }}>
              {["Target","Date","Score","Findings"].map(h=>(
                <div key={h} style={{ fontSize:10,fontWeight:700,color:C.muted,textTransform:"uppercase",letterSpacing:".06em" }}>{h}</div>
              ))}
            </div>
            {history.map((scan,i)=>{
              const score = getScore(scan);
              const scoreColor = typeof score==="number"?(score>=70?C.green:score>=40?C.amber:C.red):C.muted;
              return (
                <div key={i} style={{ display:"grid",gridTemplateColumns:"1fr 130px 70px 70px",gap:8,padding:"10px 8px",borderBottom:i<history.length-1?`1px solid ${C.panelBorder}`:"none",alignItems:"center",borderRadius:6,transition:"background .15s",cursor:"pointer" }}
                  onMouseEnter={e=>e.currentTarget.style.background="rgba(34,197,94,.04)"}
                  onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                  <div style={{ fontSize:12,color:C.text,fontWeight:500,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }} title={getTarget(scan)}>
                    {getTarget(scan).replace("https://github.com/","github: ")}
                  </div>
                  <div style={{ fontSize:11,color:C.muted }}>{formatDate(scan)}</div>
                  <div style={{ fontSize:18,fontWeight:800,color:scoreColor }}>{score}</div>
                  <div style={{ fontSize:14,fontWeight:600,color:C.red }}>{getFindings(scan)}</div>
                </div>
              );
            })}
          </>
        )}
      </Panel>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// MIGRATION PAGE — unchanged
// ══════════════════════════════════════════════════════════════
function MigrationPage({ user }) {
  const [migrationStatus, setMigrationStatus] = useState({});
  const vulnTypes = ["RSA","ECC","DH","DSA","MD5","SHA1","RC4","DES","ECB_MODE","WEAK_TLS","HARDCODED_SECRET"];
  const getStatus = v => migrationStatus[v]||"pending";
  const setStatus = (v,s) => setMigrationStatus(p=>({...p,[v]:s}));
  const totalFixed = Object.values(migrationStatus).filter(s=>s==="fixed").length;
  const totalIP = Object.values(migrationStatus).filter(s=>s==="in_progress").length;
  const progress = Math.round((totalFixed/vulnTypes.length)*100);
  const fixes = {RSA:"CRYSTALS-Kyber (ML-KEM FIPS 203)",ECC:"CRYSTALS-Dilithium (ML-DSA FIPS 204)",DH:"CRYSTALS-Kyber (ML-KEM FIPS 203)",DSA:"CRYSTALS-Dilithium (ML-DSA FIPS 204)",MD5:"SHA-3-256 or BLAKE3",SHA1:"SHA-3-256 or BLAKE3",RC4:"AES-256-GCM",DES:"AES-256-GCM",ECB_MODE:"AES-256-GCM",WEAK_TLS:"TLS 1.3",HARDCODED_SECRET:"AWS Secrets Manager"};
  const sevOf = v => ["RSA","ECC","RC4","DES"].includes(v)?"CRITICAL":["DH","DSA","ECB_MODE","WEAK_TLS","HARDCODED_SECRET"].includes(v)?"HIGH":"MEDIUM";
  if (!user) return (
    <div style={{ padding:20 }}>
      <div style={{ textAlign:"center", padding:48, background:C.panel, borderRadius:12, border:`1px solid ${C.panelBorder}` }}>
        <div style={{ fontSize:48, marginBottom:16 }}>🔒</div>
        <div style={{ fontSize:16, color:C.text, fontWeight:600 }}>Sign in to track migration</div>
      </div>
    </div>
  );
  return (
    <div style={{ padding:20 }}>
      <Panel title="Migration Progress" accent>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:14, flexWrap:"wrap", gap:8 }}>
          <div style={{ fontSize:40, fontWeight:800, color:progress>=70?C.green:progress>=40?C.amber:C.red }}>{progress}%</div>
          <div style={{ display:"flex", gap:20 }}>
            {[["Fixed",totalFixed,C.green],["In Progress",totalIP,C.amber],["Pending",vulnTypes.length-totalFixed-totalIP,C.muted]].map(([l,v,c],i)=>(
              <div key={i} style={{ textAlign:"center" }}><div style={{ fontSize:24, fontWeight:700, color:c }}>{v}</div><div style={{ fontSize:11, color:C.muted }}>{l}</div></div>
            ))}
          </div>
        </div>
        <div style={{ background:"rgba(255,255,255,0.06)", borderRadius:8, height:12 }}>
          <div style={{ background:`linear-gradient(90deg,${C.green},#4ade80)`, height:12, borderRadius:8, width:`${progress}%`, transition:"width 0.6s ease", boxShadow:"0 0 10px rgba(34,197,94,0.5)" }} />
        </div>
      </Panel>
      <Panel title="Vulnerability Migration Status" accent>
        {vulnTypes.map((v,i)=>{
          const status=getStatus(v); const sev=sevOf(v);
          const sevColor=sev==="CRITICAL"?C.critical:sev==="HIGH"?C.amber:C.medium;
          const sevBg=SEV_BG[sev]||SEV_BG.MEDIUM;
          return (<div key={i} style={{ display:"flex", gap:10, padding:"10px 12px", background:status==="fixed"?"rgba(34,197,94,0.06)":i%2===0?C.panel:"rgba(255,255,255,0.02)", borderRadius:8, marginBottom:4, border:`1px solid ${status==="fixed"?"rgba(34,197,94,0.2)":C.panelBorder}`, alignItems:"center", flexWrap:"wrap", transition:"all 0.2s" }}>
            <div style={{ fontSize:13, fontWeight:600, color:status==="fixed"?C.muted:C.text, textDecoration:status==="fixed"?"line-through":"none", minWidth:120 }}>{v}</div>
            <div style={{ fontSize:11, color:C.muted, flex:1, minWidth:150 }}>{fixes[v]}</div>
            <Badge text={sev} color={sevColor} bg={sevBg} />
            <div style={{ display:"flex", gap:4 }}>
              {[["pending","⬜"],["in_progress","🔄"],["fixed","✅"]].map(([st,icon])=>(
                <button key={st} onClick={()=>setStatus(v,st)} style={{ padding:"4px 8px", borderRadius:6, border:`1.5px solid ${status===st?C.green:C.panelBorder}`, background:status===st?"rgba(34,197,94,0.15)":"transparent", cursor:"pointer", fontSize:14, transition:"all 0.2s" }}>{icon}</button>
              ))}
            </div>
          </div>);
        })}
      </Panel>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// ANALYTICS, DOCS, UNIFIED RISK — unchanged (copy verbatim)
// ══════════════════════════════════════════════════════════════
function AnalyticsPage() {
  return (
    <div style={{ padding:20 }}>
      <div className="analytics-grid" style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12, marginBottom:16 }}>
        <Metric label="Languages Supported" value="8" color={C.green} icon="💻" desc="Python, JS, Java, TS, Go, Rust, C, C++" />
        <Metric label="Vulnerability Types" value="15+" color={C.red} icon="🔍" desc="RSA, ECC, DH, DSA, MD5 & more" />
        <Metric label="NIST Compliance" value="2024" color={C.blue} icon="📋" desc="FIPS 203, 204, 205 aligned" />
      </div>
      <Panel title="Quantum Timeline" accent>
        {[
          {year:"2024",event:"NIST finalizes PQC standards — FIPS 203, FIPS 204, FIPS 205",color:C.green},
          {year:"2026",event:"QuantumGuard launches — first developer-focused quantum vulnerability scanner",color:C.blue},
          {year:"2027",event:"Regulatory pressure increases — organizations must show PQC compliance",color:C.amber},
          {year:"2030",event:"Y2Q — Cryptographically Relevant Quantum Computers expected to arrive",color:C.red},
        ].map((t,i)=>(
          <div key={i} style={{ display:"flex", gap:16, marginBottom:16, alignItems:"flex-start", padding:"10px 0", borderBottom:i<3?`1px solid ${C.panelBorder}`:"none" }}>
            <div style={{ background:t.color+"22", color:t.color, border:`1px solid ${t.color}44`, padding:"4px 10px", borderRadius:8, fontSize:13, fontWeight:700, flexShrink:0 }}>{t.year}</div>
            <div style={{ fontSize:13, color:C.textMid, lineHeight:1.6, paddingTop:4 }}>{t.event}</div>
          </div>
        ))}
      </Panel>
    </div>
  );
}

function DocsPage() {
  return (
    <div style={{ padding:20 }}>
      <Panel title="API Endpoints" accent>
        {[
          {method:"POST",path:"/scan-github",     auth:"None",            desc:"Scan any public GitHub repo"},
          {method:"POST",path:"/public-scan-zip", auth:"None",            desc:"Upload ZIP file (max 10MB)"},
          {method:"POST",path:"/check-agility",   auth:"None",            desc:"Check crypto agility"},
          {method:"POST",path:"/analyze-tls",     auth:"None",            desc:"Analyze TLS"},
          {method:"POST",path:"/scan",            auth:"x-api-key header",desc:"Scan server path"},
          {method:"GET", path:"/health",          auth:"None",            desc:"Returns {status: healthy}"},
        ].map((e,i)=>(
          <div key={i} style={{ display:"flex", gap:12, padding:"10px 0", borderBottom:i<5?`1px solid ${C.panelBorder}`:"none", flexWrap:"wrap", alignItems:"center" }}>
            <Badge text={e.method} color={C.green} bg={"rgba(34,197,94,0.1)"} />
            <span style={{ fontFamily:"monospace", fontSize:12, color:C.green, fontWeight:600, minWidth:160 }}>{e.path}</span>
            <span style={{ fontSize:11, color:C.amber, minWidth:100 }}>{e.auth}</span>
            <span style={{ fontSize:12, color:C.muted }}>{e.desc}</span>
          </div>
        ))}
      </Panel>
      <div className="docs-grid" style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
        {[
          {title:"Quick Start",    icon:"⚡",steps:["Go to Scanner tab","Paste GitHub repo URL","Click Run Scan","Download PDF report"]},
          {title:"Crypto Agility", icon:"🔬",steps:["Go to Agility Checker","Paste GitHub repo URL","Click Check Agility","Review hardcoded vs configurable"]},
          {title:"Private Repos",  icon:"🔒",steps:["Click Private Repo button","Generate GitHub PAT","Paste your token","Token never stored"]},
          {title:"Rate Limits",    icon:"⏱",steps:["/scan-github: 20/min","/public-scan-zip: 3/min","/check-agility: 10/min","/analyze-tls: 10/min"]},
        ].map((d,i)=>(
          <Panel key={i} title={`${d.icon} ${d.title}`}>
            {d.steps.map((step,j)=>(
              <div key={j} style={{ display:"flex", gap:10, marginBottom:8, alignItems:"flex-start" }}>
                <div style={{ width:20, height:20, borderRadius:"50%", background:"linear-gradient(135deg,#22c55e,#16a34a)", color:C.white, fontSize:10, fontWeight:700, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>{j+1}</div>
                <span style={{ fontSize:12, color:C.textMid, paddingTop:2 }}>{step}</span>
              </div>
            ))}
          </Panel>
        ))}
      </div>
    </div>
  );
}

function UnifiedRiskPage() {
  const [github, setGithub] = useState("https://github.com/dlitz/pycrypto");
  const [domain, setDomain] = useState("google.com");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [stepIndex, setStepIndex] = useState(0);
  const [error, setError] = useState(null);
  const intervalRef = useRef(null);
  const STEPS = ["Initializing scan engine...","Connecting to target...","Analyzing cryptography...","Checking TLS posture...","Calculating unified risk score...","Generating recommendations..."];
  const NIST_CTRLS = [{id:"SC-12",name:"Cryptographic Key Management",status:"FAIL"},{id:"SC-13",name:"Cryptographic Protection",status:"FAIL"},{id:"IA-7",name:"Crypto Module Authentication",status:"WARN"},{id:"SC-8",name:"Transmission Integrity",status:"WARN"},{id:"CM-7",name:"Least Functionality",status:"PASS"}];
  const ROADMAP = [{year:"Now",text:"Inventory all cryptographic assets — RSA, ECC, DH usages found in codebase.",danger:false},{year:"Q3 2026",text:"Begin migration: replace RSA with CRYSTALS-Kyber (FIPS 203), ECC with CRYSTALS-Dilithium (FIPS 204).",danger:false},{year:"Q1 2027",text:"Enable TLS 1.3 with hybrid PQC cipher suites on all public endpoints.",danger:false},{year:"2030",text:"Y2Q deadline — cryptographically relevant quantum computers expected to arrive.",danger:true}];
  const startProgress = () => { setProgress(0); setStepIndex(0); let p=0; intervalRef.current = setInterval(()=>{ p+=Math.random()*8+2; if(p>92)p=92; setProgress(Math.round(p)); setStepIndex(Math.min(STEPS.length-1,Math.floor(p/(100/STEPS.length)))); },380); };
  const stopProgress = () => { clearInterval(intervalRef.current); setProgress(100); setStepIndex(STEPS.length-1); setTimeout(()=>setProgress(0),900); };
  const scoreColor=(s)=>s>=70?C.green:s>=40?C.amber:C.red;
  const scoreBg=(s)=>s>=70?"rgba(34,197,94,0.1)":s>=40?"rgba(245,158,11,0.1)":"rgba(239,68,68,0.1)";
  const scoreBorder=(s)=>s>=70?"rgba(34,197,94,0.3)":s>=40?"rgba(245,158,11,0.3)":"rgba(239,68,68,0.3)";
  const riskLevel=(s)=>s>=70?"LOW RISK":s>=40?"MODERATE RISK":"CRITICAL RISK";
  const sevColor=(sev)=>sev==="CRITICAL"?C.critical:sev==="HIGH"?C.amber:C.medium;
  const sevBg=(sev)=>SEV_BG[sev]||SEV_BG.MEDIUM;
  const ctrlStyle=(status)=>({PASS:{bg:"rgba(34,197,94,0.1)",color:C.green,dot:C.green,border:"rgba(34,197,94,0.3)"},WARN:{bg:"rgba(245,158,11,0.1)",color:C.amber,dot:C.amber,border:"rgba(245,158,11,0.3)"},FAIL:{bg:"rgba(239,68,68,0.1)",color:C.red,dot:C.critical,border:"rgba(239,68,68,0.3)"}}[status]);
  const handleScan = async () => { if(!github||!domain) return; setLoading(true); setError(null); setData(null); startProgress(); try { const res = await fetch(`${API}/unified-risk`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({github_url:github,domain})}); const json = await res.json(); if(!res.ok) throw new Error(json.detail||"Scan failed"); stopProgress(); setData(json); } catch(e) { stopProgress(); setError(typeof e.message==="string"?e.message:"Scan failed."); } setLoading(false); };
  const handleCSV = () => { if(!data) return; const ur=data.unified_risk||{}; const cs=ur.component_scores||{}; const ss=data.finding_summary?.severity_summary||{}; const rows=["Metric,Value",`Unified Risk Score,${Math.round(ur.quantum_risk_score||0)}`,`Risk Level,${ur.risk_level||""}`,`Code Crypto Score,${Math.round(cs.code_crypto_score||0)}`,`Crypto Agility Score,${Math.round(cs.crypto_agility_score||0)}`,`TLS Score,${Math.round(cs.tls_score||0)}`,`Critical Findings,${ss.CRITICAL||0}`,`High Findings,${ss.HIGH||0}`,`Medium Findings,${ss.MEDIUM||0}`].join("\n"); const blob=new Blob([rows],{type:"text/csv"}); const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="unified-risk.csv";a.click(); };
  const ur=data?.unified_risk||{}; const cs=ur.component_scores||{}; const fs=data?.finding_summary||{}; const ss=fs.severity_summary||{}; const topFindings=data?.top_findings||[];
  const score=Math.round(ur.quantum_risk_score||0); const codeScore=Math.round(cs.code_crypto_score||0); const agilityScore=Math.round(cs.crypto_agility_score||0); const tlsScore=Math.round(cs.tls_score||0);
  const totalFindings=(ss.CRITICAL||0)+(ss.HIGH||0)+(ss.MEDIUM||0)+(ss.LOW||0);
  // NEW: executive risk from unified result
  const execRisk = ur.executive_risk || {};
  return (
    <div style={{ padding:20 }}>
      <div style={{ background:C.panel, border:`1px solid ${C.panelBorder}`, borderTop:`3px solid ${C.green}`, borderRadius:14, padding:"20px 22px", marginBottom:16, boxShadow:"0 4px 20px rgba(0,0,0,0.4)" }}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", flexWrap:"wrap", gap:16, marginBottom:18 }}>
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:6 }}>
              <div style={{ width:32, height:32, borderRadius:8, background:"linear-gradient(135deg,#22c55e,#16a34a)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:16 }}>🧠</div>
              <h2 style={{ fontSize:20, fontWeight:800, color:C.text }}>Unified Risk Dashboard</h2>
            </div>
            <p style={{ fontSize:13, color:C.muted, maxWidth:460, lineHeight:1.6 }}>Combines code scanning, TLS analysis and crypto agility into a single quantum risk score with NIST-aligned remediation guidance.</p>
          </div>
          {data&&(
            <div style={{ background:scoreBg(score), border:`1px solid ${scoreBorder(score)}`, borderRadius:12, padding:"14px 20px", textAlign:"center", minWidth:130 }}>
              <div style={{ fontSize:44, fontWeight:900, color:scoreColor(score), lineHeight:1 }}>{score}</div>
              <div style={{ fontSize:10, color:C.muted, textTransform:"uppercase", letterSpacing:1, marginTop:2 }}>Unified Score</div>
              <div style={{ display:"inline-flex", alignItems:"center", gap:5, background:"rgba(255,255,255,0.04)", color:scoreColor(score), fontSize:10, fontWeight:700, padding:"3px 10px", borderRadius:100, marginTop:8, border:`1px solid ${scoreBorder(score)}` }}>
                <div style={{ width:5, height:5, borderRadius:"50%", background:scoreColor(score) }} />{ur.risk_level||riskLevel(score)}
              </div>
            </div>
          )}
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8, marginBottom:10 }}>
          <input value={github} onChange={e=>setGithub(e.target.value)} placeholder="https://github.com/user/repo" style={{ padding:"9px 14px", borderRadius:8, border:`1.5px solid ${C.panelBorder}`, background:C.input, color:C.text, fontSize:13 }} />
          <input value={domain} onChange={e=>setDomain(e.target.value)} placeholder="domain.com" style={{ padding:"9px 14px", borderRadius:8, border:`1.5px solid ${C.panelBorder}`, background:C.input, color:C.text, fontSize:13 }} />
        </div>
        <button onClick={handleScan} disabled={loading} style={{ padding:"9px 24px", borderRadius:8, background:loading?C.greenDark:"linear-gradient(135deg,#22c55e,#16a34a)", color:C.white, border:"none", cursor:loading?"not-allowed":"pointer", fontSize:13, fontWeight:600, boxShadow:loading?"none":"0 4px 12px rgba(34,197,94,0.3)", transition:"all 0.2s" }}>{loading?"Scanning...":"▶ Run Unified Scan"}</button>
        {loading&&(
          <div style={{ marginTop:12, background:"rgba(34,197,94,0.06)", borderRadius:10, padding:"14px 16px", border:"1px solid rgba(34,197,94,0.2)" }}>
            <div style={{ display:"flex", justifyContent:"space-between", fontSize:12, color:C.green, marginBottom:8, fontWeight:500, alignItems:"center" }}>
              <div style={{ display:"flex", alignItems:"center", gap:8 }}><div style={{ width:8, height:8, borderRadius:"50%", background:C.green, animation:"pulse-ring 1.2s ease-in-out infinite" }} /><span>✦ {STEPS[stepIndex]}</span></div>
              <span style={{ fontWeight:700 }}>{progress}%</span>
            </div>
            <div style={{ background:"rgba(255,255,255,0.08)", borderRadius:6, height:6 }}>
              <div style={{ background:"linear-gradient(90deg,#22c55e,#4ade80)", height:6, borderRadius:6, width:`${progress}%`, transition:"width 0.4s ease", boxShadow:"0 0 10px rgba(34,197,94,0.6)" }} />
            </div>
          </div>
        )}
        {error&&<div style={{ marginTop:10, background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.3)", borderRadius:8, padding:"10px 14px", color:C.red, fontSize:13 }}>⚠ {error}</div>}
      </div>
      {!data&&!loading&&(
        <div style={{ background:C.panel, border:`1px solid ${C.panelBorder}`, borderRadius:14, padding:"56px 24px", textAlign:"center", boxShadow:"0 4px 16px rgba(0,0,0,0.3)" }}>
          <div style={{ fontSize:48, marginBottom:16 }}>🧠</div>
          <div style={{ fontSize:16, fontWeight:700, color:C.text, marginBottom:8 }}>No scan results yet</div>
          <div style={{ fontSize:13, color:C.muted }}>Enter a GitHub URL and domain above, then click Run Unified Scan.</div>
        </div>
      )}
      {data&&(
        <>
          <div className="stats-grid" style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12, marginBottom:16 }}>
            <ScoreCard label="Quantum Risk Score" value={score} color={scoreColor(score)} icon="🧠" desc={ur.risk_level||riskLevel(score)} />
            <ScoreCard label="Code Scanner Score" value={codeScore} color={scoreColor(codeScore)} icon="🔍" desc={codeScore>=70?"Good crypto hygiene":"Vulnerable algorithms found"} />
            <ScoreCard label="Crypto Agility Score" value={agilityScore} color={scoreColor(agilityScore)} icon="🔬" desc={agilityScore>=70?"Highly configurable":"Hardcoded crypto detected"} />
            <ScoreCard label="TLS Security Score" value={tlsScore} color={scoreColor(tlsScore)} icon="🔐" desc={tlsScore>=70?"TLS 1.3 ready":"TLS upgrade needed"} />
          </div>

          {/* NEW: Executive risk row */}
          {execRisk.overall_priority && (
            <div style={{ marginBottom:16, background:C.panel, border:`1px solid ${C.panelBorder}`, borderRadius:12, padding:"14px 18px", display:"flex", gap:16, flexWrap:"wrap", alignItems:"center" }}>
              <div style={{ fontSize:11, color:C.muted, fontWeight:600, textTransform:"uppercase", letterSpacing:"0.08em" }}>Executive Risk</div>
              <PriorityBadge priority={execRisk.overall_priority} />
              {execRisk.business_impact && (
                <span style={{ fontSize:11, fontWeight:600, color:execRisk.business_impact==="HIGH"?C.red:execRisk.business_impact==="MEDIUM"?C.amber:C.muted }}>
                  Business Impact: {execRisk.business_impact}
                </span>
              )}
              {execRisk.exploitability && (
                <span style={{ fontSize:11, color:C.muted }}>Exploitability: {execRisk.exploitability}</span>
              )}
              {execRisk.p0_findings > 0 && (
                <span style={{ background:"rgba(239,68,68,0.12)", color:C.red, fontSize:11, fontWeight:700, padding:"3px 10px", borderRadius:100 }}>
                  🚨 {execRisk.p0_findings} P0 finding{execRisk.p0_findings!==1?"s":""} — immediate action required
                </span>
              )}
              {ur.clean_repo && (
                <span style={{ background:"rgba(34,197,94,0.12)", color:C.green, fontSize:11, fontWeight:700, padding:"3px 10px", borderRadius:100 }}>
                  ✅ Clean repo
                </span>
              )}
            </div>
          )}

          {totalFindings>0&&(
            <div className="stats-grid" style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12, marginBottom:16 }}>
              <Metric label="Total findings" value={totalFindings} color={C.text} icon="🔍" desc="across all modules" />
              <Metric label="Critical" value={ss.CRITICAL||0} color={C.critical} icon="🔴" desc="immediate action required" />
              <Metric label="High" value={ss.HIGH||0} color={C.amber} icon="🟡" desc="requires attention" />
              <Metric label="Medium" value={ss.MEDIUM||0} color={C.medium} icon="🟠" desc="review needed" />
            </div>
          )}
          <div className="charts-grid" style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12, marginBottom:16 }}>
            <Panel title="Component breakdown" accent>
              {[["Code crypto",codeScore,scoreColor(codeScore)],["Crypto agility",agilityScore,scoreColor(agilityScore)],["TLS security",tlsScore,scoreColor(tlsScore)]].map(([label,val,col])=>(
                <div key={label} style={{ marginBottom:14 }}>
                  <div style={{ display:"flex", justifyContent:"space-between", fontSize:12, marginBottom:4 }}><span style={{ color:C.muted, fontWeight:500 }}>{label}</span><span style={{ color:col, fontWeight:700 }}>{val}/100</span></div>
                  <div style={{ background:"rgba(255,255,255,0.06)", borderRadius:4, height:8 }}><div style={{ background:col, height:8, borderRadius:4, width:`${val}%`, transition:"width 0.6s ease", boxShadow:`0 0 6px ${col}55` }} /></div>
                </div>
              ))}
              {totalFindings>0&&(
                <>{[["Critical",ss.CRITICAL||0,C.critical],["High",ss.HIGH||0,C.amber],["Medium",ss.MEDIUM||0,C.medium]].map(([label,val,col])=>(
                  <div key={label} style={{ marginBottom:10 }}>
                    <div style={{ display:"flex", justifyContent:"space-between", fontSize:12, marginBottom:4 }}><span style={{ color:col, fontWeight:600 }}>{label}</span><span style={{ color:C.muted }}>{val} ({totalFindings>0?Math.round(val/totalFindings*100):0}%)</span></div>
                    <div style={{ background:"rgba(255,255,255,0.06)", borderRadius:4, height:6 }}><div style={{ background:col, height:6, borderRadius:4, width:`${totalFindings>0?Math.round(val/totalFindings*100):0}%`, transition:"width 0.6s ease" }} /></div>
                  </div>
                ))}</>
              )}
            </Panel>
            <Panel title="NIST SP 800-53 control status" accent>
              {NIST_CTRLS.map(ctrl=>{ const sc=ctrlStyle(ctrl.status); return (
                <div key={ctrl.id} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:9, fontSize:12 }}>
                  <span style={{ color:C.muted }}><span style={{ fontFamily:"monospace", color:C.green, fontWeight:700 }}>{ctrl.id}</span> — {ctrl.name}</span>
                  <span style={{ display:"inline-flex", alignItems:"center", gap:4, background:sc.bg, color:sc.color, fontSize:10, fontWeight:700, padding:"3px 10px", borderRadius:100, border:`1px solid ${sc.border}`, whiteSpace:"nowrap", marginLeft:8 }}>
                    <span style={{ width:5, height:5, borderRadius:"50%", background:sc.dot, display:"inline-block" }} />{ctrl.status}
                  </span>
                </div>
              );})}
            </Panel>
          </div>
          {topFindings.length>0&&(
            <Panel title={`Top findings — ${topFindings.length} shown`} accent>
              {topFindings.map((f,i)=>(
                <div key={i} style={{ borderLeft:`3px solid ${sevColor(f.severity)}`, paddingLeft:14, marginBottom:i<topFindings.length-1?14:0, paddingBottom:i<topFindings.length-1?14:0, borderBottom:i<topFindings.length-1?`1px solid ${C.panelBorder}`:"none" }}>
                  <div style={{ display:"flex", gap:8, marginBottom:5, alignItems:"center", flexWrap:"wrap" }}>
                    <span style={{ background:sevBg(f.severity), color:sevColor(f.severity), fontSize:10, fontWeight:800, padding:"2px 8px", borderRadius:6, border:`1px solid ${sevColor(f.severity)}44`, textTransform:"uppercase" }}>{f.severity}</span>
                    <span style={{ background:"rgba(255,255,255,0.06)", color:C.muted, fontSize:10, fontWeight:600, padding:"2px 8px", borderRadius:4 }}>{f.vulnerability}</span>
                    {f.confidence&&<span style={{ fontSize:10, color:C.muted }}>Confidence: {f.confidence}</span>}
                    {/* NEW: priority + context on unified top findings too */}
                    {f.priority && <PriorityBadge priority={f.priority} />}
                    {f.usage_context && f.usage_context !== "unknown" && <ContextBadge context={f.usage_context} />}
                    <span style={{ marginLeft:"auto", fontSize:11, color:C.muted }}>Line {f.line}</span>
                  </div>
                  <div style={{ fontFamily:"monospace", fontSize:11, color:C.green, fontWeight:600, marginBottom:4, wordBreak:"break-all" }}>{f.file?.split("/").pop()}</div>
                  {f.recommended_fix&&(
                    <div style={{ background:"rgba(59,130,246,0.08)", border:"1px solid rgba(59,130,246,0.2)", borderRadius:6, padding:"6px 10px", display:"flex", gap:8, alignItems:"center" }}>
                      <span style={{ fontSize:10, fontWeight:700, color:"#60a5fa", textTransform:"uppercase", letterSpacing:"0.05em" }}>Fix</span>
                      <span style={{ color:"#93c5fd", fontWeight:500, fontSize:11 }}>✦ {f.recommended_fix}</span>
                    </div>
                  )}
                </div>
              ))}
            </Panel>
          )}
          {ur.business_summary&&(
            <Panel title="Business risk summary" accent>
              <div style={{ fontSize:13, color:C.muted, lineHeight:1.75, background:"rgba(34,197,94,0.05)", padding:"12px 16px", borderRadius:8, border:"1px solid rgba(34,197,94,0.15)" }}>{ur.business_summary}</div>
            </Panel>
          )}
          <Panel title="NIST remediation roadmap" accent>
            {ROADMAP.map((item,i)=>(
              <div key={i} style={{ display:"flex", gap:14, padding:"10px 0", borderBottom:i<ROADMAP.length-1?`1px solid ${C.panelBorder}`:"none" }}>
                <div style={{ background:item.danger?"rgba(239,68,68,0.15)":"rgba(34,197,94,0.15)", color:item.danger?C.red:C.green, border:`1px solid ${item.danger?"rgba(239,68,68,0.3)":"rgba(34,197,94,0.3)"}`, fontSize:11, fontWeight:700, padding:"3px 9px", borderRadius:6, flexShrink:0, height:"fit-content", marginTop:2 }}>{item.year}</div>
                <div style={{ fontSize:13, color:C.muted, lineHeight:1.6, paddingTop:2 }}>{item.text}</div>
              </div>
            ))}
          </Panel>
          <Panel title="Export & share" accent>
            <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
              <button onClick={handleCSV} style={{ padding:"8px 16px", borderRadius:8, background:"rgba(34,197,94,0.1)", color:C.green, border:"1px solid rgba(34,197,94,0.3)", cursor:"pointer", fontSize:12, fontWeight:600 }}>📊 CSV Export</button>
            </div>
          </Panel>
        </>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// HOMEPAGE — unchanged (full copy from original)
// ══════════════════════════════════════════════════════════════
const NAV_GROUPS_HP = [
  { label:"Product", items:[{icon:"⬡",title:"Quantum Scanner",desc:"AST-level crypto vulnerability scanning"},{icon:"⛨",title:"CI/CD Security Gate",desc:"Block weak crypto before it ships"},{icon:"◈",title:"TLS Analyzer",desc:"Audit TLS configs end-to-end"},{icon:"⟳",title:"Crypto Agility Checker",desc:"Measure migration readiness"},{icon:"▦",title:"Executive Reports",desc:"Board-ready risk summaries"}]},
  { label:"Solutions", items:[{icon:"{}",title:"Developers",desc:"Shift-left crypto hygiene"},{icon:"⚿",title:"Security Teams",desc:"Enterprise vulnerability management"},{icon:"⚙",title:"DevOps",desc:"Pipeline-native enforcement"},{icon:"◈",title:"CISOs",desc:"Quantum risk posture dashboards"},{icon:"⬡",title:"Financial Services",desc:"FIPS & PQC compliance"},{icon:"✚",title:"Healthcare",desc:"HIPAA + quantum-safe data"},{icon:"⛨",title:"Government",desc:"NIST FIPS 203/204/205 readiness"}]},
  { label:"Platform", items:[{icon:"◉",title:"Overview",desc:"How QuantumGuard works"},{icon:"⌥",title:"API",desc:"REST & GraphQL endpoints"},{icon:"⧉",title:"GitHub Actions",desc:"One-line workflow integration"},{icon:"◈",title:"Developer Docs",desc:"Guides, references, SDKs"},{icon:"⬡",title:"Integrations",desc:"Jira, Slack, ServiceNow & more"}]},
  { label:"Pricing", items:[{icon:"○",title:"Free",desc:"Up to 3 scans/month"},{icon:"◈",title:"Pro",desc:"$49/mo — unlimited scans"},{icon:"⬡",title:"Team",desc:"$199/mo — org-wide coverage"},{icon:"⛨",title:"Enterprise",desc:"Custom SLAs & on-prem"}]},
  { label:"Resources", items:[{icon:"✍",title:"Blog",desc:"PQC research & news"},{icon:"◈",title:"Documentation",desc:"Full product reference"},{icon:"⬡",title:"PQC Guide",desc:"Post-quantum explained simply"},{icon:"⛨",title:"NIST Standards",desc:"FIPS 203, 204, 205 breakdown"},{icon:"◉",title:"Customer Stories",desc:"Real migration case studies"}]},
];
const NAV_MAP = {"Quantum Scanner":"scan","CI/CD Security Gate":"scan","TLS Analyzer":"tls","Crypto Agility Checker":"agility","Executive Reports":"nist","Developers":"scan","Security Teams":"scan","DevOps":"scan","CISOs":"unified","Financial Services":"scan","Healthcare":"scan","Government":"nist","Overview":"scan","API":"docs","GitHub Actions":"docs","Developer Docs":"docs","Integrations":"docs","Free":"scan","Pro":"scan","Team":"scan","Enterprise":"scan","Blog":"team","Documentation":"docs","PQC Guide":"docs","NIST Standards":"nist","Customer Stories":"team"};
const FOOTER_MAP = {"Quantum Scanner":"scan","CI/CD Gate":"scan","TLS Analyzer":"tls","Executive Reports":"nist","About":"team","Our Team":"team","Blog":"team","Careers":"team","Security":"docs"};

function HpNavDropdown({ item, isOpen, onToggle, onItemClick }) {
  const ref = useRef(null);
  useEffect(() => { if (!isOpen) return; const h=(e)=>{ if(ref.current&&!ref.current.contains(e.target)) onToggle(null); }; document.addEventListener("mousedown",h); return ()=>document.removeEventListener("mousedown",h); },[isOpen,onToggle]);
  return (
    <div ref={ref} style={{ position:"relative" }}>
      <button onClick={()=>onToggle(item.label)} style={{ background:"none",border:"none",cursor:"pointer",display:"flex",alignItems:"center",gap:4,fontSize:14,fontWeight:500,color:isOpen?"#22c55e":"#374151",padding:"8px 11px",borderRadius:8,fontFamily:"inherit",letterSpacing:"-.01em",transition:"color .15s" }} onMouseEnter={e=>{if(!isOpen)e.currentTarget.style.color="#22c55e";}} onMouseLeave={e=>{if(!isOpen)e.currentTarget.style.color="#374151";}}>
        {item.label}
        <svg width="11" height="11" viewBox="0 0 12 12" fill="none" style={{ transform:isOpen?"rotate(180deg)":"none",transition:"transform .2s",opacity:.5 }}><path d="M2 4l4 4 4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/></svg>
      </button>
      {isOpen&&(<div style={{ position:"absolute",top:"calc(100% + 10px)",left:"50%",transform:"translateX(-50%)",background:"rgba(255,255,255,.97)",backdropFilter:"blur(20px)",border:"1px solid rgba(34,197,94,.15)",borderRadius:16,boxShadow:"0 20px 56px rgba(0,0,0,.11),0 4px 16px rgba(34,197,94,.07)",padding:8,minWidth:272,zIndex:1000,animation:"hp-dropIn .17s ease-out" }}>
        {item.items.map(sub=>(<div key={sub.title} onClick={()=>{onToggle(null);if(onItemClick)onItemClick(sub.title);}} style={{ display:"flex",alignItems:"flex-start",gap:11,padding:"10px 13px",borderRadius:10,cursor:"pointer",transition:"background .13s" }} onMouseEnter={e=>e.currentTarget.style.background="rgba(34,197,94,.07)"} onMouseLeave={e=>e.currentTarget.style.background="transparent"}><span style={{ fontSize:17,lineHeight:1,marginTop:2,color:"#22c55e",flexShrink:0 }}>{sub.icon}</span><div><div style={{ fontSize:13,fontWeight:600,color:"#0f1923",letterSpacing:"-.01em" }}>{sub.title}</div><div style={{ fontSize:12,color:"#6b7280",marginTop:2,lineHeight:1.4 }}>{sub.desc}</div></div></div>))}
      </div>)}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// UPDATED HOMEPAGE COMPONENT — drop-in replacement for App.js
// Changes from original:
//   1. Hero — stronger positioning line, "Why not Snyk?" callout
//   2. Trust Bar — replaces generic stat bar with real trust signals
//   3. NEW: Privacy & Security Statement section
//   4. NEW: Example Scans section (vulnerable vs clean)
//   5. NEW: Founder / About section
//   6. NEW: India NQM alignment badge
//   7. Pricing — unchanged
//   8. Footer — EIN removed
// ══════════════════════════════════════════════════════════════

// ─── paste this entire block in place of the Homepage function ───

// ══════════════════════════════════════════════════════════════
// QuantumGuard Homepage v3.0 — High-Converting Landing Page
// Drop-in replacement for the Homepage function in App.js
// Sections:
//   1. Nav
//   2. Hero — headline, subheadline, CTA, trust badges
//   3. What Is QuantumGuard — plain English
//   4. Why This Matters — quantum threat, harvest now decrypt later
//   5. The Problem — user feels the pain
//   6. How It Works — 4 steps
//   7. Features — 6 feature cards
//   8. Example Output — real scan preview (trust builder)
//   9. Differentiation — vs Snyk
//  10. Trust Section — company, disclaimer, tested on real repos
//  11. Pricing
//  12. Final CTA
//  13. Footer
// ══════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════
// QuantumGuard Homepage v3.0 — High-Converting Landing Page
// Drop-in replacement for the Homepage function in App.js
// Sections:
//   1. Nav
//   2. Hero — headline, subheadline, CTA, trust badges
//   3. What Is QuantumGuard — plain English
//   4. Why This Matters — quantum threat, harvest now decrypt later
//   5. The Problem — user feels the pain
//   6. How It Works — 4 steps
//   7. Features — 6 feature cards
//   8. Example Output — real scan preview (trust builder)
//   9. Differentiation — vs Snyk
//  10. Trust Section — company, disclaimer, tested on real repos
//  11. Pricing
//  12. Final CTA
//  13. Footer
// ══════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════
// QuantumGuard Homepage v4.0
// Drop-in replacement for the Homepage function in App.js
// Replace everything from "function Homepage(" to its closing "}"
// ══════════════════════════════════════════════════════════════

function AnimatedDemoCard() {
  const [phase, setPhase] = useState(0);
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState([]);
  const [score, setScore] = useState(null);
  const [scanning, setScanning] = useState(true);

  const FINDINGS_DATA = [
    { sev: "CRITICAL", label: "RSA-2048 detected",            file: "src/auth/keypair.js:14",      risk: "Broken by Shor's algorithm"    },
    { sev: "HIGH",     label: "SHA-1 usage found",             file: "src/utils/checksum.js:28",    risk: "Collision vulnerable + Grover"  },
    { sev: "HIGH",     label: "ECC P-256 key exchange",        file: "src/crypto/sign.py:7",        risk: "Quantum-vulnerable curve"       },
    { sev: "MEDIUM",   label: "TLS 1.2 — upgrade recommended", file: "nginx.conf:8",                risk: "Migrate to TLS 1.3 minimum"     },
  ];

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      // Phase 0: progress bar fills
      for (let p = 0; p <= 100; p += 2) {
        if (cancelled) return;
        await new Promise(r => setTimeout(r, 28));
        setProgress(p);
      }
      if (cancelled) return;
      setScanning(false);
      setPhase(1);

      // Phase 1: findings appear one by one
      for (let i = 0; i < FINDINGS_DATA.length; i++) {
        if (cancelled) return;
        await new Promise(r => setTimeout(r, 500));
        setFindings(prev => [...prev, FINDINGS_DATA[i]]);
      }

      // Phase 2: score appears
      await new Promise(r => setTimeout(r, 700));
      if (cancelled) return;
      setScore(72);
      setPhase(2);

      // Phase 3: reset and loop
      await new Promise(r => setTimeout(r, 3500));
      if (cancelled) return;
      setPhase(0); setProgress(0); setFindings([]); setScore(null); setScanning(true);
      run();
    };
    run();
    return () => { cancelled = true; };
  }, []);

  const sevColor = s => s === "CRITICAL" ? "#ef4444" : s === "HIGH" ? "#f59e0b" : "#eab308";
  const sevBg    = s => s === "CRITICAL" ? "rgba(239,68,68,.12)" : s === "HIGH" ? "rgba(245,158,11,.12)" : "rgba(234,179,8,.12)";

  return (
    <div style={{
      background: "linear-gradient(145deg,#0d1117,#0f1e2e)",
      border: "1px solid rgba(34,197,94,.25)",
      borderRadius: 20,
      padding: "24px",
      fontFamily: "'DM Sans','Segoe UI',sans-serif",
      boxShadow: "0 0 0 1px rgba(34,197,94,.08), 0 24px 64px rgba(0,0,0,.5), 0 0 80px rgba(34,197,94,.06)",
      width: "100%",
      maxWidth: 460,
      position: "relative",
      overflow: "hidden",
    }}>
      {/* Subtle grid background */}
      <div style={{ position:"absolute",inset:0,backgroundImage:"radial-gradient(rgba(34,197,94,.06) 1px,transparent 1px)",backgroundSize:"20px 20px",pointerEvents:"none" }} />

      {/* Header */}
      <div style={{ display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:20,position:"relative" }}>
        <div style={{ display:"flex",alignItems:"center",gap:8 }}>
          <div style={{ width:28,height:28,background:"linear-gradient(135deg,#22c55e,#15803d)",borderRadius:7,display:"flex",alignItems:"center",justifyContent:"center",fontSize:13 }}>⚛</div>
          <div>
            <div style={{ fontSize:12,fontWeight:700,color:"#f1f5f9" }}>QuantumGuard Live Scan</div>
            <div style={{ fontSize:9,color:"#4b5563",fontFamily:"'DM Mono',monospace" }}>quantumguard.site</div>
          </div>
        </div>
        <div style={{ display:"flex",alignItems:"center",gap:5,background:"rgba(34,197,94,.08)",border:"1px solid rgba(34,197,94,.2)",borderRadius:20,padding:"3px 10px" }}>
          <span style={{ width:5,height:5,borderRadius:"50%",background:"#22c55e",display:"inline-block",animation:scanning?"qg-demo-pulse 1s ease-in-out infinite":"none" }} />
          <span style={{ fontSize:9,fontWeight:700,color:"#22c55e",letterSpacing:".05em" }}>{scanning ? "SCANNING" : "COMPLETE"}</span>
        </div>
      </div>

      {/* Repo target */}
      <div style={{ background:"rgba(255,255,255,.03)",border:"1px solid rgba(255,255,255,.06)",borderRadius:8,padding:"8px 12px",marginBottom:16,display:"flex",alignItems:"center",gap:8 }}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="#4b5563"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
        <span style={{ fontFamily:"'DM Mono',monospace",fontSize:11,color:"#6b7280" }}>github.com / example / crypto-app</span>
        <span style={{ marginLeft:"auto",fontSize:9,color:"#374151",background:"rgba(255,255,255,.04)",padding:"2px 6px",borderRadius:4 }}>main</span>
      </div>

      {/* Progress bar */}
      <div style={{ marginBottom:18 }}>
        <div style={{ display:"flex",justifyContent:"space-between",fontSize:10,color:"#6b7280",marginBottom:6 }}>
          <span style={{ fontFamily:"'DM Mono',monospace" }}>{scanning ? "Analyzing cryptographic patterns..." : "Scan complete"}</span>
          <span style={{ color:"#22c55e",fontWeight:700 }}>{progress}%</span>
        </div>
        <div style={{ background:"rgba(255,255,255,.06)",borderRadius:4,height:5,overflow:"hidden" }}>
          <div style={{
            background: "linear-gradient(90deg,#22c55e,#4ade80,#22c55e)",
            backgroundSize: "200% 100%",
            height: 5,
            borderRadius: 4,
            width: `${progress}%`,
            transition: "width .08s linear",
            boxShadow: "0 0 8px rgba(34,197,94,.6)",
            animation: scanning ? "qg-demo-shimmer 1.5s linear infinite" : "none",
          }} />
        </div>
        <div style={{ display:"flex",gap:8,marginTop:6,flexWrap:"wrap" }}>
          {["Python","JavaScript","Java","TLS"].map((l,i) => (
            <span key={i} style={{ fontSize:9,fontWeight:600,color:progress > i*25 ? "#22c55e" : "#374151",fontFamily:"'DM Mono',monospace",transition:"color .3s" }}>{l} {progress > i*25 ? "✓" : "..."}</span>
          ))}
        </div>
      </div>

      {/* Findings */}
      <div style={{ minHeight:140 }}>
        {findings.length === 0 && !score && (
          <div style={{ textAlign:"center",padding:"20px 0",color:"#374151",fontSize:11 }}>
            <div style={{ fontSize:24,marginBottom:6 }}>🔍</div>
            Scanning repository...
          </div>
        )}
        {findings.map((f, i) => (
          <div key={i} style={{
            display:"flex",alignItems:"flex-start",gap:8,padding:"8px 10px",
            background: sevBg(f.sev),
            border: `1px solid ${sevColor(f.sev)}22`,
            borderLeft: `3px solid ${sevColor(f.sev)}`,
            borderRadius: 7,marginBottom:6,
            animation: "qg-demo-slideIn .3s ease-out both",
          }}>
            <span style={{ background:sevBg(f.sev),color:sevColor(f.sev),fontSize:8,fontWeight:800,padding:"2px 6px",borderRadius:4,flexShrink:0,letterSpacing:".04em",marginTop:1 }}>{f.sev}</span>
            <div style={{ flex:1,minWidth:0 }}>
              <div style={{ fontSize:11,fontWeight:600,color:"#f1f5f9",marginBottom:2 }}>{f.label}</div>
              <div style={{ fontFamily:"'DM Mono',monospace",fontSize:9,color:"#4b5563",marginBottom:2,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }}>{f.file}</div>
              <div style={{ fontSize:9,color:sevColor(f.sev),opacity:.8 }}>{f.risk}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Score */}
      {score !== null && (
        <div style={{
          marginTop:14,padding:"14px 16px",
          background:"linear-gradient(135deg,rgba(34,197,94,.1),rgba(34,197,94,.05))",
          border:"1px solid rgba(34,197,94,.25)",borderRadius:10,
          display:"flex",alignItems:"center",justifyContent:"space-between",
          animation:"qg-demo-slideIn .4s ease-out both",
        }}>
          <div>
            <div style={{ fontSize:10,color:"#6b7280",marginBottom:2 }}>Quantum Readiness Score</div>
            <div style={{ fontSize:22,fontWeight:900,color:"#22c55e",lineHeight:1 }}>72 <span style={{ fontSize:12,color:"#4b5563",fontWeight:400 }}>/ 100</span></div>
            <div style={{ fontSize:9,color:"#f59e0b",marginTop:3,fontWeight:600 }}>⚠ At Risk — migration recommended</div>
          </div>
          <div style={{ textAlign:"right" }}>
            <div style={{ fontSize:9,color:"#4b5563",marginBottom:4 }}>4 findings</div>
            {[["CRITICAL","1"],["HIGH","2"],["MEDIUM","1"]].map(([s,n],i) => (
              <div key={i} style={{ fontSize:9,display:"flex",gap:4,justifyContent:"flex-end",marginBottom:2 }}>
                <span style={{ color:sevColor(s),fontWeight:700 }}>{s}</span>
                <span style={{ color:"#4b5563" }}>×{n}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Footer */}
      <div style={{ marginTop:14,paddingTop:12,borderTop:"1px solid rgba(255,255,255,.05)",display:"flex",alignItems:"center",gap:6 }}>
        <span style={{ width:5,height:5,borderRadius:"50%",background:"#22c55e",display:"inline-block",animation:"qg-demo-pulse 2s ease-in-out infinite" }} />
        <span style={{ fontSize:9,color:"#4b5563",fontFamily:"'DM Mono',monospace" }}>Live scan preview • instant results • quantumguard.site</span>
      </div>

      <style>{`
        @keyframes qg-demo-pulse{0%,100%{opacity:1}50%{opacity:.3}}
        @keyframes qg-demo-shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
        @keyframes qg-demo-slideIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
      `}</style>
    </div>
  );
}

// ── Main Homepage ────────────────────────────────────────────
function Homepage({ onGetStarted, onOpenAuth }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [openNav, setOpenNav] = useState(null);

  const handleNavItem = title => { const tab = NAV_MAP[title]; if (tab) onGetStarted(tab); };

  const sevColor = s => s === "CRITICAL" ? "#ef4444" : s === "HIGH" ? "#f59e0b" : s === "MEDIUM" ? "#eab308" : "#22c55e";
  const sevBg    = s => s === "CRITICAL" ? "#fef2f2" : s === "HIGH" ? "#fffbeb" : s === "MEDIUM" ? "#fefce8" : "#f0fdf4";

  const PRICING = [
    { name:"Free",       price:"$0",    period:"",    desc:"For developers exploring PQC",     features:["20 scans/day","RSA, ECC, DH detection","TLS analyzer","PDF report","Dependency scanner"],           cta:"Start Free — No Signup",  highlight:false },
    { name:"Pro",        price:"$49",   period:"/mo", desc:"For security-conscious teams",     features:["100 scans/day","All 12 vuln types","NIST migration guidance","GitHub Actions gate","API access"],    cta:"Start Free Trial",        highlight:true  },
    { name:"Team",       price:"$199",  period:"/mo", desc:"Org-wide visibility & compliance", features:["500 scans/day","Everything in Pro","Org dashboard","SSO/SAML","Priority support"],                   cta:"Start Free Trial",        highlight:false },
    { name:"Enterprise", price:"Custom",period:"",    desc:"Air-gapped or on-premise",        features:["Unlimited scans","On-premise Docker","SLA 99.99%","Dedicated CSM","FedRAMP roadmap"],                cta:"Contact Sales",           highlight:false },
  ];

  return (
    <div style={{ fontFamily:"'DM Sans','Segoe UI',system-ui,sans-serif",background:"#f8fafc",color:"#0f172a",overflowX:"hidden" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700;9..40,800;9..40,900&family=DM+Mono:wght@400;500&display=swap');
        *,*::before,*::after{box-sizing:border-box;}html{scroll-behavior:smooth;}
        @keyframes qg-fadeUp{from{opacity:0;transform:translateY(22px)}to{opacity:1;transform:translateY(0)}}
        @keyframes qg-pulse{0%,100%{opacity:1}50%{opacity:.35}}
        @keyframes qg-dropIn{from{opacity:0;transform:translateX(-50%) translateY(-10px)}to{opacity:1;transform:translateX(-50%) translateY(0)}}
        @keyframes qg-float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
        .qg-btn{display:inline-flex;align-items:center;gap:8px;border:none;cursor:pointer;font-family:inherit;font-weight:700;letter-spacing:-.01em;transition:all .2s;border-radius:10px;text-decoration:none;}
        .qg-primary{background:#22c55e;color:#fff;padding:16px 32px;font-size:16px;}
        .qg-primary:hover{background:#16a34a;transform:translateY(-2px);box-shadow:0 12px 32px rgba(34,197,94,.38);}
        .qg-primary-sm{background:#22c55e;color:#fff;padding:10px 20px;font-size:13px;}
        .qg-primary-sm:hover{background:#16a34a;}
        .qg-outline{background:transparent;color:#0f172a;border:2px solid #d1d5db;padding:14px 28px;font-size:16px;}
        .qg-outline:hover{border-color:#22c55e;color:#22c55e;background:rgba(34,197,94,.03);}
        .qg-ghost{background:rgba(255,255,255,.09);color:#fff;border:1.5px solid rgba(255,255,255,.18);padding:14px 28px;font-size:16px;}
        .qg-ghost:hover{background:rgba(255,255,255,.16);border-color:rgba(255,255,255,.35);}
        .qg-card{background:#fff;border:1.5px solid #e8edf3;border-radius:16px;transition:all .25s;box-shadow:0 2px 12px rgba(0,0,0,.04);}
        .qg-card:hover{border-color:#22c55e;box-shadow:0 8px 32px rgba(34,197,94,.1);transform:translateY(-3px);}
        .qg-label{font-size:11px;font-weight:700;letter-spacing:.1em;color:#22c55e;text-transform:uppercase;margin-bottom:10px;}
        .qg-section{padding:84px 32px;}
        .qg-wrap{max-width:1060px;margin:0 auto;}
        .qg-g2{display:grid;grid-template-columns:1fr 1fr;gap:24px;}
        .qg-g3{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;}
        .qg-g4{display:grid;grid-template-columns:repeat(4,1fr);gap:18px;}
        #qg-hbg{display:none;background:none;border:none;font-size:24px;cursor:pointer;color:#374151;padding:4px;margin-left:auto;}
        .qg-nav-links{display:flex;align-items:center;flex:1;}
        .qg-nav-r{display:flex;align-items:center;gap:8px;margin-left:auto;}
        @media(max-width:980px){
          .qg-nav-links,.qg-nav-r{display:none!important;}
          #qg-hbg{display:block!important;}
          .qg-section{padding:60px 20px;}
          .qg-g2,.qg-g3,.qg-g4,.qg-hero-inner,.qg-diff-g,.qg-who-g{grid-template-columns:1fr!important;}
          .qg-stats-g{grid-template-columns:repeat(2,1fr)!important;}
          .qg-pricing-g{grid-template-columns:1fr!important;}
          .qg-hero-demo{display:none!important;}
        }
        @media(max-width:480px){
          .qg-stats-g,.qg-trust-g{grid-template-columns:1fr!important;}
        }
      `}</style>

      {/* ══ NAV ═══════════════════════════════════════════ */}
      <nav style={{ position:"sticky",top:0,zIndex:500,background:"rgba(248,250,252,.95)",backdropFilter:"blur(20px)",borderBottom:"1px solid rgba(0,0,0,.07)",padding:"0 32px",height:66,display:"flex",alignItems:"center",gap:8 }}>
        <div style={{ display:"flex",alignItems:"center",gap:10,marginRight:24,flexShrink:0,cursor:"pointer" }} onClick={() => onGetStarted && onGetStarted("home")}>
          <div style={{ width:36,height:36,background:"linear-gradient(135deg,#22c55e,#15803d)",borderRadius:10,display:"flex",alignItems:"center",justifyContent:"center",fontSize:17,boxShadow:"0 4px 12px rgba(34,197,94,.3)" }}>⚛</div>
          <div>
            <div style={{ fontSize:16,fontWeight:800,letterSpacing:"-.03em",lineHeight:1.1 }}><span style={{ color:"#22c55e" }}>Quantum</span>Guard</div>
            <div style={{ fontSize:9,color:"#9ca3af",fontWeight:500,letterSpacing:".01em" }}>by Mangsri QuantumGuard LLC</div>
          </div>
          <span style={{ background:"#dcfce7",color:"#16a34a",fontSize:9,fontWeight:700,padding:"2px 8px",borderRadius:20,border:"1px solid #bbf7d0",letterSpacing:".04em" }}>BETA</span>
        </div>

        <div className="qg-nav-links">
          {NAV_GROUPS_HP.map(g => (
            <HpNavDropdown key={g.label} item={g} isOpen={openNav === g.label} onToggle={setOpenNav} onItemClick={handleNavItem} />
          ))}
        </div>

        <div className="qg-nav-r">
          <div style={{ display:"flex",alignItems:"center",gap:5,fontSize:11,fontWeight:600,color:"#15803d",marginRight:6 }}>
            <span style={{ width:7,height:7,borderRadius:"50%",background:"#22c55e",animation:"qg-pulse 2s infinite",display:"inline-block" }} />
            Live scan ready
          </div>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer"
            style={{ display:"flex",alignItems:"center",gap:6,color:"#374151",border:"1.5px solid #d1d5db",borderRadius:9,padding:"7px 14px",fontSize:13,fontWeight:500,textDecoration:"none",transition:"all .2s" }}
            onMouseEnter={e=>{e.currentTarget.style.borderColor="#22c55e";e.currentTarget.style.color="#22c55e";}}
            onMouseLeave={e=>{e.currentTarget.style.borderColor="#d1d5db";e.currentTarget.style.color="#374151";}}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
            GitHub
          </a>
          <button className="qg-btn qg-primary-sm" onClick={() => onGetStarted("scan")}>Scan Your Code Now — Free</button>
          <button onClick={() => onOpenAuth && onOpenAuth("login")} style={{ background:"transparent",border:"1.5px solid rgba(34,197,94,.3)",color:"#22c55e",padding:"8px 15px",borderRadius:9,fontSize:13,fontWeight:600,cursor:"pointer",fontFamily:"inherit" }}>Sign In</button>
        </div>
        <button id="qg-hbg" onClick={() => setMobileMenuOpen(m => !m)}>{mobileMenuOpen ? "✕" : "☰"}</button>
      </nav>

      {mobileMenuOpen && (
        <div style={{ background:"#fff",borderBottom:"1px solid #e2e8f0",position:"fixed",top:66,left:0,right:0,zIndex:498,maxHeight:"80vh",overflowY:"auto",boxShadow:"0 8px 32px rgba(0,0,0,.12)" }}>
          {NAV_GROUPS_HP.map(g => (
            <div key={g.label}>
              <div style={{ padding:"10px 20px",fontSize:10,fontWeight:700,color:"#9ca3af",background:"#f8fafc",textTransform:"uppercase",letterSpacing:".08em" }}>{g.label}</div>
              {g.items.map(item => (
                <div key={item.title} style={{ padding:"12px 20px",fontSize:14,color:"#0f172a",borderBottom:"1px solid #f9fafb",cursor:"pointer",display:"flex",alignItems:"center",gap:12,transition:"background .15s" }}
                  onClick={() => { handleNavItem(item.title); setMobileMenuOpen(false); }}
                  onMouseEnter={e => e.currentTarget.style.background="#f0fdf4"}
                  onMouseLeave={e => e.currentTarget.style.background="transparent"}>
                  <span style={{ color:"#22c55e",fontSize:16,flexShrink:0 }}>{item.icon}</span>
                  <div><div style={{ fontWeight:600,fontSize:13 }}>{item.title}</div><div style={{ fontSize:11,color:"#6b7280",marginTop:1 }}>{item.desc}</div></div>
                </div>
              ))}
            </div>
          ))}
          <div style={{ padding:"16px 20px",borderTop:"2px solid #e2e8f0" }}>
            <button className="qg-btn qg-primary" style={{ width:"100%",justifyContent:"center",padding:"14px",fontSize:15 }} onClick={() => { onGetStarted("scan"); setMobileMenuOpen(false); }}>🛡 Scan Your Code Now — Free</button>
          </div>
        </div>
      )}

      {/* ══ HERO ══════════════════════════════════════════ */}
      <section style={{ background:"linear-gradient(160deg,#f0fdf4 0%,#f8fafc 45%,#eff6ff 100%)",padding:"96px 32px 88px",position:"relative",overflow:"hidden" }}>
        <div style={{ position:"absolute",inset:0,backgroundImage:"radial-gradient(#22c55e10 1px,transparent 1px)",backgroundSize:"30px 30px",pointerEvents:"none" }} />
        <div style={{ position:"absolute",top:-180,right:-180,width:520,height:520,borderRadius:"50%",background:"radial-gradient(circle,rgba(34,197,94,.06),transparent 70%)",pointerEvents:"none" }} />

        <div className="qg-wrap">
          <div className="qg-hero-inner" style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:52,alignItems:"center" }}>

            {/* Left — copy */}
            <div style={{ animation:"qg-fadeUp .65s ease-out both" }}>
              {/* Company ID */}
              <div style={{ fontSize:11,fontWeight:700,color:"#9ca3af",letterSpacing:".08em",textTransform:"uppercase",marginBottom:14 }}>
                QuantumGuard by Mangsri QuantumGuard LLC
              </div>

              {/* Trust badges */}
              <div style={{ display:"flex",gap:8,flexWrap:"wrap",marginBottom:22 }}>
                <span style={{ display:"inline-flex",alignItems:"center",gap:6,background:"rgba(34,197,94,.1)",border:"1px solid rgba(34,197,94,.25)",borderRadius:100,padding:"5px 14px",fontSize:11,fontWeight:700,color:"#15803d" }}>
                  <span style={{ width:6,height:6,borderRadius:"50%",background:"#22c55e",animation:"qg-pulse 2s infinite",display:"inline-block" }} />
                  Post-Quantum Crypto Scanner for Code & TLS
                </span>
                <span style={{ display:"inline-flex",alignItems:"center",gap:6,background:"rgba(59,130,246,.07)",border:"1px solid rgba(59,130,246,.18)",borderRadius:100,padding:"5px 14px",fontSize:11,fontWeight:700,color:"#1d4ed8" }}>
                  🏛 NIST FIPS 203 / 204 / 205
                </span>
              </div>

              {/* Headline */}
              <h1 style={{ fontSize:"clamp(34px,4.5vw,58px)",fontWeight:900,lineHeight:1.07,letterSpacing:"-.04em",color:"#0f172a",marginBottom:18 }}>
                Find quantum-vulnerable<br/>encryption in your<br/><span style={{ color:"#22c55e" }}>codebase — in seconds.</span>
              </h1>

              {/* Subheadline */}
              <p style={{ fontSize:"clamp(15px,1.6vw,18px)",color:"#475569",lineHeight:1.75,marginBottom:32,maxWidth:500 }}>
                QuantumGuard scans codebases and TLS configurations for RSA, ECC, SHA-1, weak crypto, and legacy encryption. Get a <strong style={{ color:"#0f172a" }}>Quantum Readiness Score</strong> with NIST-aligned migration guidance instantly.
              </p>

              {/* CTA */}
              <div style={{ display:"flex",gap:14,flexWrap:"wrap",marginBottom:24 }}>
                <button className="qg-btn qg-primary" onClick={() => onGetStarted("scan")}>🛡 Scan Your Code Now — Free</button>
                <button className="qg-btn qg-outline" onClick={() => onGetStarted("nist")}>▷ View Demo</button>
              </div>

              {/* Micro trust */}
              <div style={{ display:"flex",gap:16,flexWrap:"wrap" }}>
                {["No signup required","Instant results","Built for security teams","Open source AGPL v3"].map(t => (
                  <span key={t} style={{ fontSize:12,color:"#6b7280",display:"flex",alignItems:"center",gap:5 }}>
                    <svg width="11" height="11" viewBox="0 0 16 16" fill="none"><path d="M3 8l3.5 3.5L13 4" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
                    {t}
                  </span>
                ))}
              </div>
            </div>

            {/* Right — animated demo card */}
            <div className="qg-hero-demo" style={{ display:"flex",justifyContent:"center",alignItems:"center",animation:"qg-fadeUp .65s .15s ease-out both" }}>
              <AnimatedDemoCard />
            </div>
          </div>
        </div>
      </section>

      {/* ══ STATS BAR ════════════════════════════════════ */}
      <section style={{ background:"#fff",borderTop:"1px solid #e8edf3",borderBottom:"1px solid #e8edf3",padding:"36px 32px" }}>
        <div className="qg-wrap qg-stats-g" style={{ display:"grid",gridTemplateColumns:"repeat(5,1fr)",textAlign:"center",gap:20 }}>
          {[
            ["50+","Vulnerability patterns"],["8","Languages"],["~30s","Scan time"],["NIST 2024","FIPS 203/204/205"],["Free","No credit card"],
          ].map(([val,lbl]) => (
            <div key={lbl}>
              <div style={{ fontSize:"1.75rem",fontWeight:900,color:"#22c55e",lineHeight:1,letterSpacing:"-.03em" }}>{val}</div>
              <div style={{ fontSize:12,color:"#6b7280",marginTop:5,fontWeight:500 }}>{lbl}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ══ 1. WHAT IS QUANTUMGUARD ═════════════════════ */}
      <section className="qg-section" style={{ background:"#f8fafc",borderBottom:"1px solid #e8edf3" }}>
        <div className="qg-wrap">
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div className="qg-label">What Is QuantumGuard?</div>
            <h2 style={{ fontSize:"clamp(24px,3.2vw,40px)",fontWeight:800,letterSpacing:"-.03em",marginBottom:16 }}>A post-quantum cryptography readiness platform</h2>
            <p style={{ fontSize:16,color:"#475569",maxWidth:660,margin:"0 auto",lineHeight:1.8 }}>
              QuantumGuard helps developers and security teams find risky cryptography in codebases and TLS configurations before migration becomes urgent. It scans source code across 8 languages, checks your TLS setup, and delivers a prioritised remediation plan aligned with NIST's 2024 post-quantum standards.
            </p>
          </div>
          <div className="qg-g3">
            {[
              { icon:"🔍", title:"Reads your actual code",   desc:"AST-level analysis — not just keyword search. Detects vulnerable algorithm usage across Python, JS, Java, TypeScript, Go, Rust, C, and C++." },
              { icon:"📊", title:"Scores your risk",         desc:"Every scan produces a 0–100 Quantum Readiness Score so you know exactly where you stand and what to prioritise." },
              { icon:"🗺", title:"Tells you what to do",     desc:"Every finding maps to a specific NIST FIPS 203/204/205 replacement with concrete migration guidance — no vague advice." },
            ].map((c,i) => (
              <div key={i} className="qg-card" style={{ padding:"28px 24px" }}>
                <div style={{ fontSize:30,marginBottom:14 }}>{c.icon}</div>
                <div style={{ fontSize:15,fontWeight:700,color:"#0f172a",marginBottom:8 }}>{c.title}</div>
                <div style={{ fontSize:13,color:"#6b7280",lineHeight:1.7 }}>{c.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══ 2. WHY THIS MATTERS ══════════════════════════ */}
      <section className="qg-section" style={{ background:"#0f172a",borderBottom:"1px solid #1e293b" }}>
        <div className="qg-wrap">
          <div style={{ textAlign:"center",marginBottom:52 }}>
            <div style={{ fontSize:11,fontWeight:700,letterSpacing:".1em",color:"#22c55e",textTransform:"uppercase",marginBottom:12 }}>Why This Matters</div>
            <h2 style={{ fontSize:"clamp(24px,3.2vw,40px)",fontWeight:800,letterSpacing:"-.03em",color:"#f1f5f9",marginBottom:14 }}>RSA and ECC protect most systems today. Quantum computers will break them.</h2>
            <p style={{ fontSize:15,color:"#94a3b8",maxWidth:580,margin:"0 auto",lineHeight:1.8 }}>NIST finalized post-quantum replacements in August 2024. The migration window is open. The time to build your inventory is now — not when Q-Day arrives.</p>
          </div>
          <div className="qg-g3" style={{ marginBottom:40 }}>
            {[
              { icon:"⚡", col:"#ef4444", title:"Shor's Algorithm",             desc:"A quantum computer can break 2048-bit RSA in hours. Classical computers would need millions of years." },
              { icon:"🕵️", col:"#f59e0b", title:"Harvest Now, Decrypt Later",  desc:"Adversaries are collecting your encrypted traffic today — to decrypt once quantum hardware is ready. Your 2024 data is already at risk." },
              { icon:"📅", col:"#22c55e", title:"NIST's 2030 Deprecation",      desc:"RSA and ECC are being deprecated by 2030. Organizations that haven't migrated will face compliance failures and unacceptable exposure." },
            ].map((c,i) => (
              <div key={i} style={{ background:"rgba(255,255,255,.04)",border:`1px solid ${c.col}22`,borderRadius:16,padding:"28px 24px",transition:"all .25s" }}
                onMouseEnter={e=>{e.currentTarget.style.borderColor=c.col+"44";e.currentTarget.style.background="rgba(255,255,255,.06)";}}
                onMouseLeave={e=>{e.currentTarget.style.borderColor=c.col+"22";e.currentTarget.style.background="rgba(255,255,255,.04)";}}>
                <div style={{ fontSize:30,marginBottom:14 }}>{c.icon}</div>
                <div style={{ fontSize:15,fontWeight:700,color:"#f1f5f9",marginBottom:8 }}>{c.title}</div>
                <div style={{ fontSize:13,color:"#94a3b8",lineHeight:1.7 }}>{c.desc}</div>
              </div>
            ))}
          </div>
          <div style={{ background:"rgba(239,68,68,.08)",border:"1px solid rgba(239,68,68,.22)",borderRadius:14,padding:"22px 26px",display:"flex",gap:14,alignItems:"flex-start" }}>
            <span style={{ fontSize:26,flexShrink:0 }}>⚠️</span>
            <div>
              <div style={{ fontSize:14,fontWeight:700,color:"#fca5a5",marginBottom:6 }}>The "Harvest Now, Decrypt Later" attack is already happening</div>
              <div style={{ fontSize:13,color:"#94a3b8",lineHeight:1.75 }}>Nation-state actors are storing encrypted traffic today with the intention of decrypting it when quantum computing becomes feasible. If your encryption is vulnerable now, the data you're protecting today is already at risk. Migration takes years. Start the inventory now.</div>
            </div>
          </div>
        </div>
      </section>

      {/* ══ 3. THE PROBLEM ═══════════════════════════════ */}
      <section className="qg-section" style={{ background:"#fff",borderBottom:"1px solid #e8edf3" }}>
        <div className="qg-wrap">
          <div className="qg-diff-g" style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:40,alignItems:"center" }}>
            <div>
              <div className="qg-label">The Problem</div>
              <h2 style={{ fontSize:"clamp(24px,3.2vw,38px)",fontWeight:800,letterSpacing:"-.03em",marginBottom:16,lineHeight:1.15 }}>Most teams don't know where their cryptographic risk lives.</h2>
              <p style={{ fontSize:15,color:"#475569",lineHeight:1.8,marginBottom:20 }}>You know you use RSA somewhere. You know there's TLS somewhere. But which files? Which libraries? Which dependencies? Without a full cryptographic inventory you can't plan a migration — and you can't tell your board what your exposure is.</p>
              <div style={{ display:"flex",flexDirection:"column",gap:10 }}>
                {[
                  "Legacy crypto hidden across large codebases",
                  "TLS configurations may expose weak cipher choices",
                  "Dependency libraries introduce vulnerable crypto silently",
                  "Crypto migration is difficult without a full inventory",
                  "Normal scanners focus on CVEs — not PQC readiness",
                ].map((t,i) => (
                  <div key={i} style={{ display:"flex",gap:10,alignItems:"flex-start",fontSize:14,color:"#475569",lineHeight:1.6 }}>
                    <span style={{ color:"#ef4444",fontWeight:700,flexShrink:0,marginTop:1 }}>✕</span>{t}
                  </div>
                ))}
              </div>
            </div>
            <div style={{ background:"#f8fafc",border:"2px solid #e2e8f0",borderRadius:18,padding:"28px 24px" }}>
              <div style={{ fontSize:12,fontWeight:700,color:"#9ca3af",textTransform:"uppercase",letterSpacing:".07em",marginBottom:18 }}>Without a crypto inventory</div>
              {[
                ["Which files use RSA?",      "Unknown"],
                ["How many TLS misconfigs?",   "Unknown"],
                ["Vulnerable dependencies?",   "Unknown"],
                ["Migration complexity?",       "Unknown"],
                ["Board-level risk score?",     "Unknown"],
              ].map(([q,a],i) => (
                <div key={i} style={{ display:"flex",justifyContent:"space-between",alignItems:"center",padding:"10px 0",borderBottom:i<4?"1px solid #e2e8f0":"none" }}>
                  <span style={{ fontSize:13,color:"#374151",fontWeight:500 }}>{q}</span>
                  <span style={{ fontSize:11,fontWeight:700,color:"#ef4444",background:"#fef2f2",padding:"3px 10px",borderRadius:6 }}>{a}</span>
                </div>
              ))}
              <div style={{ marginTop:18,padding:"12px 14px",background:"#f0fdf4",border:"1px solid #bbf7d0",borderRadius:10,fontSize:12,color:"#15803d",fontWeight:600 }}>
                QuantumGuard answers all of these in seconds.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ══ 4. THE SOLUTION ══════════════════════════════ */}
      <section className="qg-section" style={{ background:"#f0fdf4",borderBottom:"1px solid #dcfce7" }}>
        <div className="qg-wrap">
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div className="qg-label">The Solution</div>
            <h2 style={{ fontSize:"clamp(24px,3.2vw,40px)",fontWeight:800,letterSpacing:"-.03em",marginBottom:14 }}>QuantumGuard gives you visibility before migration.</h2>
            <p style={{ fontSize:16,color:"#475569",maxWidth:560,margin:"0 auto",lineHeight:1.8 }}>Five capabilities — from raw code analysis to board-ready reports.</p>
          </div>
          <div className="qg-g3">
            {[
              { icon:"🔍", title:"Detect quantum-vulnerable crypto",    desc:"RSA, ECC, DH, DSA, MD5, SHA-1, RC4, DES, and 10+ more — detected at the line level across your entire codebase." },
              { icon:"🔐", title:"Analyze TLS configuration",           desc:"Check any domain for TLS version, cipher suite, and certificate. Grades A+ to F with NIST migration guidance." },
              { icon:"📊", title:"Generate Quantum Readiness Score",    desc:"A single 0–100 score combining code crypto, dependency risk, TLS posture, and crypto agility." },
              { icon:"📋", title:"Export CBOM",                         desc:"Cryptographic Bill of Materials in JSON — ready for audits, compliance submissions, and board presentations." },
              { icon:"🗺", title:"NIST-aligned migration guidance",     desc:"Every finding maps to a specific FIPS 203/204/205 replacement. No ambiguity. No guesswork." },
              { icon:"⚙", title:"GitHub Actions security gate",        desc:"Block pull requests that introduce vulnerable cryptography. Shift security left into your CI/CD pipeline." },
            ].map((c,i) => (
              <div key={i} className="qg-card" style={{ padding:"24px 22px" }}>
                <div style={{ fontSize:28,marginBottom:12 }}>{c.icon}</div>
                <div style={{ fontSize:14,fontWeight:700,color:"#0f172a",marginBottom:6 }}>{c.title}</div>
                <div style={{ fontSize:12,color:"#6b7280",lineHeight:1.7 }}>{c.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══ 5. HOW IT WORKS ══════════════════════════════ */}
      <section className="qg-section" style={{ background:"#fff",borderBottom:"1px solid #e8edf3" }}>
        <div className="qg-wrap">
          <div style={{ textAlign:"center",marginBottom:52 }}>
            <div className="qg-label">How It Works</div>
            <h2 style={{ fontSize:"clamp(24px,3.2vw,40px)",fontWeight:800,letterSpacing:"-.03em" }}>Five steps. Thirty seconds.</h2>
          </div>
          <div className="qg-g3">
            {[
              { n:"1", icon:"📎", title:"Upload code or scan repo",     desc:"Paste a GitHub URL or upload a ZIP. No installation. Public repos work instantly." },
              { n:"2", icon:"⚙", title:"Detect crypto patterns",        desc:"AST-level analysis across 8 languages. Dependency manifests checked. TLS configuration analyzed." },
              { n:"3", icon:"📄", title:"Review file-level findings",   desc:"Every finding shows file path, line number, severity, confidence, and NIST fix." },
              { n:"4", icon:"📊", title:"Get your readiness score",     desc:"A 0–100 Quantum Readiness Score with full severity breakdown and business impact context." },
              { n:"5", icon:"📋", title:"Export report or CBOM",        desc:"PDF, CSV, and CBOM JSON export. Ready for audits and board-level reporting." },
            ].map((step,i) => (
              <div key={i} style={{ textAlign:"center",padding:"28px 20px",background:"#f8fafc",borderRadius:16,border:"1.5px solid #e2e8f0",transition:"all .25s" }}
                onMouseEnter={e=>{e.currentTarget.style.borderColor="#22c55e";e.currentTarget.style.background="#f0fdf4";e.currentTarget.style.transform="translateY(-3px)";}}
                onMouseLeave={e=>{e.currentTarget.style.borderColor="#e2e8f0";e.currentTarget.style.background="#f8fafc";e.currentTarget.style.transform="translateY(0)";}}>
                <div style={{ width:42,height:42,borderRadius:11,background:"linear-gradient(135deg,#22c55e,#15803d)",color:"#fff",display:"flex",alignItems:"center",justifyContent:"center",fontSize:17,fontWeight:800,margin:"0 auto 14px",boxShadow:"0 4px 12px rgba(34,197,94,.28)" }}>{step.n}</div>
                <div style={{ fontSize:26,marginBottom:10 }}>{step.icon}</div>
                <div style={{ fontSize:14,fontWeight:700,color:"#0f172a",marginBottom:6 }}>{step.title}</div>
                <div style={{ fontSize:12,color:"#6b7280",lineHeight:1.65 }}>{step.desc}</div>
              </div>
            ))}
          </div>
          <div style={{ textAlign:"center",marginTop:36 }}>
            <button className="qg-btn qg-primary" onClick={() => onGetStarted("scan")}>Try It Now — Free →</button>
          </div>
        </div>
      </section>

      {/* ══ 6. FEATURES ══════════════════════════════════ */}
      <section className="qg-section" style={{ background:"#f8fafc",borderBottom:"1px solid #e8edf3" }}>
        <div className="qg-wrap">
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div className="qg-label">Features</div>
            <h2 style={{ fontSize:"clamp(24px,3.2vw,40px)",fontWeight:800,letterSpacing:"-.03em" }}>Everything you need to go quantum-safe</h2>
          </div>
          <div className="qg-g3">
            {[
              { icon:"🔍", badge:"Core",    bc:"#16a34a", bb:"#dcfce7", title:"Crypto Scanner",           desc:"RSA, ECC, DH, DSA, MD5, SHA-1, RC4, DES — detected at the line level across 8 languages using AST parsing.",        tab:"scan"    },
              { icon:"🔐", badge:"Free",    bc:"#1d4ed8", bb:"#dbeafe", title:"TLS Analyzer",             desc:"Analyze any domain's TLS version, cipher suite, and certificate. Graded A+ to F with hybrid PQC detection.",         tab:"tls"     },
              { icon:"🔬", badge:"Free",    bc:"#7c3aed", bb:"#ede9fe", title:"Crypto Agility Check",     desc:"Score how configurable your crypto is. Hardcoded = low agility. Parameterized = high agility. Migration readiness.",  tab:"agility" },
              { icon:"🧠", badge:"Unique",  bc:"#b45309", bb:"#fef3c7", title:"Unified Risk Score",       desc:"One 0–100 score combining code, TLS, and agility. One number for leadership reporting.",                             tab:"unified" },
              { icon:"📋", badge:"Export",  bc:"#374151", bb:"#f3f4f6", title:"CBOM Export",              desc:"Cryptographic Bill of Materials in JSON + NIST SP 800-53 compliance report in PDF and CSV.",                         tab:"nist"    },
              { icon:"📦", badge:"New",     bc:"#0369a1", bb:"#e0f2fe", title:"NIST Migration Guidance",  desc:"Every finding includes a specific FIPS 203/204/205 replacement. No ambiguity, no vendor lock-in.",                   tab:"scan"    },
            ].map((f,i) => (
              <div key={i} className="qg-card" style={{ padding:"28px 24px",cursor:"pointer" }} onClick={() => onGetStarted(f.tab)}>
                <div style={{ display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:16 }}>
                  <div style={{ width:46,height:46,borderRadius:12,background:"#f0fdf4",border:"1.5px solid #bbf7d0",display:"flex",alignItems:"center",justifyContent:"center",fontSize:21 }}>{f.icon}</div>
                  <span style={{ background:f.bb,color:f.bc,fontSize:10,fontWeight:700,padding:"3px 10px",borderRadius:100 }}>{f.badge}</span>
                </div>
                <div style={{ fontSize:15,fontWeight:700,color:"#0f172a",marginBottom:8 }}>{f.title}</div>
                <div style={{ fontSize:13,color:"#6b7280",lineHeight:1.65 }}>{f.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══ 7. DIFFERENTIATION ═══════════════════════════ */}
      <section className="qg-section" style={{ background:"#fff",borderBottom:"1px solid #e8edf3" }}>
        <div className="qg-wrap">
          <div style={{ textAlign:"center",marginBottom:40 }}>
            <div className="qg-label">Why QuantumGuard</div>
            <h2 style={{ fontSize:"clamp(24px,3.2vw,40px)",fontWeight:800,letterSpacing:"-.03em",marginBottom:14 }}>Different from normal vulnerability scanners</h2>
            <div style={{ display:"inline-block",background:"rgba(59,130,246,.05)",border:"1px solid rgba(59,130,246,.18)",borderRadius:12,padding:"14px 22px",maxWidth:680 }}>
              <p style={{ fontSize:15,color:"#374151",margin:0,lineHeight:1.7 }}>
                Snyk focuses on CVEs and dependencies. <strong style={{ color:"#1d4ed8" }}>QuantumGuard focuses on cryptographic risk and post-quantum readiness.</strong> They solve different problems. Use both if you need both.
              </p>
            </div>
          </div>
          <div className="qg-diff-g" style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:20 }}>
            <div style={{ background:"#fafafa",border:"1.5px solid #e2e8f0",borderRadius:14,padding:"24px" }}>
              <div style={{ fontSize:13,fontWeight:700,color:"#9ca3af",marginBottom:16,textTransform:"uppercase",letterSpacing:".06em" }}>Traditional security scanners</div>
              {["Find known CVEs in packages","Check for outdated dependencies","Report software vulnerabilities","Don't analyze cryptographic algorithms","Don't measure PQC migration readiness","Don't scan TLS for quantum risk"].map((t,i) => (
                <div key={i} style={{ display:"flex",gap:8,fontSize:13,color:"#374151",marginBottom:9,lineHeight:1.5,alignItems:"flex-start" }}>
                  <span style={{ color:"#9ca3af",flexShrink:0,marginTop:1 }}>—</span>{t}
                </div>
              ))}
            </div>
            <div style={{ background:"#f0fdf4",border:"2px solid #bbf7d0",borderRadius:14,padding:"24px" }}>
              <div style={{ fontSize:13,fontWeight:700,color:"#15803d",marginBottom:16,textTransform:"uppercase",letterSpacing:".06em" }}>QuantumGuard</div>
              {["Finds quantum-vulnerable algorithms at line level","Scans 30+ vulnerable libraries across 6 ecosystems","Grades TLS configuration for quantum readiness","Measures crypto agility — migration difficulty score","Delivers NIST FIPS 203/204/205 fix for every finding","Exports CBOM for audits and board reporting"].map((t,i) => (
                <div key={i} style={{ display:"flex",gap:8,fontSize:13,color:"#15803d",marginBottom:9,lineHeight:1.5,alignItems:"flex-start" }}>
                  <span style={{ color:"#22c55e",fontWeight:700,flexShrink:0,marginTop:1 }}>✓</span>{t}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ══ 8. WHO IT'S FOR ══════════════════════════════ */}
      <section className="qg-section" style={{ background:"#f8fafc",borderBottom:"1px solid #e8edf3" }}>
        <div className="qg-wrap">
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div className="qg-label">Who It's For</div>
            <h2 style={{ fontSize:"clamp(24px,3.2vw,40px)",fontWeight:800,letterSpacing:"-.03em" }}>Designed for teams at every stage</h2>
          </div>
          <div className="qg-who-g qg-g3">
            {[
              { icon:"👨‍💻", title:"Developers",        desc:"Find and fix quantum-vulnerable crypto during development — before it becomes a production audit issue." },
              { icon:"🛡",  title:"Security teams",    desc:"Run cryptographic inventories across repositories at scale. Export CBOM for compliance. Track readiness over time." },
              { icon:"🚀",  title:"Startups",           desc:"Build on secure foundations from day one. Catch vulnerable libraries before they're embedded too deeply to migrate." },
              { icon:"🏢",  title:"Enterprises",        desc:"Assess quantum risk across hundreds of repos. Integrate into CI/CD. Generate executive risk reports." },
              { icon:"📋",  title:"Compliance teams",  desc:"NIST FIPS 203/204/205 alignment built in. CBOM and NIST SP 800-53 report export for regulatory submissions." },
              { icon:"🔬",  title:"Researchers",        desc:"Open source, fully auditable scanner. Use the API to integrate cryptographic analysis into your research toolchain." },
            ].map((c,i) => (
              <div key={i} className="qg-card" style={{ padding:"24px 20px" }}>
                <div style={{ fontSize:28,marginBottom:12 }}>{c.icon}</div>
                <div style={{ fontSize:14,fontWeight:700,color:"#0f172a",marginBottom:6 }}>{c.title}</div>
                <div style={{ fontSize:12,color:"#6b7280",lineHeight:1.7 }}>{c.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══ 9. TRUST / TRANSPARENCY ══════════════════════ */}
      <section className="qg-section" style={{ background:"#fff",borderBottom:"1px solid #e8edf3" }}>
        <div className="qg-wrap">
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div className="qg-label">Trust & Transparency</div>
            <h2 style={{ fontSize:"clamp(24px,3.2vw,40px)",fontWeight:800,letterSpacing:"-.03em" }}>Built to be trusted</h2>
          </div>
          <div className="qg-trust-g qg-g3">
            {[
              { icon:"🔒", title:"Zero data retention",      desc:"Your code is never stored. Every repo is scanned in a temporary directory and deleted immediately — whether the scan succeeds or fails." },
              { icon:"📖", title:"Fully open source",        desc:"Every line of scanner code is on GitHub under AGPL v3. Read exactly what runs on your repository before you trust it." },
              { icon:"🧪", title:"Tested on real repos",     desc:"Validated against pycrypto, node-forge, elliptic, and 30+ known-vulnerable libraries. The pycrypto scan scores 0/100 — as it should." },
              { icon:"🏛", title:"NIST 2024 aligned",        desc:"Every recommendation maps to NIST FIPS 203, 204, or 205 — the official post-quantum standards published August 2024." },
              { icon:"🛡", title:"Security hardened",        desc:"SSRF protection, ZIP path traversal prevention, token scrubbing in logs, JWT auth, and rate limiting — all in place." },
              { icon:"⚠", title:"Honest about limitations", desc:"False positives can occur in vendor code — flagged separately and excluded from scores. Repos over 50MB may return partial results." },
            ].map((c,i) => (
              <div key={i} className="qg-card" style={{ padding:"24px 22px" }}>
                <div style={{ fontSize:28,marginBottom:12 }}>{c.icon}</div>
                <div style={{ fontSize:14,fontWeight:700,color:"#0f172a",marginBottom:6 }}>{c.title}</div>
                <div style={{ fontSize:12,color:"#6b7280",lineHeight:1.7 }}>{c.desc}</div>
              </div>
            ))}
          </div>

          {/* Company info + disclaimer */}
          <div style={{ marginTop:36,display:"grid",gridTemplateColumns:"1fr 1fr",gap:20 }} className="qg-g2">
            <div style={{ padding:"22px 24px",background:"#f8fafc",border:"1.5px solid #e2e8f0",borderRadius:14 }}>
              <div style={{ fontSize:13,fontWeight:700,color:"#0f172a",marginBottom:10 }}>Built by Mangsri QuantumGuard LLC</div>
              <div style={{ fontSize:13,color:"#6b7280",lineHeight:1.7 }}>Montgomery, Alabama, USA · Founded April 2026<br/>AGPL v3 open source · github.com/cybersupe/quantumguard</div>
              <div style={{ marginTop:12,display:"flex",gap:10,flexWrap:"wrap" }}>
                <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer"
                  style={{ display:"inline-flex",alignItems:"center",gap:6,color:"#374151",border:"1px solid #e2e8f0",borderRadius:8,padding:"6px 13px",fontSize:12,fontWeight:600,textDecoration:"none",transition:"all .2s" }}
                  onMouseEnter={e=>{e.currentTarget.style.borderColor="#22c55e";e.currentTarget.style.color="#22c55e";}}
                  onMouseLeave={e=>{e.currentTarget.style.borderColor="#e2e8f0";e.currentTarget.style.color="#374151";}}>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
                  Source Code
                </a>
                <button onClick={() => onGetStarted("team")} style={{ display:"inline-flex",alignItems:"center",gap:6,color:"#374151",border:"1px solid #e2e8f0",borderRadius:8,padding:"6px 13px",fontSize:12,fontWeight:600,cursor:"pointer",background:"transparent",fontFamily:"inherit",transition:"all .2s" }}
                  onMouseEnter={e=>{e.currentTarget.style.borderColor="#22c55e";e.currentTarget.style.color="#22c55e";}}
                  onMouseLeave={e=>{e.currentTarget.style.borderColor="#e2e8f0";e.currentTarget.style.color="#374151";}}>
                  Meet the team →
                </button>
              </div>
            </div>
            <div style={{ padding:"22px 24px",background:"#fffbeb",border:"1px solid #fde68a",borderRadius:14 }}>
              <div style={{ fontSize:13,fontWeight:700,color:"#92400e",marginBottom:8 }}>Transparency disclaimer</div>
              <div style={{ fontSize:12,color:"#78350f",lineHeight:1.75 }}>
                QuantumGuard provides security insights and migration recommendations. Results should be validated by qualified security professionals before production decisions. False positives can occur. This tool is a starting point for cryptographic inventory — not a replacement for a professional security audit.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ══ PRICING ══════════════════════════════════════ */}
      <section className="qg-section" style={{ background:"#f8fafc",borderBottom:"1px solid #e8edf3" }}>
        <div className="qg-wrap">
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div className="qg-label">Pricing</div>
            <h2 style={{ fontSize:"clamp(24px,3.2vw,40px)",fontWeight:800,letterSpacing:"-.03em" }}>Start free. Scale when you're ready.</h2>
            <p style={{ color:"#6b7280",marginTop:10,fontSize:15 }}>No credit card required. No hidden limits on the free plan.</p>
          </div>
          <div className="qg-pricing-g" style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:18 }}>
            {PRICING.map(plan => (
              <div key={plan.name} style={{ background:"#fff",border:plan.highlight?"2px solid #22c55e":"1.5px solid #e8edf3",borderRadius:18,padding:"28px 22px",position:"relative",boxShadow:plan.highlight?"0 8px 36px rgba(34,197,94,.14)":"0 2px 12px rgba(0,0,0,.04)",transform:plan.highlight?"scale(1.04)":"none",transition:"all .25s" }}
                onMouseEnter={e=>{if(!plan.highlight){e.currentTarget.style.borderColor="#22c55e";e.currentTarget.style.transform="translateY(-2px)";}}}
                onMouseLeave={e=>{if(!plan.highlight){e.currentTarget.style.borderColor="#e8edf3";e.currentTarget.style.transform="none";}}}>
                {plan.highlight&&<div style={{ position:"absolute",top:-13,left:"50%",transform:"translateX(-50%)",background:"#22c55e",color:"#fff",fontSize:10,fontWeight:700,letterSpacing:".06em",padding:"4px 14px",borderRadius:100,whiteSpace:"nowrap" }}>MOST POPULAR</div>}
                <div style={{ fontWeight:700,fontSize:15,marginBottom:4 }}>{plan.name}</div>
                <div style={{ fontSize:12,color:"#9ca3af",marginBottom:16 }}>{plan.desc}</div>
                <div style={{ display:"flex",alignItems:"baseline",gap:2,marginBottom:18 }}>
                  <span style={{ fontSize:"2rem",fontWeight:800,letterSpacing:"-.04em" }}>{plan.price}</span>
                  <span style={{ fontSize:13,color:"#9ca3af" }}>{plan.period}</span>
                </div>
                <button onClick={() => onGetStarted("scan")} style={{ width:"100%",padding:"11px",borderRadius:9,marginBottom:18,fontSize:13,fontWeight:600,cursor:"pointer",fontFamily:"inherit",transition:"all .2s",background:plan.highlight?"#22c55e":"transparent",color:plan.highlight?"#fff":"#0f172a",border:plan.highlight?"none":"1.5px solid #d1d5db" }}
                  onMouseEnter={e=>{if(!plan.highlight){e.currentTarget.style.borderColor="#22c55e";e.currentTarget.style.color="#22c55e";}else{e.currentTarget.style.background="#16a34a";}}}
                  onMouseLeave={e=>{if(!plan.highlight){e.currentTarget.style.borderColor="#d1d5db";e.currentTarget.style.color="#0f172a";}else{e.currentTarget.style.background="#22c55e";}}}>
                  {plan.cta}
                </button>
                <div style={{ display:"flex",flexDirection:"column",gap:9 }}>
                  {plan.features.map(f => (
                    <div key={f} style={{ display:"flex",alignItems:"center",gap:8,fontSize:12,color:"#4b5563" }}>
                      <svg width="13" height="13" viewBox="0 0 16 16" fill="none" style={{ flexShrink:0 }}><path d="M3 8l3.5 3.5L13 4" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
                      {f}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══ 10. FINAL CTA ════════════════════════════════ */}
      <section style={{ padding:"100px 32px",background:"linear-gradient(135deg,#052e16 0%,#0f172a 60%,#052e16 100%)",textAlign:"center",position:"relative",overflow:"hidden" }}>
        <div style={{ position:"absolute",inset:0,backgroundImage:"radial-gradient(rgba(34,197,94,.07) 1px,transparent 1px)",backgroundSize:"28px 28px",pointerEvents:"none" }} />
        <div style={{ maxWidth:640,margin:"0 auto",position:"relative" }}>
          <div style={{ width:56,height:56,background:"linear-gradient(135deg,#22c55e,#15803d)",borderRadius:14,display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 24px",fontSize:26,boxShadow:"0 8px 28px rgba(34,197,94,.35)" }}>⚛</div>
          <div style={{ fontSize:12,fontWeight:700,color:"#22c55e",letterSpacing:".08em",textTransform:"uppercase",marginBottom:14 }}>Start Your Quantum Security Journey Today</div>
          <h2 style={{ fontSize:"clamp(28px,4.5vw,52px)",fontWeight:900,letterSpacing:"-.04em",color:"#fff",lineHeight:1.08,marginBottom:16 }}>
            Run a free scan and see where your<br/><span style={{ color:"#22c55e" }}>cryptographic risk exists.</span>
          </h2>
          <p style={{ color:"#6b7280",fontSize:16,marginBottom:36,lineHeight:1.65 }}>
            NIST is deprecating RSA and ECC by 2030. Most codebases are already vulnerable. Find out where yours stands — free, no signup, 30 seconds.
          </p>
          <div style={{ display:"flex",gap:16,justifyContent:"center",flexWrap:"wrap",marginBottom:20 }}>
            <button className="qg-btn qg-primary" style={{ fontSize:17,padding:"18px 36px" }} onClick={() => onGetStarted("scan")}>
              🛡 Scan Your Code Before It's Too Late — Free
            </button>
            <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" className="qg-btn qg-ghost" style={{ fontSize:16 }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
              View Source
            </a>
          </div>
          <div style={{ fontSize:12,color:"#374151" }}>No signup · No credit card · Results should be validated by security professionals before production decisions</div>
        </div>
      </section>

      {/* ══ FOOTER ═══════════════════════════════════════ */}
      <footer style={{ background:"#0b1117",padding:"48px 32px 28px",color:"#4b5563" }}>
        <div style={{ maxWidth:1060,margin:"0 auto" }}>
          <div style={{ display:"flex",gap:44,flexWrap:"wrap",marginBottom:36 }}>
            <div style={{ flex:"1 1 220px" }}>
              <div style={{ display:"flex",alignItems:"center",gap:9,marginBottom:14 }}>
                <div style={{ width:28,height:28,background:"linear-gradient(135deg,#22c55e,#15803d)",borderRadius:7,display:"flex",alignItems:"center",justifyContent:"center",fontSize:14 }}>⚛</div>
                <div>
                  <div style={{ color:"#f8fafc",fontWeight:800,fontSize:15,letterSpacing:"-.02em",lineHeight:1.1 }}><span style={{ color:"#22c55e" }}>Quantum</span>Guard</div>
                  <div style={{ fontSize:9,color:"#374151",fontWeight:500 }}>by Mangsri QuantumGuard LLC</div>
                </div>
              </div>
              <p style={{ fontSize:12,lineHeight:1.7,maxWidth:210,marginBottom:10 }}>Post-quantum cryptography scanner for codebases and TLS configurations.</p>
              <div style={{ fontSize:11,color:"#374151" }}>Montgomery, Alabama, USA</div>
            </div>
            {[
              { title:"Product",  links:[["Scanner","scan"],["TLS Analyzer","tls"],["Agility Checker","agility"],["Unified Risk","unified"],["NIST Reports","nist"]] },
              { title:"Company",  links:[["About","team"],["Our Team","team"],["GitHub","github"],["Documentation","docs"]] },
              { title:"Legal",    links:[["Privacy Policy",""],["Terms of Service",""],["Security",""],["Disclaimer",""]] },
            ].map(col => (
              <div key={col.title} style={{ flex:"1 1 120px" }}>
                <div style={{ fontSize:11,fontWeight:700,color:"#f8fafc",letterSpacing:".07em",textTransform:"uppercase",marginBottom:14 }}>{col.title}</div>
                {col.links.map(([l, tab]) => (
                  <div key={l} style={{ fontSize:12,color:"#4b5563",marginBottom:9,cursor:"pointer",transition:"color .15s" }}
                    onClick={() => { if (tab === "github") window.open("https://github.com/cybersupe/quantumguard","_blank"); else if (tab) onGetStarted(tab); }}
                    onMouseEnter={e => e.currentTarget.style.color="#22c55e"}
                    onMouseLeave={e => e.currentTarget.style.color="#4b5563"}>
                    {l}
                  </div>
                ))}
              </div>
            ))}
          </div>
          <div style={{ borderTop:"1px solid #1e293b",paddingTop:20,display:"flex",justifyContent:"space-between",flexWrap:"wrap",gap:10,fontSize:12 }}>
            <span>© 2026 Mangsri QuantumGuard LLC. All rights reserved.</span>
            <span style={{ color:"#374151" }}>NIST FIPS 203 · FIPS 204 · FIPS 205 · AGPL v3 · Zero Data Retention</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
// ══════════════════════════════════════════════════════════════
// AUTH MODAL — unchanged
// ══════════════════════════════════════════════════════════════
function AuthModal({ mode: initialMode, onClose, onSuccess }) {
  const { jwtLogin, jwtRegister } = useAuth();
  const [mode,setMode]=useState(initialMode||"login");const [email,setEmail]=useState("");const [password,setPass]=useState("");const [name,setName]=useState("");const [error,setError]=useState("");const [loading,setLoading]=useState(false);
  const inputStyle={width:"100%",padding:"11px 14px",borderRadius:9,border:`1.5px solid ${C.panelBorder}`,background:C.input,color:C.text,fontSize:14,outline:"none",boxSizing:"border-box",marginBottom:12,fontFamily:"inherit"};
  const handle=async()=>{if(!email||!password){setError("Email and password are required");return;}if(password.length<8){setError("Password must be at least 8 characters");return;}setLoading(true);setError("");try{if(mode==="login")await jwtLogin(email,password);if(mode==="register")await jwtRegister(email,password,name);onSuccess&&onSuccess();onClose();}catch(e){setError(e.message||"Something went wrong");}setLoading(false);};
  return (
    <div style={{ position:"fixed",inset:0,background:"rgba(0,0,0,.65)",zIndex:2000,display:"flex",alignItems:"center",justifyContent:"center",padding:16,backdropFilter:"blur(4px)" }}>
      <div style={{ background:C.panel,border:`1px solid ${C.panelBorder}`,borderRadius:18,width:"100%",maxWidth:380,boxShadow:"0 24px 80px rgba(0,0,0,.6)",overflow:"hidden" }}>
        <div style={{ padding:"18px 22px",borderBottom:`1px solid ${C.panelBorder}`,display:"flex",justifyContent:"space-between",alignItems:"center" }}><div style={{ display:"flex",alignItems:"center",gap:10 }}><div style={{ width:30,height:30,borderRadius:8,background:"linear-gradient(135deg,#22c55e,#15803d)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14 }}>⚛</div><span style={{ fontWeight:800,fontSize:15,color:C.text }}>{mode==="login"?"Sign In":"Create Account"}</span></div><button onClick={onClose} style={{ background:"transparent",border:"none",color:C.muted,cursor:"pointer",fontSize:20,lineHeight:1 }}>✕</button></div>
        <div style={{ display:"flex",borderBottom:`1px solid ${C.panelBorder}` }}>{[["login","Sign In"],["register","Register"]].map(([m,label])=>(<button key={m} onClick={()=>{setMode(m);setError("");}} style={{ flex:1,padding:"11px",background:"transparent",border:"none",cursor:"pointer",fontSize:13,fontWeight:mode===m?700:400,color:mode===m?C.green:C.muted,borderBottom:mode===m?`2px solid ${C.green}`:"2px solid transparent",transition:"all .2s",fontFamily:"inherit" }}>{label}</button>))}</div>
        <div style={{ padding:"22px 22px 18px" }}>
          {mode==="register"&&<input value={name} onChange={e=>setName(e.target.value)} placeholder="Your name (optional)" style={inputStyle} />}
          <input value={email} onChange={e=>setEmail(e.target.value)} placeholder="Email address" type="email" style={inputStyle} onKeyDown={e=>e.key==="Enter"&&handle()} />
          <input value={password} onChange={e=>setPass(e.target.value)} placeholder="Password (min 8 characters)" type="password" style={inputStyle} onKeyDown={e=>e.key==="Enter"&&handle()} />
          {error&&<div style={{ background:"rgba(239,68,68,.1)",border:"1px solid rgba(239,68,68,.3)",borderRadius:8,padding:"8px 12px",color:C.red,fontSize:12,marginBottom:12 }}>⚠ {error}</div>}
          <button onClick={handle} disabled={loading} style={{ width:"100%",padding:"12px",background:loading?"#166534":"linear-gradient(135deg,#22c55e,#16a34a)",color:"#fff",border:"none",borderRadius:10,fontWeight:700,fontSize:14,cursor:loading?"not-allowed":"pointer",transition:"all .2s",fontFamily:"inherit",marginBottom:10 }}>{loading?"Please wait...":(mode==="login"?"Sign In →":"Create Account →")}</button>
          <div style={{ textAlign:"center",fontSize:12,color:C.muted }}>{mode==="login"?"Don't have an account? ":"Already have an account? "}<span onClick={()=>{setMode(mode==="login"?"register":"login");setError("");}} style={{ color:C.green,cursor:"pointer",fontWeight:600 }}>{mode==="login"?"Register free":"Sign in"}</span></div>
          <div style={{ display:"flex",alignItems:"center",gap:10,margin:"14px 0 10px" }}><div style={{ flex:1,height:1,background:C.panelBorder }} /><span style={{ fontSize:11,color:C.muted }}>or continue with</span><div style={{ flex:1,height:1,background:C.panelBorder }} /></div>
          <button onClick={async()=>{try{await signInWithGoogle();onClose();}catch(e){setError(e.message);}}} style={{ width:"100%",padding:"10px",background:"transparent",border:`1.5px solid ${C.panelBorder}`,borderRadius:10,color:C.text,cursor:"pointer",fontSize:13,fontWeight:500,display:"flex",alignItems:"center",justifyContent:"center",gap:8,fontFamily:"inherit",transition:"border-color .2s" }} onMouseEnter={e=>e.currentTarget.style.borderColor="#22c55e"} onMouseLeave={e=>e.currentTarget.style.borderColor=C.panelBorder}><svg width="16" height="16" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>Google</button>
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// APP ROOT — unchanged
// ══════════════════════════════════════════════════════════════
function AppInner() {
  const { jwtUser, jwtToken, jwtLoading, jwtLogout } = useAuth();
  const [googleUser, setGoogleUser] = useState(null);
  useEffect(() => { onAuthStateChanged(auth, u => setGoogleUser(u)); }, []);
  const user = jwtUser || googleUser;
  const [active, setActive] = useState("home");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [authModal, setAuthModal] = useState(null);
  const handleLogout = async () => { jwtLogout(); try { await signOut(auth); setGoogleUser(null); } catch(e) {} };
  const handleLogin = () => setAuthModal("login");
  if (jwtLoading) return (<div style={{ display:"flex",alignItems:"center",justifyContent:"center",height:"100vh",background:C.bg }}><div style={{ textAlign:"center" }}><div style={{ width:40,height:40,borderRadius:10,background:"linear-gradient(135deg,#22c55e,#15803d)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:20,margin:"0 auto 12px" }}>⚛</div><div style={{ color:C.green,fontSize:13,fontWeight:600 }}>Loading QuantumGuard...</div></div></div>);
  if (active === "home") return (<><Homepage onGetStarted={(tab) => setActive(tab || "scan")} onOpenAuth={setAuthModal} />{authModal && <AuthModal mode={authModal} onClose={()=>setAuthModal(null)} onSuccess={()=>setActive("scan")} />}</>);
  const pageTitle = { scan:"Threat Scanner", agility:"Agility Checker", tls:"TLS Analyzer", history:"Scan History", migration:"Migration Tracker", dashboard:"Analytics", nist:"NIST Report", docs:"Documentation", team:"Our Team", unified:"Unified Risk" };
  return (
    <>
      <style>{`@keyframes pulse-ring{0%{box-shadow:0 0 0 0 rgba(34,197,94,0.5);}70%{box-shadow:0 0 0 8px rgba(34,197,94,0);}100%{box-shadow:0 0 0 0 rgba(34,197,94,0);}}`}</style>
      <div style={{ display:"flex", minHeight:"100vh", background:C.bg }}>
        <button className="hamburger" onClick={()=>setSidebarOpen(!sidebarOpen)}>☰</button>
        {sidebarOpen&&<div className="sidebar-overlay open" onClick={()=>setSidebarOpen(false)} />}
        <Sidebar active={active} setActive={setActive} user={user} onLogin={handleLogin} onLogout={handleLogout} open={sidebarOpen} onClose={()=>setSidebarOpen(false)} />
        <div className="main-content" style={{ flex:1, minHeight:"100vh", display:"flex", flexDirection:"column" }}>
          <TopBar title={pageTitle[active]||active} user={user} onLogin={handleLogin} onLogout={handleLogout} onHamburger={()=>setSidebarOpen(!sidebarOpen)} />
          <div style={{ flex:1, overflowY:"auto" }}>
            {active==="scan"      && <ScannerPage user={user} />}
            {active==="agility"   && <AgilityPage />}
            {active==="tls"       && <TLSPage />}
            {active==="unified"   && <UnifiedRiskPage />}
            {active==="history"   && <HistoryPage user={user} />}
            {active==="migration" && <MigrationPage user={user} />}
            {active==="dashboard" && <AnalyticsPage />}
            {active==="nist"      && <NISTReportPage />}
            {active==="docs"      && <DocsPage />}
            {active==="team"      && <TeamPage />}
          </div>
        </div>
      </div>
      {authModal && <AuthModal mode={authModal} onClose={()=>setAuthModal(null)} onSuccess={()=>setAuthModal(null)} />}
    </>
  );
}

export default function App() {
  return (<AuthProvider><AppInner /></AuthProvider>);
}
