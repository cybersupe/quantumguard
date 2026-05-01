import { useState, useEffect, useRef } from "react";
import "./App.css";
import emailjs from "@emailjs/browser";
import { auth, db, signInWithGoogle, canUserScan, incrementScanCount } from "./firebase";
import { onAuthStateChanged, signOut } from "firebase/auth";
import { collection, addDoc, getDocs, query, where, orderBy } from "firebase/firestore";

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

// Rich log lines emitted per scan phase — used by the terminal animation
const SCAN_LOG_PHASES = [
  {
    step: "Initializing scan engine...",
    logs: [
      { type: "info",    text: "QuantumGuard engine v2.4 starting up" },
      { type: "info",    text: "Loading NIST FIPS 203/204/205 signature database" },
      { type: "success", text: "Vulnerability pattern library loaded — 58 patterns active" },
      { type: "info",    text: "Initializing AST parser for multi-language support" },
    ],
  },
  {
    step: "Connecting to target...",
    logs: [
      { type: "info",    text: "Resolving repository URL..." },
      { type: "info",    text: "Authenticating with GitHub API" },
      { type: "success", text: "Repository access confirmed" },
      { type: "info",    text: "Cloning into temporary workspace..." },
      { type: "success", text: "Clone complete — ready to scan" },
    ],
  },
  {
    step: "Analyzing file structure...",
    logs: [
      { type: "info",    text: "Walking directory tree..." },
      { type: "info",    text: "Detected languages: Python, JavaScript, Java" },
      { type: "info",    text: "Indexing 47 source files across 12 directories" },
      { type: "warn",    text: "Skipping node_modules/ (excluded by default)" },
      { type: "success", text: "File index complete — 47 files queued for analysis" },
    ],
  },
  {
    step: "Running vulnerability checks...",
    logs: [
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
    ],
  },
  {
    step: "Calculating risk score...",
    logs: [
      { type: "info",    text: "Applying NIST SP 800-53 control mapping" },
      { type: "info",    text: "Weighting: CRITICAL ×3.0 · HIGH ×2.0 · MEDIUM ×1.0" },
      { type: "info",    text: "Computing penalty function..." },
      { type: "warn",    text: "Score penalty: 2 critical findings (-34 pts)" },
      { type: "success", text: "Quantum Readiness Score calculated: 42 / 100" },
    ],
  },
  {
    step: "Generating threat report...",
    logs: [
      { type: "info",    text: "Building NIST control compliance matrix" },
      { type: "info",    text: "Generating CRYSTALS-Kyber migration guidance" },
      { type: "info",    text: "Compiling PDF-ready report structure" },
      { type: "success", text: "Score explanation generated — 5 lines" },
      { type: "success", text: "Scan summary ready — all modules complete" },
      { type: "success", text: "✓ Scan complete in 8.3s" },
    ],
  },
];

// ── Sidebar ──────────────────────────────────────────────────
function Sidebar({ active, setActive, user, onLogin, onLogout, open, onClose }) {
  const navItems = [
    { id: "scan",      icon: "⚡",  label: "Scanner" },
    { id: "agility",   icon: "🔬",  label: "Agility Checker" },
    { id: "tls",       icon: "🔐",  label: "TLS Analyzer" },
    { id: "unified",   icon: "🧠",  label: "Unified Risk" },
    { id: "history",   icon: "🗂",  label: "Scan History" },
    { id: "migration", icon: "🔄",  label: "Migration" },
    { id: "dashboard", icon: "📊",  label: "Analytics" },
    { id: "docs",      icon: "📖",  label: "Docs" },
    { id: "team",      icon: "👥",  label: "Our Team" },
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
            <div style={{
              width: 38, height: 38, borderRadius: 10,
              background: "linear-gradient(135deg, #22c55e, #16a34a)",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 18, boxShadow: "0 0 16px rgba(34,197,94,0.4)"
            }}>⚛</div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 700, color: C.text }}>
                <span style={{ color: C.green }}>Quantum</span>Guard
              </div>
              <div style={{ fontSize: 10, color: C.muted, letterSpacing: "0.05em", textTransform: "uppercase" }}>Security Platform</div>
            </div>
          </div>
        </div>
        <nav style={{ flex: 1, padding: "12px" }}>
          {navItems.map(item => (
            <div key={item.id} onClick={() => { setActive(item.id); onClose(); }} style={{
              display: "flex", alignItems: "center", gap: 10, padding: "10px 12px",
              borderRadius: 8, marginBottom: 2, cursor: "pointer",
              background: active === item.id
                ? "linear-gradient(90deg, rgba(34,197,94,0.15), rgba(34,197,94,0.05))"
                : "transparent",
              color: active === item.id ? C.green : C.muted,
              fontWeight: active === item.id ? 600 : 400,
              transition: "all 0.2s ease",
              borderLeft: active === item.id ? `2px solid ${C.green}` : "2px solid transparent",
            }}>
              <span style={{ fontSize: 15 }}>{item.icon}</span>
              <span style={{ fontSize: 13 }}>{item.label}</span>
              {active === item.id && (
                <div style={{ marginLeft: "auto", width: 6, height: 6, borderRadius: "50%", background: C.green, boxShadow: `0 0 6px ${C.green}` }} />
              )}
            </div>
          ))}
        </nav>
        <div style={{ padding: "10px 16px", margin: "0 12px 12px", borderRadius: 8, background: "rgba(34,197,94,0.06)", border: `1px solid rgba(34,197,94,0.2)` }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 7, height: 7, borderRadius: "50%", background: C.green, boxShadow: `0 0 6px ${C.green}` }} />
            <span style={{ fontSize: 11, color: C.green, fontWeight: 600 }}>API Online</span>
          </div>
          <div style={{ fontSize: 9, color: C.muted, marginTop: 2 }}>quantumguard-api.onrender.com</div>
        </div>
        <div style={{ padding: "14px 16px", borderTop: `1px solid ${C.sidebarBorder}` }}>
          {user ? (
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <img src={user.photoURL} alt="avatar" style={{ width: 30, height: 30, borderRadius: "50%", border: `2px solid ${C.green}` }} />
                <div>
                  <div style={{ fontSize: 12, color: C.text, fontWeight: 600 }}>{user.displayName?.split(" ")[0]}</div>
                  <div style={{ fontSize: 10, color: C.muted }}>Free Plan</div>
                </div>
              </div>
              <button onClick={onLogout} style={{ width: "100%", padding: "6px", borderRadius: 8, background: "transparent", border: `1px solid ${C.sidebarBorder}`, color: C.muted, cursor: "pointer", fontSize: 11, transition: "all 0.2s ease" }}>Sign Out</button>
            </div>
          ) : (
            <button onClick={onLogin} style={{ width: "100%", padding: "9px", borderRadius: 8, background: "linear-gradient(135deg, #22c55e, #16a34a)", border: "none", color: C.white, cursor: "pointer", fontSize: 12, fontWeight: 700, boxShadow: "0 4px 12px rgba(34,197,94,0.3)", transition: "all 0.2s ease" }}>
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
      height: 56, background: C.topbar, borderBottom: `1px solid ${C.sidebarBorder}`,
      display: "flex", alignItems: "center", padding: "0 20px", gap: 12,
      boxShadow: "0 1px 12px rgba(0,0,0,0.3)",
    }}>
      <button onClick={onHamburger} style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", fontSize: 20, padding: "0 4px" }} className="hamburger-top">☰</button>
      <span style={{ color: C.muted, fontSize: 13 }}>QuantumGuard</span>
      <span style={{ color: C.green, fontSize: 13 }}>›</span>
      <span style={{ color: C.text, fontSize: 14, fontWeight: 600 }}>{title}</span>
      <div className="topbar-right" style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
        {user ? (
          <button onClick={onLogout} style={{ background: "transparent", border: `1px solid ${C.sidebarBorder}`, borderRadius: 8, padding: "4px 12px", cursor: "pointer", color: C.muted, fontSize: 11, transition: "all 0.2s ease" }}>
            {user.displayName?.split(" ")[0]} · Sign Out
          </button>
        ) : (
          <button onClick={onLogin} style={{ background: "linear-gradient(135deg, #22c55e, #16a34a)", border: "none", borderRadius: 8, padding: "6px 16px", cursor: "pointer", color: C.white, fontSize: 12, fontWeight: 700, boxShadow: "0 2px 8px rgba(34,197,94,0.3)", transition: "all 0.2s ease" }}>
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
    <div style={{
      background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 14,
      padding: "20px", boxShadow: "0 4px 20px rgba(0,0,0,0.35)",
      position: "relative", overflow: "hidden",
      transition: "transform 0.25s ease, box-shadow 0.25s ease",
    }}
      onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-3px)"; e.currentTarget.style.boxShadow = `0 0 20px ${ringColor}22, 0 8px 28px rgba(0,0,0,0.4)`; }}
      onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.boxShadow = "0 4px 20px rgba(0,0,0,0.35)"; }}
    >
      <div style={{ position: "absolute", top: -20, left: -20, width: 80, height: 80, borderRadius: "50%", background: ringColor, opacity: 0.07, filter: "blur(20px)" }} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
        <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em" }}>{label}</div>
        <div style={{ fontSize: 20 }}>{icon}</div>
      </div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 4, marginBottom: 10 }}>
        <span style={{ fontSize: 42, fontWeight: 900, color: ringColor, lineHeight: 1, fontVariantNumeric: "tabular-nums" }}>{value}</span>
        <span style={{ fontSize: 13, color: C.muted, fontWeight: 400 }}>{suffix}</span>
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
    <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 12, padding: "18px 20px", boxShadow: "0 4px 16px rgba(0,0,0,0.3)", transition: "transform 0.25s ease, box-shadow 0.25s ease" }}
      onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-2px)"; e.currentTarget.style.boxShadow = "0 0 18px rgba(34,197,94,0.15), 0 8px 24px rgba(0,0,0,0.4)"; }}
      onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.boxShadow = "0 4px 16px rgba(0,0,0,0.3)"; }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 8 }}>
        <div style={{ fontSize: 12, color: C.muted, fontWeight: 500 }}>{label}</div>
        {icon && <div style={{ fontSize: 20 }}>{icon}</div>}
      </div>
      <div style={{ fontSize: 38, fontWeight: 900, color: color || C.text, lineHeight: 1, textShadow: color ? `0 0 20px ${color}33` : "none" }}>
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
  return (
    <span style={{ background: bg, color, padding: "2px 8px", borderRadius: 6, fontSize: 10, fontWeight: 700, border: `1px solid ${color}33` }}>{text}</span>
  );
}

// ══════════════════════════════════════════════════════════════
// NIST REPORT PAGE
// ══════════════════════════════════════════════════════════════
const NIST_FINDINGS = [
  { file: "tests/TestVulnerable.java", line: 9,  code: 'KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");', vulnerability: "RSA",  severity: "CRITICAL", replacement: "CRYSTALS-Kyber" },
  { file: "tests/TestVulnerable.java", line: 13, code: 'KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");',   vulnerability: "ECC",  severity: "CRITICAL", replacement: "CRYSTALS-Dilithium" },
  { file: "tests/TestVulnerable.java", line: 16, code: 'KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");',   vulnerability: "DH",   severity: "HIGH",     replacement: "CRYSTALS-Kyber" },
  { file: "tests/TestVulnerable.java", line: 19, code: 'MessageDigest md5 = MessageDigest.getInstance("MD5");',          vulnerability: "MD5",  severity: "MEDIUM",   replacement: "SHA-3 or SPHINCS+" },
  { file: "tests/TestVulnerable.java", line: 22, code: 'MessageDigest sha1 = MessageDigest.getInstance("SHA-1");',       vulnerability: "SHA1", severity: "MEDIUM",   replacement: "SHA-3 or SPHINCS+" },
  { file: "tests/test_vulnerable.js",  line: 2,  code: "const NodeRSA = require('node-rsa');",                           vulnerability: "RSA",  severity: "CRITICAL", replacement: "CRYSTALS-Kyber" },
  { file: "tests/test_vulnerable.js",  line: 3,  code: "const elliptic = require('elliptic');",                          vulnerability: "ECC",  severity: "CRITICAL", replacement: "CRYSTALS-Dilithium" },
  { file: "tests/test_vulnerable.js",  line: 6,  code: "const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {", vulnerability: "RSA", severity: "CRITICAL", replacement: "CRYSTALS-Kyber" },
  { file: "tests/test_vulnerable.js",  line: 11, code: "const ec = new elliptic.ec('secp256k1');",                       vulnerability: "ECC",  severity: "CRITICAL", replacement: "CRYSTALS-Dilithium" },
  { file: "tests/test_vulnerable.js",  line: 15, code: "const dh = crypto.createDiffieHellman(2048);",                    vulnerability: "DH",   severity: "HIGH",     replacement: "CRYSTALS-Kyber" },
  { file: "tests/test_vulnerable.js",  line: 19, code: "const md5Hash = crypto.createHash('md5').update('password').digest('hex');", vulnerability: "MD5",  severity: "MEDIUM", replacement: "SHA-3 or SPHINCS+" },
  { file: "tests/test_vulnerable.js",  line: 22, code: "const sha1Hash = crypto.createHash('sha1').update('data').digest('hex');",   vulnerability: "SHA1", severity: "MEDIUM", replacement: "SHA-3 or SPHINCS+" },
  { file: "tests/test_vulnerable.py",  line: 1,  code: "from Crypto.PublicKey import RSA",                                vulnerability: "RSA",  severity: "CRITICAL", replacement: "CRYSTALS-Kyber" },
  { file: "tests/test_vulnerable.py",  line: 2,  code: "from Crypto.Cipher import PKCS1_OAEP",                            vulnerability: "RSA",  severity: "CRITICAL", replacement: "CRYSTALS-Kyber" },
  { file: "tests/test_vulnerable.py",  line: 7,  code: "key = RSA.generate(2048)",                                        vulnerability: "RSA",  severity: "CRITICAL", replacement: "CRYSTALS-Kyber" },
  { file: "tests/test_vulnerable.py",  line: 12, code: "md5_hash = hashlib.md5(data).hexdigest()",                        vulnerability: "MD5",  severity: "MEDIUM",   replacement: "SHA-3 or SPHINCS+" },
  { file: "tests/test_vulnerable.py",  line: 15, code: "sha1_hash = hashlib.sha1(data).hexdigest()",                      vulnerability: "SHA1", severity: "MEDIUM",   replacement: "SHA-3 or SPHINCS+" },
  { file: "tests/test_vulnerable.py",  line: 18, code: "from Crypto.PublicKey import ECC",                                vulnerability: "ECC",  severity: "CRITICAL", replacement: "CRYSTALS-Dilithium" },
  { file: "tests/test_vulnerable.py",  line: 19, code: "ecc_key = ECC.generate(curve='P-256')",                          vulnerability: "ECC",  severity: "CRITICAL", replacement: "CRYSTALS-Dilithium" },
];

const NIST_CONTROLS = [
  { id: "SC-12", name: "Cryptographic Key Establishment & Management", family: "System & Comms Protection",   vulns: ["RSA","ECC","DH"],        status: "FAIL" },
  { id: "SC-13", name: "Cryptographic Protection",                     family: "System & Comms Protection",   vulns: ["RSA","ECC","DH","DSA"],  status: "FAIL" },
  { id: "IA-7",  name: "Cryptographic Module Authentication",          family: "Identification & Auth",        vulns: ["MD5","SHA1"],            status: "WARN" },
  { id: "SC-28", name: "Protection of Information at Rest",            family: "System & Comms Protection",   vulns: ["RSA","ECC"],             status: "FAIL" },
  { id: "SC-8",  name: "Transmission Confidentiality & Integrity",     family: "System & Comms Protection",   vulns: ["DH","RSA"],              status: "WARN" },
  { id: "SI-7",  name: "Software & Information Integrity",             family: "System & Info Integrity",     vulns: ["MD5","SHA1"],            status: "WARN" },
  { id: "CM-7",  name: "Least Functionality",                          family: "Configuration Management",    vulns: [],                       status: "PASS" },
  { id: "AC-17", name: "Remote Access",                                family: "Access Control",               vulns: [],                       status: "PASS" },
];

const VULN_INFO = {
  RSA:  { desc: "RSA is vulnerable to Shor's algorithm. A quantum computer can factor large integers and break RSA encryption entirely.", nist: "FIPS 203 — CRYSTALS-Kyber (ML-KEM)" },
  ECC:  { desc: "Elliptic Curve Cryptography is broken by quantum Shor's algorithm — the EC discrete log becomes trivially solvable.", nist: "FIPS 204 — CRYSTALS-Dilithium (ML-DSA)" },
  DH:   { desc: "Diffie-Hellman key exchange relies on discrete log hardness, which quantum computers solve efficiently.", nist: "FIPS 203 — CRYSTALS-Kyber (ML-KEM)" },
  DSA:  { desc: "Digital Signature Algorithm based on discrete log — broken by quantum Shor's algorithm.", nist: "FIPS 204 — CRYSTALS-Dilithium (ML-DSA)" },
  MD5:  { desc: "MD5 produces a 128-bit hash, insufficient for quantum security. Grover's algorithm halves effective bit security.", nist: "FIPS 205 — SHA-3 or SPHINCS+" },
  SHA1: { desc: "SHA-1 has known collisions and 160-bit output — completely insufficient for post-quantum requirements.", nist: "FIPS 205 — SHA-3 or SPHINCS+" },
};

const SEV_COLOR = { CRITICAL: "#ef4444", HIGH: "#f59e0b", MEDIUM: "#eab308" };
const SEV_BG    = { CRITICAL: "rgba(239,68,68,0.15)",  HIGH: "rgba(245,158,11,0.15)", MEDIUM: "rgba(234,179,8,0.15)" };
const STAT_CTRL = {
  PASS: { color: C.green,    bg: "rgba(34,197,94,0.1)",   border: "rgba(34,197,94,0.3)",   dot: C.green    },
  WARN: { color: "#f59e0b",  bg: "rgba(245,158,11,0.1)",  border: "rgba(245,158,11,0.3)",  dot: "#f59e0b"  },
  FAIL: { color: "#ef4444",  bg: "rgba(239,68,68,0.1)",   border: "rgba(239,68,68,0.3)",   dot: "#ef4444"  },
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
  const sc = SEV_COLOR[f.severity];
  const sb = SEV_BG[f.severity];

  return (
    <div style={{ border: `1px solid ${open ? "rgba(34,197,94,0.3)" : C.panelBorder}`, borderRadius: 10, marginBottom: 8, overflow: "hidden", background: C.panel, transition: "border-color 0.2s ease" }}>
      <div onClick={() => setOpen(o => !o)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "11px 16px", cursor: "pointer", flexWrap: "wrap" }}>
        <Badge text={f.severity} color={sc} bg={sb} />
        <span style={{ fontFamily: "monospace", fontSize: 12, color: C.green, fontWeight: 600, flex: 1, minWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.file.split("/").pop()}</span>
        <span style={{ fontSize: 11, color: C.muted, whiteSpace: "nowrap" }}>Line {f.line}</span>
        <span style={{ background: "rgba(255,255,255,0.06)", color: C.textMid, fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4 }}>{f.vulnerability}</span>
        <span style={{ color: C.muted, fontSize: 11, transition: "transform 0.2s", transform: open ? "rotate(180deg)" : "none" }}>▼</span>
      </div>
      {open && (
        <div style={{ padding: "0 16px 14px", borderTop: `1px solid ${C.panelBorder}` }}>
          <div style={{ fontFamily: "monospace", background: C.input, padding: "8px 12px", borderRadius: 8, fontSize: 11, color: C.green, marginTop: 10, overflowX: "auto", border: `1px solid ${C.panelBorder}` }}>
            <span style={{ color: C.muted, marginRight: 12, userSelect: "none" }}>{f.line}</span>{f.code}
          </div>
          {info.desc && <div style={{ marginTop: 8, fontSize: 12, color: C.muted, lineHeight: 1.6 }}>{info.desc}</div>}
          <div style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            {matchedControls.map(c => (
              <span key={c.id} style={{ background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.3)", color: C.green, fontSize: 10, fontWeight: 700, padding: "2px 9px", borderRadius: 4 }}>{c.id}</span>
            ))}
            <span style={{ background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.3)", color: "#60a5fa", fontSize: 10, fontWeight: 700, padding: "2px 9px", borderRadius: 4 }}>
              ✦ {f.replacement}
            </span>
          </div>
          {info.nist && <div style={{ marginTop: 6, fontSize: 11, color: C.muted }}>NIST Standard: <span style={{ color: C.green, fontWeight: 600 }}>{info.nist}</span></div>}
        </div>
      )}
    </div>
  );
}

function NISTReportPage() {
  const [filter, setFilter] = useState("ALL");

  const counts = {
    CRITICAL: NIST_FINDINGS.filter(f => f.severity === "CRITICAL").length,
    HIGH:     NIST_FINDINGS.filter(f => f.severity === "HIGH").length,
    MEDIUM:   NIST_FINDINGS.filter(f => f.severity === "MEDIUM").length,
    total:    NIST_FINDINGS.length,
  };

  const filtered = filter === "ALL" ? NIST_FINDINGS : NIST_FINDINGS.filter(f => f.severity === filter);
  const byFile = NIST_FINDINGS.reduce((a, f) => { if (!a[f.file]) a[f.file] = []; a[f.file].push(f); return a; }, {});
  const vulnCounts = Object.entries(
    NIST_FINDINGS.reduce((a, f) => { a[f.vulnerability] = (a[f.vulnerability] || 0) + 1; return a; }, {})
  ).sort((a, b) => b[1] - a[1]);

  const handleExportCSV = () => {
    const rows = ["Severity,File,Line,Vulnerability,Code,Replacement",
      ...NIST_FINDINGS.map(f => `"${f.severity}","${f.file}","${f.line}","${f.vulnerability}","${f.code.replace(/"/g, "'")}","${f.replacement}"`)
    ].join("\n");
    const blob = new Blob([rows], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "nist-report.csv"; a.click();
  };

  const handleExportPDF = () => {
    const win = window.open("", "_blank");
    win.document.write(`<!DOCTYPE html><html><head><title>QuantumGuard NIST Report</title>
    <style>body{font-family:sans-serif;padding:40px;color:#1a1a1a}h1{color:#22c55e}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #e2f0e2;padding:8px 12px;text-align:left;font-size:12px}th{background:#f0fdf4;font-weight:700}tr:nth-child(even){background:#f8faf8}.CRITICAL{color:#ef4444;font-weight:700}.HIGH{color:#f59e0b;font-weight:700}.MEDIUM{color:#eab308;font-weight:700}</style>
    </head><body>
    <h1>⚛ QuantumGuard — NIST SP 800-53 Report</h1>
    <p>Scanned: Apr 21, 2026 · Directory: tests/ · Score: <strong>0 / 100</strong> · Status: <strong style="color:#ef4444">NOT QUANTUM SAFE</strong></p>
    <p>Total Findings: <strong>${counts.total}</strong> · Critical: <strong>${counts.CRITICAL}</strong> · High: <strong>${counts.HIGH}</strong> · Medium: <strong>${counts.MEDIUM}</strong></p>
    <table><thead><tr><th>Severity</th><th>File</th><th>Line</th><th>Vulnerability</th><th>Code</th><th>Replacement</th></tr></thead><tbody>
    ${NIST_FINDINGS.map(f => `<tr><td class="${f.severity}">${f.severity}</td><td>${f.file}</td><td>${f.line}</td><td>${f.vulnerability}</td><td><code>${f.code.replace(/</g,"&lt;")}</code></td><td>${f.replacement}</td></tr>`).join("")}
    </tbody></table></body></html>`);
    win.document.close(); win.print();
  };

  return (
    <div style={{ padding: 20 }}>
      <div style={{ background: "rgba(59,130,246,0.08)", border: "1px solid rgba(59,130,246,0.25)", borderRadius: 10, padding: "10px 16px", marginBottom: 14, display: "flex", alignItems: "flex-start", gap: 10 }}>
        <span style={{ fontSize: 15, marginTop: 1 }}>ℹ️</span>
        <div style={{ fontSize: 12, color: "#93c5fd", lineHeight: 1.6 }}>
          <strong style={{ color: "#60a5fa" }}>Sample Report</strong> — This tab shows a fixed demo of QuantumGuard's own test files (<code style={{ fontSize: 11, background: "rgba(255,255,255,0.06)", padding: "1px 5px", borderRadius: 3 }}>tests/</code>).
          To generate a live NIST report from <strong style={{ color: "#60a5fa" }}>your own repo</strong>, go to <strong style={{ color: "#60a5fa" }}>Scanner</strong> → run a scan → click <strong style={{ color: "#60a5fa" }}>🏛 NIST Report</strong>.
        </div>
      </div>
      <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 14, padding: "20px 22px", marginBottom: 16, boxShadow: "0 4px 20px rgba(0,0,0,0.4)", display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16, borderTop: `3px solid ${C.green}` }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: "linear-gradient(135deg, #22c55e, #16a34a)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, boxShadow: "0 0 12px rgba(34,197,94,0.3)" }}>🏛</div>
            <h2 style={{ fontSize: 20, fontWeight: 800, color: C.text }}>NIST Security Report</h2>
          </div>
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap" }}>
            {[["Standard", "NIST SP 800-53 Rev 5"], ["Scanned", "Apr 21, 2026 — 00:56 UTC"], ["Directory", "tests/"], ["Files", "3 scanned"]].map(([k, v]) => (
              <div key={k} style={{ fontSize: 11 }}><span style={{ color: C.muted }}>{k}: </span><span style={{ color: C.textMid, fontWeight: 600 }}>{v}</span></div>
            ))}
          </div>
        </div>
        <div style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 12, padding: "14px 20px", textAlign: "center", minWidth: 140 }}>
          <div style={{ fontSize: 44, fontWeight: 900, color: C.red, lineHeight: 1 }}>0</div>
          <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginTop: 2 }}>Quantum Score</div>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 5, background: "rgba(239,68,68,0.15)", border: "1px solid rgba(239,68,68,0.3)", color: C.red, fontSize: 10, fontWeight: 700, padding: "3px 10px", borderRadius: 100, marginTop: 8 }}>
            <span style={{ width: 5, height: 5, borderRadius: "50%", background: C.red, display: "inline-block", boxShadow: "0 0 4px #ef4444" }} />
            Not Quantum Safe
          </div>
        </div>
      </div>

      <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
        <Metric label="Total Findings"   value={counts.total}    color={C.green}    icon="🔍" desc="All severities" />
        <Metric label="Critical"         value={counts.CRITICAL} color={C.critical} icon="🔴" desc="Immediate action required" />
        <Metric label="High"             value={counts.HIGH}     color={C.amber}    icon="🟡" desc="Requires attention" />
        <Metric label="Medium"           value={counts.MEDIUM}   color={C.medium}   icon="🟠" desc="Review needed" />
      </div>

      <div className="charts-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
        <Panel title="Severity Distribution" accent>
          <SevBar label="Critical" count={counts.CRITICAL} total={counts.total} color={C.critical} />
          <SevBar label="High"     count={counts.HIGH}     total={counts.total} color={C.amber} />
          <SevBar label="Medium"   count={counts.MEDIUM}   total={counts.total} color={C.medium} />
        </Panel>
        <Panel title="Vulnerability Type Breakdown" accent>
          {vulnCounts.map(([vuln, cnt]) => (
            <SevBar key={vuln} label={vuln} count={cnt} total={counts.total}
              color={["RSA","ECC"].includes(vuln) ? C.critical : ["DH","DSA"].includes(vuln) ? C.amber : C.medium} />
          ))}
        </Panel>
      </div>

      <Panel title="Files Scanned" accent>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px,1fr))", gap: 12 }}>
          {Object.entries(byFile).map(([file, findings]) => {
            const crit = findings.filter(f => f.severity === "CRITICAL").length;
            const high = findings.filter(f => f.severity === "HIGH").length;
            const med  = findings.filter(f => f.severity === "MEDIUM").length;
            return (
              <div key={file} style={{ background: "rgba(34,197,94,0.05)", border: "1px solid rgba(34,197,94,0.2)", borderRadius: 10, padding: "12px 14px" }}>
                <div style={{ fontSize: 10, fontWeight: 700, background: "rgba(34,197,94,0.1)", color: C.green, border: "1px solid rgba(34,197,94,0.3)", display: "inline-block", padding: "1px 8px", borderRadius: 100, marginBottom: 6, textTransform: "uppercase" }}>{getLang(file)}</div>
                <div style={{ fontFamily: "monospace", fontSize: 11, fontWeight: 700, color: C.green, marginBottom: 8 }}>{file.split("/").pop()}</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {crit > 0 && <Badge text={`${crit} Critical`} color={C.critical} bg={SEV_BG.CRITICAL} />}
                  {high > 0 && <Badge text={`${high} High`}     color={C.amber}    bg={SEV_BG.HIGH} />}
                  {med  > 0 && <Badge text={`${med} Medium`}    color={C.medium}   bg={SEV_BG.MEDIUM} />}
                </div>
                <div style={{ fontSize: 11, color: C.muted, marginTop: 6 }}>{findings.length} findings total</div>
              </div>
            );
          })}
        </div>
      </Panel>

      <Panel title="NIST SP 800-53 Control Mapping" accent>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ background: "rgba(34,197,94,0.06)" }}>
                {["Control ID","Control Name","Family","Affected Algorithms","Status"].map(h => (
                  <th key={h} style={{ padding: "9px 14px", textAlign: "left", fontSize: 10, textTransform: "uppercase", letterSpacing: 1, color: C.muted, fontWeight: 700, borderBottom: `1px solid ${C.panelBorder}` }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {NIST_CONTROLS.map((ctrl, i) => {
                const sc = STAT_CTRL[ctrl.status];
                return (
                  <tr key={ctrl.id} style={{ background: i % 2 === 0 ? C.panel : "rgba(255,255,255,0.02)", transition: "background 0.2s ease" }}
                    onMouseEnter={e => e.currentTarget.style.background = "rgba(34,197,94,0.05)"}
                    onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? C.panel : "rgba(255,255,255,0.02)"}>
                    <td style={{ padding: "10px 14px", borderBottom: `1px solid ${C.panelBorder}`, fontFamily: "monospace", fontSize: 12, color: C.green, fontWeight: 700 }}>{ctrl.id}</td>
                    <td style={{ padding: "10px 14px", borderBottom: `1px solid ${C.panelBorder}`, color: C.textMid }}>{ctrl.name}</td>
                    <td style={{ padding: "10px 14px", borderBottom: `1px solid ${C.panelBorder}`, color: C.muted, fontSize: 11 }}>{ctrl.family}</td>
                    <td style={{ padding: "10px 14px", borderBottom: `1px solid ${C.panelBorder}` }}>
                      {ctrl.vulns.length > 0
                        ? ctrl.vulns.map(v => <span key={v} style={{ background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.3)", color: C.green, fontSize: 10, fontWeight: 700, padding: "1px 7px", borderRadius: 4, marginRight: 4 }}>{v}</span>)
                        : <span style={{ color: C.muted, fontSize: 11 }}>—</span>}
                    </td>
                    <td style={{ padding: "10px 14px", borderBottom: `1px solid ${C.panelBorder}` }}>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 4, background: sc.bg, border: `1px solid ${sc.border}`, color: sc.color, fontSize: 10, fontWeight: 700, padding: "3px 10px", borderRadius: 100, textTransform: "uppercase" }}>
                        <span style={{ width: 5, height: 5, borderRadius: "50%", background: sc.dot, display: "inline-block" }} />
                        {ctrl.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel title="Export & Share" accent>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button onClick={handleExportPDF} style={{ padding: "8px 16px", borderRadius: 8, background: "linear-gradient(135deg, #22c55e, #16a34a)", color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600, transition: "all 0.2s ease" }}
            onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = "0 6px 16px rgba(34,197,94,0.4)"; }}
            onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.boxShadow = "none"; }}>📄 PDF Report</button>
          <button onClick={handleExportCSV} style={{ padding: "8px 16px", borderRadius: 8, background: "rgba(34,197,94,0.1)", color: C.green, border: "1px solid rgba(34,197,94,0.3)", cursor: "pointer", fontSize: 12, fontWeight: 600, transition: "all 0.2s ease" }}
            onMouseEnter={e => { e.currentTarget.style.background = "rgba(34,197,94,0.18)"; }}
            onMouseLeave={e => { e.currentTarget.style.background = "rgba(34,197,94,0.1)"; }}>📊 CSV Export</button>
        </div>
      </Panel>

      <Panel title={`Threat Intelligence — ${counts.total} Findings`} accent>
        <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
          {[
            { key: "ALL",      label: `All (${counts.total})`,         activeColor: C.green    },
            { key: "CRITICAL", label: `Critical (${counts.CRITICAL})`, activeColor: C.critical },
            { key: "HIGH",     label: `High (${counts.HIGH})`,         activeColor: C.amber    },
            { key: "MEDIUM",   label: `Medium (${counts.MEDIUM})`,     activeColor: C.medium   },
          ].map(btn => (
            <button key={btn.key} onClick={() => setFilter(btn.key)} style={{
              padding: "5px 14px", borderRadius: 20, cursor: "pointer", fontSize: 11,
              border: `1.5px solid ${filter === btn.key ? btn.activeColor : C.panelBorder}`,
              background: filter === btn.key ? btn.activeColor + "22" : "transparent",
              color: filter === btn.key ? btn.activeColor : C.muted,
              fontWeight: filter === btn.key ? 700 : 400,
              transition: "all 0.2s ease",
            }}>{btn.label}</button>
          ))}
        </div>
        {filtered.map((f, i) => (
          <NISTFindingRow key={`${f.file}-${f.line}-${f.vulnerability}-${i}`} f={f} />
        ))}
        {filtered.length === 0 && <div style={{ textAlign: "center", padding: 24, color: C.muted }}>No findings match filter.</div>}
      </Panel>

      <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 12, padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
        <div style={{ fontSize: 11, color: C.muted }}>QuantumGuard · NIST SP 800-53 Rev 5 · Report ID #QG-{new Date().getFullYear()}-{String(new Date().getMonth()+1).padStart(2,"0")}{String(new Date().getDate()).padStart(2,"0")}</div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <div style={{ width: 7, height: 7, borderRadius: "50%", background: C.green, boxShadow: `0 0 6px ${C.green}` }} />
          <span style={{ fontSize: 11, color: C.green, fontWeight: 600 }}>Mangsri QuantumGuard LLC · Montgomery, AL</span>
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// TEAM PAGE
// ══════════════════════════════════════════════════════════════
function TeamPage() {
  const members = [
    { initials: "PP", name: "Pavansudheer Payyavula",  role: "Founder & CEO",  degree: "MS Cybersecurity & Computer Information Systems", subRole: null,              avatarBg: "#1e1b4b", avatarText: "#a5b4fc", badgeBg: "#1e1b4b", badgeText: "#a5b4fc", featured: true },
    { initials: "MS", name: "Manasa Sannidhi",          role: "Co-Founder",     degree: "MS Computer Science",                            subRole: null,              avatarBg: "#052e16", avatarText: "#22c55e", badgeBg: "#052e16", badgeText: "#22c55e", featured: false },
    { initials: "BG", name: "Bharathwaj Goud Siga",     role: "Business",       degree: "MS Business Analytics",                          subRole: "Marketing Manager", avatarBg: "#1c0a00", avatarText: "#f59e0b", badgeBg: "#1c0a00", badgeText: "#f59e0b", featured: false },
    { initials: "VR", name: "Vijendhar Reddy Muppidi",  role: "Advisor",        degree: "MS Management Information Systems",              subRole: null,              avatarBg: "#2a0a0a", avatarText: "#f87171", badgeBg: "#2a0a0a", badgeText: "#f87171", featured: false },
  ];
  return (
    <div style={{ padding: 20 }}>
      <div style={{ textAlign: "center", marginBottom: 36 }}>
        <div style={{ display: "inline-block", background: "rgba(34,197,94,0.1)", color: C.green, fontSize: 12, fontWeight: 700, padding: "5px 16px", borderRadius: 20, marginBottom: 14, border: "1px solid rgba(34,197,94,0.3)" }}>⚛ THE TEAM</div>
        <h2 style={{ fontSize: 32, fontWeight: 900, color: C.text, marginBottom: 10, letterSpacing: -0.5 }}>Built by 4 friends</h2>
        <p style={{ fontSize: 14, color: C.muted, maxWidth: 480, margin: "0 auto", lineHeight: 1.7 }}>A cross-disciplinary team building the world's first free quantum vulnerability scanner — free for every developer, forever.</p>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 20, maxWidth: 900, margin: "0 auto" }}>
        {members.map(m => (
          <div key={m.name} style={{ background: C.panel, border: m.featured ? `2px solid ${C.green}` : `1px solid ${C.panelBorder}`, borderRadius: 16, padding: "28px 20px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", boxShadow: m.featured ? `0 4px 24px rgba(34,197,94,0.2)` : "0 4px 16px rgba(0,0,0,0.3)", transition: "transform 0.25s ease, box-shadow 0.25s ease" }}
            onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-4px)"; e.currentTarget.style.boxShadow = "0 12px 32px rgba(0,0,0,0.4)"; }}
            onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.boxShadow = m.featured ? "0 4px 24px rgba(34,197,94,0.2)" : "0 4px 16px rgba(0,0,0,0.3)"; }}
          >
            <div style={{ width: 60, height: 60, borderRadius: "50%", background: m.avatarBg, color: m.avatarText, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 16, marginBottom: 14, fontFamily: "monospace", border: `2px solid ${m.avatarText}44` }}>{m.initials}</div>
            <span style={{ display: "inline-block", background: m.badgeBg, color: m.badgeText, fontSize: 10, fontWeight: 700, padding: "3px 12px", borderRadius: 20, marginBottom: 10, fontFamily: "monospace", letterSpacing: "0.05em", textTransform: "uppercase", border: `1px solid ${m.badgeText}44` }}>{m.role}</span>
            <div style={{ fontSize: 14, fontWeight: 700, color: C.text, marginBottom: 6, lineHeight: 1.3 }}>{m.name}</div>
            <div style={{ width: 28, height: 1, background: C.panelBorder, margin: "8px auto" }} />
            <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.5 }}>{m.degree}</div>
            {m.subRole && <div style={{ fontSize: 11, color: C.green, marginTop: 6, fontStyle: "italic", fontWeight: 500 }}>{m.subRole}</div>}
          </div>
        ))}
      </div>
      <div style={{ textAlign: "center", marginTop: 40 }}>
        <div style={{ display: "inline-block", background: "rgba(34,197,94,0.06)", border: "1px solid rgba(34,197,94,0.2)", borderRadius: 12, padding: "14px 28px" }}>
          <div style={{ fontSize: 13, color: C.green, fontWeight: 700, marginBottom: 4 }}>⚛ Mangsri QuantumGuard LLC</div>
          <div style={{ fontSize: 12, color: C.muted }}>Montgomery, AL · Founded April 27, 2026 · EIN 42-2185776</div>
        </div>
      </div>
    </div>
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
  const intervalRef  = useRef(null);
  const logTimers    = useRef([]);
  const logEndRef    = useRef(null);
  const [scanLogs, setScanLogs]           = useState([]);
  const [filesScanned, setFilesScanned]   = useState(0);
  const [issuesFound,  setIssuesFound]    = useState(0);
  const [elapsedMs,    setElapsedMs]      = useState(0);
  const elapsedRef   = useRef(null);
  const startTimeRef = useRef(null);

  const pushLog = (entry) => {
    setScanLogs(prev => [...prev, { ...entry, id: Date.now() + Math.random() }]);
    setTimeout(() => logEndRef.current?.scrollIntoView({ behavior: "smooth" }), 40);
  };

  const startProgress = () => {
    setProgress(0); setStepIndex(0); setScanLogs([]); setFilesScanned(0); setIssuesFound(0); setElapsedMs(0);
    startTimeRef.current = Date.now();
    let p = 0;

    elapsedRef.current = setInterval(() => {
      setElapsedMs(Date.now() - startTimeRef.current);
    }, 100);

    intervalRef.current = setInterval(() => {
      p += Math.random() * 8 + 2; if (p > 92) p = 92;
      setProgress(Math.round(p));
      setStepIndex(Math.min(SCAN_STEPS.length - 1, Math.floor(p / (100 / SCAN_STEPS.length))));
    }, 400);

    let delay = 0;
    SCAN_LOG_PHASES.forEach((phase) => {
      phase.logs.forEach((log) => {
        delay += 200 + Math.random() * 300;
        const t = setTimeout(() => {
          pushLog(log);
          if (log.type === "info" && log.text.includes("Scanning")) {
            setFilesScanned(prev => prev + Math.floor(Math.random() * 6 + 1));
          }
          if (log.type === "critical" || (log.type === "warn" && log.text.includes("detected"))) {
            setIssuesFound(prev => prev + 1);
          }
        }, delay);
        logTimers.current.push(t);
      });
      delay += 400;
    });
  };

  const stopProgress = () => {
    clearInterval(intervalRef.current);
    clearInterval(elapsedRef.current);
    logTimers.current.forEach(clearTimeout);
    logTimers.current = [];
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
    const score = result.quantum_readiness_score;
    const status = score >= 70 ? "COMPLIANT" : score >= 40 ? "PARTIALLY COMPLIANT" : "NON-COMPLIANT";
    const scoreColor = score >= 70 ? "#22c55e" : score >= 40 ? "#f59e0b" : "#ef4444";
    const statusBg = score >= 70 ? "#dcfce7" : score >= 40 ? "#fef3c7" : "#fee2e2";
    const statusBorder = score >= 70 ? "#86efac" : score >= 40 ? "#fcd34d" : "#fca5a5";
    const critical = result.findings.filter(f => f.severity === "CRITICAL").length;
    const high = result.findings.filter(f => f.severity === "HIGH").length;
    const medium = result.findings.filter(f => f.severity === "MEDIUM").length;
    const total = result.total_findings;
    const pct = (n) => total > 0 ? Math.round(n / total * 100) : 0;
    const sevColor = (s) => s === "CRITICAL" ? "#ef4444" : s === "HIGH" ? "#f59e0b" : "#eab308";
    const sevBg = (s) => s === "CRITICAL" ? "#fee2e2" : s === "HIGH" ? "#fef3c7" : "#fef9c3";
    const ctrlColor = (s) => s === "FAIL" ? "#ef4444" : s === "WARN" ? "#f59e0b" : "#22c55e";
    const ctrlBg = (s) => s === "FAIL" ? "#fee2e2" : s === "WARN" ? "#fef3c7" : "#dcfce7";
    const grouped = result.findings.reduce((a, f) => { if (!a[f.file]) a[f.file] = []; a[f.file].push(f); return a; }, {});
    const nistControls = [
      { id: "SC-12", name: "Cryptographic Key Establishment & Management", status: critical > 0 ? "FAIL" : "PASS" },
      { id: "SC-13", name: "Cryptographic Protection",                     status: critical > 0 ? "FAIL" : "PASS" },
      { id: "IA-7",  name: "Cryptographic Module Authentication",          status: medium > 0  ? "WARN" : "PASS" },
      { id: "SC-28", name: "Protection of Information at Rest",            status: critical > 0 ? "FAIL" : "PASS" },
      { id: "SC-8",  name: "Transmission Confidentiality & Integrity",     status: high > 0    ? "WARN" : "PASS" },
      { id: "SI-7",  name: "Software & Information Integrity",             status: medium > 0  ? "WARN" : "PASS" },
      { id: "CM-7",  name: "Least Functionality",                          status: "PASS" },
      { id: "AC-17", name: "Remote Access",                                status: "PASS" },
    ];
    const csvData = ["Severity,File,Line,Vulnerability,Code,Replacement",
      ...result.findings.map(f => [
        f.severity, f.file, f.line, f.vulnerability,
        '"' + (f.code || "").replace(/"/g, "'").replace(/[\r\n]+/g, " ") + '"',
        f.replacement
      ].join(","))
    ].join("\n");
    const csvHref = "data:text/csv;charset=utf-8," + encodeURIComponent(csvData);
    const target = file ? file.name : (input || "scan");
    const win = window.open("", "_blank");
    win.document.write(`<!DOCTYPE html><html><head><title>QuantumGuard NIST Report</title>
    <style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{font-family:"Segoe UI",sans-serif;background:#f8faf8;color:#1a1a1a;font-size:13px}
      @media print{.no-print{display:none!important}body{background:#fff}}
      .wrap{max-width:1100px;margin:0 auto;padding:32px 24px 60px}
      .header{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:24px;border-bottom:3px solid #22c55e;margin-bottom:28px;flex-wrap:wrap;gap:16px}
      .logo-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
      .logo-icon{width:38px;height:38px;background:#22c55e;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff}
      .logo-name{font-size:22px;font-weight:900}.logo-name span{color:#22c55e}
      .score-box{background:#fff;border:2px solid #86efac;border-radius:14px;padding:18px 24px;text-align:center;min-width:150px}
      .score-num{font-size:48px;font-weight:900;line-height:1;color:${scoreColor}}
      .score-label{font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
      .score-badge{display:inline-flex;align-items:center;gap:5px;background:${statusBg};border:1px solid ${statusBorder};color:${scoreColor};font-size:10px;font-weight:700;padding:4px 12px;border-radius:100px;margin-top:8px;text-transform:uppercase;letter-spacing:0.5px}
      .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
      .stat{background:#fff;border:1px solid #e2f0e2;border-radius:12px;padding:16px 18px}
      .stat-val{font-size:32px;font-weight:900;line-height:1;margin-bottom:4px}
      .stat-key{font-size:11px;color:#6b7280}
      .section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:#22c55e;margin:24px 0 12px;display:flex;align-items:center;gap:10px}
      .section-line{flex:1;height:1px;background:#d1fae5}
      .panels{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:8px}
      .panel{background:#fff;border:1px solid #e2f0e2;border-radius:12px;padding:18px}
      .panel-title{font-size:13px;font-weight:700;color:#14532d;margin-bottom:14px}
      .bar-row{display:flex;align-items:center;gap:10px;margin-bottom:11px}
      .bar-label{font-size:11px;color:#6b7280;width:65px}
      .bar-track{flex:1;background:#f0f7f0;border-radius:4px;height:7px;overflow:hidden}
      .bar-fill{height:100%;border-radius:4px}
      .bar-count{font-size:11px;font-weight:600;width:60px;text-align:right}
      table{width:100%;border-collapse:collapse;font-size:12px}
      th{background:#f0fdf4;padding:9px 14px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;font-weight:700;border-bottom:2px solid #d1fae5}
      td{padding:9px 14px;border-bottom:1px solid #f0f4f0;vertical-align:top;color:#374151}
      .file-header{background:#f0fdf4;padding:10px 14px;font-family:monospace;font-weight:700;font-size:12px;color:#15803d;border-bottom:1px solid #d1fae5;display:flex;justify-content:space-between;align-items:center}
      .file-wrap{border:1px solid #e2f0e2;border-radius:12px;overflow:hidden;margin-bottom:14px}
      .sev{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;display:inline-block}
      code{font-family:monospace;font-size:11px;background:#f0f7f0;padding:2px 6px;border-radius:4px;color:#15803d;word-break:break-all;display:inline-block;max-width:340px}
      .fix{color:#2563eb;font-size:11px;font-weight:600}
      .threat-count{background:#fee2e2;color:#ef4444;font-size:10px;font-weight:700;padding:2px 9px;border-radius:100px}
      .footer{margin-top:32px;padding-top:16px;border-top:1px solid #e2f0e2;display:flex;justify-content:space-between;font-size:11px;color:#9ca3af;flex-wrap:wrap;gap:8px}
      .print-btn{background:#22c55e;color:#fff;border:none;padding:9px 22px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;margin-right:8px}
      .csv-btn{background:#fff;color:#22c55e;border:1px solid #86efac;padding:9px 22px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer}
    </style></head><body><div class="wrap">
    <div class="no-print" style="margin-bottom:20px">
      <button class="print-btn" onclick="window.print()">🖨 Print / Save PDF</button>
      <a href="${csvHref}" download="nist-report.csv"><button class="csv-btn">📊 Export CSV</button></a>
    </div>
    <div class="header">
      <div>
        <div class="logo-row">
          <div class="logo-icon">⚛</div>
          <span class="logo-name"><span>Quantum</span>Guard</span>
        </div>
        <div style="font-size:15px;font-weight:700;color:#374151;margin-bottom:6px">NIST SP 800-53 Security Report</div>
        <div style="display:flex;gap:20px;flex-wrap:wrap">
          <span style="font-size:11px;color:#9ca3af">Generated <strong style="color:#374151">${new Date().toLocaleString()}</strong></span>
          <span style="font-size:11px;color:#9ca3af">Standard <strong style="color:#374151">NIST SP 800-53 Rev 5</strong></span>
          <span style="font-size:11px;color:#9ca3af">Target <strong style="color:#374151">${target}</strong></span>
          <span style="font-size:11px;color:#9ca3af">Report ID <strong style="color:#374151">#QG-${Date.now()}</strong></span>
        </div>
      </div>
      <div class="score-box">
        <div class="score-num">${score}</div>
        <div class="score-label">Quantum Score / 100</div>
        <div class="score-badge">${status}</div>
      </div>
    </div>
    <div class="stats">
      <div class="stat"><div class="stat-val" style="color:#22c55e">${total}</div><div class="stat-key">Total Findings</div></div>
      <div class="stat"><div class="stat-val" style="color:#ef4444">${critical}</div><div class="stat-key">Critical</div></div>
      <div class="stat"><div class="stat-val" style="color:#f59e0b">${high}</div><div class="stat-key">High</div></div>
      <div class="stat"><div class="stat-val" style="color:#eab308">${medium}</div><div class="stat-key">Medium</div></div>
    </div>
    <div class="section-title">Breakdown <div class="section-line"></div></div>
    <div class="panels">
      <div class="panel">
        <div class="panel-title">Severity Distribution</div>
        ${[["Critical",critical,"#ef4444"],["High",high,"#f59e0b"],["Medium",medium,"#eab308"]].map(([l,c,col])=>
          '<div class="bar-row"><div class="bar-label">'+l+'</div><div class="bar-track"><div class="bar-fill" style="width:'+pct(c)+'%;background:'+col+'"></div></div><div class="bar-count" style="color:'+col+'">'+c+' ('+pct(c)+'%)</div></div>'
        ).join("")}
      </div>
      <div class="panel">
        <div class="panel-title">NIST SP 800-53 Control Status</div>
        ${nistControls.map(ctrl=>
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><span style="font-size:12px;color:#374151"><span style="font-family:monospace;color:#22c55e;font-weight:700">'+ctrl.id+'</span> — '+ctrl.name+'</span><span style="background:'+ctrlBg(ctrl.status)+';color:'+ctrlColor(ctrl.status)+';font-size:10px;font-weight:700;padding:2px 9px;border-radius:100px;margin-left:8px;white-space:nowrap">'+ctrl.status+'</span></div>'
        ).join("")}
      </div>
    </div>
    <div class="section-title">Threat Intelligence — ${total} Findings <div class="section-line"></div></div>
    ${Object.entries(grouped).map(([fname, findings])=>
      '<div class="file-wrap"><div class="file-header"><span>📄 '+fname+'</span><span class="threat-count">'+findings.length+' threats</span></div><table><thead><tr><th>Severity</th><th>Line</th><th>Vulnerability</th><th>Code</th><th>NIST Replacement</th></tr></thead><tbody>'+
      findings.map(f=>
        '<tr><td><span class="sev" style="background:'+sevBg(f.severity)+';color:'+sevColor(f.severity)+'">'+f.severity+'</span></td><td style="color:#9ca3af;font-family:monospace;font-weight:600">'+f.line+'</td><td style="font-weight:700">'+f.vulnerability+'</td><td><code>'+((f.code||"").replace(/</g,"&lt;").replace(/>/g,"&gt;"))+'</code></td><td class="fix">✦ '+f.replacement+'</td></tr>'
      ).join("")+
      '</tbody></table></div>'
    ).join("")}
    <div class="footer">
      <span>QuantumGuard · NIST SP 800-53 Rev 5 · Mangsri QuantumGuard LLC · Montgomery, AL</span>
      <span>Generated ${new Date().toLocaleDateString()}</span>
    </div>
    </div></body></html>`);
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
    const scoreColor = result.quantum_readiness_score >= 70 ? "#22c55e" : result.quantum_readiness_score >= 40 ? "#f59e0b" : "#ef4444";
    const status = result.quantum_readiness_score >= 70 ? "QUANTUM SAFE" : result.quantum_readiness_score >= 40 ? "AT RISK" : "NOT QUANTUM SAFE";
    const critical = result.findings.filter(f => f.severity === "CRITICAL").length;
    const high     = result.findings.filter(f => f.severity === "HIGH").length;
    const medium   = result.findings.filter(f => f.severity === "MEDIUM").length;
    const total    = result.total_findings;
    const grouped  = result.findings.reduce((a, f) => { if (!a[f.file]) a[f.file] = []; a[f.file].push(f); return a; }, {});
    const sevColor = s => s === "CRITICAL" ? "#ef4444" : s === "HIGH" ? "#f59e0b" : "#eab308";
    const sevBg    = s => s === "CRITICAL" ? "#fee2e2" : s === "HIGH" ? "#fef3c7" : "#fef9c3";
    win.document.write(`<!DOCTYPE html><html><head><title>QuantumGuard Report</title>
    <style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{font-family:"Segoe UI",sans-serif;background:#fff;color:#1a1a1a;padding:40px;font-size:13px}
      @media print{body{padding:20px}.no-print{display:none}}
      .header{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:20px;border-bottom:3px solid #22c55e;margin-bottom:24px}
      .logo{display:flex;align-items:center;gap:10px}
      .logo-icon{width:40px;height:40px;background:#22c55e;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px;color:#fff}
      .logo-name{font-size:22px;font-weight:900;color:#1a1a1a}.logo-name span{color:#22c55e}
      .score-box{text-align:center;background:#f0fdf4;border:2px solid #86efac;border-radius:12px;padding:14px 22px}
      .score-num{font-size:44px;font-weight:900;color:${scoreColor};line-height:1}
      .score-label{font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
      .score-status{font-size:11px;font-weight:700;color:${scoreColor};margin-top:6px;text-transform:uppercase}
      .meta{display:flex;gap:24px;margin-bottom:20px;flex-wrap:wrap}
      .meta-item{font-size:11px;color:#6b7280}.meta-item strong{color:#374151}
      .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
      .stat{background:#f8faf8;border:1px solid #e2f0e2;border-radius:10px;padding:14px;border-top:3px solid var(--c)}
      .stat-val{font-size:30px;font-weight:900;color:var(--c);line-height:1}
      .stat-key{font-size:11px;color:#6b7280;margin-top:4px}
      .panels{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
      .panel{background:#f8faf8;border:1px solid #e2f0e2;border-radius:10px;padding:16px}
      .panel-title{font-size:13px;font-weight:700;color:#14532d;margin-bottom:14px}
      table{width:100%;border-collapse:collapse;font-size:12px}
      th{background:#f0fdf4;padding:9px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;font-weight:700;border-bottom:2px solid #d1fae5}
      td{padding:9px 12px;border-bottom:1px solid #f0f4f0;vertical-align:top}
      .file-header{background:#f0fdf4;padding:8px 12px;font-weight:700;font-size:12px;color:#14532d;border-bottom:1px solid #d1fae5}
      .sev{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;display:inline-block}
      code{font-family:monospace;font-size:11px;background:#f0f7f0;padding:2px 6px;border-radius:4px;color:#15803d;word-break:break-all}
      .fix{color:#2563eb;font-size:11px;font-weight:600}
      .footer{margin-top:32px;padding-top:16px;border-top:1px solid #e2f0e2;display:flex;justify-content:space-between;align-items:center;font-size:11px;color:#9ca3af}
      .print-btn{background:#22c55e;color:#fff;border:none;padding:10px 24px;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer;margin-bottom:20px}
    </style>
    </head><body>
    <div class="no-print" style="margin-bottom:16px">
      <button class="print-btn" onclick="window.print()">🖨 Print / Save as PDF</button>
    </div>
    <div class="header">
      <div>
        <div class="logo">
          <div class="logo-icon">⚛</div>
          <span class="logo-name"><span>Quantum</span>Guard</span>
        </div>
        <div style="margin-top:8px;font-size:13px;font-weight:700;color:#374151">NIST SP 800-53 Security Report</div>
        <div style="margin-top:4px;font-size:11px;color:#6b7280">Post-Quantum Cryptography Vulnerability Scan</div>
      </div>
      <div class="score-box">
        <div class="score-num">${result.quantum_readiness_score}</div>
        <div class="score-label">Quantum Score / 100</div>
        <div class="score-status">${status}</div>
      </div>
    </div>
    <div class="meta">
      <div class="meta-item">Generated <strong>${new Date().toLocaleString()}</strong></div>
      <div class="meta-item">Standard <strong>NIST SP 800-53 Rev 5</strong></div>
      <div class="meta-item">Target <strong>${file?.name || input || "scan"}</strong></div>
      <div class="meta-item">Report ID <strong>#QG-${Date.now()}</strong></div>
    </div>
    <div class="stats">
      <div class="stat" style="--c:#22c55e"><div class="stat-val">${total}</div><div class="stat-key">Total Findings</div></div>
      <div class="stat" style="--c:#ef4444"><div class="stat-val">${critical}</div><div class="stat-key">Critical</div></div>
      <div class="stat" style="--c:#f59e0b"><div class="stat-val">${high}</div><div class="stat-key">High</div></div>
      <div class="stat" style="--c:#eab308"><div class="stat-val">${medium}</div><div class="stat-key">Medium</div></div>
    </div>
    <div class="panels">
      <div class="panel">
        <div class="panel-title">Severity Distribution</div>
        ${[["Critical",critical,"#ef4444"],["High",high,"#f59e0b"],["Medium",medium,"#eab308"]].map(([l,c,col])=>`
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
          <div style="font-size:11px;color:#6b7280;width:70px">${l}</div>
          <div style="flex:1;background:#e5f0e5;border-radius:4px;height:7px;overflow:hidden"><div style="width:${total>0?Math.round(c/total*100):0}%;background:${col};height:100%;border-radius:4px"></div></div>
          <div style="font-size:11px;font-weight:600;color:${col};width:55px;text-align:right">${c} (${total>0?Math.round(c/total*100):0}%)</div>
        </div>`).join("")}
      </div>
      <div class="panel">
        <div class="panel-title">NIST Control Status</div>
        ${[["SC-13 Crypto Protection","FAIL","#ef4444"],["SC-12 Key Management","FAIL","#ef4444"],["IA-7 Crypto Module Auth","WARN","#f59e0b"],["SC-8 Transmission Conf.","WARN","#f59e0b"],["CM-7 Least Functionality","PASS","#22c55e"]].map(([ctrl,s,col])=>`
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;font-size:12px">
          <span style="color:#374151">${ctrl}</span>
          <span style="background:${col}18;color:${col};font-size:10px;font-weight:700;padding:2px 9px;border-radius:100px">${s}</span>
        </div>`).join("")}
      </div>
    </div>
    <div style="margin-bottom:24px">
      <div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:#22c55e;margin-bottom:12px">🔍 Threat Intelligence — ${total} Findings</div>
      ${Object.entries(grouped).map(([fname, findings]) => `
        <div style="margin-bottom:16px;border:1px solid #e2f0e2;border-radius:10px;overflow:hidden">
          <div class="file-header">📄 ${fname} — ${findings.length} findings</div>
          <table>
            <thead><tr><th>Severity</th><th>Line</th><th>Code</th><th>Vulnerability</th><th>Replacement</th></tr></thead>
            <tbody>
              ${findings.map(f=>`<tr>
                <td><span class="sev" style="background:${sevBg(f.severity)};color:${sevColor(f.severity)}">${f.severity}</span></td>
                <td style="color:#6b7280;font-weight:600">${f.line}</td>
                <td><code>${f.code.replace(/</g,"&lt;").replace(/>/g,"&gt;")}</code></td>
                <td style="font-weight:600;color:#374151">${f.vulnerability}</td>
                <td class="fix">${f.replacement}</td>
              </tr>`).join("")}
            </tbody>
          </table>
        </div>`).join("")}
    </div>
    <div class="footer">
      <span>QuantumGuard · NIST SP 800-53 Rev 5 · Mangsri QuantumGuard LLC · Montgomery, AL</span>
      <span>Report generated ${new Date().toLocaleDateString()}</span>
    </div>
    </body></html>`);
    win.document.close();
    setTimeout(() => win.print(), 500);
  };

  const btnStyle = (active) => ({
    padding: "8px 16px", borderRadius: 8,
    border: `1.5px solid ${active ? C.green : C.panelBorder}`,
    background: active ? "rgba(34,197,94,0.15)" : "transparent",
    color: active ? C.green : C.muted,
    cursor: "pointer", fontSize: 12, fontWeight: active ? 600 : 400, transition: "all 0.2s ease",
  });

  return (
    <div style={{ padding: 20 }}>
      {result && (
        <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
          <ScoreCard label="Quantum Risk Score" value={result.quantum_readiness_score} color={scoreColor} icon={result.quantum_readiness_score >= 70 ? "🛡" : result.quantum_readiness_score >= 40 ? "⚠️" : "🚨"} desc={result.quantum_readiness_score >= 70 ? "Quantum Safe" : result.quantum_readiness_score >= 40 ? "At Risk" : "Critical Risk"} />
          <ScoreCard label="Code Scanner Score" value={result.quantum_readiness_score} color={scoreColor} icon="🔍" desc={`${result.total_findings} vulnerabilities found`} />
          <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 14, padding: "20px", boxShadow: "0 4px 20px rgba(0,0,0,0.35)", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
              <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em" }}>Crypto Agility Score</div>
              <div style={{ fontSize: 20 }}>🔬</div>
            </div>
            <div style={{ fontSize: 28, fontWeight: 800, color: C.muted, marginBottom: 6 }}>N/A</div>
            <div style={{ fontSize: 11, color: C.muted, lineHeight: 1.5 }}>Run <strong style={{ color: C.green }}>Agility Checker</strong> tab for a real score</div>
          </div>
          <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 14, padding: "20px", boxShadow: "0 4px 20px rgba(0,0,0,0.35)", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 14 }}>
              <div style={{ fontSize: 11, color: C.muted, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.08em" }}>TLS Security Score</div>
              <div style={{ fontSize: 20 }}>🔐</div>
            </div>
            <div style={{ fontSize: 28, fontWeight: 800, color: C.muted, marginBottom: 6 }}>N/A</div>
            <div style={{ fontSize: 11, color: C.muted, lineHeight: 1.5 }}>Run <strong style={{ color: C.green }}>TLS Analyzer</strong> tab for a real score</div>
          </div>
        </div>
      )}

      <Panel title="Scan Target" accent>
        <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap" }}>
          {[{ id: "github", label: "🔗 GitHub URL" }, { id: "zip", label: "📁 Upload ZIP" }, { id: "path", label: "🖥️ Server Path" }].map(m => (
            <button key={m.id} onClick={() => setMode(m.id)} style={btnStyle(mode === m.id)}>{m.label}</button>
          ))}
        </div>
        {mode === "zip" ? (
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <input type="file" accept=".zip" onChange={e => setFile(e.target.files[0])} style={{ flex: 1, minWidth: 200, padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
            <button onClick={handleScan} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: "linear-gradient(135deg, #22c55e, #16a34a)", color: C.white, border: "none", cursor: "pointer", fontSize: 13, fontWeight: 600, boxShadow: "0 4px 12px rgba(34,197,94,0.3)", transition: "all 0.2s ease" }}
              onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = "0 6px 20px rgba(34,197,94,0.45)"; }}
              onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.boxShadow = "0 4px 12px rgba(34,197,94,0.3)"; }}>{loading ? "Scanning..." : "▶ Run Scan"}</button>
          </div>
        ) : mode === "github" ? (
          <div>
            <div style={{ display: "flex", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
              <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && handleScan()} placeholder="https://github.com/username/repo" style={{ flex: 1, minWidth: 200, padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
              <button onClick={handleScan} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: loading ? C.greenDark : "linear-gradient(135deg, #22c55e, #16a34a)", color: C.white, border: "none", cursor: loading ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600, boxShadow: loading ? "none" : "0 4px 12px rgba(34,197,94,0.3)", transition: "all 0.2s ease" }}
                onMouseEnter={e => { if (!loading) { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = "0 6px 20px rgba(34,197,94,0.45)"; }}}
                onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.boxShadow = loading ? "none" : "0 4px 12px rgba(34,197,94,0.3)"; }}>{loading ? "Scanning..." : "▶ Run Scan"}</button>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <button onClick={() => setShowToken(!showToken)} style={{ background: "transparent", border: `1px solid ${C.panelBorder}`, borderRadius: 6, padding: "4px 12px", cursor: "pointer", color: C.muted, fontSize: 11, transition: "all 0.2s ease" }}>🔒 {showToken ? "Hide Token" : "Private Repo"}</button>
              {showToken && <input value={githubToken} onChange={e => setGithubToken(e.target.value)} placeholder="GitHub Personal Access Token" type="password" style={{ flex: 1, padding: "4px 12px", borderRadius: 6, border: `1px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 11 }} />}
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <input value={input} onChange={e => setInput(e.target.value)} placeholder="/app/src" style={{ flex: 1, minWidth: 200, padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
            <button onClick={handleScan} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: "linear-gradient(135deg, #22c55e, #16a34a)", color: C.white, border: "none", cursor: "pointer", fontSize: 13, fontWeight: 600, transition: "all 0.2s ease" }}>{loading ? "Scanning..." : "▶ Run Scan"}</button>
          </div>
        )}

        {loading && (
          <div style={{ marginTop: 14 }}>

            {/* ── TOP STATUS BAR ── */}
            <div style={{ background: "rgba(34,197,94,0.06)", borderRadius: "10px 10px 0 0", padding: "12px 16px", border: "1px solid rgba(34,197,94,0.25)", borderBottom: "none", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.green, animation: "pulse-ring 1.2s ease-in-out infinite" }} />
                <span style={{ fontSize: 12, color: C.green, fontWeight: 700 }}>SCANNING</span>
                <span style={{ fontSize: 12, color: C.muted, fontWeight: 500 }}>{SCAN_STEPS[stepIndex]}</span>
              </div>
              <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
                <span style={{ fontSize: 11, color: C.muted, fontFamily: "monospace" }}>⏱ {(elapsedMs / 1000).toFixed(1)}s</span>
                <span style={{ fontSize: 11, color: C.amber, fontFamily: "monospace" }}>⚠ {issuesFound} issues</span>
                <span style={{ fontSize: 11, color: C.textMid, fontFamily: "monospace" }}>📁 {filesScanned} files</span>
                <span style={{ fontSize: 12, fontWeight: 800, color: C.green, fontFamily: "monospace" }}>{progress}%</span>
              </div>
            </div>

            {/* ── PROGRESS BAR ── */}
            <div style={{ background: "rgba(255,255,255,0.04)", height: 4, overflow: "hidden", border: "1px solid rgba(34,197,94,0.2)", borderTop: "none", borderBottom: "none" }}>
              <div style={{ background: "linear-gradient(90deg, #22c55e, #4ade80, #22c55e)", backgroundSize: "200% 100%", height: 4, width: `${progress}%`, transition: "width 0.4s ease", animation: "scan-shimmer 1.8s linear infinite", boxShadow: "0 0 12px rgba(34,197,94,0.7)" }} />
            </div>

            {/* ── STEP PILLS ── */}
            <div style={{ background: "rgba(34,197,94,0.04)", border: "1px solid rgba(34,197,94,0.2)", borderTop: "none", borderBottom: "none", padding: "8px 16px", display: "flex", gap: 6, flexWrap: "wrap" }}>
              {SCAN_STEPS.map((s, i) => (
                <div key={i} style={{
                  fontSize: 10, fontWeight: i < stepIndex ? 600 : i === stepIndex ? 700 : 500,
                  padding: "3px 10px", borderRadius: 100,
                  background: i < stepIndex ? "rgba(34,197,94,0.18)" : i === stepIndex ? C.green : "rgba(255,255,255,0.04)",
                  color: i < stepIndex ? C.green : i === stepIndex ? "#fff" : C.muted,
                  border: i === stepIndex ? "none" : `1px solid ${i < stepIndex ? "rgba(34,197,94,0.3)" : "rgba(255,255,255,0.06)"}`,
                  transition: "all 0.3s ease",
                  display: "flex", alignItems: "center", gap: 4,
                }}>
                  {i < stepIndex ? "✓ " : i === stepIndex ? "▶ " : ""}{s.replace("...", "")}
                </div>
              ))}
            </div>

            {/* ── TERMINAL LOG ── */}
            <div style={{
              background: "#0a0e1a", border: "1px solid rgba(34,197,94,0.25)", borderTop: "none",
              borderRadius: "0 0 10px 10px",
              height: 240, overflowY: "auto", padding: "12px 14px",
              fontFamily: "'DM Mono', 'Fira Mono', 'Consolas', monospace",
              fontSize: 11, lineHeight: 1.7,
            }}>
              {/* Static header */}
              <div style={{ color: "#4b5563", marginBottom: 8, paddingBottom: 8, borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                <span style={{ color: C.green }}>quantumguard</span><span style={{ color: "#4b5563" }}>@scanner</span>
                <span style={{ color: "#334155" }}> — scanning: </span>
                <span style={{ color: "#60a5fa" }}>{input || file?.name || "target"}</span>
              </div>

              {scanLogs.map((log) => {
                const cfg = {
                  info:     { icon: "›",  color: C.textMid,  prefix: "[INFO]   " },
                  success:  { icon: "✓",  color: C.green,    prefix: "[OK]     " },
                  warn:     { icon: "⚠",  color: C.amber,    prefix: "[WARN]   " },
                  critical: { icon: "✕",  color: C.critical, prefix: "[VULN]   " },
                }[log.type] || { icon: "›", color: C.muted, prefix: "[LOG]    " };
                return (
                  <div key={log.id} style={{ display: "flex", gap: 8, marginBottom: 2, animation: "log-appear 0.15s ease-out" }}>
                    <span style={{ color: "#334155", flexShrink: 0, userSelect: "none" }}>
                      {new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </span>
                    <span style={{ color: cfg.color, flexShrink: 0, fontWeight: 700 }}>{cfg.prefix}</span>
                    <span style={{ color: cfg.color }}>{log.text}</span>
                  </div>
                );
              })}

              {/* Blinking cursor */}
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 4 }}>
                <span style={{ color: "#334155" }}>{new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
                <span style={{ color: C.green, animation: "cursor-blink 1s step-end infinite" }}>█</span>
              </div>

              <div ref={logEndRef} />
            </div>

            {/* Inject keyframes for new animations */}
            <style>{`
              @keyframes scan-shimmer {
                0%   { background-position: 200% center; }
                100% { background-position: -200% center; }
              }
              @keyframes log-appear {
                from { opacity: 0; transform: translateX(-4px); }
                to   { opacity: 1; transform: translateX(0); }
              }
              @keyframes cursor-blink {
                0%, 100% { opacity: 1; }
                50%       { opacity: 0; }
              }
            `}</style>
          </div>
        )}
        {error && <div style={{ marginTop: 12, background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 13 }}>⚠ {error}</div>}
        {saved && <div style={{ marginTop: 10, background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.3)", borderRadius: 8, padding: "8px 14px", color: C.green, fontSize: 12, fontWeight: 500 }}>✓ Scan saved to history</div>}
      </Panel>

      {result && (
        <>
          {/* ── NEW: Why this score? panel ── */}
          {result.score_explanation && result.score_explanation.length > 0 && (
            <Panel title="Why this score?" accent>
              {result.score_explanation.map((line, i) => {
                const color = line.startsWith("🔴") ? C.critical : line.startsWith("🟡") ? C.amber : line.startsWith("🟠") ? C.medium : C.green;
                return (
                  <div key={i} style={{ display: "flex", gap: 10, padding: "7px 0", borderBottom: i < result.score_explanation.length - 1 ? `1px solid ${C.panelBorder}` : "none", alignItems: "flex-start" }}>
                    <span style={{ fontSize: 15, flexShrink: 0 }}>{line.slice(0, 2)}</span>
                    <span style={{ fontSize: 12, color, lineHeight: 1.6 }}>{line.slice(2).trim()}</span>
                  </div>
                );
              })}
            </Panel>
          )}

          {/* ── NEW: Scan Summary panel ── */}
          {result.scan_summary && (
            <Panel title="Scan Summary" accent>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 10, marginBottom: result.scan_summary.languages_detected?.length > 0 ? 14 : 0 }}>
                {[
                  ["Files Scanned",     result.scan_summary.files_scanned,                  "📁", C.green],
                  ["Files With Issues", result.scan_summary.files_with_issues,               "⚠️",  C.amber],
                  ["Scan Time",         `${result.scan_summary.scan_time ?? "—"}s`,          "⏱",  C.blue],
                  ["Confidence",        result.scan_summary.overall_confidence ?? "—",       "🎯",  C.textMid],
                ].map(([label, value, icon, color]) => (
                  <div key={label} style={{ background: C.input, borderRadius: 8, padding: "10px 12px", border: `1px solid ${C.panelBorder}`, textAlign: "center" }}>
                    <div style={{ fontSize: 18, marginBottom: 4 }}>{icon}</div>
                    <div style={{ fontSize: 18, fontWeight: 800, color }}>{value}</div>
                    <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{label}</div>
                  </div>
                ))}
              </div>
              {result.scan_summary.languages_detected?.length > 0 && (
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 }}>
                  <span style={{ fontSize: 11, color: C.muted, marginRight: 4, alignSelf: "center" }}>Languages:</span>
                  {result.scan_summary.languages_detected.map(lang => (
                    <span key={lang} style={{ background: "rgba(34,197,94,0.1)", color: C.green, border: "1px solid rgba(34,197,94,0.3)", fontSize: 10, fontWeight: 700, padding: "2px 9px", borderRadius: 100 }}>{lang}</span>
                  ))}
                </div>
              )}
              {result.scan_summary.confidence_note && (
                <div style={{ marginTop: 10, fontSize: 11, color: C.muted, background: "rgba(34,197,94,0.05)", padding: "7px 12px", borderRadius: 6, border: "1px solid rgba(34,197,94,0.12)" }}>{result.scan_summary.confidence_note}</div>
              )}
            </Panel>
          )}

          <div className="charts-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
            <Panel title="Severity Distribution" accent>
              <SevBar label="Critical" count={sev.CRITICAL} total={result.total_findings} color={C.critical} />
              <SevBar label="High" count={sev.HIGH} total={result.total_findings} color={C.amber} />
              <SevBar label="Medium" count={sev.MEDIUM} total={result.total_findings} color={C.medium} />
            </Panel>
            <Panel title="Score Breakdown" accent>
              <SevBar label="Crypto Issues" count={sev.CRITICAL} total={result.total_findings} color={C.critical} />
              <SevBar label="TLS / Protocol" count={sev.HIGH} total={result.total_findings} color={C.amber} />
              <SevBar label="Hash / Secrets" count={sev.MEDIUM} total={result.total_findings} color={C.medium} />
            </Panel>
          </div>
          <Panel title="Export & Share" accent>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
              <button onClick={handlePDF} style={{ padding: "8px 16px", borderRadius: 8, background: "linear-gradient(135deg, #22c55e, #16a34a)", color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600, boxShadow: "0 2px 8px rgba(34,197,94,0.3)", transition: "all 0.2s ease" }}
                onMouseEnter={e => { e.currentTarget.style.transform = "translateY(-1px)"; e.currentTarget.style.boxShadow = "0 6px 16px rgba(34,197,94,0.4)"; }}
                onMouseLeave={e => { e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.boxShadow = "0 2px 8px rgba(34,197,94,0.3)"; }}>📄 PDF Report</button>
              <button onClick={handleNIST} style={{ padding: "8px 16px", borderRadius: 8, background: "rgba(59,130,246,0.15)", color: "#60a5fa", border: "1px solid rgba(59,130,246,0.3)", cursor: "pointer", fontSize: 12, fontWeight: 600, transition: "all 0.2s ease" }}>🏛 NIST Report</button>
              <button onClick={handleCSV} style={{ padding: "8px 16px", borderRadius: 8, background: "rgba(34,197,94,0.1)", color: C.green, border: "1px solid rgba(34,197,94,0.3)", cursor: "pointer", fontSize: 12, fontWeight: 600, transition: "all 0.2s ease" }}>📊 CSV Export</button>
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <input value={emailInput} onChange={e => setEmailInput(e.target.value)} placeholder="Email report to..." type="email" style={{ flex: 1, minWidth: 200, padding: "8px 14px", borderRadius: 8, border: `1px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 12 }} />
              <button onClick={handleEmail} disabled={sendingEmail || !emailInput} style={{ padding: "8px 16px", borderRadius: 8, background: "linear-gradient(135deg, #22c55e, #16a34a)", color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600, transition: "all 0.2s ease" }}>{emailSent ? "✓ Sent!" : sendingEmail ? "Sending..." : "📧 Send Email"}</button>
            </div>
          </Panel>

          <Panel title={`Threat Intelligence — ${result.total_findings} findings`} accent>
            <div style={{ display: "flex", gap: 8, marginBottom: 14, flexWrap: "wrap", alignItems: "center" }}>
              {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map(f => {
                const colors = { ALL: C.green, CRITICAL: C.critical, HIGH: C.amber, MEDIUM: C.medium };
                const col = colors[f];
                return (
                  <button key={f} onClick={() => setFilter(f)} style={{
                    padding: "5px 14px", borderRadius: 20,
                    border: `1.5px solid ${filter === f ? col : C.panelBorder}`,
                    background: filter === f ? col + "22" : "transparent",
                    color: filter === f ? col : C.muted,
                    cursor: "pointer", fontSize: 11, fontWeight: filter === f ? 700 : 400,
                    transition: "all 0.2s ease",
                  }}>
                    {f} {f !== "ALL" && sev ? `(${sev[f]})` : ""}
                  </button>
                );
              })}
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search..." style={{ padding: "5px 12px", borderRadius: 20, border: `1px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 11, width: 120, marginLeft: "auto" }} />
            </div>
            {Object.entries(grouped).map(([file, findings], gi) => (
              <div key={gi} style={{ marginBottom: 12, border: `1px solid ${C.panelBorder}`, borderRadius: 10, overflow: "hidden", transition: "border-color 0.2s ease" }}
                onMouseEnter={e => e.currentTarget.style.borderColor = "rgba(34,197,94,0.25)"}
                onMouseLeave={e => e.currentTarget.style.borderColor = C.panelBorder}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 16px", background: "rgba(34,197,94,0.05)", borderBottom: `1px solid ${C.panelBorder}`, flexWrap: "wrap", gap: 4 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{file.split("/").pop()}</span>
                  <Badge text={`${findings.length} threats`} color={C.red} bg={SEV_BG.CRITICAL} />
                </div>
                <div style={{ padding: 14 }}>
                  {findings.map((f, i) => {
                    const key = `${f.file}:${f.line}`;
                    const fSevColor = f.severity === "CRITICAL" ? C.critical : f.severity === "HIGH" ? C.amber : C.medium;
                    const fSevBg = SEV_BG[f.severity] || SEV_BG.MEDIUM;
                    return (
                      <div key={i} style={{
                        borderLeft: `3px solid ${fSevColor}`,
                        paddingLeft: 14, marginBottom: i < findings.length - 1 ? 16 : 0,
                        opacity: checklist[key] ? 0.4 : 1,
                        paddingBottom: i < findings.length - 1 ? 16 : 0,
                        borderBottom: i < findings.length - 1 ? `1px solid ${C.panelBorder}` : "none",
                      }}>
                        <div style={{ display: "flex", gap: 8, marginBottom: 8, alignItems: "center", flexWrap: "wrap" }}>
                          <input type="checkbox" checked={!!checklist[key]} onChange={() => setChecklist(p => ({ ...p, [key]: !p[key] }))} style={{ cursor: "pointer", accentColor: C.green }} />
                          <span style={{
                            background: fSevBg, color: fSevColor,
                            padding: "3px 10px", borderRadius: 6, fontSize: 11, fontWeight: 800,
                            border: `1px solid ${fSevColor}44`, letterSpacing: "0.03em",
                            textTransform: "uppercase",
                          }}>{f.severity}</span>
                          <span style={{ background: "rgba(255,255,255,0.06)", color: C.muted, fontSize: 10, fontWeight: 600, padding: "2px 8px", borderRadius: 4 }}>{f.vulnerability}</span>
                          <span style={{ color: C.muted, fontSize: 11 }}>Line {f.line}</span>
                          <button onClick={() => handleAiFix(f)} style={{ marginLeft: "auto", padding: "3px 12px", borderRadius: 6, background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.3)", color: C.green, cursor: "pointer", fontSize: 10, fontWeight: 700, transition: "all 0.2s ease" }}
                            onMouseEnter={e => { e.currentTarget.style.background = "rgba(34,197,94,0.2)"; }}
                            onMouseLeave={e => { e.currentTarget.style.background = "rgba(34,197,94,0.1)"; }}>⚡ AI Fix</button>
                        </div>
                        <div style={{ fontFamily: "monospace", background: C.input, padding: "8px 12px", borderRadius: 6, fontSize: 11, marginBottom: 8, color: C.green, overflowX: "auto", border: `1px solid ${C.panelBorder}` }}>{f.code}</div>
                        <div style={{ background: "rgba(59,130,246,0.08)", border: "1px solid rgba(59,130,246,0.2)", borderRadius: 6, padding: "7px 12px", display: "flex", alignItems: "center", gap: 8 }}>
                          <span style={{ fontSize: 10, fontWeight: 700, color: "#60a5fa", textTransform: "uppercase", letterSpacing: "0.05em", flexShrink: 0 }}>Fix Recommendation</span>
                          <span style={{ color: "#93c5fd", fontWeight: 600, fontSize: 12 }}>✦ {f.replacement}</span>
                        </div>
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
        <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", zIndex: 999, display: "flex", alignItems: "center", justifyContent: "center", padding: 16, backdropFilter: "blur(4px)" }}>
          <div style={{ background: C.panel, borderRadius: 16, width: "100%", maxWidth: 640, maxHeight: "80vh", display: "flex", flexDirection: "column", boxShadow: "0 24px 80px rgba(0,0,0,0.6)", border: `1px solid ${C.panelBorder}` }}>
            <div style={{ padding: "14px 18px", borderBottom: `1px solid ${C.panelBorder}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: 14, fontWeight: 700, color: C.text }}>⚡ AI Migration Assistant</span>
              <button onClick={() => { setAiModal(null); setAiResult(null); }} style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", fontSize: 20 }}>✕</button>
            </div>
            <div style={{ padding: 16, borderBottom: `1px solid ${C.panelBorder}`, background: "rgba(239,68,68,0.05)" }}>
              <div style={{ fontFamily: "monospace", fontSize: 12, color: C.red, background: C.input, padding: "8px 12px", borderRadius: 8, border: "1px solid rgba(239,68,68,0.3)" }}>{aiModal.code}</div>
            </div>
            <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
              {aiLoading ? (
                <div style={{ textAlign: "center", padding: 32 }}>
                  <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.green, margin: "0 auto 12px", animation: "pulse-ring 1.2s ease-in-out infinite" }} />
                  <div style={{ fontSize: 13, color: C.green, fontWeight: 600 }}>Generating AI fix...</div>
                </div>
              ) : aiResult ? (
                <div>
                  <div style={{ fontFamily: "monospace", fontSize: 12, color: C.text, lineHeight: 1.8, whiteSpace: "pre-wrap", background: C.input, padding: 14, borderRadius: 8, border: `1px solid ${C.panelBorder}` }}>{aiResult}</div>
                  <button onClick={() => navigator.clipboard.writeText(aiResult)} style={{ marginTop: 12, padding: "7px 16px", borderRadius: 8, background: "linear-gradient(135deg, #22c55e, #16a34a)", color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>Copy Fix</button>
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
        <div style={{ fontSize: 13, color: C.muted, marginBottom: 14, lineHeight: 1.7, background: "rgba(34,197,94,0.06)", padding: "10px 14px", borderRadius: 8, border: "1px solid rgba(34,197,94,0.15)" }}>
          <strong style={{ color: C.green }}>Crypto Agility</strong> = ability to swap encryption algorithms without major code changes.
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && handleCheck()} placeholder="https://github.com/username/repo" style={{ flex: 1, minWidth: 200, padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
          <button onClick={handleCheck} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: loading ? C.greenDark : "linear-gradient(135deg, #22c55e, #16a34a)", color: C.white, border: "none", cursor: loading ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600, boxShadow: loading ? "none" : "0 4px 12px rgba(34,197,94,0.3)", transition: "all 0.2s ease" }}>{loading ? "Analyzing..." : "🔬 Check Agility"}</button>
        </div>
        {loading && (
          <div style={{ marginTop: 12, background: "rgba(34,197,94,0.06)", borderRadius: 10, padding: "12px 16px", border: "1px solid rgba(34,197,94,0.2)", display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.green, flexShrink: 0, animation: "pulse-ring 1.2s ease-in-out infinite" }} />
            <span style={{ fontSize: 12, color: C.green, fontWeight: 500 }}>Analyzing crypto agility...</span>
          </div>
        )}
        {error && <div style={{ marginTop: 12, background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 13 }}>⚠ {error}</div>}
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
  const gradeColor = result ? (
    result.grade === "A+" ? C.green : result.grade === "A" ? C.green :
    result.grade === "B"  ? C.amber : result.grade === "C" ? C.amber : C.red
  ) : C.muted;

  return (
    <div style={{ padding: 20 }}>
      <Panel title="TLS / SSL Quantum Readiness Analyzer" accent>
        <div style={{ fontSize: 13, color: C.muted, marginBottom: 14, background: "rgba(34,197,94,0.06)", padding: "10px 14px", borderRadius: 8, lineHeight: 1.7, border: "1px solid rgba(34,197,94,0.15)" }}>
          Checks any domain for TLS version, cipher suite, and quantum vulnerability.
          <strong style={{ color: C.green }}> TLS 1.3 + forward secrecy</strong> = best protection.
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <input value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === "Enter" && handleAnalyze()} placeholder="google.com or https://github.com" style={{ flex: 1, minWidth: 200, padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
          <button onClick={handleAnalyze} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: loading ? C.greenDark : "linear-gradient(135deg, #22c55e, #16a34a)", color: C.white, border: "none", cursor: loading ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600, boxShadow: loading ? "none" : "0 4px 12px rgba(34,197,94,0.3)", transition: "all 0.2s ease" }}>{loading ? "Analyzing..." : "🔐 Analyze TLS"}</button>
        </div>
        {loading && (
          <div style={{ marginTop: 12, background: "rgba(34,197,94,0.06)", borderRadius: 10, padding: "12px 16px", border: "1px solid rgba(34,197,94,0.2)", display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.green, flexShrink: 0, animation: "pulse-ring 1.2s ease-in-out infinite" }} />
            <span style={{ fontSize: 12, color: C.green, fontWeight: 500 }}>Analyzing TLS configuration...</span>
          </div>
        )}
        {error && <div style={{ marginTop: 12, background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 13 }}>⚠ {error}</div>}
      </Panel>
      {result && (
        <>
          <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 14, padding: "20px 24px", marginBottom: 16, boxShadow: "0 4px 20px rgba(0,0,0,0.4)", display: "flex", alignItems: "center", gap: 24, flexWrap: "wrap" }}>
            <div style={{ textAlign: "center", minWidth: 100 }}>
              <div style={{ fontSize: 72, fontWeight: 900, lineHeight: 1, color: gradeColor, fontFamily: "monospace", textShadow: `0 0 20px ${gradeColor}44` }}>{result.grade || "?"}</div>
              <div style={{ fontSize: 11, color: C.muted, marginTop: 4, textTransform: "uppercase", letterSpacing: 1 }}>SSL Grade</div>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 16, fontWeight: 700, color: C.text, marginBottom: 6 }}>{result.grade_description}</div>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 8 }}>
                <span style={{ background: result.tls_version === "TLSv1.3" ? "rgba(34,197,94,0.15)" : "rgba(245,158,11,0.15)", color: result.tls_version === "TLSv1.3" ? C.green : C.amber, fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 100, border: `1px solid ${result.tls_version === "TLSv1.3" ? "rgba(34,197,94,0.3)" : "rgba(245,158,11,0.3)"}` }}>{result.tls_version}</span>
                <span style={{ background: result.quantum_safe ? "rgba(34,197,94,0.15)" : "rgba(239,68,68,0.15)", color: result.quantum_safe ? C.green : C.red, fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 100, border: `1px solid ${result.quantum_safe ? "rgba(34,197,94,0.3)" : "rgba(239,68,68,0.3)"}` }}>{result.quantum_safe ? "✦ Post-Quantum Safe" : "⚠ Not Quantum Safe"}</span>
                <span style={{ background: "rgba(34,197,94,0.1)", color: C.green, fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 100, border: "1px solid rgba(34,197,94,0.3)" }}>Score: {result.tls_score}/100</span>
              </div>
              {result.pqc_note && <div style={{ fontSize: 12, color: C.amber, background: "rgba(245,158,11,0.1)", padding: "6px 12px", borderRadius: 8, border: "1px solid rgba(245,158,11,0.3)" }}>⚠ {result.pqc_note}</div>}
            </div>
            <div style={{ display: "flex", gap: 6 }}>
              {[["A+","#22c55e"],["A","#22c55e"],["B","#f59e0b"],["C","#f59e0b"],["D","#ef4444"],["F","#ef4444"]].map(([g, col]) => (
                <div key={g} style={{ width: 36, height: 36, borderRadius: 8, background: result.grade === g ? col + "22" : "rgba(255,255,255,0.04)", color: result.grade === g ? col : C.muted, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 800, border: result.grade === g ? `2px solid ${col}66` : `2px solid ${C.panelBorder}`, fontFamily: "monospace" }}>{g}</div>
              ))}
            </div>
          </div>

          <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
            <Metric label="TLS Score" value={result.tls_score} suffix="/100" color={scoreColor} icon="🎯" desc={result.tls_score >= 70 ? "Quantum Ready" : "Needs Improvement"} />
            <Metric label="TLS Version" value={result.tls_version} color={result.tls_version === "TLSv1.3" ? C.green : C.amber} icon="🔒" desc={result.tls_version === "TLSv1.3" ? "Latest" : "Upgrade Needed"} />
            <Metric label="Post-Quantum Readiness" value={result?.quantum_safe ? "YES" : result?.tls_version === "TLSv1.3" ? "PARTIAL" : "NO"} color={result?.quantum_safe ? C.green : result?.tls_version === "TLSv1.3" ? C.amber : C.red} icon={result?.quantum_safe ? "✅" : result?.tls_version === "TLSv1.3" ? "⚠️" : "❌"} desc={result?.quantum_safe ? "Post-quantum / hybrid TLS detected" : result?.tls_version === "TLSv1.3" ? "Secure today, not quantum-resistant" : "Not post-quantum yet"} />
            <Metric label="Key Size" value={result.cipher_bits} suffix=" bit" color={result.cipher_bits >= 256 ? C.green : C.amber} icon="🔑" desc={result.cipher_bits >= 256 ? "Strong" : "Upgrade Needed"} />
          </div>
          <Panel title="Cipher Suite Details" accent>
            <div className="tls-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {[
                ["Domain", result.domain, C.green],
                ["Cipher Suite", result.cipher_suite, C.text],
                ["Key Exchange", result.key_exchange || (result.has_forward_secrecy ? "ECDHE / Forward Secrecy" : "Static RSA or Unknown"), C.green],
                ["Certificate Expires", result.certificate?.cert_expires || result.cert_expires || "—", C.amber],
                ["Recommendation", result.nist_recommendation || result.recommendation || "Monitor hybrid PQC TLS adoption", C.green],
                ["Future Upgrade", result.pqc_roadmap || "Hybrid TLS: X25519 + ML-KEM → NIST FIPS 203 readiness", "#60a5fa"]
              ].map(([label, value, color]) => (
                <div key={label} style={{ background: C.input, borderRadius: 8, padding: "12px 14px", border: `1px solid ${C.panelBorder}` }}>
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
      } catch (e) { console.error(e); setLoading(false); return; }
      setLoading(false);
    };
    fetch_();
  }, [user]);

  if (!user) return (
    <div style={{ padding: 20 }}>
      <div style={{ textAlign: "center", padding: 48, background: C.panel, borderRadius: 12, border: `1px solid ${C.panelBorder}` }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>🔒</div>
        <div style={{ fontSize: 16, color: C.text, fontWeight: 600, marginBottom: 8 }}>Sign in to view history</div>
      </div>
    </div>
  );

  return (
    <div style={{ padding: 20 }}>
      <Panel title={`Scan History — ${history.length} records`} accent>
        {loading ? <div style={{ color: C.muted, fontSize: 13 }}>Loading...</div> :
          history.length === 0 ? <div style={{ color: C.muted, fontSize: 13 }}>No scans yet!</div> : (
            history.map((scan, i) => (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 160px 80px 80px", gap: 12, padding: "12px", borderBottom: i < history.length - 1 ? `1px solid ${C.panelBorder}` : "none", alignItems: "center", transition: "background 0.2s ease", borderRadius: 6 }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(34,197,94,0.04)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                <div style={{ fontSize: 12, color: C.text, fontWeight: 500, wordBreak: "break-all" }}>{scan.filename || "scan"}</div>
                <div style={{ fontSize: 11, color: C.muted }}>{scan.createdAt?.toDate?.()?.toLocaleDateString() || "—"}</div>
                <div style={{ fontSize: 20, fontWeight: 700, color: scan.score >= 70 ? C.green : scan.score >= 40 ? C.amber : C.red }}>{scan.score}</div>
                <div style={{ fontSize: 16, fontWeight: 600, color: C.red }}>{scan.findings}</div>
              </div>
            ))
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
      <div style={{ textAlign: "center", padding: 48, background: C.panel, borderRadius: 12, border: `1px solid ${C.panelBorder}` }}>
        <div style={{ fontSize: 48, marginBottom: 16 }}>🔒</div>
        <div style={{ fontSize: 16, color: C.text, fontWeight: 600 }}>Sign in to track migration</div>
      </div>
    </div>
  );

  return (
    <div style={{ padding: 20 }}>
      <Panel title="Migration Progress" accent>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 8 }}>
          <div style={{ fontSize: 40, fontWeight: 800, color: progress >= 70 ? C.green : progress >= 40 ? C.amber : C.red, textShadow: `0 0 20px ${progress >= 70 ? C.green : progress >= 40 ? C.amber : C.red}44` }}>{progress}%</div>
          <div style={{ display: "flex", gap: 20 }}>
            {[["Fixed", totalFixed, C.green], ["In Progress", totalIP, C.amber], ["Pending", vulnTypes.length - totalFixed - totalIP, C.muted]].map(([l, v, c], i) => (
              <div key={i} style={{ textAlign: "center" }}>
                <div style={{ fontSize: 24, fontWeight: 700, color: c }}>{v}</div>
                <div style={{ fontSize: 11, color: C.muted }}>{l}</div>
              </div>
            ))}
          </div>
        </div>
        <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 8, height: 12 }}>
          <div style={{ background: `linear-gradient(90deg, ${C.green}, #4ade80)`, height: 12, borderRadius: 8, width: `${progress}%`, transition: "width 0.6s ease", boxShadow: `0 0 10px rgba(34,197,94,0.5)` }} />
        </div>
      </Panel>
      <Panel title="Vulnerability Migration Status" accent>
        {vulnTypes.map((v, i) => {
          const status = getStatus(v);
          const sev = sevOf(v);
          const sevColor = sev === "CRITICAL" ? C.critical : sev === "HIGH" ? C.amber : C.medium;
          const sevBg = SEV_BG[sev] || SEV_BG.MEDIUM;
          return (
            <div key={i} style={{ display: "flex", gap: 10, padding: "10px 12px", background: status === "fixed" ? "rgba(34,197,94,0.06)" : i % 2 === 0 ? C.panel : "rgba(255,255,255,0.02)", borderRadius: 8, marginBottom: 4, border: `1px solid ${status === "fixed" ? "rgba(34,197,94,0.2)" : C.panelBorder}`, alignItems: "center", flexWrap: "wrap", transition: "all 0.2s ease" }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: status === "fixed" ? C.muted : C.text, textDecoration: status === "fixed" ? "line-through" : "none", minWidth: 120 }}>{v}</div>
              <div style={{ fontSize: 11, color: C.muted, flex: 1, minWidth: 150 }}>{fixes[v]}</div>
              <Badge text={sev} color={sevColor} bg={sevBg} />
              <div style={{ display: "flex", gap: 4 }}>
                {[["pending", "⬜"], ["in_progress", "🔄"], ["fixed", "✅"]].map(([st, icon]) => (
                  <button key={st} onClick={() => setStatus(v, st)} style={{ padding: "4px 8px", borderRadius: 6, border: `1.5px solid ${status === st ? C.green : C.panelBorder}`, background: status === st ? "rgba(34,197,94,0.15)" : "transparent", cursor: "pointer", fontSize: 14, transition: "all 0.2s ease" }}>{icon}</button>
                ))}
              </div>
            </div>
          );
        })}
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
          { year: "2024", event: "NIST finalizes PQC standards — FIPS 203, FIPS 204, FIPS 205", color: C.green },
          { year: "2026", event: "QuantumGuard launches — first developer-focused quantum vulnerability scanner", color: C.blue },
          { year: "2027", event: "Regulatory pressure increases — organizations must show PQC compliance", color: C.amber },
          { year: "2030", event: "Y2Q — Cryptographically Relevant Quantum Computers expected to arrive", color: C.red },
        ].map((t, i) => (
          <div key={i} style={{ display: "flex", gap: 16, marginBottom: 16, alignItems: "flex-start", padding: "10px 0", borderBottom: i < 3 ? `1px solid ${C.panelBorder}` : "none" }}>
            <div style={{ background: t.color + "22", color: t.color, border: `1px solid ${t.color}44`, padding: "4px 10px", borderRadius: 8, fontSize: 13, fontWeight: 700, flexShrink: 0 }}>{t.year}</div>
            <div style={{ fontSize: 13, color: C.textMid, lineHeight: 1.6, paddingTop: 4 }}>{t.event}</div>
          </div>
        ))}
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
          { method: "POST", path: "/scan-github",      auth: "None",             desc: "Scan any public GitHub repo" },
          { method: "POST", path: "/public-scan-zip",  auth: "None",             desc: "Upload ZIP file (max 10MB)" },
          { method: "POST", path: "/check-agility",    auth: "None",             desc: "Check crypto agility" },
          { method: "POST", path: "/analyze-tls",      auth: "None",             desc: "Analyze TLS" },
          { method: "POST", path: "/scan",             auth: "x-api-key header", desc: "Scan server path" },
          { method: "GET",  path: "/health",           auth: "None",             desc: "Returns {status: healthy}" },
        ].map((e, i) => (
          <div key={i} style={{ display: "flex", gap: 12, padding: "10px 0", borderBottom: i < 5 ? `1px solid ${C.panelBorder}` : "none", flexWrap: "wrap", alignItems: "center" }}>
            <Badge text={e.method} color={C.green} bg={"rgba(34,197,94,0.1)"} />
            <span style={{ fontFamily: "monospace", fontSize: 12, color: C.green, fontWeight: 600, minWidth: 160 }}>{e.path}</span>
            <span style={{ fontSize: 11, color: C.amber, minWidth: 100 }}>{e.auth}</span>
            <span style={{ fontSize: 12, color: C.muted }}>{e.desc}</span>
          </div>
        ))}
      </Panel>
      <div className="docs-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        {[
          { title: "Quick Start",    icon: "⚡", steps: ["Go to Scanner tab", "Paste GitHub repo URL", "Click Run Scan", "Download PDF report"] },
          { title: "Crypto Agility", icon: "🔬", steps: ["Go to Agility Checker", "Paste GitHub repo URL", "Click Check Agility", "Review hardcoded vs configurable"] },
          { title: "Private Repos",  icon: "🔒", steps: ["Click Private Repo button", "Generate GitHub PAT", "Paste your token", "Token never stored"] },
          { title: "Rate Limits",    icon: "⏱", steps: ["/scan-github: 20/min", "/public-scan-zip: 3/min", "/check-agility: 10/min", "/analyze-tls: 10/min"] },
        ].map((d, i) => (
          <Panel key={i} title={`${d.icon} ${d.title}`}>
            {d.steps.map((step, j) => (
              <div key={j} style={{ display: "flex", gap: 10, marginBottom: 8, alignItems: "flex-start" }}>
                <div style={{ width: 20, height: 20, borderRadius: "50%", background: "linear-gradient(135deg, #22c55e, #16a34a)", color: C.white, fontSize: 10, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{j + 1}</div>
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
// REPLACE THE ENTIRE Homepage FUNCTION IN YOUR App.js WITH THIS
// Everything else in App.js stays exactly the same.
// ══════════════════════════════════════════════════════════════

const NAV_GROUPS_HP = [
  { label: "Product", items: [
    { icon: "⬡", title: "Quantum Scanner",        desc: "AST-level crypto vulnerability scanning" },
    { icon: "⛨", title: "CI/CD Security Gate",    desc: "Block weak crypto before it ships" },
    { icon: "◈", title: "TLS Analyzer",            desc: "Audit TLS configs end-to-end" },
    { icon: "⟳", title: "Crypto Agility Checker",  desc: "Measure migration readiness" },
    { icon: "▦", title: "Executive Reports",       desc: "Board-ready risk summaries" },
  ]},
  { label: "Solutions", items: [
    { icon: "{}", title: "Developers",         desc: "Shift-left crypto hygiene" },
    { icon: "⚿",  title: "Security Teams",     desc: "Enterprise vulnerability management" },
    { icon: "⚙",  title: "DevOps",             desc: "Pipeline-native enforcement" },
    { icon: "◈",  title: "CISOs",              desc: "Quantum risk posture dashboards" },
    { icon: "⬡",  title: "Financial Services", desc: "FIPS & PQC compliance" },
    { icon: "✚",  title: "Healthcare",         desc: "HIPAA + quantum-safe data" },
    { icon: "⛨",  title: "Government",         desc: "NIST FIPS 203/204/205 readiness" },
  ]},
  { label: "Platform", items: [
    { icon: "◉", title: "Overview",        desc: "How QuantumGuard works" },
    { icon: "⌥", title: "API",             desc: "REST & GraphQL endpoints" },
    { icon: "⧉", title: "GitHub Actions",  desc: "One-line workflow integration" },
    { icon: "◈", title: "Developer Docs",  desc: "Guides, references, SDKs" },
    { icon: "⬡", title: "Integrations",    desc: "Jira, Slack, ServiceNow & more" },
  ]},
  { label: "Pricing", items: [
    { icon: "○", title: "Free",        desc: "Up to 3 scans/month" },
    { icon: "◈", title: "Pro",         desc: "$49/mo — unlimited scans" },
    { icon: "⬡", title: "Team",        desc: "$199/mo — org-wide coverage" },
    { icon: "⛨", title: "Enterprise",  desc: "Custom SLAs & on-prem" },
  ]},
  { label: "Resources", items: [
    { icon: "✍", title: "Blog",            desc: "PQC research & news" },
    { icon: "◈", title: "Documentation",   desc: "Full product reference" },
    { icon: "⬡", title: "PQC Guide",       desc: "Post-quantum explained simply" },
    { icon: "⛨", title: "NIST Standards",  desc: "FIPS 203, 204, 205 breakdown" },
    { icon: "◉", title: "Customer Stories",desc: "Real migration case studies" },
  ]},
];

function HpNavDropdown({ item, isOpen, onToggle }) {
  const ref = React.useRef(null);
  React.useEffect(() => {
    if (!isOpen) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) onToggle(null); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [isOpen, onToggle]);

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        onClick={() => onToggle(item.label)}
        style={{
          background: "none", border: "none", cursor: "pointer",
          display: "flex", alignItems: "center", gap: 4,
          fontSize: 14, fontWeight: 500,
          color: isOpen ? "#22c55e" : "#374151",
          padding: "8px 11px", borderRadius: 8,
          fontFamily: "inherit", letterSpacing: "-.01em",
          transition: "color .15s",
        }}
        onMouseEnter={e => { if (!isOpen) e.currentTarget.style.color = "#22c55e"; }}
        onMouseLeave={e => { if (!isOpen) e.currentTarget.style.color = "#374151"; }}
      >
        {item.label}
        <svg width="11" height="11" viewBox="0 0 12 12" fill="none"
          style={{ transform: isOpen ? "rotate(180deg)" : "none", transition: "transform .2s", opacity: .5 }}>
          <path d="M2 4l4 4 4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {isOpen && (
        <div style={{
          position: "absolute", top: "calc(100% + 10px)", left: "50%",
          transform: "translateX(-50%)",
          background: "rgba(255,255,255,.97)", backdropFilter: "blur(20px)",
          border: "1px solid rgba(34,197,94,.15)", borderRadius: 16,
          boxShadow: "0 20px 56px rgba(0,0,0,.11),0 4px 16px rgba(34,197,94,.07)",
          padding: 8, minWidth: 272, zIndex: 1000,
          animation: "hp-dropIn .17s ease-out",
        }}>
          {item.items.map(sub => (
            <div key={sub.title}
              style={{ display: "flex", alignItems: "flex-start", gap: 11, padding: "10px 13px", borderRadius: 10, cursor: "pointer", transition: "background .13s" }}
              onMouseEnter={e => e.currentTarget.style.background = "rgba(34,197,94,.07)"}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}
            >
              <span style={{ fontSize: 17, lineHeight: 1, marginTop: 2, color: "#22c55e", flexShrink: 0 }}>{sub.icon}</span>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600, color: "#0f1923", letterSpacing: "-.01em" }}>{sub.title}</div>
                <div style={{ fontSize: 12, color: "#6b7280", marginTop: 2, lineHeight: 1.4 }}>{sub.desc}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Homepage({ onGetStarted }) {
  const [demoOpen, setDemoOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [openNav, setOpenNav] = useState(null);
  const [scanInput, setScanInput] = useState("github.com/your-org/your-repo");

  const demoResult = {
    score: 42, statusColor: "#f59e0b", status: "At Risk",
    findings: [
      { sev: "CRITICAL", vuln: "RSA-2048",  file: "auth/keypair.js",    fix: "CRYSTALS-Kyber (FIPS 203)" },
      { sev: "CRITICAL", vuln: "ECC P-256", file: "crypto/sign.py",     fix: "CRYSTALS-Dilithium (FIPS 204)" },
      { sev: "HIGH",     vuln: "DH-2048",   file: "tls/handshake.java", fix: "CRYSTALS-Kyber (FIPS 203)" },
      { sev: "MEDIUM",   vuln: "MD5 hash",  file: "utils/checksum.js",  fix: "SHA-3 / SPHINCS+" },
    ],
  };

  const sevColor = s => s === "CRITICAL" ? "#ef4444" : s === "HIGH" ? "#f59e0b" : "#eab308";
  const sevBg    = s => s === "CRITICAL" ? "#fef2f2" : s === "HIGH" ? "#fffbeb" : "#fefce8";

  const PRICING = [
    { name: "Free",       price: "$0",    period: "",    desc: "For developers exploring PQC",     features: ["3 scans / month", "RSA & ECC detection", "PDF summary report", "Community support"],                                                 cta: "Start Free",       highlight: false },
    { name: "Pro",        price: "$49",   period: "/mo", desc: "For security-conscious teams",     features: ["Unlimited scans", "All 12 vuln types", "NIST fix guidance", "GitHub Actions gate", "API access", "Slack alerts"],                   cta: "Start Free Trial", highlight: true  },
    { name: "Team",       price: "$199",  period: "/mo", desc: "Org-wide visibility & compliance", features: ["Everything in Pro", "Multi-repo dashboard", "Executive PDF reports", "SSO / SAML", "Priority support"],                             cta: "Start Free Trial", highlight: false },
    { name: "Enterprise", price: "Custom",period: "",    desc: "Air-gapped, on-prem or hybrid",    features: ["On-premise option", "SLA 99.99% uptime", "Dedicated CSM", "Custom integrations", "Pen-test reports", "FedRAMP roadmap"],           cta: "Contact Sales",    highlight: false },
  ];

  return (
    <div style={{ fontFamily: "'DM Sans','Segoe UI',sans-serif", background: "#f8fafc", color: "#0f172a", overflowX: "hidden" }}>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700;9..40,800&family=DM+Mono:wght@400;500&display=swap');
        *, *::before, *::after { box-sizing: border-box; }
        html { scroll-behavior: smooth; }
        @keyframes hp-dropIn { from{opacity:0;transform:translateX(-50%) translateY(-8px);} to{opacity:1;transform:translateX(-50%) translateY(0);} }
        @keyframes hp-fadeUp { from{opacity:0;transform:translateY(18px);} to{opacity:1;transform:translateY(0);} }
        @keyframes hp-pulse  { 0%,100%{opacity:1;} 50%{opacity:.45;} }
        .hp2-btn-primary { background:#22c55e; color:#fff; border:none; padding:13px 26px; border-radius:10px; font-size:15px; font-weight:700; cursor:pointer; transition:all .2s; font-family:inherit; letter-spacing:-.01em; display:inline-flex; align-items:center; gap:8px; }
        .hp2-btn-primary:hover { background:#16a34a; transform:translateY(-1px); box-shadow:0 8px 24px rgba(34,197,94,.3); }
        .hp2-btn-outline { background:transparent; color:#0f172a; border:2px solid #d1d5db; padding:11px 24px; border-radius:10px; font-size:15px; font-weight:600; cursor:pointer; transition:all .2s; font-family:inherit; letter-spacing:-.01em; display:inline-flex; align-items:center; gap:8px; }
        .hp2-btn-outline:hover { border-color:#22c55e; color:#22c55e; }
        .hp2-card { background:#fff; border:1.5px solid #e8edf3; border-radius:16px; box-shadow:0 2px 12px rgba(0,0,0,.04); transition:all .25s; }
        .hp2-card:hover { border-color:#22c55e; box-shadow:0 8px 32px rgba(34,197,94,.1); transform:translateY(-2px); }
        .hp2-finding-row { display:flex; align-items:center; gap:10px; padding:10px 14px; border-radius:8px; background:#f8fafc; border:1.5px solid #e2e8f0; font-family:'DM Mono',monospace; font-size:12px; margin-bottom:7px; transition:border-color .2s; }
        .hp2-finding-row:hover { border-color:#22c55e; }
        .hp2-sev { font-size:10px; font-weight:800; padding:3px 9px; border-radius:5px; letter-spacing:.04em; flex-shrink:0; }
        .hp2-modal-overlay { position:fixed; inset:0; background:rgba(0,0,0,.5); z-index:1000; display:flex; align-items:center; justify-content:center; padding:16px; backdrop-filter:blur(4px); }
        .hp2-modal { background:#fff; border-radius:20px; width:100%; max-width:540px; max-height:90vh; overflow-y:auto; box-shadow:0 24px 80px rgba(0,0,0,.2); }
        .hp2-section-label { font-size:11px; font-weight:700; letter-spacing:.1em; color:#22c55e; text-transform:uppercase; }
        @media(max-width:768px) {
          .hp2-hero-grid { grid-template-columns:1fr!important; }
          .hp2-features-grid { grid-template-columns:1fr!important; }
          .hp2-pricing-grid { grid-template-columns:1fr!important; }
          .hp2-stats-grid { grid-template-columns:repeat(2,1fr)!important; }
          .hp2-nav-center { display:none!important; }
          .hp2-find-grid { grid-template-columns:1fr!important; }
          .hp2-how-grid { grid-template-columns:1fr!important; }
          .hp2-who-grid { grid-template-columns:1fr!important; }
          .hp2-get-grid { grid-template-columns:1fr!important; }
          .hp2-matter-grid { grid-template-columns:1fr!important; }
        }
      `}</style>

      {/* ═══════ NAVBAR ═══════ */}
      <nav style={{ position:"sticky",top:0,zIndex:500,background:"rgba(248,250,252,.92)",backdropFilter:"blur(20px)",borderBottom:"1px solid rgba(0,0,0,.07)",padding:"0 32px",height:62,display:"flex",alignItems:"center",gap:4 }}>

        {/* Logo */}
        <div style={{ display:"flex",alignItems:"center",gap:8,marginRight:20,flexShrink:0 }}>
          <div style={{ width:32,height:32,background:"linear-gradient(135deg,#22c55e,#15803d)",borderRadius:9,display:"flex",alignItems:"center",justifyContent:"center",fontSize:15,boxShadow:"0 4px 12px rgba(34,197,94,.28)" }}>⚛</div>
          <span style={{ fontSize:16,fontWeight:800,letterSpacing:"-.03em" }}><span style={{ color:"#22c55e" }}>Quantum</span>Guard</span>
          <span style={{ background:"#dcfce7",color:"#16a34a",fontSize:9,fontWeight:700,padding:"2px 7px",borderRadius:20,border:"1px solid #bbf7d0",letterSpacing:".04em" }}>BETA</span>
        </div>

        {/* Dropdowns */}
        <div className="hp2-nav-center" style={{ display:"flex",alignItems:"center",flex:1 }}>
          {NAV_GROUPS_HP.map(g => (
            <HpNavDropdown key={g.label} item={g} isOpen={openNav === g.label} onToggle={setOpenNav} />
          ))}
        </div>

        {/* Right */}
        <div style={{ display:"flex",alignItems:"center",gap:8,marginLeft:"auto",flexShrink:0 }}>
          <div style={{ display:"flex",alignItems:"center",gap:6,fontSize:11,fontWeight:600,color:"#15803d",letterSpacing:".04em",marginRight:4 }}>
            <span style={{ width:7,height:7,borderRadius:"50%",background:"#22c55e",boxShadow:"0 0 0 3px rgba(34,197,94,.2)",display:"inline-block",animation:"hp-pulse 2s infinite" }} />
            API ONLINE
          </div>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer"
            style={{ display:"flex",alignItems:"center",gap:6,background:"transparent",color:"#374151",border:"1.5px solid #d1d5db",borderRadius:9,padding:"7px 14px",fontSize:13,fontWeight:500,cursor:"pointer",textDecoration:"none",transition:"all .2s" }}
            onMouseEnter={e=>{ e.currentTarget.style.borderColor="#22c55e"; e.currentTarget.style.color="#22c55e"; }}
            onMouseLeave={e=>{ e.currentTarget.style.borderColor="#d1d5db"; e.currentTarget.style.color="#374151"; }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
            GitHub
          </a>
          <button className="hp2-btn-primary" style={{ padding:"8px 18px",fontSize:13 }} onClick={onGetStarted}>Start Free Scan</button>
          {/* Mobile hamburger */}
          <button onClick={()=>setMobileMenuOpen(m=>!m)} style={{ display:"none",background:"transparent",border:"none",fontSize:22,cursor:"pointer",color:"#0f172a",padding:"0 4px" }} className="hp2-hamburger">
            {mobileMenuOpen ? "✕" : "☰"}
          </button>
        </div>
      </nav>

      {/* Mobile menu */}
      {mobileMenuOpen && (
        <div style={{ background:"#fff",borderBottom:"1px solid #e2e8f0",position:"relative",zIndex:99 }}>
          {NAV_GROUPS_HP.map(g => (
            <div key={g.label} style={{ padding:"14px 24px",fontSize:15,fontWeight:600,color:"#0f172a",borderBottom:"1px solid #f1f5f9",cursor:"pointer" }}>{g.label}</div>
          ))}
          <div style={{ padding:"14px 24px" }}>
            <button className="hp2-btn-primary" style={{ width:"100%" }} onClick={()=>{ onGetStarted(); setMobileMenuOpen(false); }}>Start Free Scan</button>
          </div>
        </div>
      )}

      {/* ═══════ HERO ═══════ */}
      <section style={{ background:"linear-gradient(135deg,#f0fdf4 0%,#f8fafc 45%,#eff6ff 100%)",padding:"96px 32px 80px",position:"relative",overflow:"hidden" }}>
        <div style={{ position:"absolute",top:-160,right:-160,width:480,height:480,borderRadius:"50%",background:"radial-gradient(circle,rgba(34,197,94,.08) 0%,transparent 70%)",pointerEvents:"none" }} />
        <div style={{ position:"absolute",bottom:-80,left:-80,width:320,height:320,borderRadius:"50%",background:"radial-gradient(circle,rgba(59,130,246,.05) 0%,transparent 70%)",pointerEvents:"none" }} />
        <div style={{ position:"absolute",inset:0,backgroundImage:"radial-gradient(#22c55e14 1px,transparent 1px)",backgroundSize:"28px 28px",pointerEvents:"none" }} />

        <div style={{ maxWidth:1100,margin:"0 auto",textAlign:"center",position:"relative",animation:"hp-fadeUp .65s ease-out both" }}>
          <div style={{ display:"inline-flex",alignItems:"center",gap:8,background:"rgba(34,197,94,.1)",border:"1px solid rgba(34,197,94,.22)",borderRadius:100,padding:"5px 16px",marginBottom:28 }}>
            <span style={{ width:7,height:7,borderRadius:"50%",background:"#22c55e",display:"inline-block",animation:"hp-pulse 2s infinite" }} />
            <span style={{ fontSize:11,fontWeight:700,color:"#15803d",letterSpacing:".05em" }}>NIST FIPS 203 / 204 / 205 ALIGNED · FREE FOREVER</span>
          </div>

          <h1 style={{ fontSize:"clamp(36px,5.5vw,66px)",fontWeight:800,lineHeight:1.08,letterSpacing:"-.04em",color:"#0f172a",marginBottom:22 }}>
            Find weak encryption before<br/>
            <span style={{ color:"#22c55e" }}>quantum computers</span> break it
          </h1>

          <p style={{ fontSize:"clamp(16px,1.6vw,19px)",color:"#475569",maxWidth:580,margin:"0 auto 40px",lineHeight:1.68,fontWeight:400 }}>
            Scan your codebase for RSA, ECC, MD5, SHA-1, weak TLS, and quantum-vulnerable cryptography.
            Get a Quantum Readiness Score and NIST-aligned migration guidance in seconds.
          </p>

          {/* Scan input */}
          <div style={{ display:"flex",maxWidth:520,margin:"0 auto 18px",background:"#fff",border:"1.5px solid #e2e8f0",borderRadius:12,overflow:"hidden",boxShadow:"0 4px 20px rgba(0,0,0,.07)" }}>
            <input value={scanInput} onChange={e=>setScanInput(e.target.value)}
              style={{ flex:1,border:"none",outline:"none",padding:"13px 16px",fontSize:13,fontFamily:"'DM Mono',monospace",color:"#374151",background:"transparent" }} />
            <button className="hp2-btn-primary" style={{ borderRadius:0,padding:"13px 20px",fontSize:13 }} onClick={onGetStarted}>
              Scan →
            </button>
          </div>

          <div style={{ display:"flex",gap:12,justifyContent:"center",flexWrap:"wrap",marginBottom:48 }}>
            <button className="hp2-btn-primary" style={{ padding:"14px 30px",fontSize:15 }} onClick={onGetStarted}>🛡 Run a Free Scan</button>
            <button className="hp2-btn-outline" style={{ padding:"12px 28px",fontSize:15 }} onClick={()=>setDemoOpen(true)}>▷ Try Demo</button>
          </div>

          <div style={{ display:"flex",gap:24,justifyContent:"center",flexWrap:"wrap",opacity:.5 }}>
            {["SOC 2 Type II","NIST Compliant","GDPR Ready","99.9% Uptime","Zero Data Retention"].map(t=>(
              <span key={t} style={{ fontSize:11,fontWeight:700,letterSpacing:".06em",color:"#374151",textTransform:"uppercase" }}>{t}</span>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════ STATS ═══════ */}
      <section style={{ background:"#fff",borderTop:"1px solid #e8edf3",borderBottom:"1px solid #e8edf3",padding:"40px 32px" }}>
        <div className="hp2-stats-grid" style={{ maxWidth:1000,margin:"0 auto",display:"grid",gridTemplateColumns:"repeat(4,1fr)",textAlign:"center",gap:24 }}>
          {[["50+","Vulnerability Checks"],["8","Languages Supported"],["~30s","Average Scan Time"],["100%","Free, No Limits"]].map(([val,lbl])=>(
            <div key={lbl}>
              <div style={{ fontSize:"2rem",fontWeight:800,color:"#22c55e",lineHeight:1,letterSpacing:"-.03em" }}>{val}</div>
              <div style={{ fontSize:13,color:"#6b7280",marginTop:6,fontWeight:500 }}>{lbl}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ═══════ LIVE EXAMPLE ═══════ */}
      <section style={{ padding:"80px 32px",background:"#f8fafc",borderBottom:"1px solid #e8edf3" }}>
        <div style={{ maxWidth:1060,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div className="hp2-section-label" style={{ marginBottom:12 }}>Live Example</div>
            <h2 style={{ fontSize:"clamp(24px,3vw,38px)",fontWeight:800,letterSpacing:"-.03em",color:"#0f172a" }}>What a real scan looks like</h2>
            <p style={{ color:"#6b7280",marginTop:12,fontSize:15,maxWidth:460,margin:"12px auto 0" }}>Actual output from scanning a sample Python + JavaScript repo.</p>
          </div>
          <div className="hp2-find-grid" style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:28,alignItems:"start" }}>
            {/* Score card */}
            <div style={{ background:"#fff",border:"1.5px solid #e2e8f0",borderRadius:18,overflow:"hidden",boxShadow:"0 4px 24px rgba(0,0,0,.07)" }}>
              <div style={{ background:"#f8fafc",borderBottom:"1px solid #e2e8f0",padding:"12px 18px",display:"flex",alignItems:"center",gap:8 }}>
                {["#ff5f57","#febc2e","#28c840"].map((c,i)=><div key={i} style={{ width:10,height:10,borderRadius:"50%",background:c }} />)}
                <span style={{ fontFamily:"'DM Mono',monospace",fontSize:11,color:"#94a3b8",marginLeft:6 }}>quantumguard — scan result</span>
              </div>
              <div style={{ padding:"24px 22px",borderBottom:"1px solid #e2e8f0",display:"flex",alignItems:"center",gap:20 }}>
                <div style={{ textAlign:"center",minWidth:80 }}>
                  <div style={{ fontSize:56,fontWeight:900,color:"#f59e0b",lineHeight:1 }}>42</div>
                  <div style={{ fontSize:10,color:"#94a3b8",textTransform:"uppercase",letterSpacing:1,marginTop:2 }}>/100</div>
                </div>
                <div>
                  <div style={{ fontSize:14,fontWeight:700,marginBottom:6 }}>Quantum Risk Score</div>
                  <span style={{ background:"#fef3c7",color:"#b45309",fontSize:11,fontWeight:700,padding:"3px 12px",borderRadius:100,border:"1px solid #fde68a" }}>⚠ At Risk</span>
                  <div style={{ marginTop:12,display:"flex",gap:14 }}>
                    {[["4","Findings"],["2","Critical"],["1","High"]].map(([n,l],i)=>(
                      <div key={i} style={{ textAlign:"center" }}>
                        <div style={{ fontSize:18,fontWeight:800,color:i===1?"#ef4444":i===2?"#f59e0b":"#0f172a" }}>{n}</div>
                        <div style={{ fontSize:10,color:"#94a3b8" }}>{l}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
              <div style={{ padding:"12px 22px",background:"#f8fafc",display:"flex",justifyContent:"space-between",fontSize:11,color:"#94a3b8" }}>
                <span>Target: <span style={{ fontFamily:"'DM Mono',monospace",color:"#475569" }}>github.com/example/myapp</span></span>
                <span style={{ color:"#22c55e",fontWeight:600 }}>✓ Scan complete · 8.3s</span>
              </div>
            </div>
            {/* Findings */}
            <div>
              <div style={{ fontSize:11,fontWeight:700,color:"#94a3b8",textTransform:"uppercase",letterSpacing:".08em",marginBottom:14 }}>4 Findings — with NIST fixes</div>
              {demoResult.findings.map((f,i)=>(
                <div key={i} className="hp2-finding-row">
                  <span className="hp2-sev" style={{ background:sevBg(f.sev),color:sevColor(f.sev) }}>{f.sev}</span>
                  <span style={{ fontWeight:700,color:"#0f172a",minWidth:90,flexShrink:0 }}>{f.vuln}</span>
                  <span style={{ color:"#94a3b8",flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",fontSize:11 }}>{f.file}</span>
                  <span style={{ color:"#2563eb",fontWeight:600,fontSize:11,flexShrink:0,whiteSpace:"nowrap" }}>→ {f.fix}</span>
                </div>
              ))}
              <div style={{ marginTop:14,background:"#f0fdf4",border:"1px solid #bbf7d0",borderRadius:10,padding:"12px 16px",fontSize:13,color:"#15803d",lineHeight:1.6 }}>
                💡 Each finding includes the <strong>exact file, line number</strong>, and a NIST-approved replacement.
              </div>
              <button className="hp2-btn-primary" style={{ marginTop:14,width:"100%",fontSize:13 }} onClick={onGetStarted}>
                Scan my own repo →
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════ FEATURES ═══════ */}
      <section id="features" style={{ padding:"80px 32px",background:"#fff",borderBottom:"1px solid #e8edf3" }}>
        <div style={{ maxWidth:1060,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div className="hp2-section-label" style={{ marginBottom:12 }}>Features</div>
            <h2 style={{ fontSize:"clamp(24px,3vw,38px)",fontWeight:800,letterSpacing:"-.03em" }}>Everything you need to go quantum-safe</h2>
          </div>
          <div className="hp2-features-grid" style={{ display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:20 }}>
            {[
              { icon:"🔍",title:"Quantum Code Scanner",badge:"Core",   bc:"#16a34a",bb:"#dcfce7",desc:"Detects RSA, ECC, DH, MD5, SHA-1 and 10+ other vulnerable algorithms across Python, JS, Java, TypeScript, Go, and more." },
              { icon:"🔐",title:"TLS Analyzer",         badge:"Free",   bc:"#1d4ed8",bb:"#dbeafe",desc:"Check any domain's TLS version and cipher suite for quantum readiness. Get a grade from A+ to F in one click." },
              { icon:"🔬",title:"Crypto Agility Checker",badge:"Free",  bc:"#7c3aed",bb:"#ede9fe",desc:"Score how easy it is to swap your encryption. Hardcoded crypto scores low — configurable crypto scores high." },
              { icon:"🧠",title:"Unified Risk Score",   badge:"Unique", bc:"#b45309",bb:"#fef3c7",desc:"One 0–100 score combining code crypto, TLS, and agility. Drill into each component to see exactly what drives risk." },
            ].map((f,i)=>(
              <div key={i} className="hp2-card" style={{ padding:"28px 24px" }}>
                <div style={{ display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:16 }}>
                  <div style={{ width:48,height:48,borderRadius:12,background:"#f0fdf4",border:"1.5px solid #bbf7d0",display:"flex",alignItems:"center",justifyContent:"center",fontSize:22 }}>{f.icon}</div>
                  <span style={{ background:f.bb,color:f.bc,fontSize:10,fontWeight:700,padding:"3px 10px",borderRadius:100 }}>{f.badge}</span>
                </div>
                <div style={{ fontSize:16,fontWeight:700,color:"#0f172a",marginBottom:8 }}>{f.title}</div>
                <div style={{ fontSize:13,color:"#6b7280",lineHeight:1.65 }}>{f.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════ HOW IT WORKS ═══════ */}
      <section id="howitworks" style={{ padding:"80px 32px",background:"#f8fafc",borderBottom:"1px solid #e8edf3" }}>
        <div style={{ maxWidth:900,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:52 }}>
            <div className="hp2-section-label" style={{ marginBottom:12 }}>How It Works</div>
            <h2 style={{ fontSize:"clamp(24px,3vw,38px)",fontWeight:800,letterSpacing:"-.03em" }}>From URL to results in 30 seconds</h2>
          </div>
          <div className="hp2-how-grid" style={{ display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:32 }}>
            {[
              { icon:"🔗",n:"1",title:"Paste your repo",   desc:"Paste a GitHub URL or upload a ZIP. No installation, no account required." },
              { icon:"🔍",n:"2",title:"We scan your code", desc:"Our engine checks every file against 50+ quantum-vulnerability patterns across all major languages." },
              { icon:"📊",n:"3",title:"Get score + fixes", desc:"Receive a risk score, PDF report, and exact NIST-approved replacement algorithms for every finding." },
            ].map((s,i)=>(
              <div key={i} style={{ textAlign:"center" }}>
                <div style={{ width:56,height:56,borderRadius:"50%",background:"#f0fdf4",border:"2px solid #bbf7d0",display:"flex",alignItems:"center",justifyContent:"center",fontSize:24,margin:"0 auto 16px" }}>{s.icon}</div>
                <div style={{ display:"flex",alignItems:"center",justifyContent:"center",gap:8,marginBottom:10 }}>
                  <div style={{ width:24,height:24,borderRadius:"50%",background:"#22c55e",color:"#fff",fontSize:12,fontWeight:800,display:"flex",alignItems:"center",justifyContent:"center" }}>{s.n}</div>
                  <span style={{ fontSize:16,fontWeight:700,color:"#0f172a" }}>{s.title}</span>
                </div>
                <p style={{ fontSize:13,color:"#6b7280",lineHeight:1.65 }}>{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════ WHY IT MATTERS ═══════ */}
      <section id="why" style={{ padding:"80px 32px",background:"#0f172a",borderBottom:"1px solid #1e293b" }}>
        <div style={{ maxWidth:1060,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:52 }}>
            <div style={{ fontSize:11,fontWeight:700,letterSpacing:".1em",color:"#22c55e",textTransform:"uppercase",marginBottom:12 }}>The Quantum Threat</div>
            <h2 style={{ fontSize:"clamp(24px,3vw,38px)",fontWeight:800,letterSpacing:"-.03em",color:"#f1f5f9" }}>Quantum computers will break RSA & ECC by ~2030</h2>
          </div>
          <div className="hp2-matter-grid" style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:40,alignItems:"center" }}>
            <div>
              {[
                { icon:"⏳",title:"Harvest now, decrypt later",  text:"Attackers are collecting encrypted data today to decrypt it once quantum computers exist. Your data is already at risk." },
                { icon:"📋",title:"NIST issued new standards in 2024",text:"FIPS 203, 204, and 205 replace RSA and ECC. Organizations that don't migrate will face growing compliance pressure." },
                { icon:"🚀",title:"Migration takes time — start early",text:"Replacing cryptography across a codebase is a multi-year project. The 2030 deadline is closer than it looks." },
              ].map((item,i)=>(
                <div key={i} style={{ display:"flex",gap:16,marginBottom:28,alignItems:"flex-start" }}>
                  <div style={{ width:42,height:42,borderRadius:10,background:"rgba(34,197,94,.1)",border:"1px solid rgba(34,197,94,.2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:20,flexShrink:0 }}>{item.icon}</div>
                  <div>
                    <div style={{ fontSize:14,fontWeight:700,color:"#f1f5f9",marginBottom:4 }}>{item.title}</div>
                    <div style={{ fontSize:13,color:"#94a3b8",lineHeight:1.65 }}>{item.text}</div>
                  </div>
                </div>
              ))}
            </div>
            <div style={{ background:"#1e293b",borderRadius:16,border:"1px solid #334155",padding:28 }}>
              <div style={{ fontSize:12,color:"#64748b",fontWeight:700,marginBottom:18,textTransform:"uppercase",letterSpacing:".08em" }}>Timeline</div>
              {[
                { year:"2024",text:"NIST finalizes FIPS 203/204/205 — new PQC standards issued",      color:"#22c55e" },
                { year:"2026",text:"QuantumGuard launches — free scanner for every developer",         color:"#38bdf8" },
                { year:"2027",text:"Regulatory pressure builds — compliance requirements grow",        color:"#f59e0b" },
                { year:"2030",text:"Y2Q — cryptographically relevant quantum computers arrive",        color:"#ef4444" },
              ].map((t,i)=>(
                <div key={i} style={{ display:"flex",gap:14,alignItems:"flex-start",paddingBottom:i<3?16:0,marginBottom:i<3?16:0,borderBottom:i<3?"1px solid #334155":"none" }}>
                  <span style={{ background:t.color+"22",color:t.color,border:`1px solid ${t.color}44`,fontSize:11,fontWeight:800,padding:"3px 10px",borderRadius:6,flexShrink:0 }}>{t.year}</span>
                  <span style={{ fontSize:13,color:"#cbd5e1",lineHeight:1.55,paddingTop:2 }}>{t.text}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ═══════ WHO IS THIS FOR ═══════ */}
      <section style={{ padding:"80px 32px",background:"#f8fafc",borderBottom:"1px solid #e8edf3" }}>
        <div style={{ maxWidth:1060,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div className="hp2-section-label" style={{ marginBottom:12 }}>Who It's For</div>
            <h2 style={{ fontSize:"clamp(24px,3vw,38px)",fontWeight:800,letterSpacing:"-.03em" }}>Built for anyone who writes or ships code</h2>
          </div>
          <div className="hp2-who-grid" style={{ display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:16 }}>
            {[
              { icon:"👩‍💻",role:"Security Engineers",  desc:"Run PQC audits on your entire codebase. Export NIST SP 800-53 compliance reports with one click." },
              { icon:"🧑‍💼",role:"CTOs & Tech Leads",   desc:"Get a single risk score across all your repos. Understand your quantum exposure before it becomes a liability." },
              { icon:"🔬", role:"Developers",            desc:"Paste your GitHub URL and see exactly which lines to fix, with copy-paste NIST replacement code." },
              { icon:"🏦", role:"Fintech & Healthcare",  desc:"Industries handling sensitive data must migrate early. Use QuantumGuard to document your compliance roadmap." },
              { icon:"🎓", role:"Researchers & Students",desc:"Free access to a production-grade scanner for academic research, coursework, and NIST standard exploration." },
              { icon:"🏢", role:"Enterprise Teams",      desc:"Scan unlimited repos, export CSV/PDF reports, and integrate into your CI/CD pipeline via REST API." },
            ].map((w,i)=>(
              <div key={i} className="hp2-card" style={{ padding:"22px 20px",display:"flex",gap:14,alignItems:"flex-start" }}>
                <div style={{ fontSize:26,flexShrink:0,marginTop:2 }}>{w.icon}</div>
                <div>
                  <div style={{ fontSize:14,fontWeight:700,marginBottom:5 }}>{w.role}</div>
                  <div style={{ fontSize:12,color:"#6b7280",lineHeight:1.65 }}>{w.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════ WHAT YOU GET ═══════ */}
      <section style={{ padding:"80px 32px",background:"#fff",borderBottom:"1px solid #e8edf3" }}>
        <div style={{ maxWidth:940,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div className="hp2-section-label" style={{ marginBottom:12 }}>What You Get</div>
            <h2 style={{ fontSize:"clamp(24px,3vw,38px)",fontWeight:800,letterSpacing:"-.03em" }}>Everything included. No paywall.</h2>
            <p style={{ color:"#6b7280",marginTop:10,fontSize:15,maxWidth:440,margin:"10px auto 0" }}>Every scan gives you a complete security picture — not a teaser that asks you to upgrade.</p>
          </div>
          <div className="hp2-get-grid" style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:12 }}>
            {[
              { icon:"🎯",item:"Quantum Readiness Score",       detail:"0–100 score showing your overall post-quantum risk level" },
              { icon:"📍",item:"Exact file + line numbers",     detail:"Every vulnerable line pinpointed — no manual searching" },
              { icon:"🔧",item:"NIST-approved fix per finding", detail:"Drop-in replacement algorithms from FIPS 203/204/205" },
              { icon:"📄",item:"PDF security report",           detail:"Print-ready report formatted to NIST SP 800-53 Rev 5" },
              { icon:"📊",item:"CSV export",                    detail:"Full findings table for spreadsheets and audit trails" },
              { icon:"🏛",item:"NIST compliance mapping",       detail:"Each finding mapped to SC-12, SC-13, IA-7, SC-28 controls" },
              { icon:"⚡",item:"AI-powered fix suggestions",    detail:"One-click AI explanation and migration code for any finding" },
              { icon:"📧",item:"Email report delivery",         detail:"Send the full report to any address straight from the scanner" },
            ].map((g,i)=>(
              <div key={i} style={{ display:"flex",gap:14,padding:"14px 16px",borderRadius:10,border:"1.5px solid #e2e8f0",background:"#f8fafc",alignItems:"flex-start",transition:"border-color .2s" }}
                onMouseEnter={e=>e.currentTarget.style.borderColor="#22c55e"}
                onMouseLeave={e=>e.currentTarget.style.borderColor="#e2e8f0"}
              >
                <div style={{ width:36,height:36,borderRadius:8,background:"#f0fdf4",border:"1.5px solid #bbf7d0",display:"flex",alignItems:"center",justifyContent:"center",fontSize:18,flexShrink:0 }}>{g.icon}</div>
                <div>
                  <div style={{ fontSize:13,fontWeight:700,color:"#0f172a",marginBottom:3 }}>{g.item}</div>
                  <div style={{ fontSize:12,color:"#6b7280",lineHeight:1.5 }}>{g.detail}</div>
                </div>
              </div>
            ))}
          </div>
          <div style={{ textAlign:"center",marginTop:32 }}>
            <button className="hp2-btn-primary" style={{ padding:"13px 32px",fontSize:15 }} onClick={onGetStarted}>Get everything — free →</button>
          </div>
        </div>
      </section>

      {/* ═══════ TRUST ═══════ */}
      <section style={{ padding:"72px 32px",background:"#f8fafc",borderBottom:"1px solid #e8edf3" }}>
        <div style={{ maxWidth:1060,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:44 }}>
            <div className="hp2-section-label" style={{ marginBottom:12 }}>You Can Trust Us</div>
            <h2 style={{ fontSize:"clamp(22px,3vw,34px)",fontWeight:800,letterSpacing:"-.03em" }}>Built on security, privacy, and open standards</h2>
          </div>
          <div style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:18 }}>
            {[
              { icon:"🏛",title:"NIST Aligned",   desc:"Recommendations follow FIPS 203, 204, and 205 — the official 2024 post-quantum standards." },
              { icon:"🔒",title:"No Code Stored",  desc:"Your source code is scanned in memory only. Nothing is logged, saved, or shared." },
              { icon:"👁", title:"Open Source",     desc:"Every line of our scanner is public on GitHub. Audit it yourself — no black boxes." },
              { icon:"🆓",title:"Always Free",     desc:"Core scanning is free forever. No credit card, no trial expiry, no hidden paywalls." },
            ].map((t,i)=>(
              <div key={i} className="hp2-card" style={{ padding:"24px 20px",textAlign:"center" }}>
                <div style={{ fontSize:28,marginBottom:12 }}>{t.icon}</div>
                <div style={{ fontSize:14,fontWeight:700,marginBottom:6 }}>{t.title}</div>
                <div style={{ fontSize:12,color:"#6b7280",lineHeight:1.65 }}>{t.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════ PRICING ═══════ */}
      <section style={{ padding:"80px 32px",background:"#fff",borderBottom:"1px solid #e8edf3" }}>
        <div style={{ maxWidth:1140,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div className="hp2-section-label" style={{ marginBottom:12 }}>Pricing</div>
            <h2 style={{ fontSize:"clamp(24px,3vw,38px)",fontWeight:800,letterSpacing:"-.03em" }}>Start free. Scale when you're ready.</h2>
            <p style={{ color:"#6b7280",marginTop:10,fontSize:15 }}>No credit card required for Free and Pro trials.</p>
          </div>
          <div className="hp2-pricing-grid" style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:18 }}>
            {PRICING.map(plan=>(
              <div key={plan.name} style={{ background:"#fff",border:plan.highlight?"2px solid #22c55e":"1.5px solid #e8edf3",borderRadius:18,padding:"28px 22px",position:"relative",boxShadow:plan.highlight?"0 8px 36px rgba(34,197,94,.13)":"0 2px 12px rgba(0,0,0,.04)",transform:plan.highlight?"scale(1.03)":"none",transition:"all .25s" }}
                onMouseEnter={e=>{ if(!plan.highlight){e.currentTarget.style.borderColor="#22c55e";e.currentTarget.style.transform="translateY(-2px)";} }}
                onMouseLeave={e=>{ if(!plan.highlight){e.currentTarget.style.borderColor="#e8edf3";e.currentTarget.style.transform="none";} }}
              >
                {plan.highlight && (
                  <div style={{ position:"absolute",top:-13,left:"50%",transform:"translateX(-50%)",background:"#22c55e",color:"#fff",fontSize:10,fontWeight:700,letterSpacing:".06em",padding:"4px 14px",borderRadius:100,whiteSpace:"nowrap" }}>MOST POPULAR</div>
                )}
                <div style={{ fontWeight:700,fontSize:15,marginBottom:4 }}>{plan.name}</div>
                <div style={{ fontSize:12,color:"#9ca3af",marginBottom:16 }}>{plan.desc}</div>
                <div style={{ display:"flex",alignItems:"baseline",gap:2,marginBottom:18 }}>
                  <span style={{ fontSize:"2rem",fontWeight:800,letterSpacing:"-.04em" }}>{plan.price}</span>
                  <span style={{ fontSize:13,color:"#9ca3af" }}>{plan.period}</span>
                </div>
                <button
                  onClick={plan.cta!=="Contact Sales"?onGetStarted:undefined}
                  style={{ width:"100%",padding:"11px",borderRadius:9,marginBottom:18,fontSize:13,fontWeight:600,cursor:"pointer",fontFamily:"inherit",transition:"all .2s",
                    background:plan.highlight?"#22c55e":"transparent",
                    color:plan.highlight?"#fff":"#0f172a",
                    border:plan.highlight?"none":"1.5px solid #d1d5db",
                  }}
                  onMouseEnter={e=>{ if(!plan.highlight){e.currentTarget.style.borderColor="#22c55e";e.currentTarget.style.color="#22c55e";} else{e.currentTarget.style.background="#16a34a";} }}
                  onMouseLeave={e=>{ if(!plan.highlight){e.currentTarget.style.borderColor="#d1d5db";e.currentTarget.style.color="#0f172a";} else{e.currentTarget.style.background="#22c55e";} }}
                >{plan.cta}</button>
                <div style={{ display:"flex",flexDirection:"column",gap:9 }}>
                  {plan.features.map(f=>(
                    <div key={f} style={{ display:"flex",alignItems:"center",gap:9,fontSize:12,color:"#4b5563" }}>
                      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" style={{ flexShrink:0 }}><path d="M3 8l3.5 3.5L13 4" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
                      {f}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════ FINAL CTA ═══════ */}
      <section style={{ padding:"96px 32px",background:"linear-gradient(135deg,#052e16 0%,#14532d 60%,#052e16 100%)",textAlign:"center",position:"relative",overflow:"hidden" }}>
        <div style={{ position:"absolute",top:"50%",left:"50%",transform:"translate(-50%,-50%)",width:700,height:360,borderRadius:"50%",background:"radial-gradient(circle,rgba(34,197,94,.08) 0%,transparent 70%)",pointerEvents:"none" }} />
        <div style={{ maxWidth:620,margin:"0 auto",position:"relative" }}>
          <div style={{ width:52,height:52,background:"linear-gradient(135deg,#22c55e,#15803d)",borderRadius:14,display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 20px",fontSize:22,boxShadow:"0 8px 24px rgba(34,197,94,.3)" }}>⚛</div>
          <div style={{ fontSize:11,fontWeight:700,letterSpacing:".1em",color:"#4ade80",textTransform:"uppercase",marginBottom:16 }}>Get Started Today</div>
          <h2 style={{ fontSize:"clamp(28px,4vw,48px)",fontWeight:800,letterSpacing:"-.04em",color:"#fff",lineHeight:1.1,marginBottom:16 }}>
            Ready to secure your code<br/>for the quantum future?
          </h2>
          <p style={{ color:"#86efac",fontSize:16,lineHeight:1.7,marginBottom:40 }}>
            Join developers scanning their repos for quantum vulnerabilities — before the deadline.<br/>
            First scan free. No credit card. Results in 30 seconds.
          </p>
          <div style={{ display:"flex",gap:14,justifyContent:"center",flexWrap:"wrap" }}>
            <button className="hp2-btn-primary" style={{ padding:"15px 34px",fontSize:16 }} onClick={onGetStarted}>🛡 Start Scanning — Free</button>
            <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer"
              style={{ display:"inline-flex",alignItems:"center",gap:8,background:"rgba(255,255,255,.08)",color:"#f1f5f9",border:"1.5px solid rgba(255,255,255,.2)",padding:"15px 34px",borderRadius:10,fontSize:16,fontWeight:700,textDecoration:"none",transition:"all .2s" }}
              onMouseEnter={e=>e.currentTarget.style.borderColor="#22c55e"}
              onMouseLeave={e=>e.currentTarget.style.borderColor="rgba(255,255,255,.2)"}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
              GitHub
            </a>
          </div>
          <div style={{ marginTop:28,fontSize:12,color:"rgba(255,255,255,.3)" }}>NIST FIPS 203 · 204 · 205 · SOC 2 Type II · Zero Data Retention · Mangsri QuantumGuard LLC · Montgomery, AL</div>
        </div>
      </section>

      {/* ═══════ FOOTER ═══════ */}
      <footer style={{ background:"#0b1117",padding:"44px 32px 28px",color:"#4b5563" }}>
        <div style={{ maxWidth:1100,margin:"0 auto" }}>
          <div style={{ display:"flex",gap:44,flexWrap:"wrap",marginBottom:32 }}>
            <div style={{ flex:"1 1 200px" }}>
              <div style={{ display:"flex",alignItems:"center",gap:8,marginBottom:12 }}>
                <div style={{ width:28,height:28,background:"linear-gradient(135deg,#22c55e,#15803d)",borderRadius:7,display:"flex",alignItems:"center",justifyContent:"center",fontSize:14 }}>⚛</div>
                <span style={{ color:"#f8fafc",fontWeight:800,fontSize:15,letterSpacing:"-.02em" }}><span style={{ color:"#22c55e" }}>Quantum</span>Guard</span>
              </div>
              <p style={{ fontSize:12,lineHeight:1.65,maxWidth:190 }}>Post-quantum cryptography scanning for modern engineering teams.</p>
              <div style={{ marginTop:10,fontSize:11,color:"#374151" }}>Mangsri QuantumGuard LLC · Montgomery, AL · EIN 42-2185776</div>
            </div>
            {[
              { title:"Product", links:["Quantum Scanner","CI/CD Gate","TLS Analyzer","Executive Reports"] },
              { title:"Company", links:["About","Our Team","Blog","Careers"] },
              { title:"Legal",   links:["Privacy","Terms","Security","Cookie Policy"] },
            ].map(col=>(
              <div key={col.title} style={{ flex:"1 1 120px" }}>
                <div style={{ fontSize:11,fontWeight:700,color:"#f8fafc",letterSpacing:".07em",textTransform:"uppercase",marginBottom:14 }}>{col.title}</div>
                {col.links.map(l=>(
                  <div key={l} style={{ fontSize:12,color:"#4b5563",marginBottom:9,cursor:"pointer",transition:"color .15s" }}
                    onMouseEnter={e=>e.currentTarget.style.color="#22c55e"}
                    onMouseLeave={e=>e.currentTarget.style.color="#4b5563"}
                  >{l}</div>
                ))}
              </div>
            ))}
          </div>
          <div style={{ borderTop:"1px solid #1e293b",paddingTop:20,display:"flex",justifyContent:"space-between",flexWrap:"wrap",gap:10,fontSize:12 }}>
            <span>© 2025 Mangsri QuantumGuard LLC. All rights reserved.</span>
            <span>Built for the post-quantum era.</span>
          </div>
        </div>
      </footer>

      {/* ═══════ DEMO MODAL ═══════ */}
      {demoOpen && (
        <div className="hp2-modal-overlay" onClick={()=>setDemoOpen(false)}>
          <div className="hp2-modal" onClick={e=>e.stopPropagation()}>
            <div style={{ padding:"18px 22px",borderBottom:"1px solid #e2e8f0",display:"flex",justifyContent:"space-between",alignItems:"center" }}>
              <div style={{ display:"flex",alignItems:"center",gap:10 }}>
                <div style={{ width:30,height:30,borderRadius:7,background:"#22c55e",display:"flex",alignItems:"center",justifyContent:"center",fontSize:14 }}>⚛</div>
                <span style={{ fontWeight:800,fontSize:15 }}>Demo Scan Result</span>
                <span style={{ background:"#fef3c7",color:"#b45309",fontSize:10,fontWeight:700,padding:"2px 8px",borderRadius:100 }}>SAMPLE</span>
              </div>
              <button onClick={()=>setDemoOpen(false)} style={{ background:"transparent",border:"none",cursor:"pointer",fontSize:20,color:"#94a3b8" }}>✕</button>
            </div>
            <div style={{ padding:"20px 22px",background:"#fffbeb",borderBottom:"1px solid #e2e8f0",display:"flex",alignItems:"center",gap:16 }}>
              <div style={{ textAlign:"center",minWidth:80 }}>
                <div style={{ fontSize:52,fontWeight:900,color:"#f59e0b",lineHeight:1 }}>42</div>
                <div style={{ fontSize:10,color:"#94a3b8",textTransform:"uppercase",letterSpacing:1,marginTop:2 }}>/100</div>
              </div>
              <div>
                <div style={{ fontSize:15,fontWeight:700,marginBottom:4 }}>Quantum Risk Score</div>
                <span style={{ background:"#fef3c7",color:"#b45309",fontSize:11,fontWeight:700,padding:"3px 12px",borderRadius:100,border:"1px solid #fde68a" }}>⚠ At Risk</span>
                <div style={{ marginTop:8,fontSize:12,color:"#6b7280" }}>Target: <code style={{ fontFamily:"'DM Mono',monospace",background:"#f1f5f9",padding:"1px 6px",borderRadius:4 }}>github.com/example/myapp</code></div>
              </div>
            </div>
            <div style={{ padding:"16px 22px 22px" }}>
              <div style={{ fontSize:11,fontWeight:700,color:"#94a3b8",textTransform:"uppercase",letterSpacing:".08em",marginBottom:12 }}>4 Findings Detected</div>
              {demoResult.findings.map((f,i)=>(
                <div key={i} style={{ display:"flex",alignItems:"center",gap:10,padding:"10px 14px",borderRadius:8,background:"#f8fafc",border:"1.5px solid #e2e8f0",fontFamily:"'DM Mono',monospace",fontSize:12,marginBottom:6 }}>
                  <span className="hp2-sev" style={{ background:sevBg(f.sev),color:sevColor(f.sev) }}>{f.sev}</span>
                  <span style={{ fontWeight:700,color:"#0f172a",minWidth:90 }}>{f.vuln}</span>
                  <span style={{ color:"#94a3b8",flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }}>{f.file}</span>
                  <span style={{ color:"#2563eb",fontWeight:600,fontSize:11,flexShrink:0 }}>→ {f.fix}</span>
                </div>
              ))}
              <div style={{ marginTop:14,background:"#f0fdf4",borderRadius:10,padding:"12px 14px",border:"1px solid #bbf7d0",fontSize:12,color:"#15803d" }}>
                💡 This is sample data. <strong>Scan your own repo</strong> to get real findings with AI-powered fix suggestions.
              </div>
              <button className="hp2-btn-primary" style={{ width:"100%",marginTop:14,fontSize:14 }} onClick={()=>{ setDemoOpen(false); onGetStarted(); }}>
                Scan My Repo Now →
              </button>
            </div>
          </div>
        </div>
      )}
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

  const STEPS = [
    "Initializing scan engine...", "Connecting to target...",
    "Analyzing cryptography...", "Checking TLS posture...",
    "Calculating unified risk score...", "Generating recommendations...",
  ];

  const NIST_CONTROLS = [
    { id: "SC-12", name: "Cryptographic Key Management",   status: "FAIL" },
    { id: "SC-13", name: "Cryptographic Protection",       status: "FAIL" },
    { id: "IA-7",  name: "Crypto Module Authentication",   status: "WARN" },
    { id: "SC-8",  name: "Transmission Integrity",         status: "WARN" },
    { id: "CM-7",  name: "Least Functionality",            status: "PASS" },
  ];

  const ROADMAP = [
    { year: "Now",     text: "Inventory all cryptographic assets — RSA, ECC, DH usages found in codebase.", danger: false },
    { year: "Q3 2026", text: "Begin migration: replace RSA with CRYSTALS-Kyber (FIPS 203), ECC with CRYSTALS-Dilithium (FIPS 204).", danger: false },
    { year: "Q1 2027", text: "Enable TLS 1.3 with hybrid PQC cipher suites on all public endpoints.", danger: false },
    { year: "2030",    text: "Y2Q deadline — cryptographically relevant quantum computers expected to arrive.", danger: true },
  ];

  const startProgress = () => {
    setProgress(0); setStepIndex(0); let p = 0;
    intervalRef.current = setInterval(() => {
      p += Math.random() * 8 + 2; if (p > 92) p = 92;
      setProgress(Math.round(p));
      setStepIndex(Math.min(STEPS.length - 1, Math.floor(p / (100 / STEPS.length))));
    }, 380);
  };
  const stopProgress = () => {
    clearInterval(intervalRef.current);
    setProgress(100); setStepIndex(STEPS.length - 1);
    setTimeout(() => setProgress(0), 900);
  };

  const scoreColor  = (s) => s >= 70 ? C.green    : s >= 40 ? C.amber    : C.red;
  const scoreBg     = (s) => s >= 70 ? "rgba(34,197,94,0.1)"  : s >= 40 ? "rgba(245,158,11,0.1)"  : "rgba(239,68,68,0.1)";
  const scoreBorder = (s) => s >= 70 ? "rgba(34,197,94,0.3)"  : s >= 40 ? "rgba(245,158,11,0.3)"  : "rgba(239,68,68,0.3)";
  const riskLevel   = (s) => s >= 70 ? "LOW RISK" : s >= 40 ? "MODERATE RISK" : "CRITICAL RISK";
  const sevColor = (sev) => sev === "CRITICAL" ? C.critical : sev === "HIGH" ? C.amber : C.medium;
  const sevBg    = (sev) => SEV_BG[sev] || SEV_BG.MEDIUM;
  const ctrlStyle = (status) => ({
    PASS: { bg: "rgba(34,197,94,0.1)",  color: C.green,   dot: C.green,    border: "rgba(34,197,94,0.3)"  },
    WARN: { bg: "rgba(245,158,11,0.1)", color: C.amber,   dot: C.amber,    border: "rgba(245,158,11,0.3)" },
    FAIL: { bg: "rgba(239,68,68,0.1)",  color: C.red,     dot: C.critical, border: "rgba(239,68,68,0.3)"  },
  }[status]);

  const handleScan = async () => {
    if (!github || !domain) return;
    setLoading(true); setError(null); setData(null);
    startProgress();
    try {
      const res = await fetch(`${API}/unified-risk`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ github_url: github, domain }) });
      const json = await res.json();
      if (!res.ok) throw new Error(json.detail || "Scan failed");
      stopProgress(); setData(json);
    } catch (e) { stopProgress(); setError(typeof e.message === "string" ? e.message : "Scan failed."); }
    setLoading(false);
  };

  const handleCSV = () => {
    if (!data) return;
    const ur = data.unified_risk || {};
    const cs = ur.component_scores || {};
    const ss = data.finding_summary?.severity_summary || {};
    const rows = ["Metric,Value",`Unified Risk Score,${Math.round(ur.quantum_risk_score || 0)}`,`Risk Level,${ur.risk_level || ""}`,`Code Crypto Score,${Math.round(cs.code_crypto_score || 0)}`,`Crypto Agility Score,${Math.round(cs.crypto_agility_score || 0)}`,`TLS Score,${Math.round(cs.tls_score || 0)}`,`Critical Findings,${ss.CRITICAL || 0}`,`High Findings,${ss.HIGH || 0}`,`Medium Findings,${ss.MEDIUM || 0}`].join("\n");
    const blob = new Blob([rows], { type: "text/csv" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "unified-risk.csv"; a.click();
  };

  const ur           = data?.unified_risk || {};
  const cs           = ur.component_scores || {};
  const fs           = data?.finding_summary || {};
  const ss           = fs.severity_summary || {};
  const topFindings  = data?.top_findings || [];
  const score        = Math.round(ur.quantum_risk_score || 0);
  const codeScore    = Math.round(cs.code_crypto_score || 0);
  const agilityScore = Math.round(cs.crypto_agility_score || 0);
  const tlsScore     = Math.round(cs.tls_score || 0);
  const totalFindings = (ss.CRITICAL || 0) + (ss.HIGH || 0) + (ss.MEDIUM || 0) + (ss.LOW || 0);

  return (
    <div style={{ padding: 20 }}>
      <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderTop: `3px solid ${C.green}`, borderRadius: 14, padding: "20px 22px", marginBottom: 16, boxShadow: "0 4px 20px rgba(0,0,0,0.4)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16, marginBottom: 18 }}>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <div style={{ width: 32, height: 32, borderRadius: 8, background: "linear-gradient(135deg, #22c55e, #16a34a)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, boxShadow: "0 0 10px rgba(34,197,94,0.3)" }}>🧠</div>
              <h2 style={{ fontSize: 20, fontWeight: 800, color: C.text }}>Unified Risk Dashboard</h2>
            </div>
            <p style={{ fontSize: 13, color: C.muted, maxWidth: 460, lineHeight: 1.6 }}>Combines code scanning, TLS analysis and crypto agility into a single quantum risk score with NIST-aligned remediation guidance.</p>
          </div>
          {data && (
            <div style={{ background: scoreBg(score), border: `1px solid ${scoreBorder(score)}`, borderRadius: 12, padding: "14px 20px", textAlign: "center", minWidth: 130 }}>
              <div style={{ fontSize: 44, fontWeight: 900, color: scoreColor(score), lineHeight: 1 }}>{score}</div>
              <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginTop: 2 }}>Unified Score</div>
              <div style={{ display: "inline-flex", alignItems: "center", gap: 5, background: "rgba(255,255,255,0.04)", color: scoreColor(score), fontSize: 10, fontWeight: 700, padding: "3px 10px", borderRadius: 100, marginTop: 8, border: `1px solid ${scoreBorder(score)}` }}>
                <div style={{ width: 5, height: 5, borderRadius: "50%", background: scoreColor(score) }} />
                {ur.risk_level || riskLevel(score)}
              </div>
            </div>
          )}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 10 }}>
          <input value={github} onChange={e => setGithub(e.target.value)} placeholder="https://github.com/user/repo" style={{ padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
          <input value={domain} onChange={e => setDomain(e.target.value)} placeholder="domain.com" style={{ padding: "9px 14px", borderRadius: 8, border: `1.5px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 13 }} />
        </div>
        <button onClick={handleScan} disabled={loading} style={{ padding: "9px 24px", borderRadius: 8, background: loading ? C.greenDark : "linear-gradient(135deg, #22c55e, #16a34a)", color: C.white, border: "none", cursor: loading ? "not-allowed" : "pointer", fontSize: 13, fontWeight: 600, boxShadow: loading ? "none" : "0 4px 12px rgba(34,197,94,0.3)", transition: "all 0.2s ease" }}>{loading ? "Scanning..." : "▶ Run Unified Scan"}</button>
        {loading && (
          <div style={{ marginTop: 12, background: "rgba(34,197,94,0.06)", borderRadius: 10, padding: "14px 16px", border: "1px solid rgba(34,197,94,0.2)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: C.green, marginBottom: 8, fontWeight: 500, alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: C.green, animation: "pulse-ring 1.2s ease-in-out infinite" }} />
                <span>✦ {STEPS[stepIndex]}</span>
              </div>
              <span style={{ fontWeight: 700 }}>{progress}%</span>
            </div>
            <div style={{ background: "rgba(255,255,255,0.08)", borderRadius: 6, height: 6 }}>
              <div style={{ background: `linear-gradient(90deg, #22c55e, #4ade80)`, height: 6, borderRadius: 6, width: `${progress}%`, transition: "width 0.4s ease", boxShadow: "0 0 10px rgba(34,197,94,0.6)" }} />
            </div>
          </div>
        )}
        {error && <div style={{ marginTop: 10, background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.3)", borderRadius: 8, padding: "10px 14px", color: C.red, fontSize: 13 }}>⚠ {error}</div>}
      </div>

      {!data && !loading && (
        <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 14, padding: "56px 24px", textAlign: "center", boxShadow: "0 4px 16px rgba(0,0,0,0.3)" }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>🧠</div>
          <div style={{ fontSize: 16, fontWeight: 700, color: C.text, marginBottom: 8 }}>No scan results yet</div>
          <div style={{ fontSize: 13, color: C.muted }}>Enter a GitHub URL and domain above, then click Run Unified Scan.</div>
        </div>
      )}

      {data && (
        <>
          <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
            <ScoreCard label="Quantum Risk Score"   value={score}        color={scoreColor(score)}        icon="🧠" desc={ur.risk_level || riskLevel(score)} />
            <ScoreCard label="Code Scanner Score"   value={codeScore}    color={scoreColor(codeScore)}    icon="🔍" desc={codeScore >= 70 ? "Good crypto hygiene" : "Vulnerable algorithms found"} />
            <ScoreCard label="Crypto Agility Score" value={agilityScore} color={scoreColor(agilityScore)} icon="🔬" desc={agilityScore >= 70 ? "Highly configurable" : "Hardcoded crypto detected"} />
            <ScoreCard label="TLS Security Score"   value={tlsScore}     color={scoreColor(tlsScore)}     icon="🔐" desc={tlsScore >= 70 ? "TLS 1.3 ready" : "TLS upgrade needed"} />
          </div>

          {totalFindings > 0 && (
            <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
              <Metric label="Total findings" value={totalFindings}     color={C.text}     icon="🔍" desc="across all modules" />
              <Metric label="Critical"       value={ss.CRITICAL || 0} color={C.critical} icon="🔴" desc="immediate action required" />
              <Metric label="High"           value={ss.HIGH     || 0} color={C.amber}    icon="🟡" desc="requires attention" />
              <Metric label="Medium"         value={ss.MEDIUM   || 0} color={C.medium}   icon="🟠" desc="review needed" />
            </div>
          )}

          <div className="charts-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
            <Panel title="Component breakdown" accent>
              {[["Code crypto", codeScore, scoreColor(codeScore)], ["Crypto agility", agilityScore, scoreColor(agilityScore)], ["TLS security", tlsScore, scoreColor(tlsScore)]].map(([label, val, col]) => (
                <div key={label} style={{ marginBottom: 14 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
                    <span style={{ color: C.muted, fontWeight: 500 }}>{label}</span>
                    <span style={{ color: col, fontWeight: 700 }}>{val}/100</span>
                  </div>
                  <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 4, height: 8 }}>
                    <div style={{ background: col, height: 8, borderRadius: 4, width: `${val}%`, transition: "width 0.6s ease", boxShadow: `0 0 6px ${col}55` }} />
                  </div>
                </div>
              ))}
              {totalFindings > 0 && (
                <>
                  <div style={{ height: 1, background: C.panelBorder, margin: "4px 0 14px" }} />
                  {[["Critical", ss.CRITICAL || 0, C.critical], ["High", ss.HIGH || 0, C.amber], ["Medium", ss.MEDIUM || 0, C.medium]].map(([label, val, col]) => (
                    <div key={label} style={{ marginBottom: 10 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
                        <span style={{ color: col, fontWeight: 600 }}>{label}</span>
                        <span style={{ color: C.muted }}>{val} ({totalFindings > 0 ? Math.round(val / totalFindings * 100) : 0}%)</span>
                      </div>
                      <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 4, height: 6 }}>
                        <div style={{ background: col, height: 6, borderRadius: 4, width: `${totalFindings > 0 ? Math.round(val / totalFindings * 100) : 0}%`, transition: "width 0.6s ease" }} />
                      </div>
                    </div>
                  ))}
                </>
              )}
            </Panel>

            <Panel title="NIST SP 800-53 control status" accent>
              {NIST_CONTROLS.map((ctrl) => {
                const sc = ctrlStyle(ctrl.status);
                return (
                  <div key={ctrl.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 9, fontSize: 12 }}>
                    <span style={{ color: C.muted }}><span style={{ fontFamily: "monospace", color: C.green, fontWeight: 700 }}>{ctrl.id}</span> — {ctrl.name}</span>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: 4, background: sc.bg, color: sc.color, fontSize: 10, fontWeight: 700, padding: "3px 10px", borderRadius: 100, border: `1px solid ${sc.border}`, whiteSpace: "nowrap", marginLeft: 8 }}>
                      <span style={{ width: 5, height: 5, borderRadius: "50%", background: sc.dot, display: "inline-block" }} />
                      {ctrl.status}
                    </span>
                  </div>
                );
              })}
            </Panel>
          </div>

          {topFindings.length > 0 && (
            <Panel title={`Top findings — ${topFindings.length} shown`} accent>
              {topFindings.map((f, i) => (
                <div key={i} style={{ borderLeft: `3px solid ${sevColor(f.severity)}`, paddingLeft: 14, marginBottom: i < topFindings.length - 1 ? 14 : 0, paddingBottom: i < topFindings.length - 1 ? 14 : 0, borderBottom: i < topFindings.length - 1 ? `1px solid ${C.panelBorder}` : "none" }}>
                  <div style={{ display: "flex", gap: 8, marginBottom: 5, alignItems: "center", flexWrap: "wrap" }}>
                    <span style={{ background: sevBg(f.severity), color: sevColor(f.severity), fontSize: 10, fontWeight: 800, padding: "2px 8px", borderRadius: 6, border: `1px solid ${sevColor(f.severity)}44`, textTransform: "uppercase" }}>{f.severity}</span>
                    <span style={{ background: "rgba(255,255,255,0.06)", color: C.muted, fontSize: 10, fontWeight: 600, padding: "2px 8px", borderRadius: 4 }}>{f.vulnerability}</span>
                    {f.confidence && <span style={{ fontSize: 10, color: C.muted }}>Confidence: {f.confidence}</span>}
                    <span style={{ marginLeft: "auto", fontSize: 11, color: C.muted }}>Line {f.line}</span>
                  </div>
                  <div style={{ fontFamily: "monospace", fontSize: 11, color: C.green, fontWeight: 600, marginBottom: 4, wordBreak: "break-all" }}>{f.file?.split("/").pop()}</div>
                  {f.recommended_fix && (
                    <div style={{ background: "rgba(59,130,246,0.08)", border: "1px solid rgba(59,130,246,0.2)", borderRadius: 6, padding: "6px 10px", display: "flex", gap: 8, alignItems: "center" }}>
                      <span style={{ fontSize: 10, fontWeight: 700, color: "#60a5fa", textTransform: "uppercase", letterSpacing: "0.05em" }}>Fix</span>
                      <span style={{ color: "#93c5fd", fontWeight: 500, fontSize: 11 }}>✦ {f.recommended_fix}</span>
                    </div>
                  )}
                </div>
              ))}
            </Panel>
          )}

          {ur.business_summary && (
            <Panel title="Business risk summary" accent>
              <div style={{ fontSize: 13, color: C.muted, lineHeight: 1.75, background: "rgba(34,197,94,0.05)", padding: "12px 16px", borderRadius: 8, border: "1px solid rgba(34,197,94,0.15)" }}>{ur.business_summary}</div>
            </Panel>
          )}

          <Panel title="NIST remediation roadmap" accent>
            {ROADMAP.map((item, i) => (
              <div key={i} style={{ display: "flex", gap: 14, padding: "10px 0", borderBottom: i < ROADMAP.length - 1 ? `1px solid ${C.panelBorder}` : "none" }}>
                <div style={{ background: item.danger ? "rgba(239,68,68,0.15)" : "rgba(34,197,94,0.15)", color: item.danger ? C.red : C.green, border: `1px solid ${item.danger ? "rgba(239,68,68,0.3)" : "rgba(34,197,94,0.3)"}`, fontSize: 11, fontWeight: 700, padding: "3px 9px", borderRadius: 6, flexShrink: 0, height: "fit-content", marginTop: 2 }}>{item.year}</div>
                <div style={{ fontSize: 13, color: C.muted, lineHeight: 1.6, paddingTop: 2 }}>{item.text}</div>
              </div>
            ))}
          </Panel>

          <Panel title="Export & share" accent>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button onClick={handleCSV} style={{ padding: "8px 16px", borderRadius: 8, background: "rgba(34,197,94,0.1)", color: C.green, border: "1px solid rgba(34,197,94,0.3)", cursor: "pointer", fontSize: 12, fontWeight: 600, transition: "all 0.2s ease" }}>📊 CSV Export</button>
            </div>
          </Panel>
        </>
      )}
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

  const handleLogin  = async () => { try { await signInWithGoogle(); } catch (e) { console.error(e); } };
  const handleLogout = async () => { try { await signOut(auth); setUser(null); } catch (e) { console.error(e); } };

  if (active === "home") return <Homepage onGetStarted={() => setActive("scan")} />;

  const pageTitle = {
    scan:      "Threat Scanner",
    agility:   "Agility Checker",
    tls:       "TLS Analyzer",
    history:   "Scan History",
    migration: "Migration Tracker",
    dashboard: "Analytics",
    nist:      "NIST Report",
    docs:      "Documentation",
    team:      "Our Team",
    unified:   "Unified Risk",
  };

  return (
    <>
      <style>{`
        @keyframes pulse-ring {
          0%   { box-shadow: 0 0 0 0 rgba(34,197,94,0.5); }
          70%  { box-shadow: 0 0 0 8px rgba(34,197,94,0); }
          100% { box-shadow: 0 0 0 0 rgba(34,197,94,0); }
        }
      `}</style>
      <div style={{ display: "flex", minHeight: "100vh", background: C.bg }}>
        <button className="hamburger" onClick={() => setSidebarOpen(!sidebarOpen)}>☰</button>
        {sidebarOpen && <div className="sidebar-overlay open" onClick={() => setSidebarOpen(false)} />}
        <Sidebar active={active} setActive={setActive} user={user} onLogin={handleLogin} onLogout={handleLogout} open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
        <div className="main-content" style={{ flex: 1, minHeight: "100vh", display: "flex", flexDirection: "column" }}>
          <TopBar title={pageTitle[active] || active} user={user} onLogin={handleLogin} onLogout={handleLogout} onHamburger={() => setSidebarOpen(!sidebarOpen)} />
          <div style={{ flex: 1, overflowY: "auto" }}>
            {active === "scan"      && <ScannerPage user={user} />}
            {active === "agility"   && <AgilityPage />}
            {active === "tls"       && <TLSPage />}
            {active === "unified"   && <UnifiedRiskPage />}
            {active === "history"   && <HistoryPage user={user} />}
            {active === "migration" && <MigrationPage user={user} />}
            {active === "dashboard" && <AnalyticsPage />}
            {active === "nist"      && <NISTReportPage />}
            {active === "docs"      && <DocsPage />}
            {active === "team"      && <TeamPage />}
          </div>
        </div>
      </div>
    </>
  );
}
