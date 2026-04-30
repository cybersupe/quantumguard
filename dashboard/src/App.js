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
    { id: "scan",      icon: "⚡",  label: "Scanner" },
    { id: "agility",   icon: "🔬",  label: "Agility Checker" },
    { id: "tls",       icon: "🔐",  label: "TLS Analyzer" },
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
      <button onClick={onHamburger} style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", fontSize: 20, padding: "0 4px" }} className="hamburger-top">☰</button>
      <span style={{ color: C.muted, fontSize: 13 }}>QuantumGuard</span>
      <span style={{ color: C.greenMid, fontSize: 13 }}>›</span>
      <span style={{ color: C.text, fontSize: 14, fontWeight: 600 }}>{title}</span>
      <div className="topbar-right" style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
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
// NIST REPORT PAGE
// ══════════════════════════════════════════════════════════════

// Clean deduplicated findings — no comment lines, unique per file+line+vuln
const NIST_FINDINGS = [
  // ── TestVulnerable.java ──
  { file: "tests/TestVulnerable.java", line: 9,  code: 'KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");', vulnerability: "RSA",  severity: "CRITICAL", replacement: "CRYSTALS-Kyber" },
  { file: "tests/TestVulnerable.java", line: 13, code: 'KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");',   vulnerability: "ECC",  severity: "CRITICAL", replacement: "CRYSTALS-Dilithium" },
  { file: "tests/TestVulnerable.java", line: 16, code: 'KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");',   vulnerability: "DH",   severity: "HIGH",     replacement: "CRYSTALS-Kyber" },
  { file: "tests/TestVulnerable.java", line: 19, code: 'MessageDigest md5 = MessageDigest.getInstance("MD5");',          vulnerability: "MD5",  severity: "MEDIUM",   replacement: "SHA-3 or SPHINCS+" },
  { file: "tests/TestVulnerable.java", line: 22, code: 'MessageDigest sha1 = MessageDigest.getInstance("SHA-1");',       vulnerability: "SHA1", severity: "MEDIUM",   replacement: "SHA-3 or SPHINCS+" },
  // ── test_vulnerable.js ──
  { file: "tests/test_vulnerable.js",  line: 2,  code: "const NodeRSA = require('node-rsa');",                           vulnerability: "RSA",  severity: "CRITICAL", replacement: "CRYSTALS-Kyber" },
  { file: "tests/test_vulnerable.js",  line: 3,  code: "const elliptic = require('elliptic');",                          vulnerability: "ECC",  severity: "CRITICAL", replacement: "CRYSTALS-Dilithium" },
  { file: "tests/test_vulnerable.js",  line: 6,  code: "const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {", vulnerability: "RSA", severity: "CRITICAL", replacement: "CRYSTALS-Kyber" },
  { file: "tests/test_vulnerable.js",  line: 11, code: "const ec = new elliptic.ec('secp256k1');",                       vulnerability: "ECC",  severity: "CRITICAL", replacement: "CRYSTALS-Dilithium" },
  { file: "tests/test_vulnerable.js",  line: 15, code: "const dh = crypto.createDiffieHellman(2048);",                    vulnerability: "DH",   severity: "HIGH",     replacement: "CRYSTALS-Kyber" },
  { file: "tests/test_vulnerable.js",  line: 19, code: "const md5Hash = crypto.createHash('md5').update('password').digest('hex');", vulnerability: "MD5",  severity: "MEDIUM", replacement: "SHA-3 or SPHINCS+" },
  { file: "tests/test_vulnerable.js",  line: 22, code: "const sha1Hash = crypto.createHash('sha1').update('data').digest('hex');",   vulnerability: "SHA1", severity: "MEDIUM", replacement: "SHA-3 or SPHINCS+" },
  // ── test_vulnerable.py ──
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

const SEV_COLOR = { CRITICAL: C.critical, HIGH: C.amber, MEDIUM: C.medium };
const SEV_BG    = { CRITICAL: C.redLight, HIGH: C.amberLight, MEDIUM: "#fef9c3" };
const STAT_CTRL = { PASS: { color: C.green,    bg: C.greenLighter, border: C.greenMid,   dot: C.green    },
                    WARN: { color: C.amber,    bg: C.amberLight,   border: "#fcd34d",    dot: C.amber    },
                    FAIL: { color: C.critical, bg: C.redLight,     border: "#fca5a5",    dot: C.critical } };

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
    <div style={{ border: `1px solid ${open ? C.greenMid : C.panelBorder}`, borderRadius: 10, marginBottom: 8, overflow: "hidden", background: C.white, transition: "border-color 0.15s" }}>
      <div onClick={() => setOpen(o => !o)} style={{ display: "flex", alignItems: "center", gap: 10, padding: "11px 16px", cursor: "pointer", flexWrap: "wrap", gap: 8 }}>
        <Badge text={f.severity} color={sc} bg={sb} />
        <span style={{ fontFamily: "monospace", fontSize: 12, color: C.green, fontWeight: 600, flex: 1, minWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.file.split("/").pop()}</span>
        <span style={{ fontSize: 11, color: C.muted, whiteSpace: "nowrap" }}>Line {f.line}</span>
        <span style={{ background: C.input, color: C.textMid, fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 4 }}>{f.vulnerability}</span>
        <span style={{ color: C.muted, fontSize: 11, transition: "transform 0.2s", transform: open ? "rotate(180deg)" : "none" }}>▼</span>
      </div>
      {open && (
        <div style={{ padding: "0 16px 14px", borderTop: `1px solid ${C.panelBorder}` }}>
          <div style={{ fontFamily: "monospace", background: C.input, padding: "8px 12px", borderRadius: 8, fontSize: 11, color: C.greenDark, marginTop: 10, overflowX: "auto" }}>
            <span style={{ color: C.muted, marginRight: 12, userSelect: "none" }}>{f.line}</span>{f.code}
          </div>
          {info.desc && <div style={{ marginTop: 8, fontSize: 12, color: C.muted, lineHeight: 1.6 }}>{info.desc}</div>}
          <div style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            {matchedControls.map(c => (
              <span key={c.id} style={{ background: C.greenLighter, border: `1px solid ${C.greenMid}`, color: C.green, fontSize: 10, fontWeight: 700, padding: "2px 9px", borderRadius: 4 }}>{c.id}</span>
            ))}
            <span style={{ background: C.blueLight, border: "1px solid #93c5fd", color: C.blue, fontSize: 10, fontWeight: 700, padding: "2px 9px", borderRadius: 4 }}>
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

  // Group by file for file summary
  const byFile = NIST_FINDINGS.reduce((a, f) => { if (!a[f.file]) a[f.file] = []; a[f.file].push(f); return a; }, {});

  // Vuln type counts
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
    <style>body{font-family:sans-serif;padding:40px;color:#1a1a1a}h1{color:#16a34a}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #e2f0e2;padding:8px 12px;text-align:left;font-size:12px}th{background:#f0fdf4;font-weight:700}tr:nth-child(even){background:#f8faf8}.CRITICAL{color:#dc2626;font-weight:700}.HIGH{color:#d97706;font-weight:700}.MEDIUM{color:#ca8a04;font-weight:700}</style>
    </head><body>
    <h1>⚛ QuantumGuard — NIST SP 800-53 Report</h1>
    <p>Scanned: Apr 21, 2026 · Directory: tests/ · Score: <strong>0 / 100</strong> · Status: <strong style="color:#dc2626">NOT QUANTUM SAFE</strong></p>
    <p>Total Findings: <strong>${counts.total}</strong> · Critical: <strong>${counts.CRITICAL}</strong> · High: <strong>${counts.HIGH}</strong> · Medium: <strong>${counts.MEDIUM}</strong></p>
    <table><thead><tr><th>Severity</th><th>File</th><th>Line</th><th>Vulnerability</th><th>Code</th><th>Replacement</th></tr></thead><tbody>
    ${NIST_FINDINGS.map(f => `<tr><td class="${f.severity}">${f.severity}</td><td>${f.file}</td><td>${f.line}</td><td>${f.vulnerability}</td><td><code>${f.code.replace(/</g,"&lt;")}</code></td><td>${f.replacement}</td></tr>`).join("")}
    </tbody></table></body></html>`);
    win.document.close(); win.print();
  };

  return (
    <div style={{ padding: 20 }}>

      {/* ── Header card ── */}
      <div style={{ background: C.white, border: `1px solid ${C.panelBorder}`, borderRadius: 14, padding: "20px 22px", marginBottom: 16, boxShadow: "0 1px 4px rgba(0,0,0,0.04)", display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16, borderTop: `3px solid ${C.green}` }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
            <div style={{ width: 32, height: 32, borderRadius: 8, background: C.green, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>🏛</div>
            <h2 style={{ fontSize: 20, fontWeight: 800, color: C.text }}>NIST Security Report</h2>
          </div>
          <div style={{ display: "flex", gap: 18, flexWrap: "wrap" }}>
            {[["Standard", "NIST SP 800-53 Rev 5"], ["Scanned", "Apr 21, 2026 — 00:56 UTC"], ["Directory", "tests/"], ["Files", "3 scanned"]].map(([k, v]) => (
              <div key={k} style={{ fontSize: 11 }}><span style={{ color: C.muted }}>{k}: </span><span style={{ color: C.textMid, fontWeight: 600 }}>{v}</span></div>
            ))}
          </div>
        </div>
        <div style={{ background: C.greenLighter, border: `1px solid ${C.greenMid}`, borderRadius: 12, padding: "14px 20px", textAlign: "center", minWidth: 140 }}>
          <div style={{ fontSize: 44, fontWeight: 900, color: C.red, lineHeight: 1 }}>0</div>
          <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginTop: 2 }}>Quantum Score</div>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 5, background: C.redLight, border: "1px solid #fca5a5", color: C.red, fontSize: 10, fontWeight: 700, padding: "3px 10px", borderRadius: 100, marginTop: 8, textTransform: "uppercase", letterSpacing: 0.5 }}>
            <span style={{ width: 5, height: 5, borderRadius: "50%", background: C.red, display: "inline-block" }} />
            Not Quantum Safe
          </div>
        </div>
      </div>

      {/* ── Stats ── */}
      <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
        <Metric label="Total Findings"   value={counts.total}    color={C.green}    icon="🔍" desc="All severities" />
        <Metric label="Critical"         value={counts.CRITICAL} color={C.critical} icon="🔴" desc="Immediate action required" />
        <Metric label="High"             value={counts.HIGH}     color={C.amber}    icon="🟡" desc="Requires attention" />
        <Metric label="Medium"           value={counts.MEDIUM}   color={C.medium}   icon="🟠" desc="Review needed" />
      </div>

      {/* ── Breakdown panels ── */}
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

      {/* ── Files scanned ── */}
      <Panel title="Files Scanned" accent>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px,1fr))", gap: 12 }}>
          {Object.entries(byFile).map(([file, findings]) => {
            const crit = findings.filter(f => f.severity === "CRITICAL").length;
            const high = findings.filter(f => f.severity === "HIGH").length;
            const med  = findings.filter(f => f.severity === "MEDIUM").length;
            return (
              <div key={file} style={{ background: C.greenLighter, border: `1px solid ${C.greenMid}`, borderRadius: 10, padding: "12px 14px" }}>
                <div style={{ fontSize: 10, fontWeight: 700, background: C.white, color: C.green, border: `1px solid ${C.greenMid}`, display: "inline-block", padding: "1px 8px", borderRadius: 100, marginBottom: 6, textTransform: "uppercase" }}>{getLang(file)}</div>
                <div style={{ fontFamily: "monospace", fontSize: 11, fontWeight: 700, color: C.green, marginBottom: 8 }}>{file.split("/").pop()}</div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {crit > 0 && <Badge text={`${crit} Critical`} color={C.critical} bg={C.redLight} />}
                  {high > 0 && <Badge text={`${high} High`}     color={C.amber}    bg={C.amberLight} />}
                  {med  > 0 && <Badge text={`${med} Medium`}    color={C.medium}   bg="#fef9c3" />}
                </div>
                <div style={{ fontSize: 11, color: C.muted, marginTop: 6 }}>{findings.length} findings total</div>
              </div>
            );
          })}
        </div>
      </Panel>

      {/* ── NIST Controls Mapping ── */}
      <Panel title="NIST SP 800-53 Control Mapping" accent>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ background: C.greenLighter }}>
                {["Control ID","Control Name","Family","Affected Algorithms","Status"].map(h => (
                  <th key={h} style={{ padding: "9px 14px", textAlign: "left", fontSize: 10, textTransform: "uppercase", letterSpacing: 1, color: C.muted, fontWeight: 700, borderBottom: `1px solid ${C.panelBorder}` }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {NIST_CONTROLS.map((ctrl, i) => {
                const sc = STAT_CTRL[ctrl.status];
                return (
                  <tr key={ctrl.id} style={{ background: i % 2 === 0 ? C.white : C.bg }} onMouseEnter={e => e.currentTarget.style.background = C.greenLighter} onMouseLeave={e => e.currentTarget.style.background = i % 2 === 0 ? C.white : C.bg}>
                    <td style={{ padding: "10px 14px", borderBottom: `1px solid ${C.panelBorder}`, fontFamily: "monospace", fontSize: 12, color: C.green, fontWeight: 700, whiteSpace: "nowrap" }}>{ctrl.id}</td>
                    <td style={{ padding: "10px 14px", borderBottom: `1px solid ${C.panelBorder}`, color: C.textMid }}>{ctrl.name}</td>
                    <td style={{ padding: "10px 14px", borderBottom: `1px solid ${C.panelBorder}`, color: C.muted, fontSize: 11 }}>{ctrl.family}</td>
                    <td style={{ padding: "10px 14px", borderBottom: `1px solid ${C.panelBorder}` }}>
                      {ctrl.vulns.length > 0
                        ? ctrl.vulns.map(v => <span key={v} style={{ background: C.greenLighter, border: `1px solid ${C.greenMid}`, color: C.green, fontSize: 10, fontWeight: 700, padding: "1px 7px", borderRadius: 4, marginRight: 4 }}>{v}</span>)
                        : <span style={{ color: C.muted, fontSize: 11 }}>—</span>}
                    </td>
                    <td style={{ padding: "10px 14px", borderBottom: `1px solid ${C.panelBorder}` }}>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 4, background: sc.bg, border: `1px solid ${sc.border}`, color: sc.color, fontSize: 10, fontWeight: 700, padding: "3px 10px", borderRadius: 100, textTransform: "uppercase", letterSpacing: 0.5 }}>
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

      {/* ── Export ── */}
      <Panel title="Export & Share" accent>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button onClick={handleExportPDF} style={{ padding: "8px 16px", borderRadius: 8, background: C.green, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📄 PDF Report</button>
          <button onClick={handleExportCSV} style={{ padding: "8px 16px", borderRadius: 8, background: C.greenLight, color: C.green, border: `1px solid ${C.greenMid}`, cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📊 CSV Export</button>
        </div>
      </Panel>

      {/* ── Findings ── */}
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
              background: filter === btn.key ? btn.activeColor + "18" : C.white,
              color: filter === btn.key ? btn.activeColor : C.muted,
              fontWeight: filter === btn.key ? 700 : 400,
              transition: "all 0.15s",
            }}>{btn.label}</button>
          ))}
        </div>
        {filtered.map((f, i) => (
          <NISTFindingRow key={`${f.file}-${f.line}-${f.vulnerability}-${i}`} f={f} />
        ))}
        {filtered.length === 0 && <div style={{ textAlign: "center", padding: 24, color: C.muted }}>No findings match filter.</div>}
      </Panel>

      {/* ── Footer ── */}
      <div style={{ background: C.white, border: `1px solid ${C.panelBorder}`, borderRadius: 12, padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
        <div style={{ fontSize: 11, color: C.muted }}>QuantumGuard · NIST SP 800-53 Rev 5 · Report ID #QG-{new Date().getFullYear()}-{String(new Date().getMonth()+1).padStart(2,"0")}{String(new Date().getDate()).padStart(2,"0")}</div>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <div style={{ width: 7, height: 7, borderRadius: "50%", background: C.green }}></div>
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
    { initials: "PP", name: "Pavansudheer Payyavula",  role: "Founder & CEO",  degree: "MS Cybersecurity & Computer Information Systems", subRole: null,              avatarBg: "#EEEDFE", avatarText: "#3C3489", badgeBg: "#EEEDFE", badgeText: "#3C3489", featured: true },
    { initials: "MS", name: "Manasa Sannidhi",          role: "Co-Founder",     degree: "MS Computer Science",                            subRole: null,              avatarBg: "#E1F5EE", avatarText: "#085041", badgeBg: "#E1F5EE", badgeText: "#085041", featured: false },
    { initials: "BG", name: "Bharathwaj Goud Siga",     role: "Business",       degree: "MS Business Analytics",                          subRole: "Marketing Manager", avatarBg: "#FAEEDA", avatarText: "#633806", badgeBg: "#FAEEDA", badgeText: "#633806", featured: false },
    { initials: "VR", name: "Vijendhar Reddy Muppidi",  role: "Advisor",        degree: "MS Management Information Systems",              subRole: null,              avatarBg: "#FAECE7", avatarText: "#712B13", badgeBg: "#FAECE7", badgeText: "#712B13", featured: false },
  ];
  return (
    <div style={{ padding: 20 }}>
      <div style={{ textAlign: "center", marginBottom: 36 }}>
        <div style={{ display: "inline-block", background: C.greenLighter, color: C.green, fontSize: 12, fontWeight: 700, padding: "5px 16px", borderRadius: 20, marginBottom: 14, border: `1px solid ${C.greenMid}` }}>⚛ THE TEAM</div>
        <h2 style={{ fontSize: 32, fontWeight: 900, color: C.text, marginBottom: 10, letterSpacing: -0.5 }}>Built by 4 friends</h2>
        <p style={{ fontSize: 14, color: C.muted, maxWidth: 480, margin: "0 auto", lineHeight: 1.7 }}>A cross-disciplinary team building the world's first free quantum vulnerability scanner — free for every developer, forever.</p>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 20, maxWidth: 900, margin: "0 auto" }}>
        {members.map(m => (
          <div key={m.name} style={{ background: C.white, border: m.featured ? `2px solid ${C.green}` : `1px solid ${C.panelBorder}`, borderRadius: 16, padding: "28px 20px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", boxShadow: m.featured ? "0 4px 20px rgba(22,163,74,0.12)" : "0 1px 4px rgba(0,0,0,0.04)" }}>
            <div style={{ width: 60, height: 60, borderRadius: "50%", background: m.avatarBg, color: m.avatarText, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: 16, marginBottom: 14, fontFamily: "monospace" }}>{m.initials}</div>
            <span style={{ display: "inline-block", background: m.badgeBg, color: m.badgeText, fontSize: 10, fontWeight: 700, padding: "3px 12px", borderRadius: 20, marginBottom: 10, fontFamily: "monospace", letterSpacing: "0.05em", textTransform: "uppercase" }}>{m.role}</span>
            <div style={{ fontSize: 14, fontWeight: 700, color: C.text, marginBottom: 6, lineHeight: 1.3 }}>{m.name}</div>
            <div style={{ width: 28, height: 1, background: C.panelBorder, margin: "8px auto" }} />
            <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.5 }}>{m.degree}</div>
            {m.subRole && <div style={{ fontSize: 11, color: C.green, marginTop: 6, fontStyle: "italic", fontWeight: 500 }}>{m.subRole}</div>}
          </div>
        ))}
      </div>
      <div style={{ textAlign: "center", marginTop: 40 }}>
        <div style={{ display: "inline-block", background: C.greenLighter, border: `1px solid ${C.greenMid}`, borderRadius: 12, padding: "14px 28px" }}>
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
    const score = result.quantum_readiness_score;
    const status = score >= 70 ? "COMPLIANT" : score >= 40 ? "PARTIALLY COMPLIANT" : "NON-COMPLIANT";
    const scoreColor = score >= 70 ? "#16a34a" : score >= 40 ? "#d97706" : "#dc2626";
    const statusBg = score >= 70 ? "#dcfce7" : score >= 40 ? "#fef3c7" : "#fee2e2";
    const statusBorder = score >= 70 ? "#86efac" : score >= 40 ? "#fcd34d" : "#fca5a5";
    const critical = result.findings.filter(f => f.severity === "CRITICAL").length;
    const high = result.findings.filter(f => f.severity === "HIGH").length;
    const medium = result.findings.filter(f => f.severity === "MEDIUM").length;
    const total = result.total_findings;
    const pct = (n) => total > 0 ? Math.round(n / total * 100) : 0;
    const sevColor = (s) => s === "CRITICAL" ? "#dc2626" : s === "HIGH" ? "#d97706" : "#ca8a04";
    const sevBg = (s) => s === "CRITICAL" ? "#fee2e2" : s === "HIGH" ? "#fef3c7" : "#fef9c3";
    const ctrlColor = (s) => s === "FAIL" ? "#dc2626" : s === "WARN" ? "#d97706" : "#16a34a";
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
      .header{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:24px;border-bottom:3px solid #16a34a;margin-bottom:28px;flex-wrap:wrap;gap:16px}
      .logo-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
      .logo-icon{width:38px;height:38px;background:#16a34a;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff}
      .logo-name{font-size:22px;font-weight:900}.logo-name span{color:#16a34a}
      .score-box{background:#fff;border:2px solid #86efac;border-radius:14px;padding:18px 24px;text-align:center;min-width:150px}
      .score-num{font-size:48px;font-weight:900;line-height:1;color:${scoreColor}}
      .score-label{font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
      .score-badge{display:inline-flex;align-items:center;gap:5px;background:${statusBg};border:1px solid ${statusBorder};color:${scoreColor};font-size:10px;font-weight:700;padding:4px 12px;border-radius:100px;margin-top:8px;text-transform:uppercase}
      .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
      .stat{background:#fff;border:1px solid #e2f0e2;border-radius:12px;padding:16px 18px}
      .stat-val{font-size:32px;font-weight:900;line-height:1;margin-bottom:4px}
      .stat-key{font-size:11px;color:#6b7280}
      .section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:#16a34a;margin:24px 0 12px;display:flex;align-items:center;gap:10px}
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
      .threat-count{background:#fee2e2;color:#dc2626;font-size:10px;font-weight:700;padding:2px 9px;border-radius:100px}
      .footer{margin-top:32px;padding-top:16px;border-top:1px solid #e2f0e2;display:flex;justify-content:space-between;font-size:11px;color:#9ca3af;flex-wrap:wrap;gap:8px}
      .print-btn{background:#16a34a;color:#fff;border:none;padding:9px 22px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer;margin-right:8px}
      .csv-btn{background:#fff;color:#16a34a;border:1px solid #86efac;padding:9px 22px;border-radius:8px;font-size:12px;font-weight:700;cursor:pointer}
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
      <div class="stat"><div class="stat-val" style="color:#16a34a">${total}</div><div class="stat-key">Total Findings</div></div>
      <div class="stat"><div class="stat-val" style="color:#dc2626">${critical}</div><div class="stat-key">Critical</div></div>
      <div class="stat"><div class="stat-val" style="color:#d97706">${high}</div><div class="stat-key">High</div></div>
      <div class="stat"><div class="stat-val" style="color:#ca8a04">${medium}</div><div class="stat-key">Medium</div></div>
    </div>
    <div class="section-title">Breakdown <div class="section-line"></div></div>
    <div class="panels">
      <div class="panel">
        <div class="panel-title">Severity Distribution</div>
        ${[["Critical",critical,"#dc2626"],["High",high,"#d97706"],["Medium",medium,"#ca8a04"]].map(([l,c,col])=>
          '<div class="bar-row"><div class="bar-label">'+l+'</div><div class="bar-track"><div class="bar-fill" style="width:'+pct(c)+'%;background:'+col+'"></div></div><div class="bar-count" style="color:'+col+'">'+c+' ('+pct(c)+'%)</div></div>'
        ).join("")}
      </div>
      <div class="panel">
        <div class="panel-title">NIST SP 800-53 Control Status</div>
        ${nistControls.map(ctrl=>
          '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><span style="font-size:12px;color:#374151"><span style="font-family:monospace;color:#16a34a;font-weight:700">'+ctrl.id+'</span> — '+ctrl.name+'</span><span style="background:'+ctrlBg(ctrl.status)+';color:'+ctrlColor(ctrl.status)+';font-size:10px;font-weight:700;padding:2px 9px;border-radius:100px;margin-left:8px;white-space:nowrap">'+ctrl.status+'</span></div>'
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
    const scoreColor = result.quantum_readiness_score >= 70 ? "#16a34a" : result.quantum_readiness_score >= 40 ? "#d97706" : "#dc2626";
    const status = result.quantum_readiness_score >= 70 ? "QUANTUM SAFE" : result.quantum_readiness_score >= 40 ? "AT RISK" : "NOT QUANTUM SAFE";
    const critical = result.findings.filter(f => f.severity === "CRITICAL").length;
    const high     = result.findings.filter(f => f.severity === "HIGH").length;
    const medium   = result.findings.filter(f => f.severity === "MEDIUM").length;
    const total    = result.total_findings;
    const grouped  = result.findings.reduce((a, f) => { if (!a[f.file]) a[f.file] = []; a[f.file].push(f); return a; }, {});
    const sevColor = s => s === "CRITICAL" ? "#dc2626" : s === "HIGH" ? "#d97706" : "#ca8a04";
    const sevBg    = s => s === "CRITICAL" ? "#fee2e2" : s === "HIGH" ? "#fef3c7" : "#fef9c3";
    const bar      = (count, tot, color) => `<div style="background:#f0f0f0;border-radius:4px;height:8px;margin-top:4px"><div style="background:${color};height:8px;border-radius:4px;width:${tot>0?Math.round(count/tot*100):0}%"></div></div>`;

    const csvRows = ["Severity,File,Line,Vulnerability,Code,Replacement",
      ...result.findings.map(f => [
        f.severity, f.file, f.line, f.vulnerability,
        '"' + (f.code || "").replace(/"/g, "'").replace(/\n/g, " ") + '"',
        f.replacement
      ].join(","))
    ].join("\n");
    const csvUrl = "data:text/csv;charset=utf-8," + encodeURIComponent(csvRows);
            win.document.write(`<!DOCTYPE html><html><head><title>QuantumGuard Report</title>
    <style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{font-family:"Segoe UI",sans-serif;background:#fff;color:#1a1a1a;padding:40px;font-size:13px}
      @media print{body{padding:20px}.no-print{display:none}}
      .header{display:flex;justify-content:space-between;align-items:flex-start;padding-bottom:20px;border-bottom:3px solid #16a34a;margin-bottom:24px}
      .logo{display:flex;align-items:center;gap:10px}
      .logo-icon{width:40px;height:40px;background:#16a34a;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:22px;color:#fff}
      .logo-name{font-size:22px;font-weight:900;color:#1a1a1a}.logo-name span{color:#16a34a}
      .score-box{text-align:center;background:#f0fdf4;border:2px solid #86efac;border-radius:12px;padding:14px 22px}
      .score-num{font-size:44px;font-weight:900;color:${scoreColor};line-height:1}
      .score-label{font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-top:2px}
      .score-status{font-size:11px;font-weight:700;color:${scoreColor};margin-top:6px;text-transform:uppercase;letter-spacing:0.5px}
      .meta{display:flex;gap:24px;margin-bottom:20px;flex-wrap:wrap}
      .meta-item{font-size:11px;color:#6b7280}.meta-item strong{color:#374151}
      .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
      .stat{background:#f8faf8;border:1px solid #e2f0e2;border-radius:10px;padding:14px;border-top:3px solid var(--c)}
      .stat-val{font-size:30px;font-weight:900;color:var(--c);line-height:1}
      .stat-key{font-size:11px;color:#6b7280;margin-top:4px}
      .section{margin-bottom:24px}
      .section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:#16a34a;margin-bottom:12px;padding-bottom:6px;border-bottom:1px solid #d1fae5;display:flex;align-items:center;gap:8px}
      .panels{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
      .panel{background:#f8faf8;border:1px solid #e2f0e2;border-radius:10px;padding:16px}
      .panel-title{font-size:13px;font-weight:700;color:#14532d;margin-bottom:14px}
      .bar-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
      .bar-label{font-size:11px;color:#6b7280;width:70px}
      .bar-track{flex:1;background:#e5f0e5;border-radius:4px;height:7px;overflow:hidden}
      .bar-fill{height:100%;border-radius:4px}
      .bar-count{font-size:11px;font-weight:600;width:55px;text-align:right}
      table{width:100%;border-collapse:collapse;font-size:12px}
      th{background:#f0fdf4;padding:9px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;font-weight:700;border-bottom:2px solid #d1fae5}
      td{padding:9px 12px;border-bottom:1px solid #f0f4f0;vertical-align:top}
      tr:hover td{background:#f9fafb}
      .file-header{background:#f0fdf4;padding:8px 12px;font-weight:700;font-size:12px;color:#14532d;border-bottom:1px solid #d1fae5}
      .sev{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;display:inline-block}
      code{font-family:monospace;font-size:11px;background:#f0f7f0;padding:2px 6px;border-radius:4px;color:#15803d;word-break:break-all}
      .fix{color:#2563eb;font-size:11px;font-weight:600}
      .footer{margin-top:32px;padding-top:16px;border-top:1px solid #e2f0e2;display:flex;justify-content:space-between;align-items:center;font-size:11px;color:#9ca3af}
      .print-btn{background:#16a34a;color:#fff;border:none;padding:10px 24px;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer;margin-bottom:20px}
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
      <div class="stat" style="--c:#16a34a"><div class="stat-val">${total}</div><div class="stat-key">Total Findings</div></div>
      <div class="stat" style="--c:#dc2626"><div class="stat-val">${critical}</div><div class="stat-key">Critical</div></div>
      <div class="stat" style="--c:#d97706"><div class="stat-val">${high}</div><div class="stat-key">High</div></div>
      <div class="stat" style="--c:#ca8a04"><div class="stat-val">${medium}</div><div class="stat-key">Medium</div></div>
    </div>

    <div class="panels">
      <div class="panel">
        <div class="panel-title">Severity Distribution</div>
        ${[["Critical",critical,"#dc2626"],["High",high,"#d97706"],["Medium",medium,"#ca8a04"]].map(([l,c,col])=>`
        <div class="bar-row">
          <div class="bar-label">${l}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${total>0?Math.round(c/total*100):0}%;background:${col}"></div></div>
          <div class="bar-count" style="color:${col}">${c} (${total>0?Math.round(c/total*100):0}%)</div>
        </div>`).join("")}
      </div>
      <div class="panel">
        <div class="panel-title">NIST Control Status</div>
        ${[["SC-13 Crypto Protection","FAIL","#dc2626"],["SC-12 Key Management","FAIL","#dc2626"],["IA-7 Crypto Module Auth","WARN","#d97706"],["SC-8 Transmission Conf.","WARN","#d97706"],["CM-7 Least Functionality","PASS","#16a34a"]].map(([ctrl,s,col])=>`
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;font-size:12px">
          <span style="color:#374151">${ctrl}</span>
          <span style="background:${col}18;color:${col};font-size:10px;font-weight:700;padding:2px 9px;border-radius:100px">${s}</span>
        </div>`).join("")}
      </div>
    </div>

    <div class="section">
      <div class="section-title">🔍 Threat Intelligence — ${total} Findings</div>
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
              <SevBar label="Crypto Issues" count={sev.CRITICAL} total={result.total_findings} color={C.critical} />
              <SevBar label="TLS / Protocol" count={sev.HIGH} total={result.total_findings} color={C.amber} />
              <SevBar label="Hash / Secrets" count={sev.MEDIUM} total={result.total_findings} color={C.medium} />
            </Panel>
          </div>
          <Panel title="Export & Share" accent>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
              <button onClick={handlePDF} style={{ padding: "8px 16px", borderRadius: 8, background: C.green, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📄 PDF Report</button>
              <button onClick={handleNIST} style={{ padding: "8px 16px", borderRadius: 8, background: C.blue, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>🏛 NIST Report</button>
              <button onClick={handleCSV} style={{ padding: "8px 16px", borderRadius: 8, background: C.greenLight, color: C.green, border: `1px solid ${C.greenMid}`, cursor: "pointer", fontSize: 12, fontWeight: 600 }}>📊 CSV Export</button>
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <input value={emailInput} onChange={e => setEmailInput(e.target.value)} placeholder="Email report to..." type="email" style={{ flex: 1, minWidth: 200, padding: "8px 14px", borderRadius: 8, border: `1px solid ${C.panelBorder}`, background: C.input, color: C.text, fontSize: 12 }} />
              <button onClick={handleEmail} disabled={sendingEmail || !emailInput} style={{ padding: "8px 16px", borderRadius: 8, background: C.green, color: C.white, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600 }}>{emailSent ? "✓ Sent!" : sendingEmail ? "Sending..." : "📧 Send Email"}</button>
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
                  <span style={{ fontSize: 12, fontWeight: 600, color: C.text }}>{file.split("/").pop()}</span>
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
              <span style={{ fontSize: 14, fontWeight: 700, color: C.text }}>⚡ AI Migration Assistant</span>
              <button onClick={() => { setAiModal(null); setAiResult(null); }} style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", fontSize: 20 }}>✕</button>
            </div>
            <div style={{ padding: 16, borderBottom: `1px solid ${C.panelBorder}`, background: C.greenLighter }}>
              <div style={{ fontFamily: "monospace", fontSize: 12, color: C.red, background: C.white, padding: "8px 12px", borderRadius: 8, border: `1px solid #fca5a5` }}>{aiModal.code}</div>
            </div>
            <div style={{ flex: 1, overflowY: "auto", padding: 16 }}>
              {aiLoading ? (
                <div style={{ textAlign: "center", padding: 32 }}>
                  <div style={{ fontSize: 13, color: C.green, fontWeight: 600 }}>Generating AI fix...</div>
                </div>
              ) : aiResult ? (
                <div>
                  <div style={{ fontFamily: "monospace", fontSize: 12, color: C.text, lineHeight: 1.8, whiteSpace: "pre-wrap", background: C.input, padding: 14, borderRadius: 8 }}>{aiResult}</div>
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
    result.grade === "A+" ? "#16a34a" :
    result.grade === "A"  ? "#16a34a" :
    result.grade === "B"  ? "#d97706" :
    result.grade === "C"  ? "#d97706" :
    result.grade === "D"  ? "#dc2626" : "#dc2626"
  ) : C.muted;

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
          {/* ── SSL Grade Card ── */}
          <div style={{ background: C.white, border: `1px solid ${C.panelBorder}`, borderRadius: 14, padding: "20px 24px", marginBottom: 16, boxShadow: "0 1px 4px rgba(0,0,0,0.04)", display: "flex", alignItems: "center", gap: 24, flexWrap: "wrap" }}>
            {/* Big Grade */}
            <div style={{ textAlign: "center", minWidth: 100 }}>
              <div style={{ fontSize: 72, fontWeight: 900, lineHeight: 1, color: gradeColor, fontFamily: "monospace" }}>{result.grade || "?"}</div>
              <div style={{ fontSize: 11, color: C.muted, marginTop: 4, textTransform: "uppercase", letterSpacing: 1 }}>SSL Grade</div>
            </div>
            {/* Grade info */}
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 16, fontWeight: 700, color: C.text, marginBottom: 6 }}>{result.grade_description}</div>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 8 }}>
                <span style={{ background: result.tls_version === "TLSv1.3" ? C.greenLight : C.amberLight, color: result.tls_version === "TLSv1.3" ? C.green : C.amber, fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 100 }}>{result.tls_version}</span>
                <span style={{ background: result.quantum_safe ? C.greenLight : C.redLight, color: result.quantum_safe ? C.green : C.red, fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 100 }}>{result.quantum_safe ? "✦ Post-Quantum Safe" : "⚠ Not Quantum Safe"}</span>
                <span style={{ background: C.greenLighter, color: C.green, fontSize: 11, fontWeight: 700, padding: "3px 10px", borderRadius: 100 }}>Score: {result.tls_score}/100</span>
              </div>
              {result.pqc_note && <div style={{ fontSize: 12, color: C.amber, background: C.amberLight, padding: "6px 12px", borderRadius: 8, border: `1px solid #fcd34d` }}>⚠ {result.pqc_note}</div>}
            </div>
            {/* Grade scale */}
            <div style={{ display: "flex", gap: 6 }}>
              {[["A+","#16a34a"],["A","#16a34a"],["B","#d97706"],["C","#f59e0b"],["D","#dc2626"],["F","#dc2626"]].map(([g, col]) => (
                <div key={g} style={{ width: 36, height: 36, borderRadius: 8, background: result.grade === g ? col : "#f3f4f6", color: result.grade === g ? "#fff" : "#9ca3af", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 800, border: result.grade === g ? `2px solid ${col}` : "2px solid transparent", fontFamily: "monospace" }}>{g}</div>
              ))}
            </div>
          </div>

          <div className="stats-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 12, marginBottom: 16 }}>
            <Metric label="TLS Score" value={result.tls_score} suffix="/100" color={scoreColor} icon="🎯" desc={result.tls_score >= 70 ? "Quantum Ready" : "Needs Improvement"} />
            <Metric label="TLS Version" value={result.tls_version} color={result.tls_version === "TLSv1.3" ? C.green : C.amber} icon="🔒" desc={result.tls_version === "TLSv1.3" ? "Latest" : "Upgrade Needed"} />
            <Metric
  label="Post-Quantum Readiness"
  value={
    result?.quantum_safe
      ? "YES"
      : result?.tls_version === "TLSv1.3"
      ? "PARTIAL"
      : "NO"
  }
  color={
    result?.quantum_safe
      ? C.green
      : result?.tls_version === "TLSv1.3"
      ? C.amber
      : C.red
  }
  icon={
    result?.quantum_safe
      ? "✅"
      : result?.tls_version === "TLSv1.3"
      ? "⚠️"
      : "❌"
  }
  desc={
    result?.quantum_safe
      ? "Post-quantum / hybrid TLS detected"
      : result?.tls_version === "TLSv1.3"
      ? "Secure today (forward secrecy), not quantum-resistant"
      : result?.rsa_key_exchange
      ? "Static RSA key exchange"
      : "Not post-quantum yet"
  }
/>
            <Metric label="Key Size" value={result.cipher_bits} suffix=" bit" color={result.cipher_bits >= 256 ? C.green : C.amber} icon="🔑" desc={result.cipher_bits >= 256 ? "Strong" : "Upgrade Needed"} />
          </div>
          <Panel title="Cipher Suite Details" accent>
            <div className="tls-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {[["Domain", result.domain, C.green], ["Cipher Suite", result.cipher_suite, C.text], ["Certificate Expires", result.certificate?.cert_expires || result.cert_expires || "—", C.amber], ["Recommendation", result.nist_recommendation || result.recommendation || "Monitor hybrid PQC TLS adoption", C.green]].map(([label, value, color], i) => (
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
      </div>
    </div>
  );

  return (
    <div style={{ padding: 20 }}>
      <Panel title={`Scan History — ${history.length} records`} accent>
        {loading ? <div style={{ color: C.muted, fontSize: 13 }}>Loading...</div> :
          history.length === 0 ? <div style={{ color: C.muted, fontSize: 13 }}>No scans yet!</div> : (
            history.map((scan, i) => (
              <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 160px 80px 80px", gap: 12, padding: "12px", borderBottom: i < history.length - 1 ? `1px solid ${C.panelBorder}` : "none", alignItems: "center" }}>
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
          <div style={{ fontSize: 40, fontWeight: 800, color: progress >= 70 ? C.green : progress >= 40 ? C.amber : C.red }}>{progress}%</div>
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
                  <button key={st} onClick={() => setStatus(v, st)} style={{ padding: "4px 8px", borderRadius: 6, border: `1.5px solid ${status === st ? C.green : C.panelBorder}`, background: status === st ? C.greenLight : C.white, cursor: "pointer", fontSize: 14 }}>{icon}</button>
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
            <div style={{ background: t.color, color: C.white, padding: "4px 10px", borderRadius: 8, fontSize: 13, fontWeight: 700, flexShrink: 0 }}>{t.year}</div>
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
          { method: "POST", path: "/scan-github",      auth: "None",           desc: "Scan any public GitHub repo" },
          { method: "POST", path: "/public-scan-zip",  auth: "None",           desc: "Upload ZIP file (max 10MB)" },
          { method: "POST", path: "/check-agility",    auth: "None",           desc: "Check crypto agility" },
          { method: "POST", path: "/analyze-tls",      auth: "None",           desc: "Analyze TLS" },
          { method: "POST", path: "/scan",             auth: "x-api-key header", desc: "Scan server path" },
          { method: "GET",  path: "/health",           auth: "None",           desc: "Returns {status: healthy}" },
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
          { title: "Quick Start",    icon: "⚡", steps: ["Go to Scanner tab", "Paste GitHub repo URL", "Click Run Scan", "Download PDF report"] },
          { title: "Crypto Agility", icon: "🔬", steps: ["Go to Agility Checker", "Paste GitHub repo URL", "Click Check Agility", "Review hardcoded vs configurable"] },
          { title: "Private Repos",  icon: "🔒", steps: ["Click Private Repo button", "Generate GitHub PAT", "Paste your token", "Token never stored"] },
          { title: "Rate Limits",    icon: "⏱", steps: ["/scan-github: 20/min", "/public-scan-zip: 3/min", "/check-agility: 10/min", "/analyze-tls: 10/min"] },
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
function Homepage({ onGetStarted }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const navItems = [
    { label: "Features", id: "features" },
    { label: "How It Works", id: "howitworks" },
    { label: "Pricing", id: "pricing" },
    { label: "Documentation", id: "docs" },
  ];

  return (
    <div style={{ minHeight: "100vh", background: C.bg, fontFamily: "'Segoe UI', sans-serif", overflowX: "hidden" }}>
      <nav style={{ background: "rgba(255,255,255,0.95)", backdropFilter: "blur(12px)", borderBottom: `1px solid ${C.panelBorder}`, padding: "0 24px", height: 66, display: "flex", alignItems: "center", justifyContent: "space-between", boxShadow: "0 1px 6px rgba(0,0,0,0.06)", position: "sticky", top: 0, zIndex: 100 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{ width: 38, height: 38, borderRadius: 10, background: C.green, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20 }}>⚛</div>
          <span style={{ fontSize: 19, fontWeight: 800, letterSpacing: -0.5 }}><span style={{ color: C.green }}>Quantum</span>Guard</span>
          <span style={{ background: C.greenLighter, color: C.green, fontSize: 10, fontWeight: 700, padding: "2px 8px", borderRadius: 20, border: `1px solid ${C.greenMid}`, marginLeft: 4 }}>BETA</span>
        </div>
        <div className="nav-links" style={{ display: "flex", alignItems: "center", gap: 32 }}>
          {navItems.map(item => (
            <span key={item.id} onClick={() => document.getElementById(item.id)?.scrollIntoView({ behavior: "smooth" })} style={{ fontSize: 14, color: C.muted, cursor: "pointer", fontWeight: 500 }}>{item.label}</span>
          ))}
        </div>
        <div className="nav-right" style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ fontSize: 13, color: C.muted, textDecoration: "none", fontWeight: 500 }}>★ GitHub</a>
          <button onClick={onGetStarted} style={{ background: C.green, color: C.white, padding: "9px 22px", borderRadius: 10, border: "none", cursor: "pointer", fontSize: 14, fontWeight: 700 }}>Get Started Free →</button>
        </div>
        <button className="nav-hamburger" onClick={() => setMobileMenuOpen(m => !m)} style={{ display: "none", background: "transparent", border: "none", fontSize: 26, cursor: "pointer", color: C.text, padding: "4px 8px" }}>
          {mobileMenuOpen ? "✕" : "☰"}
        </button>
      </nav>

      {mobileMenuOpen && (
        <div style={{ position: "fixed", top: 66, left: 0, right: 0, background: C.white, borderBottom: `1px solid ${C.panelBorder}`, zIndex: 99, padding: "8px 0", boxShadow: "0 4px 12px rgba(0,0,0,0.1)" }}>
          {navItems.map(item => (
            <div key={item.id} onClick={() => { document.getElementById(item.id)?.scrollIntoView({ behavior: "smooth" }); setMobileMenuOpen(false); }} style={{ padding: "16px 24px", fontSize: 16, fontWeight: 600, color: C.text, borderBottom: `1px solid ${C.panelBorder}`, cursor: "pointer" }}>{item.label}</div>
          ))}
          <div style={{ padding: "16px 24px" }}>
            <button onClick={() => { onGetStarted(); setMobileMenuOpen(false); }} style={{ width: "100%", padding: "13px", background: C.green, color: C.white, border: "none", borderRadius: 10, fontSize: 15, fontWeight: 700, cursor: "pointer" }}>Get Started Free →</button>
          </div>
        </div>
      )}

      <div style={{ background: "linear-gradient(135deg, #f0fdf4 0%, #f8faf8 50%, #f0f9ff 100%)", borderBottom: `1px solid ${C.panelBorder}`, padding: "0 40px" }}>
        <div className="hero-grid" style={{ maxWidth: 1200, margin: "0 auto", padding: "70px 0 60px", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 70, alignItems: "center" }}>
          <div>
            <div style={{ display: "inline-flex", alignItems: "center", gap: 8, background: C.white, border: `1px solid ${C.greenMid}`, borderRadius: 30, padding: "6px 14px", marginBottom: 28 }}>
              <span style={{ fontSize: 14 }}>🏛</span>
              <span style={{ fontSize: 12, color: C.green, fontWeight: 700 }}>Submitted to NIST NCCoE & NIST PQC Team</span>
            </div>
            <h1 style={{ fontSize: "clamp(34px,4.5vw,58px)", fontWeight: 900, lineHeight: 1.1, marginBottom: 22, color: C.text, letterSpacing: -1 }}>
              Is Your Code<br /><span style={{ color: C.green }}>Quantum Safe?</span>
            </h1>
            <p style={{ fontSize: 17, color: C.muted, lineHeight: 1.75, marginBottom: 36, maxWidth: 500 }}>
              Quantum computers will break RSA and ECC encryption by 2030. QuantumGuard scans your codebase in <strong style={{ color: C.text }}>30 seconds</strong> and gives you exact NIST-approved fixes — completely free.
            </p>
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginBottom: 36 }}>
              <button onClick={onGetStarted} style={{ background: C.green, color: C.white, padding: "14px 30px", borderRadius: 12, border: "none", cursor: "pointer", fontSize: 16, fontWeight: 700, boxShadow: "0 4px 16px rgba(22,163,74,0.35)" }}>🛡 Scan My Code Now</button>
              <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ background: C.white, color: C.text, padding: "14px 30px", borderRadius: 12, border: `1.5px solid ${C.panelBorder}`, fontSize: 15, fontWeight: 600, textDecoration: "none", display: "flex", alignItems: "center", gap: 8 }}>★ Star on GitHub</a>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 20 }}>
              {["✓ Free Forever", "✓ No Signup Required", "✓ NIST FIPS 203/204/205", "✓ Open Source"].map((text, i) => (
                <span key={i} style={{ fontSize: 13, color: C.green, fontWeight: 600 }}>{text}</span>
              ))}
            </div>
          </div>
          <div className="hero-preview" style={{ background: C.white, borderRadius: 20, boxShadow: "0 24px 80px rgba(0,0,0,0.12)", border: `1px solid ${C.panelBorder}`, overflow: "hidden" }}>
            <div style={{ background: C.green, padding: "12px 18px", display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ display: "flex", gap: 6 }}>{["#ff5f57","#febc2e","#28c840"].map((c,i) => <div key={i} style={{ width: 12, height: 12, borderRadius: "50%", background: c }}></div>)}</div>
              <span style={{ color: "rgba(255,255,255,0.8)", fontSize: 12, marginLeft: 8, fontFamily: "monospace" }}>quantumguard.site — Scanner</span>
            </div>
            <div style={{ padding: 20 }}>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10, marginBottom: 14 }}>
                {[["58","Score",C.amber,C.amberLight],["8","Threats",C.red,C.redLight],["0","Critical",C.green,C.greenLighter],["6","High",C.amber,C.amberLight]].map(([n,l,c,bg],i) => (
                  <div key={i} style={{ background: bg, borderRadius: 10, padding: 12, textAlign: "center" }}>
                    <div style={{ fontSize: 22, fontWeight: 800, color: c }}>{n}</div>
                    <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{l}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div style={{ background: C.white, borderBottom: `1px solid ${C.panelBorder}`, padding: "28px 40px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", textAlign: "center" }}>
          <p style={{ fontSize: 12, color: C.muted, fontWeight: 600, marginBottom: 16, textTransform: "uppercase", letterSpacing: 1 }}>Trusted by developers scanning real repositories</p>
          <div className="stats-bar-grid" style={{ maxWidth: 900, margin: "0 auto", display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 20 }}>
            {[["50+","Vulnerability Checks"],["8","Languages"],["99.9%","Uptime"],["< 30s","Scan Time"],["100%","Private"]].map(([num,label],i) => (
              <div key={i} style={{ textAlign: "center" }}>
                <div style={{ fontSize: 26, fontWeight: 900, color: C.green, letterSpacing: -1 }}>{num}</div>
                <div style={{ fontSize: 11, color: C.muted, marginTop: 3 }}>{label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div id="features" style={{ maxWidth: 1200, margin: "0 auto", padding: "80px 40px" }}>
        <div style={{ textAlign: "center", marginBottom: 56 }}>
          <div style={{ display: "inline-block", background: C.greenLighter, color: C.green, fontSize: 12, fontWeight: 700, padding: "5px 16px", borderRadius: 20, marginBottom: 16, border: `1px solid ${C.greenMid}` }}>FEATURES</div>
          <h2 style={{ fontSize: 38, fontWeight: 900, color: C.text, marginBottom: 14, letterSpacing: -0.5 }}>Everything to go quantum-safe</h2>
          <p style={{ color: C.muted, fontSize: 16, maxWidth: 560, margin: "0 auto", lineHeight: 1.7 }}>Comprehensive quantum vulnerability detection and NIST-approved migration tools — all free</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px,1fr))", gap: 22 }}>
          {[
            { icon: "🔍", title: "Threat Scanner",         desc: "Scan GitHub repos, ZIP files, or server paths. Detects 15+ quantum-vulnerable algorithms in 30 seconds.",           badge: "Core",       badgeColor: C.green },
            { icon: "🏛", title: "NIST Compliance Report", desc: "Generate professional FIPS 203/204/205 compliance reports with NIST references per finding.",                       badge: "Enterprise", badgeColor: C.blue },
            { icon: "🔐", title: "TLS Analyzer",           desc: "Check any domain's TLS version, cipher suite, and quantum safety rating instantly.",                               badge: "Free",       badgeColor: C.green },
            { icon: "🔬", title: "Agility Checker",        desc: "Detect hardcoded vs configurable crypto. Score 0-100 for migration readiness.",                                    badge: "Free",       badgeColor: C.green },
            { icon: "🤖", title: "AI Fix Assistant",       desc: "Claude-powered exact replacement code for every vulnerability found in your codebase.",                            badge: "Pro",        badgeColor: "#7c3aed" },
            { icon: "🔄", title: "Migration Tracker",      desc: "Track 11 vulnerability types from Pending to Fixed across your entire organization.",                              badge: "Free",       badgeColor: C.green },
          ].map((f, i) => (
            <div key={i} style={{ background: C.white, borderRadius: 16, padding: 26, border: `1px solid ${C.panelBorder}`, boxShadow: "0 1px 6px rgba(0,0,0,0.04)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
                <div style={{ width: 50, height: 50, borderRadius: 14, background: C.greenLighter, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24 }}>{f.icon}</div>
                <span style={{ background: f.badgeColor + "18", color: f.badgeColor, fontSize: 10, fontWeight: 700, padding: "3px 10px", borderRadius: 20 }}>{f.badge}</span>
              </div>
              <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 8, color: C.text }}>{f.title}</div>
              <div style={{ fontSize: 13, color: C.muted, lineHeight: 1.65 }}>{f.desc}</div>
            </div>
          ))}
        </div>
      </div>

      <div id="howitworks" style={{ background: C.white, borderTop: `1px solid ${C.panelBorder}`, borderBottom: `1px solid ${C.panelBorder}`, padding: "80px 40px" }}>
        <div style={{ maxWidth: 1100, margin: "0 auto" }}>
          <div style={{ textAlign: "center", marginBottom: 56 }}>
            <div style={{ display: "inline-block", background: C.greenLighter, color: C.green, fontSize: 12, fontWeight: 700, padding: "5px 16px", borderRadius: 20, marginBottom: 16, border: `1px solid ${C.greenMid}` }}>HOW IT WORKS</div>
            <h2 style={{ fontSize: 38, fontWeight: 900, color: C.text, marginBottom: 14, letterSpacing: -0.5 }}>From URL to report in 30 seconds</h2>
          </div>
          <div className="how-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 40 }}>
            {[
              { step: "1", icon: "🔗", title: "Paste GitHub URL",    desc: "Enter any public or private GitHub repository URL." },
              { step: "2", icon: "🔍", title: "We Scan Your Code",   desc: "Our engine checks every line against 15+ NIST-aligned vulnerability patterns." },
              { step: "3", icon: "📊", title: "Get Full Report",     desc: "Receive Quantum Readiness Score, NIST compliance report, PDF export, and AI-powered fixes." },
            ].map((s,i) => (
              <div key={i} style={{ textAlign: "center" }}>
                <div style={{ width: 66, height: 66, borderRadius: "50%", background: C.green, color: C.white, fontSize: 26, fontWeight: 900, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px", boxShadow: "0 4px 14px rgba(22,163,74,0.3)" }}>{s.step}</div>
                <div style={{ fontSize: 38, marginBottom: 14 }}>{s.icon}</div>
                <div style={{ fontSize: 18, fontWeight: 800, marginBottom: 10, color: C.text }}>{s.title}</div>
                <div style={{ fontSize: 14, color: C.muted, lineHeight: 1.75, maxWidth: 280, margin: "0 auto" }}>{s.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div id="pricing" style={{ maxWidth: 1200, margin: "0 auto", padding: "80px 40px" }}>
        <div style={{ textAlign: "center", marginBottom: 56 }}>
          <div style={{ display: "inline-block", background: C.greenLighter, color: C.green, fontSize: 12, fontWeight: 700, padding: "5px 16px", borderRadius: 20, marginBottom: 16, border: `1px solid ${C.greenMid}` }}>PRICING</div>
          <h2 style={{ fontSize: 38, fontWeight: 900, color: C.text, marginBottom: 14, letterSpacing: -0.5 }}>Simple, transparent pricing</h2>
        </div>
        <div className="pricing-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 24, maxWidth: 1000, margin: "0 auto" }}>
          {[
            { name: "Free",       price: "$0",     period: "forever",  color: C.text,    highlight: false, features: ["Web scanner","GitHub URL + ZIP scan","15+ vulnerability types","PDF & NIST reports","TLS Analyzer","Agility Checker","10 scans/day"],                               cta: "Get Started Free",  ctaAction: onGetStarted },
            { name: "Pro",        price: "$29",    period: "/month",   color: C.green,   highlight: true,  badge: "Most Popular", features: ["Everything in Free","Unlimited scans","AI-powered fix suggestions","5 team members","Full API access","Priority support"],                  cta: "Coming Soon",       ctaAction: null },
            { name: "Enterprise", price: "Custom", period: "",         color: "#7c3aed", highlight: false, features: ["Everything in Pro","Unlimited team members","Self-hosted deployment","SSO / SAML login","Audit logs","SOC2 compliance"],                                           cta: "Contact Us",        ctaAction: () => window.open("mailto:thisispayyavula@gmail.com?subject=QuantumGuard Enterprise Inquiry") },
          ].map((p,i) => (
            <div key={i} style={{ background: C.white, borderRadius: 20, padding: 30, border: p.highlight ? `2px solid ${C.green}` : `1px solid ${C.panelBorder}`, boxShadow: p.highlight ? "0 12px 32px rgba(22,163,74,0.15)" : "0 2px 8px rgba(0,0,0,0.04)", position: "relative" }}>
              {p.badge && <div style={{ position: "absolute", top: -14, left: "50%", transform: "translateX(-50%)", background: C.green, color: C.white, padding: "5px 18px", borderRadius: 20, fontSize: 11, fontWeight: 700, whiteSpace: "nowrap" }}>{p.badge}</div>}
              <div style={{ fontSize: 16, fontWeight: 700, color: C.text, marginBottom: 8 }}>{p.name}</div>
              <div style={{ marginBottom: 4 }}><span style={{ fontSize: 42, fontWeight: 900, color: p.color, letterSpacing: -1 }}>{p.price}</span><span style={{ fontSize: 14, color: C.muted }}>{p.period}</span></div>
              <div style={{ height: 1, background: C.panelBorder, margin: "20px 0" }}></div>
              {p.features.map((f,j) => (<div key={j} style={{ display: "flex", gap: 10, marginBottom: 10 }}><span style={{ color: C.green, fontWeight: 700, fontSize: 14, flexShrink: 0 }}>✓</span><span style={{ fontSize: 13, color: C.muted }}>{f}</span></div>))}
              <button onClick={p.ctaAction} style={{ width: "100%", marginTop: 24, padding: "12px", borderRadius: 12, background: p.highlight ? C.green : "transparent", color: p.highlight ? C.white : p.color, border: `2px solid ${p.color}`, cursor: p.ctaAction ? "pointer" : "default", fontSize: 14, fontWeight: 700 }}>{p.cta}</button>
            </div>
          ))}
        </div>
      </div>

      <div id="docs" style={{ background: C.white, borderTop: `1px solid ${C.panelBorder}`, padding: "80px 40px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto" }}>
          <div style={{ textAlign: "center", marginBottom: 56 }}>
            <div style={{ display: "inline-block", background: C.greenLighter, color: C.green, fontSize: 12, fontWeight: 700, padding: "5px 16px", borderRadius: 20, marginBottom: 16, border: `1px solid ${C.greenMid}` }}>DOCUMENTATION</div>
            <h2 style={{ fontSize: 38, fontWeight: 900, color: C.text, marginBottom: 14, letterSpacing: -0.5 }}>Integrate in minutes</h2>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))", gap: 20 }}>
            {[
              { icon: "⚡", title: "Quick Start",   desc: "Scan your first repo in 30 seconds. No installation required.", steps: ["Paste GitHub URL","Click Run Scan","Download report"] },
              { icon: "🔌", title: "REST API",       desc: "Integrate QuantumGuard into your stack with our REST API.",     steps: ["POST /scan-github","POST /check-agility","POST /analyze-tls"] },
              { icon: "🔄", title: "GitHub Actions", desc: "Auto-scan on every push with our CI/CD workflow.",              steps: ["Copy workflow YAML","Add to .github/workflows/","Push to trigger"] },
              { icon: "🖥",  title: "Self-Hosting",  desc: "Run QuantumGuard inside your own network.",                    steps: ["Clone the repo","Run Docker container","Code never leaves you"] },
            ].map((d,i) => (
              <div key={i} style={{ background: C.greenLighter, borderRadius: 16, padding: 26, border: `1px solid ${C.greenMid}` }}>
                <div style={{ fontSize: 30, marginBottom: 12 }}>{d.icon}</div>
                <div style={{ fontSize: 16, fontWeight: 800, color: C.text, marginBottom: 8 }}>{d.title}</div>
                <div style={{ fontSize: 13, color: C.muted, marginBottom: 16, lineHeight: 1.65 }}>{d.desc}</div>
                {d.steps.map((step,j) => (
                  <div key={j} style={{ display: "flex", gap: 10, marginBottom: 7, alignItems: "center" }}>
                    <div style={{ width: 20, height: 20, borderRadius: "50%", background: C.green, color: C.white, fontSize: 10, fontWeight: 700, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>{j+1}</div>
                    <span style={{ fontSize: 12, color: C.textMid, fontWeight: 500 }}>{step}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={{ background: "linear-gradient(135deg, #16a34a 0%, #15803d 100%)", padding: "80px 40px", textAlign: "center" }}>
        <h2 style={{ fontSize: 42, fontWeight: 900, color: C.white, marginBottom: 16, letterSpacing: -0.5 }}>Ready to secure your code?</h2>
        <p style={{ color: "rgba(255,255,255,0.8)", marginBottom: 36, fontSize: 16, maxWidth: 480, margin: "0 auto 36px", lineHeight: 1.7 }}>Join developers scanning their codebases for quantum vulnerabilities before the 2030 deadline.</p>
        <div style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap" }}>
          <button onClick={onGetStarted} style={{ background: C.white, color: C.green, padding: "15px 34px", borderRadius: 12, border: "none", cursor: "pointer", fontSize: 16, fontWeight: 800 }}>🛡 Start Scanning Now — Free</button>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ background: "rgba(255,255,255,0.15)", color: C.white, padding: "15px 34px", borderRadius: 12, border: "2px solid rgba(255,255,255,0.3)", fontSize: 16, fontWeight: 700, textDecoration: "none" }}>★ Star on GitHub</a>
        </div>
      </div>

      <div style={{ background: C.white, borderTop: `1px solid ${C.panelBorder}`, padding: "28px 40px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 30, height: 30, borderRadius: 8, background: C.green, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 15 }}>⚛</div>
            <span style={{ fontSize: 14, fontWeight: 700 }}><span style={{ color: C.green }}>Quantum</span>Guard</span>
            <span style={{ fontSize: 12, color: C.muted }}>by MANGSRI · Open Source · Free Forever</span>
          </div>
          <div style={{ display: "flex", gap: 20, flexWrap: "wrap", alignItems: "center" }}>
            {[["About","/about.html"],["Privacy Policy","/privacy.html"],["Terms","/terms.html"]].map(([label,href],i) => (
              <a key={i} href={href} style={{ color: C.muted, fontSize: 13, textDecoration: "none", fontWeight: 500 }}>{label}</a>
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
  };

  return (
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
          {active === "history"   && <HistoryPage user={user} />}
          {active === "migration" && <MigrationPage user={user} />}
          {active === "dashboard" && <AnalyticsPage />}
          {active === "nist"      && <NISTReportPage />}
          {active === "docs"      && <DocsPage />}
          {active === "team"      && <TeamPage />}
        </div>
      </div>
    </div>
  );
}
