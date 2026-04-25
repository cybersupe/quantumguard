import { useState, useEffect, useRef } from "react";
import "./App.css";
import emailjs from "@emailjs/browser";
import { auth, db, signInWithGoogle, canUserScan, incrementScanCount } from "./firebase";
import { onAuthStateChanged, signOut } from "firebase/auth";
import { collection, addDoc, getDocs, query, where, orderBy } from "firebase/firestore";

const API = "https://quantumguard-api.onrender.com";

// Splunk-inspired color palette
const C = {
  bg: "#0b0c0e",
  sidebar: "#13161b",
  topbar: "#16191f",
  panel: "#1a1d23",
  panelBorder: "#2d3139",
  panelHeader: "#1e2128",
  input: "#0f1114",
  purple: "#7B5FFF",
  purpleLight: "#9f85ff",
  green: "#53C28B",
  greenDark: "#2d6e4e",
  red: "#E85C4A",
  redDark: "#7a2d24",
  amber: "#F5A623",
  amberDark: "#7a5012",
  blue: "#3B82F6",
  cyan: "#22D3EE",
  text: "#C4C9D4",
  textBright: "#E8EAF0",
  muted: "#5a6070",
  white: "#FFFFFF",
  rowAlt: "#1d2028",
  critical: "#E85C4A",
  high: "#F5A623",
  medium: "#F0C040",
  low: "#53C28B",
};

const SCAN_STEPS = [
  "Initializing scan engine...", "Connecting to target...", "Analyzing file structure...",
  "Running vulnerability checks...", "Calculating risk score...", "Generating threat report...",
];

// ── Splunk-style icon sidebar ──────────────────────────────────
function Sidebar({ active, setActive, user, onLogin, onLogout, open, onClose }) {
  const navItems = [
    { id: "scan", icon: "⚡", label: "Threat Scanner" },
    { id: "agility", icon: "🔬", label: "Agility Checker" },
    { id: "history", icon: "🗂", label: "Scan History" },
    { id: "migration", icon: "🔄", label: "Migration" },
    { id: "dashboard", icon: "📊", label: "Analytics" },
    { id: "docs", icon: "📖", label: "Docs" },
  ];

  return (
    <>
      {open && <div className="sidebar-overlay open" onClick={onClose} />}
      <div className={`sidebar${open ? " open" : ""}`} style={{
        width: 56, minHeight: "100vh", background: C.sidebar,
        borderRight: `1px solid ${C.panelBorder}`, display: "flex",
        flexDirection: "column", position: "fixed", left: 0, top: 0, zIndex: 100,
      }}>
        {/* Logo */}
        <div style={{ width: 56, height: 56, display: "flex", alignItems: "center", justifyContent: "center", borderBottom: `1px solid ${C.panelBorder}`, flexShrink: 0 }}>
          <div style={{ width: 30, height: 30, borderRadius: 6, background: C.purple, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>⚛</div>
        </div>

        {/* Nav icons */}
        <nav style={{ flex: 1, padding: "8px 0" }}>
          {navItems.map(item => (
            <div key={item.id} title={item.label} onClick={() => { setActive(item.id); onClose(); }}
              style={{
                width: 56, height: 48, display: "flex", alignItems: "center", justifyContent: "center",
                cursor: "pointer", fontSize: 18, position: "relative",
                background: active === item.id ? `${C.purple}22` : "transparent",
                borderLeft: active === item.id ? `3px solid ${C.purple}` : "3px solid transparent",
              }}>
              {item.icon}
            </div>
          ))}
        </nav>

        {/* User avatar */}
        <div style={{ padding: "12px 0", borderTop: `1px solid ${C.panelBorder}`, display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
          {user ? (
            <img src={user.photoURL} alt="avatar" title={user.displayName} onClick={onLogout}
              style={{ width: 32, height: 32, borderRadius: "50%", cursor: "pointer", border: `2px solid ${C.purple}` }} />
          ) : (
            <div title="Sign in with Google" onClick={onLogin}
              style={{ width: 32, height: 32, borderRadius: "50%", background: C.purple, display: "flex", alignItems: "center", justifyContent: "center", cursor: "pointer", fontSize: 14 }}>
              G
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ── Splunk-style top bar ───────────────────────────────────────
function TopBar({ title, subtitle, user, onLogin, onLogout, darkMode, setDarkMode, onHamburger }) {
  const navLabels = { scan: "Threat Scanner", agility: "Agility Checker", history: "Scan History", migration: "Migration Tracker", dashboard: "Analytics", docs: "Documentation" };
  return (
    <div style={{
      height: 48, background: C.topbar, borderBottom: `1px solid ${C.panelBorder}`,
      display: "flex", alignItems: "center", padding: "0 16px", gap: 12, flexShrink: 0,
    }}>
      <button className="hamburger-top" onClick={onHamburger} style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", fontSize: 18, padding: "0 4px" }}>☰</button>
      <span style={{ color: C.muted, fontSize: 12 }}>QuantumGuard</span>
      <span style={{ color: C.muted, fontSize: 12 }}>›</span>
      <span style={{ color: C.textBright, fontSize: 12, fontWeight: 600 }}>{title}</span>
      {subtitle && <span style={{ color: C.muted, fontSize: 11, marginLeft: 8 }}>— {subtitle}</span>}
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: C.green }}></div>
          <span style={{ fontSize: 10, color: C.green, fontFamily: "monospace" }}>API ONLINE</span>
        </div>
        <span style={{ fontSize: 10, color: C.muted, fontFamily: "monospace" }}>{new Date().toLocaleString()}</span>
        <button onClick={() => setDarkMode && setDarkMode(d => !d)} style={{ background: "transparent", border: `1px solid ${C.panelBorder}`, borderRadius: 4, padding: "2px 8px", cursor: "pointer", color: C.muted, fontSize: 10 }}>
          {darkMode ? "☀" : "🌙"}
        </button>
        {user ? (
          <button onClick={onLogout} style={{ background: "transparent", border: `1px solid ${C.panelBorder}`, borderRadius: 4, padding: "2px 10px", cursor: "pointer", color: C.muted, fontSize: 10 }}>
            {user.displayName?.split(" ")[0]} · Sign Out
          </button>
        ) : (
          <button onClick={onLogin} style={{ background: C.purple, border: "none", borderRadius: 4, padding: "4px 12px", cursor: "pointer", color: C.white, fontSize: 11, fontWeight: 600 }}>
            Sign In
          </button>
        )}
      </div>
    </div>
  );
}

// ── Splunk panel wrapper ───────────────────────────────────────
function Panel({ title, children, style = {} }) {
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 4, marginBottom: 16, ...style }}>
      {title && (
        <div style={{ padding: "8px 14px", borderBottom: `1px solid ${C.panelBorder}`, background: C.panelHeader, borderRadius: "4px 4px 0 0" }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: C.text, textTransform: "uppercase", letterSpacing: 1 }}>{title}</span>
        </div>
      )}
      <div style={{ padding: 16 }}>{children}</div>
    </div>
  );
}

// ── Metric tile ────────────────────────────────────────────────
function Metric({ label, value, suffix = "", color, desc }) {
  return (
    <div style={{ background: C.panel, border: `1px solid ${C.panelBorder}`, borderRadius: 4, padding: "14px 18px" }}>
      <div style={{ fontSize: 10, color: C.muted, textTransform: "uppercase", letterSpacing: 1, marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 40, fontWeight: 800, color: color || C.textBright, fontFamily: "monospace", lineHeight: 1 }}>
        {value}<span style={{ fontSize: 14, color: C.muted }}>{suffix}</span>
      </div>
      {desc && <div style={{ fontSize: 10, color: C.muted, marginTop: 6 }}>{desc}</div>}
    </div>
  );
}

// ── Severity bar ───────────────────────────────────────────────
function SevBar({ label, count, total, color }) {
  const pct = total > 0 ? Math.round(count / total * 100) : 0;
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 4 }}>
        <span style={{ color, fontFamily: "monospace", fontWeight: 700 }}>{label}</span>
        <span style={{ color: C.muted, fontFamily: "monospace" }}>{count} ({pct}%)</span>
      </div>
      <div style={{ background: C.input, borderRadius: 2, height: 6 }}>
        <div style={{ background: color, height: 6, borderRadius: 2, width: `${pct}%`, transition: "width 0.6s" }}></div>
      </div>
    </div>
  );
}

// ── Log-viewer finding row ─────────────────────────────────────
function FindingRow({ f, checked, onCheck }) {
  const sevColor = f.severity === "CRITICAL" ? C.critical : f.severity === "HIGH" ? C.high : f.severity === "MEDIUM" ? C.medium : C.low;
  return (
    <div style={{
      display: "grid", gridTemplateColumns: "24px 80px 1fr 1fr 180px", gap: 8,
      padding: "7px 12px", borderBottom: `1px solid ${C.panelBorder}`,
      background: checked ? `${C.greenDark}22` : "transparent",
      opacity: checked ? 0.5 : 1, alignItems: "start",
      cursor: "pointer",
    }} onClick={onCheck}>
      <input type="checkbox" checked={!!checked} onChange={onCheck} onClick={e => e.stopPropagation()} style={{ marginTop: 2 }} />
      <span style={{ fontFamily: "monospace", fontSize: 10, fontWeight: 700, color: sevColor, background: `${sevColor}18`, padding: "1px 6px", borderRadius: 2, textAlign: "center" }}>{f.severity}</span>
      <span style={{ fontFamily: "monospace", fontSize: 10, color: C.cyan, wordBreak: "break-all" }}>{f.file.split("/").pop()}:{f.line}</span>
      <span style={{ fontFamily: "monospace", fontSize: 10, color: C.text, wordBreak: "break-all" }}>{f.code}</span>
      <span style={{ fontFamily: "monospace", fontSize: 10, color: C.green, wordBreak: "break-all" }}>{f.replacement}</span>
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
      await emailjs.send("service_vy8yxbq","template_mgydwpx",{to_email:emailInput,score:result.quantum_readiness_score,total:result.total_findings,filename:file?.name||input||"scan"},"vATUvI1IlAtH0ooKaQlY9");
      setEmailSent(true); setTimeout(()=>setEmailSent(false),3000);
    } catch(e){alert("Email failed.");}
    setSendingEmail(false);
  };

  const scoreColor = result ? (result.quantum_readiness_score >= 70 ? C.green : result.quantum_readiness_score >= 40 ? C.amber : C.red) : C.muted;
  const sev = result ? { CRITICAL: result.findings.filter(f=>f.severity==="CRITICAL").length, HIGH: result.findings.filter(f=>f.severity==="HIGH").length, MEDIUM: result.findings.filter(f=>f.severity==="MEDIUM").length } : null;
  const filtered = result ? result.findings.filter(f=>(filter==="ALL"||f.severity===filter)&&(search===""||f.file.toLowerCase().includes(search.toLowerCase())||f.code.toLowerCase().includes(search.toLowerCase()))) : [];
  const grouped = filtered.reduce((a,f)=>{if(!a[f.file])a[f.file]=[];a[f.file].push(f);return a;},{});

  const handleCSV = () => {
    if (!result) return;
    const blob = new Blob(["Severity,File,Line,Code,Fix\n"+result.findings.map(f=>`"${f.severity}","${f.file}","${f.line}","${f.code.replace(/"/g,"'")}","${f.replacement}"`).join("\n")],{type:"text/csv"});
    const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="quantumguard.csv";a.click();
  };

  const handlePDF = () => {
    if (!result) return;
    const win=window.open("https://twitter.com/intent/tweet?text="+encodeURIComponent("QuantumGuard: "+result.quantum_readiness_score+"/100 — "+result.total_findings+" vulnerabilities
quantumguard-one.vercel.app #QuantumSecurity"),"_blank");
    win.document.write(`<html><head><title>QuantumGuard Report</title><style>body{font-family:monospace;padding:32px;background:#0b0c0e;color:#C4C9D4;}h1{color:#7B5FFF;}.score{font-size:64px;font-weight:800;color:${scoreColor};}.finding{border-left:3px solid #E85C4A;padding:8px 14px;margin:8px 0;background:#1a1d23;}.HIGH{border-color:#F5A623;}.MEDIUM{border-color:#F0C040;}.LOW{border-color:#53C28B;}code{color:#22D3EE;font-size:11px;}</style></head><body><h1>⚛ QuantumGuard Threat Report</h1><p>Generated: ${new Date().toLocaleString()}</p><p>Target: ${result.github_url||"ZIP Upload"}</p><div class="score">${result.quantum_readiness_score}/100</div><p>Total: ${result.total_findings} | Critical: ${sev?.CRITICAL} | High: ${sev?.HIGH} | Medium: ${sev?.MEDIUM}</p><hr/>${result.findings.map(f=>`<div class="finding ${f.severity}"><b>[${f.severity}]</b> ${f.file.split("/").pop()}:${f.line}<br/><code>${f.code}</code><br/>Fix: ${f.replacement}</div>`).join("")}</body></html>`);
    win.document.close(); win.print();
  };

  return (
    <div style={{ padding: 16 }}>
      {/* Search bar */}
      <Panel title="Scan Target">
        <div style={{ display: "flex", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
          {[{id:"github",label:"GitHub URL"},{id:"zip",label:"ZIP Upload"},{id:"path",label:"Server Path"}].map(m=>(
            <button key={m.id} onClick={()=>setMode(m.id)} style={{ padding:"4px 12px", borderRadius:3, border:`1px solid ${mode===m.id?C.purple:C.panelBorder}`, background:mode===m.id?`${C.purple}22`:"transparent", color:mode===m.id?C.purpleLight:C.muted, cursor:"pointer", fontSize:11 }}>
              {m.label}
            </button>
          ))}
        </div>
        {mode==="zip" ? (
          <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
            <input type="file" accept=".zip" onChange={e=>setFile(e.target.files[0])} style={{flex:1,minWidth:200,padding:"7px 12px",borderRadius:3,border:`1px solid ${C.panelBorder}`,background:C.input,color:C.text,fontSize:12,fontFamily:"monospace"}} />
            <button onClick={handleScan} disabled={loading} style={{padding:"7px 20px",borderRadius:3,background:C.purple,color:C.white,border:"none",cursor:"pointer",fontSize:12,fontWeight:700}}>{loading?"SCANNING...":"▶ RUN SCAN"}</button>
          </div>
        ) : mode==="github" ? (
          <div>
            <div style={{display:"flex",gap:8,marginBottom:6,flexWrap:"wrap"}}>
              <input value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleScan()} placeholder="https://github.com/username/repo" style={{flex:1,minWidth:200,padding:"7px 12px",borderRadius:3,border:`1px solid ${C.panelBorder}`,background:C.input,color:C.text,fontSize:12,fontFamily:"monospace"}} />
              <button onClick={handleScan} disabled={loading} style={{padding:"7px 20px",borderRadius:3,background:loading?`${C.purple}88`:C.purple,color:C.white,border:"none",cursor:loading?"not-allowed":"pointer",fontSize:12,fontWeight:700}}>{loading?"SCANNING...":"▶ RUN SCAN"}</button>
            </div>
            <div style={{display:"flex",gap:8,alignItems:"center",flexWrap:"wrap"}}>
              <button onClick={()=>setShowToken(!showToken)} style={{background:"transparent",border:`1px solid ${C.panelBorder}`,borderRadius:3,padding:"3px 10px",cursor:"pointer",color:C.muted,fontSize:10}}>🔒 {showToken?"Hide Token":"Private Repo"}</button>
              {showToken&&<input value={githubToken} onChange={e=>setGithubToken(e.target.value)} placeholder="GitHub Personal Access Token" type="password" style={{flex:1,padding:"3px 10px",borderRadius:3,border:`1px solid ${C.panelBorder}`,background:C.input,color:C.text,fontSize:10,fontFamily:"monospace"}} />}
            </div>
          </div>
        ) : (
          <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
            <input value={input} onChange={e=>setInput(e.target.value)} placeholder="/app/src" style={{flex:1,minWidth:200,padding:"7px 12px",borderRadius:3,border:`1px solid ${C.panelBorder}`,background:C.input,color:C.text,fontSize:12,fontFamily:"monospace"}} />
            <button onClick={handleScan} disabled={loading} style={{padding:"7px 20px",borderRadius:3,background:C.purple,color:C.white,border:"none",cursor:"pointer",fontSize:12,fontWeight:700}}>{loading?"SCANNING...":"▶ RUN SCAN"}</button>
          </div>
        )}
        {loading && (
          <div style={{marginTop:12}}>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:10,color:C.muted,marginBottom:4,fontFamily:"monospace"}}>
              <span style={{color:C.cyan}}>» {SCAN_STEPS[stepIndex]}</span><span>{progress}%</span>
            </div>
            <div style={{background:C.input,borderRadius:2,height:3}}>
              <div style={{background:C.purple,height:3,borderRadius:2,width:`${progress}%`,transition:"width 0.4s ease"}}></div>
            </div>
          </div>
        )}
        {error && <div style={{marginTop:10,background:`${C.red}18`,border:`1px solid ${C.red}44`,borderRadius:3,padding:"8px 12px",color:C.red,fontSize:11,fontFamily:"monospace"}}>ERROR: {error}</div>}
        {saved && <div style={{marginTop:10,background:`${C.green}18`,border:`1px solid ${C.green}44`,borderRadius:3,padding:"6px 12px",color:C.green,fontSize:11,fontFamily:"monospace"}}>✓ Scan saved to history</div>}
      </Panel>

      {result && (
        <>
          {/* Metrics row */}
          <div className="stats-grid" style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:12,marginBottom:16}}>
            <Metric label="Quantum Readiness Score" value={result.quantum_readiness_score} suffix="/100" color={scoreColor} desc={result.quantum_readiness_score>=70?"QUANTUM SAFE":result.quantum_readiness_score>=40?"AT RISK":"CRITICAL RISK"} />
            <Metric label="Total Threats" value={result.total_findings} color={C.red} desc="vulnerabilities detected" />
            <Metric label="Critical" value={sev.CRITICAL} color={C.critical} desc="immediate action required" />
            <Metric label="High Risk" value={sev.HIGH} color={C.high} desc="requires attention" />
          </div>

          {/* Charts row */}
          <div className="charts-grid" style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:16}}>
            <Panel title="Severity Distribution">
              <SevBar label="CRITICAL" count={sev.CRITICAL} total={result.total_findings} color={C.critical} />
              <SevBar label="HIGH" count={sev.HIGH} total={result.total_findings} color={C.high} />
              <SevBar label="MEDIUM" count={sev.MEDIUM} total={result.total_findings} color={C.medium} />
            </Panel>
            <Panel title="Score Breakdown">
              <SevBar label="CRYPTO ISSUES (RSA/ECC/RC4/DES)" count={sev.CRITICAL} total={result.total_findings} color={C.critical} />
              <SevBar label="TLS / PROTOCOL" count={sev.HIGH} total={result.total_findings} color={C.high} />
              <SevBar label="HASH / SECRETS" count={sev.MEDIUM} total={result.total_findings} color={C.medium} />
              <div style={{fontSize:10,color:C.muted,marginTop:8,fontFamily:"monospace",background:C.input,padding:"4px 8px",borderRadius:2}}>
                SCORE = 100 − (CRITICAL×10) − (HIGH×6) − (MEDIUM×3)
              </div>
            </Panel>
          </div>

          {/* Export row */}
          <Panel title="Export & Share">
            <div style={{display:"flex",gap:8,flexWrap:"wrap",marginBottom:10}}>
              <button onClick={handlePDF} style={{padding:"5px 14px",borderRadius:3,background:C.purple,color:C.white,border:"none",cursor:"pointer",fontSize:11,fontWeight:700}}>PDF REPORT</button>
              <button onClick={handleCSV} style={{padding:"5px 14px",borderRadius:3,background:C.green,color:"#000",border:"none",cursor:"pointer",fontSize:11,fontWeight:700}}>CSV EXPORT</button>
              <button onClick={()=>{navigator.clipboard.writeText(result.findings.map(f=>`[${f.severity}] ${f.file}:${f.line} — ${f.code} → ${f.replacement}`).join("\n"));}} style={{padding:"5px 14px",borderRadius:3,background:"transparent",color:C.muted,border:`1px solid ${C.panelBorder}`,cursor:"pointer",fontSize:11}}>COPY ALL</button>
              <button onClick={()=>window.open("https://twitter.com/intent/tweet?text="+encodeURIComponent("QuantumGuard: "+result.quantum_readiness_score+"/100 vulnerabilities - quantumguard-one.vercel.app #QuantumSecurity"),"_blank")} style={{padding:"5px 14px",borderRadius:3,background:"#1DA1F2",color:C.white,border:"none",cursor:"pointer",fontSize:11}}>SHARE</button>
            </div>
            <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
              <input value={emailInput} onChange={e=>setEmailInput(e.target.value)} placeholder="Email report to..." type="email" style={{flex:1,minWidth:200,padding:"5px 12px",borderRadius:3,border:`1px solid ${C.panelBorder}`,background:C.input,color:C.text,fontSize:11,fontFamily:"monospace"}} />
              <button onClick={handleEmail} disabled={sendingEmail||!emailInput} style={{padding:"5px 14px",borderRadius:3,background:emailSent?C.green:C.purple,color:emailSent?"#000":C.white,border:"none",cursor:"pointer",fontSize:11}}>{emailSent?"✓ SENT":sendingEmail?"SENDING...":"SEND EMAIL"}</button>
            </div>
          </Panel>

          {/* Log viewer */}
          <Panel title={`Threat Intelligence Log — ${result.total_findings} findings`}>
            {/* Filter bar */}
            <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap",alignItems:"center"}}>
              {["ALL","CRITICAL","HIGH","MEDIUM"].map(f=>(
                <button key={f} onClick={()=>setFilter(f)} style={{padding:"3px 10px",borderRadius:3,border:`1px solid ${filter===f?C.purple:C.panelBorder}`,background:filter===f?`${C.purple}22`:"transparent",color:filter===f?C.purpleLight:C.muted,cursor:"pointer",fontSize:10,fontFamily:"monospace"}}>
                  {f}{f!=="ALL"&&sev?` (${sev[f]})`:""}</button>
              ))}
              <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="SEARCH..." style={{padding:"3px 10px",borderRadius:3,border:`1px solid ${C.panelBorder}`,background:C.input,color:C.text,fontSize:10,fontFamily:"monospace",width:140}} />
              <span style={{fontSize:10,color:C.muted,fontFamily:"monospace",marginLeft:"auto"}}>{filtered.length} / {result.total_findings} events</span>
            </div>
            {/* Header row */}
            <div style={{display:"grid",gridTemplateColumns:"24px 80px 1fr 1fr 180px",gap:8,padding:"5px 12px",borderBottom:`1px solid ${C.panelBorder}`,background:C.panelHeader}}>
              {["","SEVERITY","FILE : LINE","CODE","REMEDIATION"].map((h,i)=>(
                <span key={i} style={{fontSize:9,color:C.muted,fontFamily:"monospace",fontWeight:700,textTransform:"uppercase"}}>{h}</span>
              ))}
            </div>
            {/* Rows */}
            <div style={{maxHeight:400,overflowY:"auto"}}>
              {Object.entries(grouped).map(([file,findings])=>findings.map((f,i)=>{
                const key=`${f.file}:${f.line}`;
                return <FindingRow key={`${file}-${i}`} f={f} checked={checklist[key]} onCheck={()=>setChecklist(p=>({...p,[key]:!p[key]}))} />;
              }))}
              {filtered.length===0&&<div style={{padding:20,textAlign:"center",color:C.muted,fontSize:12,fontFamily:"monospace"}}>No events match filter.</div>}
            </div>
          </Panel>
        </>
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
      const res = await fetch(`${API}/check-agility`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({github_url:input})});
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail||"Check failed");
      setResult(data);
    } catch(e){setError(typeof e.message==="string"?e.message:"Check failed.");}
    setLoading(false);
  };

  const agilityColor = result ? (result.agility_score>=70?C.green:result.agility_score>=40?C.amber:C.red) : C.muted;

  return (
    <div style={{padding:16}}>
      <Panel title="Crypto Agility Analysis">
        <div style={{fontSize:11,color:C.muted,fontFamily:"monospace",marginBottom:12,lineHeight:1.7}}>
          CRYPTO AGILITY = ability to swap encryption algorithms without major code changes.<br/>
          Hardcoded algorithms (e.g. RSA.generate(2048)) score ZERO agility.<br/>
          Configurable algorithms (e.g. os.environ.get("CRYPTO_ALGO")) score HIGH agility.
        </div>
        <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
          <input value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&handleCheck()} placeholder="https://github.com/username/repo" style={{flex:1,minWidth:200,padding:"7px 12px",borderRadius:3,border:`1px solid ${C.panelBorder}`,background:C.input,color:C.text,fontSize:12,fontFamily:"monospace"}} />
          <button onClick={handleCheck} disabled={loading} style={{padding:"7px 20px",borderRadius:3,background:loading?`${C.purple}88`:C.purple,color:C.white,border:"none",cursor:loading?"not-allowed":"pointer",fontSize:12,fontWeight:700}}>{loading?"ANALYZING...":"▶ CHECK AGILITY"}</button>
        </div>
        {error&&<div style={{marginTop:10,background:`${C.red}18`,border:`1px solid ${C.red}44`,borderRadius:3,padding:"8px 12px",color:C.red,fontSize:11,fontFamily:"monospace"}}>ERROR: {error}</div>}
      </Panel>

      {result && (
        <>
          <div className="stats-grid" style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12,marginBottom:16}}>
            <Metric label="Agility Score" value={result.agility_score} suffix="/100" color={agilityColor} desc={result.agility_score>=70?"HIGH AGILITY":result.agility_score>=40?"PARTIAL AGILITY":"LOW AGILITY"} />
            <Metric label="Hardcoded Crypto" value={result.hardcoded_count} color={C.red} desc="needs to be configurable" />
            <Metric label="Configurable Crypto" value={result.configurable_count} color={C.green} desc="already agile" />
          </div>
          <Panel title="Agility Breakdown">
            <SevBar label="HARDCODED CRYPTO" count={result.hardcoded_count} total={result.hardcoded_count+result.configurable_count} color={C.red} />
            <SevBar label="CONFIGURABLE CRYPTO" count={result.configurable_count} total={result.hardcoded_count+result.configurable_count} color={C.green} />
          </Panel>
          {result.findings&&result.findings.length>0&&(
            <Panel title={`Agility Findings — ${result.findings.length} items`}>
              <div style={{maxHeight:400,overflowY:"auto"}}>
                <div style={{display:"grid",gridTemplateColumns:"80px 1fr 1fr 1fr",gap:8,padding:"5px 12px",borderBottom:`1px solid ${C.panelBorder}`,background:C.panelHeader}}>
                  {["TYPE","FILE:LINE","CODE","RECOMMENDATION"].map((h,i)=>(
                    <span key={i} style={{fontSize:9,color:C.muted,fontFamily:"monospace",fontWeight:700,textTransform:"uppercase"}}>{h}</span>
                  ))}
                </div>
                {result.findings.map((f,i)=>(
                  <div key={i} style={{display:"grid",gridTemplateColumns:"80px 1fr 1fr 1fr",gap:8,padding:"7px 12px",borderBottom:`1px solid ${C.panelBorder}`,background:i%2===0?C.panel:C.rowAlt}}>
                    <span style={{fontFamily:"monospace",fontSize:10,fontWeight:700,color:f.type==="hardcoded"?C.red:C.green,background:f.type==="hardcoded"?`${C.red}18`:`${C.green}18`,padding:"1px 6px",borderRadius:2}}>{f.type.toUpperCase()}</span>
                    <span style={{fontFamily:"monospace",fontSize:10,color:C.cyan,wordBreak:"break-all"}}>{f.file.split("/").pop()}:{f.line}</span>
                    <span style={{fontFamily:"monospace",fontSize:10,color:C.text,wordBreak:"break-all"}}>{f.code}</span>
                    <span style={{fontFamily:"monospace",fontSize:10,color:f.type==="hardcoded"?C.amber:C.green,wordBreak:"break-all"}}>{f.recommendation}</span>
                  </div>
                ))}
              </div>
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
        const q = query(collection(db,"scans"),where("userId","==",user.uid),orderBy("createdAt","desc"));
        const snap = await getDocs(q);
        setHistory(snap.docs.map(d=>({id:d.id,...d.data()})));
      } catch(e){console.error(e);}
      setLoading(false);
    };
    fetch_();
  }, [user]);

  if (!user) return (
    <div style={{padding:16}}>
      <Panel title="Scan History">
        <div style={{textAlign:"center",padding:32,color:C.muted,fontFamily:"monospace",fontSize:13}}>
          🔒 AUTHENTICATION REQUIRED — Sign in to view scan history
        </div>
      </Panel>
    </div>
  );

  return (
    <div style={{padding:16}}>
      <Panel title={`Scan History — ${history.length} records`}>
        {loading ? <div style={{color:C.muted,fontFamily:"monospace",fontSize:12}}>LOADING...</div> :
        history.length===0 ? <div style={{color:C.muted,fontFamily:"monospace",fontSize:12}}>NO RECORDS FOUND</div> : (
          <>
            <div style={{display:"grid",gridTemplateColumns:"1fr 160px 80px 80px",gap:8,padding:"5px 12px",borderBottom:`1px solid ${C.panelBorder}`,background:C.panelHeader}}>
              {["TARGET","TIMESTAMP","SCORE","THREATS"].map((h,i)=>(
                <span key={i} style={{fontSize:9,color:C.muted,fontFamily:"monospace",fontWeight:700,textTransform:"uppercase"}}>{h}</span>
              ))}
            </div>
            {history.map((scan,i)=>(
              <div key={i} style={{display:"grid",gridTemplateColumns:"1fr 160px 80px 80px",gap:8,padding:"8px 12px",borderBottom:`1px solid ${C.panelBorder}`,background:i%2===0?C.panel:C.rowAlt,alignItems:"center"}}>
                <span style={{fontFamily:"monospace",fontSize:11,color:C.cyan,wordBreak:"break-all"}}>{scan.filename||"scan"}</span>
                <span style={{fontFamily:"monospace",fontSize:10,color:C.muted}}>{scan.createdAt?.toDate?.()?.toLocaleString()||"—"}</span>
                <span style={{fontFamily:"monospace",fontSize:16,fontWeight:700,color:scan.score>=70?C.green:scan.score>=40?C.amber:C.red}}>{scan.score}</span>
                <span style={{fontFamily:"monospace",fontSize:14,fontWeight:700,color:C.red}}>{scan.findings}</span>
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
  const vulnTypes = ["RSA","ECC","DH","DSA","MD5","SHA1","RC4","DES","ECB_MODE","WEAK_TLS","HARDCODED_SECRET"];
  const getStatus = v => migrationStatus[v]||"pending";
  const setStatus = (v,s) => setMigrationStatus(p=>({...p,[v]:s}));
  const totalFixed = Object.values(migrationStatus).filter(s=>s==="fixed").length;
  const totalIP = Object.values(migrationStatus).filter(s=>s==="in_progress").length;
  const progress = Math.round((totalFixed/vulnTypes.length)*100);
  const fixes = {RSA:"CRYSTALS-Kyber (ML-KEM FIPS 203)",ECC:"CRYSTALS-Dilithium (ML-DSA FIPS 204)",DH:"CRYSTALS-Kyber (ML-KEM FIPS 203)",DSA:"CRYSTALS-Dilithium (ML-DSA FIPS 204)",MD5:"SHA-3-256 or BLAKE3",SHA1:"SHA-3-256 or BLAKE3",RC4:"AES-256-GCM",DES:"AES-256-GCM",ECB_MODE:"AES-256-GCM",WEAK_TLS:"TLS 1.3",HARDCODED_SECRET:"AWS Secrets Manager"};
  const sevOf = v=>["RSA","ECC","RC4","DES"].includes(v)?"CRITICAL":["DH","DSA","ECB_MODE","WEAK_TLS","HARDCODED_SECRET"].includes(v)?"HIGH":"MEDIUM";

  if (!user) return (
    <div style={{padding:16}}>
      <Panel title="Migration Tracker">
        <div style={{textAlign:"center",padding:32,color:C.muted,fontFamily:"monospace",fontSize:13}}>🔒 AUTHENTICATION REQUIRED</div>
      </Panel>
    </div>
  );

  return (
    <div style={{padding:16}}>
      <Panel title="Migration Progress">
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12,flexWrap:"wrap",gap:8}}>
          <span style={{fontSize:36,fontWeight:800,color:progress>=70?C.green:progress>=40?C.amber:C.red,fontFamily:"monospace"}}>{progress}%</span>
          <div style={{display:"flex",gap:20}}>
            {[["FIXED",totalFixed,C.green],["IN PROGRESS",totalIP,C.amber],["PENDING",vulnTypes.length-totalFixed-totalIP,C.muted]].map(([l,v,c],i)=>(
              <div key={i} style={{textAlign:"center"}}>
                <div style={{fontSize:22,fontWeight:700,color:c,fontFamily:"monospace"}}>{v}</div>
                <div style={{fontSize:9,color:C.muted,fontFamily:"monospace"}}>{l}</div>
              </div>
            ))}
          </div>
        </div>
        <div style={{background:C.input,borderRadius:2,height:8}}>
          <div style={{background:`linear-gradient(90deg,${C.purple},${C.green})`,height:8,borderRadius:2,width:`${progress}%`,transition:"width 0.6s"}}></div>
        </div>
      </Panel>

      <Panel title="Vulnerability Migration Status">
        <div style={{display:"grid",gridTemplateColumns:"120px 1fr 80px 140px",gap:8,padding:"5px 12px",borderBottom:`1px solid ${C.panelBorder}`,background:C.panelHeader}}>
          {["VULNERABILITY","POST-QUANTUM FIX","SEVERITY","STATUS"].map((h,i)=>(
            <span key={i} style={{fontSize:9,color:C.muted,fontFamily:"monospace",fontWeight:700}}>{h}</span>
          ))}
        </div>
        {vulnTypes.map((v,i)=>{
          const status=getStatus(v); const sev=sevOf(v);
          const sevColor=sev==="CRITICAL"?C.critical:sev==="HIGH"?C.high:C.medium;
          return (
            <div key={i} style={{display:"grid",gridTemplateColumns:"120px 1fr 80px 140px",gap:8,padding:"8px 12px",borderBottom:`1px solid ${C.panelBorder}`,background:status==="fixed"?`${C.greenDark}22`:i%2===0?C.panel:C.rowAlt,alignItems:"center"}}>
              <span style={{fontFamily:"monospace",fontSize:11,fontWeight:700,color:status==="fixed"?C.muted:C.textBright,textDecoration:status==="fixed"?"line-through":"none"}}>{v}</span>
              <span style={{fontFamily:"monospace",fontSize:10,color:C.muted}}>{fixes[v]}</span>
              <span style={{fontFamily:"monospace",fontSize:9,fontWeight:700,color:sevColor,background:`${sevColor}18`,padding:"1px 6px",borderRadius:2}}>{sev}</span>
              <div style={{display:"flex",gap:4}}>
                {[["pending","⬜"],["in_progress","🔄"],["fixed","✅"]].map(([st,icon])=>(
                  <button key={st} onClick={()=>setStatus(v,st)} style={{flex:1,padding:"3px",borderRadius:2,border:`1px solid ${status===st?(st==="fixed"?C.green:st==="in_progress"?C.amber:C.muted):C.panelBorder}`,background:status===st?`${st==="fixed"?C.greenDark:st==="in_progress"?C.amberDark:C.panelBorder}44`:"transparent",cursor:"pointer",fontSize:12}}>
                    {icon}
                  </button>
                ))}
              </div>
            </div>
          );
        })}
        <div style={{padding:"12px 0 4px",display:"flex",gap:8}}>
          <button onClick={()=>{
            const blob=new Blob([`Vulnerability,Status,Fix\n${vulnTypes.map(v=>`${v},${getStatus(v)},${fixes[v]}`).join("\n")}`],{type:"text/csv"});
            const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="migration-status.csv";a.click();
          }} style={{padding:"5px 14px",borderRadius:3,background:C.green,color:"#000",border:"none",cursor:"pointer",fontSize:11,fontWeight:700}}>EXPORT CSV</button>
          <button onClick={()=>setMigrationStatus({})} style={{padding:"5px 14px",borderRadius:3,background:"transparent",color:C.muted,border:`1px solid ${C.panelBorder}`,cursor:"pointer",fontSize:11}}>RESET</button>
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
    <div style={{padding:16}}>
      <div className="stats-grid" style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:12,marginBottom:16}}>
        <Metric label="Languages Supported" value="6" color={C.purple} desc="Python, JS, Java, TS, Go, Rust" />
        <Metric label="Vulnerability Types" value="15+" color={C.red} desc="RSA, ECC, DH, DSA, MD5 & more" />
        <Metric label="NIST Compliance" value="2024" color={C.green} desc="FIPS 203, 204, 205 aligned" />
      </div>
      <Panel title="Quantum Timeline">
        {[
          {year:"2024",event:"NIST finalizes PQC standards — FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)",color:C.green},
          {year:"2026",event:"QuantumGuard launches — first developer-focused quantum vulnerability scanner",color:C.purple},
          {year:"2027",event:"Regulatory pressure increases — organizations must show PQC compliance",color:C.amber},
          {year:"2030",event:"Y2Q — Cryptographically Relevant Quantum Computers expected to arrive",color:C.red},
        ].map((t,i)=>(
          <div key={i} style={{display:"flex",gap:16,marginBottom:14,alignItems:"flex-start",padding:"8px 0",borderBottom:`1px solid ${C.panelBorder}`}}>
            <span style={{fontFamily:"monospace",fontSize:14,fontWeight:800,color:t.color,minWidth:48}}>{t.year}</span>
            <span style={{fontFamily:"monospace",fontSize:11,color:C.text,lineHeight:1.6}}>{t.event}</span>
          </div>
        ))}
      </Panel>
      <Panel title="Vulnerability Reference">
        <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8}}>
          {[["RSA","CRITICAL","CRYSTALS-Kyber"],["ECC","CRITICAL","CRYSTALS-Dilithium"],["RC4","CRITICAL","AES-256-GCM"],["DES/3DES","CRITICAL","AES-256-GCM"],["MD5","MEDIUM","SHA-3-256"],["SHA-1","MEDIUM","SHA-3-256"],["DH","HIGH","CRYSTALS-Kyber"],["DSA","HIGH","CRYSTALS-Dilithium"],["ECB Mode","HIGH","AES-256-GCM"],["Weak TLS","HIGH","TLS 1.3"],["JWT None","CRITICAL","RS256+PQC"],["Hardcoded Keys","HIGH","Secrets Manager"]].map(([v,s,f],i)=>{
            const c=s==="CRITICAL"?C.critical:s==="HIGH"?C.high:C.medium;
            return (
              <div key={i} style={{background:C.input,borderRadius:3,padding:"8px 12px",border:`1px solid ${C.panelBorder}`}}>
                <div style={{fontFamily:"monospace",fontSize:11,fontWeight:700,color:C.textBright,marginBottom:3}}>{v}</div>
                <div style={{fontFamily:"monospace",fontSize:9,color:c,marginBottom:3}}>{s}</div>
                <div style={{fontFamily:"monospace",fontSize:9,color:C.green}}>→ {f}</div>
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
    <div style={{padding:16}}>
      <Panel title="API Endpoints">
        {[
          {method:"POST",path:"/scan-github",auth:"None",desc:"Scan any public GitHub repo. Body: {github_url, github_token?}"},
          {method:"POST",path:"/public-scan-zip",auth:"None",desc:"Upload ZIP file (max 10MB). multipart/form-data, field: file"},
          {method:"POST",path:"/check-agility",auth:"None",desc:"Check crypto agility. Body: {github_url}"},
          {method:"POST",path:"/scan",auth:"x-api-key header",desc:"Scan server path. Body: {directory}"},
          {method:"GET",path:"/health",auth:"None",desc:"Returns {status: healthy}"},
        ].map((e,i)=>(
          <div key={i} style={{display:"flex",gap:12,padding:"8px 0",borderBottom:`1px solid ${C.panelBorder}`,flexWrap:"wrap",alignItems:"center"}}>
            <span style={{fontFamily:"monospace",fontSize:10,fontWeight:700,color:C.purple,background:`${C.purple}22`,padding:"2px 8px",borderRadius:2,minWidth:36,textAlign:"center"}}>{e.method}</span>
            <span style={{fontFamily:"monospace",fontSize:11,color:C.cyan,minWidth:160}}>{e.path}</span>
            <span style={{fontFamily:"monospace",fontSize:10,color:C.amber,minWidth:100}}>{e.auth}</span>
            <span style={{fontFamily:"monospace",fontSize:10,color:C.muted}}>{e.desc}</span>
          </div>
        ))}
      </Panel>
      <div className="docs-grid" style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
        {[
          {title:"Quick Start",icon:"⚡",steps:["Go to Threat Scanner tab","Paste GitHub repo URL","Click RUN SCAN","Download PDF report"]},
          {title:"Crypto Agility",icon:"🔬",steps:["Go to Agility Checker tab","Paste GitHub repo URL","Click CHECK AGILITY","Review hardcoded vs configurable"]},
          {title:"Private Repos",icon:"🔒",steps:["Click Private Repo button","Generate GitHub PAT","Paste Personal Access Token","Token never stored server-side"]},
          {title:"Rate Limits",icon:"⏱",steps:["/scan-github: 20/minute","/public-scan-zip: 3/minute","/check-agility: 10/minute","/scan: 10/minute"]},
        ].map((d,i)=>(
          <Panel key={i} title={`${d.icon} ${d.title}`}>
            {d.steps.map((step,j)=>(
              <div key={j} style={{display:"flex",gap:8,marginBottom:6,alignItems:"flex-start"}}>
                <span style={{fontFamily:"monospace",fontSize:10,color:C.purple,fontWeight:700,minWidth:16}}>{j+1}.</span>
                <span style={{fontFamily:"monospace",fontSize:10,color:C.text}}>{step}</span>
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
  return (
    <div style={{minHeight:"100vh",background:C.bg,color:C.text,fontFamily:"'Segoe UI',monospace"}}>
      <div style={{textAlign:"center",padding:"80px 20px 60px"}}>
        <div style={{display:"inline-flex",gap:8,marginBottom:24,flexWrap:"wrap",justifyContent:"center"}}>
          {[{text:"NIST PQC 2024",color:C.purple},{text:"OPEN SOURCE",color:C.green},{text:"FREE FOREVER",color:C.red}].map((b,i)=>(
            <span key={i} style={{background:`${b.color}18`,border:`1px solid ${b.color}44`,borderRadius:3,padding:"3px 12px",fontSize:10,color:b.color,fontWeight:700,fontFamily:"monospace"}}>{b.text}</span>
          ))}
        </div>
        <h1 style={{fontSize:"clamp(28px,5vw,56px)",fontWeight:800,lineHeight:1.1,maxWidth:900,margin:"0 auto 20px",color:C.textBright}}>
          Quantum Threat Intelligence<br/><span style={{color:C.purple}}>for Your Codebase</span>
        </h1>
        <p style={{fontSize:"clamp(13px,2vw,17px)",color:C.muted,maxWidth:560,margin:"0 auto 40px",lineHeight:1.7,fontFamily:"monospace"}}>
          Enterprise-grade quantum vulnerability scanner. Detect RSA, ECC, and 15+ cryptographic weaknesses before quantum computers break them.
        </p>
        <div style={{display:"flex",gap:12,justifyContent:"center",flexWrap:"wrap"}}>
          <button onClick={onGetStarted} style={{background:C.purple,color:C.white,padding:"14px 36px",borderRadius:4,border:"none",cursor:"pointer",fontSize:14,fontWeight:700,fontFamily:"monospace"}}>▶ LAUNCH SCANNER</button>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{background:"transparent",color:C.text,padding:"14px 36px",borderRadius:4,textDecoration:"none",fontSize:14,border:`1px solid ${C.panelBorder}`,fontFamily:"monospace"}}>GITHUB →</a>
        </div>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:1,maxWidth:800,margin:"0 auto 60px",background:C.panelBorder,borderRadius:4,overflow:"hidden"}}>
        {[{num:"15+",label:"VULN TYPES"},{num:"6",label:"LANGUAGES"},{num:"2030",label:"Y2Q DEADLINE"},{num:"100%",label:"OPEN SOURCE"}].map((s,i)=>(
          <div key={i} style={{background:C.panel,padding:20,textAlign:"center"}}>
            <div style={{fontSize:28,fontWeight:800,color:C.purple,fontFamily:"monospace"}}>{s.num}</div>
            <div style={{color:C.muted,fontSize:9,marginTop:4,fontFamily:"monospace",letterSpacing:1}}>{s.label}</div>
          </div>
        ))}
      </div>
      <div style={{textAlign:"center",padding:"40px 20px",background:C.panel,borderTop:`1px solid ${C.panelBorder}`}}>
        <button onClick={onGetStarted} style={{background:C.purple,color:C.white,padding:"14px 48px",borderRadius:4,border:"none",cursor:"pointer",fontSize:14,fontWeight:700,fontFamily:"monospace"}}>▶ LAUNCH SCANNER</button>
        <p style={{color:C.muted,marginTop:16,fontSize:11,fontFamily:"monospace"}}>quantumguard-one.vercel.app · github.com/cybersupe/quantumguard · 2026</p>
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
  const [darkMode, setDarkMode] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => { onAuthStateChanged(auth, u => setUser(u)); }, []);

  const handleLogin = async () => { try { await signInWithGoogle(); } catch(e){ console.error(e); } };
  const handleLogout = async () => { try { await signOut(auth); setUser(null); } catch(e){ console.error(e); } };

  if (active === "home") return <Homepage onGetStarted={() => setActive("scan")} />;

  const pageTitle = {scan:"Threat Scanner",agility:"Agility Checker",history:"Scan History",migration:"Migration Tracker",dashboard:"Analytics",docs:"Documentation"};

  return (
    <div style={{display:"flex",minHeight:"100vh",background:C.bg,color:C.text,fontFamily:"'Segoe UI',sans-serif"}}>
      <button className="hamburger" onClick={()=>setSidebarOpen(!sidebarOpen)}>☰</button>
      {sidebarOpen && <div className="sidebar-overlay open" onClick={()=>setSidebarOpen(false)} />}

      <Sidebar active={active} setActive={setActive} user={user} onLogin={handleLogin} onLogout={handleLogout} open={sidebarOpen} onClose={()=>setSidebarOpen(false)} />

      <div className="main-content" style={{marginLeft:56,flex:1,minHeight:"100vh",display:"flex",flexDirection:"column"}}>
        <TopBar
          title={pageTitle[active]||active}
          user={user} onLogin={handleLogin} onLogout={handleLogout}
          darkMode={darkMode} setDarkMode={setDarkMode}
          onHamburger={()=>setSidebarOpen(!sidebarOpen)}
        />
        <div style={{flex:1,overflowY:"auto"}}>
          {active==="scan" && <ScannerPage user={user} />}
          {active==="agility" && <AgilityPage />}
          {active==="history" && <HistoryPage user={user} />}
          {active==="migration" && <MigrationPage user={user} />}
          {active==="dashboard" && <AnalyticsPage />}
          {active==="docs" && <DocsPage />}
        </div>
      </div>
    </div>
  );
}
