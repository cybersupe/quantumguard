import { useState, useEffect, useRef } from "react";
import "./App.css";
import { auth, db, signInWithGoogle, logOut, canUserScan, incrementScanCount, getUserProfile } from "./firebase";
import { onAuthStateChanged } from "firebase/auth";
import { collection, addDoc, getDocs, query, where, orderBy } from "firebase/firestore";

const API = "https://web-production-16177f.up.railway.app";

const SCAN_STEPS = [
  "Connecting to repository...",
  "Cloning repository...",
  "Analyzing file structure...",
  "Scanning for vulnerabilities...",
  "Calculating quantum readiness score...",
  "Generating report...",
];

function Navbar({ darkMode, setDarkMode, user, onLogin, onLogout }) {
  const bg = darkMode ? "#0f0f1a" : "#ffffff";
  const muted = darkMode ? "#888" : "#666";
  const border = darkMode ? "#1a1a2e" : "#e5e5e5";
  return (
    <nav style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "16px 40px", borderBottom: `1px solid ${border}`, position: "sticky", top: 0, background: bg, zIndex: 100, flexWrap: "wrap", gap: 12 }}>
      <div style={{ fontSize: 20, fontWeight: 700, color: "#7F77DD" }}>⚛ QuantumGuard</div>
      <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
        <a href="#features" style={{ color: muted, textDecoration: "none", fontSize: 14 }}>Features</a>
        <a href="#how" style={{ color: muted, textDecoration: "none", fontSize: 14 }}>How it works</a>
        <a href="#pricing" style={{ color: muted, textDecoration: "none", fontSize: 14 }}>Pricing</a>
        <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ color: muted, textDecoration: "none", fontSize: 14 }}>GitHub</a>
        <button onClick={() => setDarkMode(!darkMode)} style={{ background: "transparent", border: `1px solid ${border}`, borderRadius: 8, padding: "6px 12px", cursor: "pointer", color: muted, fontSize: 13 }}>
          {darkMode ? "☀️" : "🌙"}
        </button>
        {user ? (
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <img src={user.photoURL} alt="avatar" style={{ width: 32, height: 32, borderRadius: "50%" }} />
            <span style={{ color: muted, fontSize: 13 }}>{user.displayName?.split(" ")[0]}</span>
            <button onClick={onLogout} style={{ background: "transparent", border: `1px solid ${border}`, borderRadius: 8, padding: "6px 12px", cursor: "pointer", color: muted, fontSize: 13 }}>Logout</button>
          </div>
        ) : (
          <button onClick={onLogin} style={{ background: "#534AB7", color: "#fff", padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer", fontSize: 14, fontWeight: 500 }}>Sign in with Google</button>
        )}
      </div>
    </nav>
  );
}

function ScanProgressBar({ loading, progress, stepIndex, darkMode }) {
  const muted = darkMode ? "#888" : "#666";
  const border = darkMode ? "#333" : "#e5e5e5";
  if (!loading) return null;
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, color: muted, marginBottom: 8 }}>
        <span style={{ color: "#7F77DD" }}>⚡ {SCAN_STEPS[stepIndex] || "Processing..."}</span>
        <span>{progress}%</span>
      </div>
      <div style={{ background: border, borderRadius: 4, height: 6, marginBottom: 12 }}>
        <div style={{ background: "linear-gradient(90deg, #534AB7, #7F77DD)", height: 6, borderRadius: 4, width: `${progress}%`, transition: "width 0.4s ease" }}></div>
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {SCAN_STEPS.map((step, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: i < stepIndex ? "#1D9E75" : i === stepIndex ? "#7F77DD" : muted }}>
            <span>{i < stepIndex ? "✓" : i === stepIndex ? "●" : "○"}</span>
            <span style={{ display: i > 1 ? "none" : "inline" }}>{step.split(" ")[0]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ErrorBox({ error, darkMode }) {
  if (!error) return null;
  const messages = {
    "Failed to fetch": "Cannot reach the QuantumGuard server. The backend may be starting up — wait 10 seconds and try again.",
    "Invalid GitHub URL or clone failed": "Could not clone this repository. Make sure the URL is correct and the repo is public.",
    "Clone timeout": "The repository took too long to clone. Try a smaller repo or check your connection.",
    "Directory not found": "The server path does not exist. Check the path and try again.",
    "Invalid API key": "API key rejected. Contact support.",
  };
  const friendly = messages[error] || error;
  return (
    <div style={{ background: "#E24B4A22", border: "1px solid #E24B4A", borderRadius: 8, padding: 16, marginBottom: 24 }}>
      <div style={{ color: "#E24B4A", fontWeight: 600, marginBottom: 4, fontSize: 14 }}>⚠ Scan Failed</div>
      <div style={{ color: "#E24B4A", fontSize: 13, lineHeight: 1.6 }}>{friendly}</div>
      {error === "Failed to fetch" && (
        <div style={{ marginTop: 8, fontSize: 12, color: "#E24B4A88" }}>
          Tip: Railway free tier spins down after inactivity. First request may take 30 seconds.
        </div>
      )}
    </div>
  );
}

function SeverityChart({ severityCounts, darkMode }) {
  const card = darkMode ? "#1a1a2e" : "#ffffff";
  const border = darkMode ? "#333" : "#e5e5e5";
  const muted = darkMode ? "#888" : "#666";
  const total = (severityCounts.CRITICAL || 0) + (severityCounts.HIGH || 0) + (severityCounts.MEDIUM || 0);
  if (total === 0) return null;
  const bars = [
    { key: "CRITICAL", color: "#E24B4A", count: severityCounts.CRITICAL || 0 },
    { key: "HIGH", color: "#BA7517", count: severityCounts.HIGH || 0 },
    { key: "MEDIUM", color: "#1D9E75", count: severityCounts.MEDIUM || 0 },
  ];
  return (
    <div style={{ background: card, borderRadius: 12, padding: 20, marginBottom: 16, border: `1px solid ${border}` }}>
      <div style={{ fontSize: 13, fontWeight: 600, color: muted, marginBottom: 16 }}>Severity Breakdown</div>
      {bars.map(b => (
        <div key={b.key} style={{ marginBottom: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
            <span style={{ color: b.color, fontWeight: 600 }}>{b.key}</span>
            <span style={{ color: muted }}>{b.count} ({total > 0 ? Math.round(b.count / total * 100) : 0}%)</span>
          </div>
          <div style={{ background: border, borderRadius: 4, height: 8 }}>
            <div style={{ background: b.color, height: 8, borderRadius: 4, width: `${total > 0 ? (b.count / total) * 100 : 0}%`, transition: "width 0.6s ease" }}></div>
          </div>
        </div>
      ))}
    </div>
  );
}

function GroupedFindings({ findings, darkMode, filter, search, checklist, setChecklist }) {
  const bg = darkMode ? "#0f0f1a" : "#f5f5f5";
  const card = darkMode ? "#1a1a2e" : "#ffffff";
  const text = darkMode ? "#ffffff" : "#111111";
  const muted = darkMode ? "#888" : "#666";
  const border = darkMode ? "#333" : "#e5e5e5";
  const [collapsed, setCollapsed] = useState({});

  const filtered = findings.filter(f =>
    (filter === "ALL" || f.severity === filter) &&
    (search === "" || f.file.toLowerCase().includes(search.toLowerCase()) || f.code.toLowerCase().includes(search.toLowerCase()))
  );

  const grouped = filtered.reduce((acc, f) => {
    if (!acc[f.file]) acc[f.file] = [];
    acc[f.file].push(f);
    return acc;
  }, {});

  const toggleCollapse = (file) => setCollapsed(p => ({ ...p, [file]: !p[file] }));

  return (
    <div>
      <div style={{ fontSize: 12, color: muted, marginBottom: 12 }}>
        Showing {filtered.length} of {findings.length} findings across {Object.keys(grouped).length} files
      </div>
      {Object.entries(grouped).map(([file, filefindings], gi) => (
        <div key={gi} style={{ marginBottom: 12, border: `1px solid ${border}`, borderRadius: 10, overflow: "hidden" }}>
          <div onClick={() => toggleCollapse(file)} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 16px", background: card, cursor: "pointer", userSelect: "none" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <span style={{ fontFamily: "monospace", fontSize: 13, color: text }}>{file.split("/").pop()}</span>
              <span style={{ fontSize: 11, color: muted, fontFamily: "monospace" }}>{file}</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ background: "#E24B4A22", color: "#E24B4A", fontSize: 12, padding: "2px 10px", borderRadius: 20 }}>{filefindings.length} issues</span>
              <span style={{ color: muted, fontSize: 12 }}>{collapsed[file] ? "▶" : "▼"}</span>
            </div>
          </div>
          {!collapsed[file] && (
            <div style={{ background: bg, padding: "12px 16px" }}>
              {filefindings.map((f, i) => {
                const key = `${f.file}:${f.line}`;
                return (
                  <div key={i} style={{ borderLeft: `3px solid ${f.severity === "CRITICAL" ? "#E24B4A" : f.severity === "HIGH" ? "#BA7517" : "#1D9E75"}`, paddingLeft: 14, marginBottom: i < filefindings.length - 1 ? 16 : 0, opacity: checklist[key] ? 0.5 : 1 }}>
                    <div style={{ display: "flex", gap: 8, marginBottom: 6, alignItems: "center", flexWrap: "wrap" }}>
                      <input type="checkbox" checked={!!checklist[key]} onChange={() => setChecklist(p => ({ ...p, [key]: !p[key] }))} style={{ cursor: "pointer" }} />
                      <span style={{ background: f.severity === "CRITICAL" ? "#E24B4A22" : f.severity === "HIGH" ? "#BA751722" : "#1D9E7522", color: f.severity === "CRITICAL" ? "#E24B4A" : f.severity === "HIGH" ? "#BA7517" : "#1D9E75", padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600 }}>{f.severity}</span>
                      <span style={{ color: muted, fontSize: 12 }}>Line {f.line}</span>
                      {checklist[key] && <span style={{ fontSize: 11, color: "#1D9E75" }}>✓ Fixed</span>}
                    </div>
                    <div style={{ fontFamily: "monospace", background: card, padding: "8px 12px", borderRadius: 6, fontSize: 12, marginBottom: 6, color: text, overflowX: "auto", whiteSpace: "pre" }}>{f.code}</div>
                    <div style={{ fontSize: 12, color: muted }}>Fix: <span style={{ color: "#7F77DD" }}>{f.replacement}</span></div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function UserProfile({ user, darkMode }) {
  const [profile, setProfile] = useState(null);
  const card = darkMode ? "#1a1a2e" : "#ffffff";
  const text = darkMode ? "#ffffff" : "#111111";
  const muted = darkMode ? "#888" : "#666";
  const border = darkMode ? "#333" : "#e5e5e5";
  const bg = darkMode ? "#0f0f1a" : "#f5f5f5";

  useEffect(() => {
    if (!user) return;
    getUserProfile(user.uid).then(setProfile);
  }, [user]);

  if (!user || !profile) return null;

  return (
    <div style={{ maxWidth: 860, margin: "0 auto", padding: "0 20px 40px" }}>
      <h3 style={{ color: "#7F77DD", marginBottom: 16 }}>Your Profile</h3>
      <div style={{ background: card, borderRadius: 12, padding: 24, border: `1px solid ${border}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>
          <img src={user.photoURL} alt="avatar" style={{ width: 56, height: 56, borderRadius: "50%" }} />
          <div>
            <div style={{ fontSize: 18, fontWeight: 600, color: text }}>{user.displayName}</div>
            <div style={{ fontSize: 13, color: muted }}>{user.email}</div>
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 16 }}>
          {[
            { label: "Total Scans", value: profile.totalScans, color: "#7F77DD" },
            { label: "Avg Score", value: profile.avgScore, color: profile.avgScore >= 70 ? "#1D9E75" : profile.avgScore >= 40 ? "#BA7517" : "#E24B4A" },
            { label: "Total Issues", value: profile.totalFindings, color: "#E24B4A" },
            { label: "Scans Left Today", value: profile.remainingToday, color: "#1D9E75" },
          ].map((s, i) => (
            <div key={i} style={{ background: bg, borderRadius: 10, padding: 16, textAlign: "center" }}>
              <div style={{ fontSize: 28, fontWeight: 700, color: s.color }}>{s.value}</div>
              <div style={{ fontSize: 11, color: muted, marginTop: 4 }}>{s.label}</div>
            </div>
          ))}
        </div>
        <div style={{ background: bg, borderRadius: 8, padding: "12px 16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 6 }}>
            <span style={{ color: muted }}>Daily scan limit</span>
            <span style={{ color: "#7F77DD" }}>{profile.scansToday} / 10 used</span>
          </div>
          <div style={{ background: border, borderRadius: 4, height: 6 }}>
            <div style={{ background: profile.remainingToday > 3 ? "#1D9E75" : "#E24B4A", height: 6, borderRadius: 4, width: `${(profile.scansToday / 10) * 100}%`, transition: "width 0.4s" }}></div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ScanHistory({ user, darkMode }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const card = darkMode ? "#1a1a2e" : "#ffffff";
  const text = darkMode ? "#ffffff" : "#111111";
  const muted = darkMode ? "#888" : "#666";
  const border = darkMode ? "#333" : "#e5e5e5";

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

  if (!user) return null;

  return (
    <div style={{ maxWidth: 860, margin: "0 auto", padding: "0 20px 40px" }}>
      <h3 style={{ color: "#7F77DD", marginBottom: 16 }}>Your Scan History</h3>
      {loading ? (
        <div style={{ color: muted }}>Loading...</div>
      ) : history.length === 0 ? (
        <div style={{ color: muted, fontSize: 14 }}>No scans yet — run your first scan above!</div>
      ) : (
        history.map((scan, i) => (
          <div key={i} style={{ background: card, borderRadius: 12, padding: 16, marginBottom: 12, border: `1px solid ${border}`, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
            <div>
              <div style={{ fontWeight: 600, color: text, fontSize: 14 }}>{scan.filename || "Scan"}</div>
              <div style={{ color: muted, fontSize: 12 }}>{scan.createdAt?.toDate?.()?.toLocaleString() || "Just now"}</div>
            </div>
            <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: scan.score >= 70 ? "#1D9E75" : scan.score >= 40 ? "#BA7517" : "#E24B4A" }}>{scan.score}</div>
                <div style={{ fontSize: 10, color: muted }}>Score</div>
              </div>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 20, fontWeight: 700, color: "#E24B4A" }}>{scan.findings}</div>
                <div style={{ fontSize: 10, color: muted }}>Issues</div>
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  );
}

function Scanner({ darkMode, user }) {
  const [mode, setMode] = useState("github");
  const [input, setInput] = useState("");
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
  const intervalRef = useRef(null);

  const bg = darkMode ? "#0f0f1a" : "#f5f5f5";
  const card = darkMode ? "#1a1a2e" : "#ffffff";
  const text = darkMode ? "#ffffff" : "#111111";
  const muted = darkMode ? "#888" : "#666";
  const border = darkMode ? "#333" : "#e5e5e5";

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
    const { allowed } = await canUserScan(user?.uid);
    if (!allowed) {
      setError("Daily scan limit reached (10/day). Upgrade to Pro for unlimited scans.");
      return;
    }
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
        res = await fetch(`${API}/scan-github`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ github_url: input }) });
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

  const getScoreColor = (s) => s >= 70 ? "#1D9E75" : s >= 40 ? "#BA7517" : "#E24B4A";

  const severityCounts = result ? {
    CRITICAL: result.findings.filter(f => f.severity === "CRITICAL").length,
    HIGH: result.findings.filter(f => f.severity === "HIGH").length,
    MEDIUM: result.findings.filter(f => f.severity === "MEDIUM").length,
  } : null;

  const detectedLanguages = result ? [...new Set(result.findings.map(f => ({ py: "Python", js: "JavaScript", java: "Java", ts: "TypeScript" })[f.file.split(".").pop()] || f.file.split(".").pop()))] : [];

  const fileBreakdown = result ? result.findings.reduce((acc, f) => { const n = f.file.split("/").pop(); acc[n] = (acc[n] || 0) + 1; return acc; }, {}) : null;

  const handleCopy = () => {
    if (!result) return;
    navigator.clipboard.writeText(`QuantumGuard Scan Report\nScore: ${result.quantum_readiness_score}/100\nVulnerabilities: ${result.total_findings}\n\n` + result.findings.map(f => `[${f.severity}] ${f.file}:${f.line}\n${f.code}\nFix: ${f.replacement}`).join("\n\n"));
    setCopied(true); setTimeout(() => setCopied(false), 2000);
  };

  const handleCSV = () => {
    if (!result) return;
    const header = "Severity,File,Line,Code,Vulnerability,Fix\n";
    const rows = result.findings.map(f => `"${f.severity}","${f.file}","${f.line}","${f.code.replace(/"/g, "'")}","${f.vulnerability || ""}","${f.replacement}"`).join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "quantumguard-report.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  const handlePDF = () => {
    if (!result) return;
    const win = window.open("", "_blank");
    win.document.write(`<html><head><title>QuantumGuard Report</title><style>body{font-family:Arial,sans-serif;padding:40px;color:#333;}h1{color:#534AB7;}.score{font-size:48px;font-weight:bold;color:${getScoreColor(result.quantum_readiness_score)};}.finding{border-left:3px solid #E24B4A;padding:10px 16px;margin:12px 0;background:#f9f9f9;}.high{border-color:#BA7517;}.medium{border-color:#1D9E75;}code{background:#f0f0f0;padding:2px 6px;border-radius:3px;font-size:12px;}.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;}.CRITICAL{background:#E24B4A22;color:#E24B4A;}.HIGH{background:#BA751722;color:#BA7517;}.MEDIUM{background:#1D9E7522;color:#1D9E75;}</style></head><body><h1>⚛ QuantumGuard Security Report</h1><p>Generated: ${new Date().toLocaleString()}</p>${result.github_url ? `<p>Repository: ${result.github_url}</p>` : ""}<hr/><div class="score">${result.quantum_readiness_score}/100</div><p>Quantum Readiness Score</p><p><strong>Total Vulnerabilities: ${result.total_findings}</strong></p><p>Critical: ${severityCounts.CRITICAL} | High: ${severityCounts.HIGH} | Medium: ${severityCounts.MEDIUM}</p><hr/><h2>Findings</h2>${result.findings.map(f => `<div class="finding ${f.severity}"><span class="badge ${f.severity}">${f.severity}</span> <strong>${f.file}:${f.line}</strong><br/><code>${f.code}</code><br/>Fix: <strong>${f.replacement}</strong></div>`).join("")}</body></html>`);
    win.document.close(); win.print();
  };

  const handleShare = () => {
    if (!result) return;
    window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(`I scanned my codebase with QuantumGuard!\n\nQuantum Readiness Score: ${result.quantum_readiness_score}/100\nVulnerabilities: ${result.total_findings}\n\nquantumguard-one.vercel.app\n\n#QuantumSecurity #CyberSecurity`)}`, "_blank");
  };

  return (
    <div id="scan" style={{ maxWidth: 860, margin: "0 auto", padding: "60px 20px", background: bg }}>
      <h2 style={{ fontSize: 28, textAlign: "center", marginBottom: 8, color: text }}>Scan Your Code</h2>
      <p style={{ color: muted, textAlign: "center", marginBottom: 32, fontSize: 14 }}>Upload a ZIP or paste a GitHub URL — free, instant, secure.</p>

      {!user && (
        <div style={{ background: "#534AB722", border: "1px solid #534AB7", borderRadius: 8, padding: 12, marginBottom: 24, textAlign: "center" }}>
          <span style={{ color: "#7F77DD", fontSize: 13 }}>💡 Sign in to save your scan history and track your daily limit!</span>
        </div>
      )}

      <div style={{ display: "flex", gap: 8, marginBottom: 16, justifyContent: "center", flexWrap: "wrap" }}>
        {["github", "zip", "path"].map(m => (
          <button key={m} onClick={() => setMode(m)} style={{ padding: "8px 20px", borderRadius: 8, border: "none", cursor: "pointer", background: mode === m ? "#534AB7" : card, color: mode === m ? "#fff" : muted, fontSize: 13, fontWeight: mode === m ? 600 : 400 }}>
            {m === "github" ? "GitHub URL" : m === "zip" ? "Upload ZIP" : "Server Path"}
          </button>
        ))}
      </div>

      <div style={{ display: "flex", gap: 12, marginBottom: 24, flexWrap: "wrap" }}>
        {mode === "zip" ? (
          <input type="file" accept=".zip" onChange={(e) => setFile(e.target.files[0])} style={{ flex: 1, minWidth: 200, padding: "12px 16px", borderRadius: 8, border: `1px solid ${border}`, background: card, color: text, fontSize: 14 }} />
        ) : (
          <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleScan()} placeholder={mode === "github" ? "https://github.com/username/repo" : "/app/src"} style={{ flex: 1, minWidth: 200, padding: "12px 16px", borderRadius: 8, border: `1px solid ${border}`, background: card, color: text, fontSize: 14 }} />
        )}
        <button onClick={handleScan} disabled={loading} style={{ padding: "12px 28px", borderRadius: 8, background: loading ? "#534AB788" : "#534AB7", color: "#fff", border: "none", cursor: loading ? "not-allowed" : "pointer", fontSize: 14, fontWeight: 600 }}>
          {loading ? "Scanning..." : "Scan →"}
        </button>
      </div>

      <ScanProgressBar loading={loading} progress={progress} stepIndex={stepIndex} darkMode={darkMode} />
      <ErrorBox error={error} darkMode={darkMode} />

      {saved && (
        <div style={{ background: "#1D9E7522", border: "1px solid #1D9E75", borderRadius: 8, padding: "10px 16px", marginBottom: 16, color: "#1D9E75", fontSize: 13 }}>
          ✓ Scan saved to your history!
        </div>
      )}

      {result && (
        <div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 16 }}>
            <div style={{ background: card, borderRadius: 12, padding: 24, textAlign: "center", border: `1px solid ${border}` }}>
              <div style={{ fontSize: 56, fontWeight: 700, color: getScoreColor(result.quantum_readiness_score), lineHeight: 1 }}>{result.quantum_readiness_score}</div>
              <div style={{ color: muted, fontSize: 14, marginTop: 8 }}>Quantum Readiness Score</div>
              <div style={{ fontSize: 12, color: getScoreColor(result.quantum_readiness_score), marginTop: 4 }}>{result.quantum_readiness_score >= 70 ? "✓ Good" : result.quantum_readiness_score >= 40 ? "⚠ Needs work" : "✗ Critical risk"}</div>
            </div>
            <div style={{ background: card, borderRadius: 12, padding: 24, textAlign: "center", border: `1px solid ${border}` }}>
              <div style={{ fontSize: 56, fontWeight: 700, color: "#E24B4A", lineHeight: 1 }}>{result.total_findings}</div>
              <div style={{ color: muted, fontSize: 14, marginTop: 8 }}>Vulnerabilities Found</div>
              <div style={{ fontSize: 12, color: muted, marginTop: 4 }}>across {Object.keys(result.findings.reduce((a, f) => ({ ...a, [f.file]: 1 }), {})).length} files</div>
            </div>
          </div>

          <SeverityChart severityCounts={severityCounts} darkMode={darkMode} />

          {detectedLanguages.length > 0 && (
            <div style={{ background: card, borderRadius: 8, padding: "12px 16px", marginBottom: 16, border: `1px solid ${border}`, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <span style={{ fontSize: 13, color: muted }}>Languages detected:</span>
              {detectedLanguages.map((l, i) => <span key={i} style={{ background: "#534AB722", color: "#7F77DD", padding: "2px 10px", borderRadius: 20, fontSize: 12 }}>{l}</span>)}
            </div>
          )}

          {fileBreakdown && (
            <div style={{ background: card, borderRadius: 8, padding: 16, marginBottom: 16, border: `1px solid ${border}` }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: text, marginBottom: 10 }}>Top affected files</div>
              {Object.entries(fileBreakdown).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([fname, count], i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                  <span style={{ fontSize: 12, color: muted, fontFamily: "monospace" }}>{fname}</span>
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ width: 80, background: border, borderRadius: 4, height: 4 }}>
                      <div style={{ background: "#E24B4A", height: 4, borderRadius: 4, width: `${(count / Math.max(...Object.values(fileBreakdown))) * 100}%` }}></div>
                    </div>
                    <span style={{ fontSize: 12, color: "#E24B4A", minWidth: 50, textAlign: "right" }}>{count} issues</span>
                  </div>
                </div>
              ))}
            </div>
          )}

          <div style={{ background: card, borderRadius: 12, padding: 24, border: `1px solid ${border}` }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, flexWrap: "wrap", gap: 8 }}>
              <h3 style={{ color: "#7F77DD", margin: 0 }}>Findings</h3>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button onClick={handleCopy} style={{ padding: "6px 14px", borderRadius: 6, background: copied ? "#1D9E75" : "transparent", color: copied ? "#fff" : muted, border: `1px solid ${border}`, cursor: "pointer", fontSize: 12 }}>{copied ? "Copied!" : "Copy"}</button>
                <button onClick={handleCSV} style={{ padding: "6px 14px", borderRadius: 6, background: "#1D9E75", color: "#fff", border: "none", cursor: "pointer", fontSize: 12 }}>CSV</button>
                <button onClick={handlePDF} style={{ padding: "6px 14px", borderRadius: 6, background: "#534AB7", color: "#fff", border: "none", cursor: "pointer", fontSize: 12 }}>PDF</button>
                <button onClick={handleShare} style={{ padding: "6px 14px", borderRadius: 6, background: "#1DA1F2", color: "#fff", border: "none", cursor: "pointer", fontSize: 12 }}>Share</button>
              </div>
            </div>

            <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap", alignItems: "center" }}>
              {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map(f => (
                <button key={f} onClick={() => setFilter(f)} style={{ padding: "4px 12px", borderRadius: 20, border: `1px solid ${border}`, background: filter === f ? "#534AB7" : "transparent", color: filter === f ? "#fff" : muted, cursor: "pointer", fontSize: 12 }}>
                  {f}{f !== "ALL" && severityCounts ? ` (${severityCounts[f]})` : ""}
                </button>
              ))}
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search files or code..." style={{ padding: "4px 12px", borderRadius: 20, border: `1px solid ${border}`, background: bg, color: text, fontSize: 12, flex: 1, minWidth: 140 }} />
            </div>

            <GroupedFindings findings={result.findings} darkMode={darkMode} filter={filter} search={search} checklist={checklist} setChecklist={setChecklist} />
          </div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [darkMode, setDarkMode] = useState(true);
  const [user, setUser] = useState(null);

  useEffect(() => {
    onAuthStateChanged(auth, (u) => setUser(u));
  }, []);

  const handleLogin = async () => {
    try { await signInWithGoogle(); } catch (e) { console.error(e); }
  };

 const handleLogout = async () => {
  try { 
    await auth.signOut(); 
    setUser(null);
  } catch (e) { 
    console.error(e); 
  }
};

  const bg = darkMode ? "#0f0f1a" : "#f5f5f5";
  const card = darkMode ? "#1a1a2e" : "#ffffff";
  const text = darkMode ? "#ffffff" : "#111111";
  const muted = darkMode ? "#888" : "#666";
  const border = darkMode ? "#222" : "#e5e5e5";

  return (
    <div style={{ minHeight: "100vh", background: bg, color: text, fontFamily: "sans-serif" }}>
      <Navbar darkMode={darkMode} setDarkMode={setDarkMode} user={user} onLogin={handleLogin} onLogout={handleLogout} />

      <div style={{ textAlign: "center", padding: "80px 20px 60px" }}>
        <div style={{ display: "inline-flex", gap: 8, marginBottom: 24, flexWrap: "wrap", justifyContent: "center" }}>
          <span style={{ background: "#534AB722", border: "1px solid #534AB7", borderRadius: 20, padding: "4px 14px", fontSize: 12, color: "#7F77DD" }}>NIST PQC 2024</span>
          <span style={{ background: "#1D9E7522", border: "1px solid #1D9E75", borderRadius: 20, padding: "4px 14px", fontSize: 12, color: "#1D9E75" }}>Open Source</span>
          <span style={{ background: "#E24B4A22", border: "1px solid #E24B4A", borderRadius: 20, padding: "4px 14px", fontSize: 12, color: "#E24B4A" }}>Free Forever</span>
        </div>
        <h1 style={{ fontSize: "clamp(32px, 6vw, 56px)", fontWeight: 700, lineHeight: 1.15, maxWidth: 800, margin: "0 auto 24px", color: text }}>
          Find Weak Encryption<br />
          <span style={{ color: "#7F77DD" }}>Before Quantum Computers Do</span>
        </h1>
        <p style={{ fontSize: "clamp(15px, 2vw, 19px)", color: muted, maxWidth: 600, margin: "0 auto 40px", lineHeight: 1.7 }}>
          Scan your codebase and find every encryption algorithm that quantum computers will break. Get a clear migration plan aligned with NIST 2024 standards.
        </p>
        <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
          <a href="#scan" style={{ background: "#534AB7", color: "#fff", padding: "16px 36px", borderRadius: 10, textDecoration: "none", fontSize: 16, fontWeight: 600 }}>Start Free Scan →</a>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ background: card, color: text, padding: "16px 36px", borderRadius: 10, textDecoration: "none", fontSize: 16, border: `1px solid ${border}` }}>View on GitHub</a>
        </div>
        <p style={{ color: muted, fontSize: 13, marginTop: 16 }}>No credit card. Paste a GitHub URL and scan instantly.</p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16, maxWidth: 860, margin: "0 auto 80px", padding: "0 20px" }}>
        {[{ num: "15+", label: "Vulnerabilities Detected" }, { num: "4", label: "Languages Supported" }, { num: "2030", label: "Quantum Deadline" }, { num: "100%", label: "Free & Open Source" }].map((s, i) => (
          <div key={i} style={{ background: card, borderRadius: 12, padding: 24, textAlign: "center", border: `1px solid ${border}` }}>
            <div style={{ fontSize: 32, fontWeight: 700, color: "#7F77DD" }}>{s.num}</div>
            <div style={{ color: muted, fontSize: 13, marginTop: 6 }}>{s.label}</div>
          </div>
        ))}
      </div>

      <div id="features" style={{ maxWidth: 900, margin: "0 auto 80px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: "clamp(24px, 4vw, 36px)", marginBottom: 8, color: text }}>Everything you need</h2>
        <p style={{ textAlign: "center", color: muted, marginBottom: 48, fontSize: 16 }}>Built for developers and security teams who need to act now</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 20 }}>
          {[
            { icon: "🔍", title: "Deep scanning", desc: "Scans every file line by line across Python, JS, Java, TypeScript codebases" },
            { icon: "📊", title: "Readiness score", desc: "Get a clear 0-100 Quantum Readiness Score with severity breakdown chart" },
            { icon: "🛡️", title: "15+ vulnerabilities", desc: "Detects RSA, ECC, DH, DSA, MD5, SHA-1, RC4, DES, ECB, weak TLS, JWT flaws, weak random and more" },
            { icon: "📄", title: "3 export formats", desc: "Download PDF reports, export CSV for spreadsheets, or copy to clipboard" },
            { icon: "🎯", title: "NIST approved fixes", desc: "Every finding comes with CRYSTALS-Kyber or Dilithium migration recommendation" },
            { icon: "💾", title: "Scan history", desc: "Sign in with Google to save and track all your past scans over time" },
          ].map((f, i) => (
            <div key={i} style={{ background: card, borderRadius: 16, padding: 28, border: `1px solid ${border}` }}>
              <div style={{ fontSize: 28, marginBottom: 12 }}>{f.icon}</div>
              <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 8, color: text }}>{f.title}</div>
              <div style={{ fontSize: 13, color: muted, lineHeight: 1.6 }}>{f.desc}</div>
            </div>
          ))}
        </div>
      </div>

      <div id="how" style={{ maxWidth: 700, margin: "0 auto 80px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: "clamp(24px, 4vw, 36px)", marginBottom: 8, color: text }}>How it works</h2>
        <p style={{ textAlign: "center", color: muted, marginBottom: 48, fontSize: 16 }}>Five steps to quantum-proof your codebase</p>
        <div style={{ position: "relative" }}>
          <div style={{ position: "absolute", left: 20, top: 0, bottom: 0, width: 2, background: border }}></div>
          {[
            { icon: "📁", title: "Upload or paste URL", desc: "ZIP your project or paste a GitHub URL. Supports Python, JavaScript, Java and TypeScript." },
            { icon: "🔍", title: "Scanner runs", desc: "Line-by-line analysis detects 15+ vulnerability types including RSA, ECC, DES, JWT flaws and weak random." },
            { icon: "⚠️", title: "Vulnerabilities flagged", desc: "Every issue shown with exact file, line number, severity and vulnerable code snippet." },
            { icon: "📊", title: "Review findings", desc: "Filter by severity, search files, see grouped findings per file with severity chart." },
            { icon: "📄", title: "Export your report", desc: "Download PDF or CSV, copy to clipboard, or share on Twitter." },
          ].map((s, i) => (
            <div key={i} style={{ display: "flex", gap: 24, marginBottom: 32 }}>
              <div style={{ width: 42, height: 42, borderRadius: "50%", background: "#534AB7", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20, flexShrink: 0, zIndex: 1 }}>{s.icon}</div>
              <div style={{ background: card, borderRadius: 16, padding: "20px 24px", flex: 1, border: `1px solid ${border}` }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8, flexWrap: "wrap" }}>
                  <span style={{ background: "#534AB722", color: "#7F77DD", padding: "2px 10px", borderRadius: 20, fontSize: 12, fontWeight: 600 }}>Step {i + 1}</span>
                  <span style={{ fontSize: 15, fontWeight: 600, color: text }}>{s.title}</span>
                </div>
                <div style={{ fontSize: 13, color: muted, lineHeight: 1.6 }}>{s.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div id="pricing" style={{ maxWidth: 900, margin: "0 auto 80px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: "clamp(24px, 4vw, 36px)", marginBottom: 8, color: text }}>Simple pricing</h2>
        <p style={{ textAlign: "center", color: muted, marginBottom: 48, fontSize: 16 }}>Start free. Upgrade when you're ready.</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 20 }}>
          {[
            { name: "Free", price: "$0", period: "forever", desc: "For individual developers", features: ["CLI tool", "Web dashboard", "ZIP upload", "GitHub URL scan", "PDF & CSV reports", "Scan history", "10 scans/day"], cta: "Start Free", highlight: false },
            { name: "Pro", price: "$29", period: "/month", desc: "For security teams", features: ["Everything in Free", "Unlimited scans", "AI-powered reports", "Unlimited file size", "Priority support", "Team members", "API access"], cta: "Coming Soon", highlight: true },
            { name: "Enterprise", price: "Custom", period: "", desc: "For large organizations", features: ["Everything in Pro", "CI/CD integration", "SSO login", "Custom reports", "Dedicated support", "SOC2 compliance"], cta: "Contact Us", highlight: false },
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

      <div style={{ maxWidth: 700, margin: "0 auto 80px", padding: "0 20px" }}>
        <h2 style={{ textAlign: "center", fontSize: "clamp(24px, 4vw, 36px)", marginBottom: 48, color: text }}>FAQ</h2>
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

      <div style={{ textAlign: "center", padding: "80px 20px", background: card, borderTop: `1px solid ${border}`, borderBottom: `1px solid ${border}` }}>
        <h2 style={{ fontSize: "clamp(24px, 4vw, 40px)", marginBottom: 16, color: text }}>Ready to quantum-proof your code?</h2>
        <p style={{ color: muted, marginBottom: 40, fontSize: 16, maxWidth: 500, margin: "0 auto 40px" }}>Join developers and security teams protecting their code from the quantum threat.</p>
        <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
          <a href="#scan" style={{ background: "#534AB7", color: "#fff", padding: "16px 40px", borderRadius: 10, textDecoration: "none", fontSize: 16, fontWeight: 600 }}>Start Free Scan →</a>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ background: "transparent", color: text, padding: "16px 40px", borderRadius: 10, textDecoration: "none", fontSize: 16, border: `1px solid ${border}` }}>GitHub</a>
        </div>
      </div>

      <Scanner darkMode={darkMode} user={user} />
      <UserProfile user={user} darkMode={darkMode} />
      <ScanHistory user={user} darkMode={darkMode} />

      <div style={{ textAlign: "center", padding: "32px 20px", borderTop: `1px solid ${border}`, color: muted, fontSize: 13 }}>
        <div style={{ marginBottom: 12, display: "flex", justifyContent: "center", gap: 24, flexWrap: "wrap" }}>
          <a href="#features" style={{ color: muted, textDecoration: "none" }}>Features</a>
          <a href="#how" style={{ color: muted, textDecoration: "none" }}>How it works</a>
          <a href="#pricing" style={{ color: muted, textDecoration: "none" }}>Pricing</a>
          <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ color: muted, textDecoration: "none" }}>GitHub</a>
        </div>
        <div>QuantumGuard by MANGSRI — Open Source Quantum Security Scanner — 2026</div>
      </div>
    </div>
  );
}