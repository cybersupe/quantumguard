import React, { useState, useEffect, useRef } from "react";

/* ═══════════════════════════════════════════════════════
   QUANTUMGUARD — Premium Investor-Level SaaS Landing
   Upgraded from existing LandingPage.jsx
   • Brand color: #22c55e  (kept as primary accent)
   • onStart prop fully preserved
   • Dashboard preview card kept & polished
   • All existing sections kept + 9 new sections added
═══════════════════════════════════════════════════════ */

const FontLink = () => (
  <style>{`
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600;9..40,700;9..40,800&family=DM+Mono:wght@400;500&display=swap');
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    ::selection { background: #22c55e22; }
    @keyframes fadeUp   { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }
    @keyframes pulse    { 0%,100%{opacity:1;} 50%{opacity:.45;} }
    @keyframes scanMove { 0%{top:0%} 100%{top:102%} }
    @keyframes dropIn   { from{opacity:0;transform:translateX(-50%) translateY(-8px);} to{opacity:1;transform:translateX(-50%) translateY(0);} }
    .qg-nav-link:hover  { color: #22c55e !important; }
    .qg-btn-primary     { background:#22c55e; color:#fff; border:none; border-radius:10px; padding:11px 22px; font-size:.875rem; font-weight:600; cursor:pointer; font-family:inherit; letter-spacing:-.01em; transition:all .2s; display:inline-flex; align-items:center; gap:7px; }
    .qg-btn-primary:hover { background:#16a34a; transform:translateY(-1px); box-shadow:0 8px 24px rgba(34,197,94,.28); }
    .qg-btn-outline     { background:transparent; color:#0f1923; border:1.5px solid #d1d5db; border-radius:10px; padding:11px 22px; font-size:.875rem; font-weight:500; cursor:pointer; font-family:inherit; letter-spacing:-.01em; transition:all .2s; display:inline-flex; align-items:center; gap:7px; }
    .qg-btn-outline:hover { border-color:#22c55e; color:#22c55e; }
    .qg-card { background:#fff; border:1px solid #e8edf3; border-radius:18px; box-shadow:0 2px 12px rgba(0,0,0,.04); }
    .qg-hover-row:hover { background:#f8fafc !important; }
    .qg-feature-card:hover { transform:translateY(-3px); box-shadow:0 12px 32px rgba(0,0,0,.08); }
    .qg-feature-card { transition:all .25s; }
    .qg-plan-card:hover { transform:translateY(-2px); }
    .qg-plan-card { transition:all .25s; }
    .scan-beam { position:absolute; left:0; right:0; height:2px; background:linear-gradient(90deg,transparent,#22c55e,transparent); animation:scanMove 1.6s linear infinite; pointer-events:none; }
    @media (max-width:900px) {
      .qg-hero-grid { grid-template-columns: 1fr !important; }
      .qg-features-grid { grid-template-columns: repeat(2,1fr) !important; }
      .qg-stats-grid { grid-template-columns: repeat(3,1fr) !important; }
      .qg-pricing-grid { grid-template-columns: repeat(2,1fr) !important; }
      .qg-how-grid { grid-template-columns: repeat(2,1fr) !important; }
    }
    @media (max-width:600px) {
      .qg-features-grid { grid-template-columns: 1fr !important; }
      .qg-stats-grid { grid-template-columns: repeat(2,1fr) !important; }
      .qg-pricing-grid { grid-template-columns: 1fr !important; }
      .qg-how-grid { grid-template-columns: 1fr !important; }
      .qg-nav-links { display: none !important; }
    }
  `}</style>
);

const ShieldIcon = ({ size = 16, color = "#fff" }) => (
  <svg width={size} height={size} fill="none" viewBox="0 0 24 24" stroke={color} strokeWidth="2.2">
    <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" />
  </svg>
);

const GithubIcon = ({ size = 15 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
  </svg>
);

const ChevronDown = ({ open }) => (
  <svg width="11" height="11" viewBox="0 0 12 12" fill="none"
    style={{ transform: open ? "rotate(180deg)" : "none", transition: "transform .2s", opacity: .5 }}>
    <path d="M2 4l4 4 4-4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const CheckIcon = () => (
  <svg width="14" height="14" viewBox="0 0 16 16" fill="none" style={{ flexShrink: 0 }}>
    <path d="M3 8l3.5 3.5L13 4" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const Chip = ({ type, label }) => {
  const map = {
    critical: { bg: "#fef2f2", color: "#dc2626" },
    high:     { bg: "#fffbeb", color: "#d97706" },
    medium:   { bg: "#fefce8", color: "#b45309" },
  };
  const s = map[type] || map.medium;
  return (
    <span style={{ padding:"2px 8px", borderRadius:"5px", fontSize:".6rem", fontWeight:700,
      letterSpacing:".04em", background:s.bg, color:s.color, flexShrink:0, border:`1px solid ${s.color}30` }}>
      {label}
    </span>
  );
};

/* ── Nav data ── */
const NAV_GROUPS = [
  { label: "Product", items: [
    { icon:"⬡", title:"Quantum Scanner",       desc:"AST-level crypto vulnerability scanning" },
    { icon:"⛨", title:"CI/CD Security Gate",   desc:"Block weak crypto before it ships" },
    { icon:"◈", title:"TLS Analyzer",           desc:"Audit TLS configs end-to-end" },
    { icon:"⟳", title:"Crypto Agility Checker", desc:"Measure migration readiness" },
    { icon:"▦", title:"Executive Reports",      desc:"Board-ready risk summaries" },
  ]},
  { label: "Solutions", items: [
    { icon:"{}", title:"Developers",        desc:"Shift-left crypto hygiene" },
    { icon:"⚿",  title:"Security Teams",    desc:"Enterprise vulnerability management" },
    { icon:"⚙",  title:"DevOps",            desc:"Pipeline-native enforcement" },
    { icon:"◈",  title:"CISOs",             desc:"Quantum risk posture dashboards" },
    { icon:"⬡",  title:"Financial Services",desc:"FIPS & PQC compliance" },
    { icon:"✚",  title:"Healthcare",        desc:"HIPAA + quantum-safe data" },
    { icon:"⛨",  title:"Government",        desc:"NIST FIPS 203/204/205 readiness" },
  ]},
  { label: "Platform", items: [
    { icon:"◉", title:"Overview",       desc:"How QuantumGuard works" },
    { icon:"⌥", title:"API",            desc:"REST & GraphQL endpoints" },
    { icon:"⧉", title:"GitHub Actions", desc:"One-line workflow integration" },
    { icon:"◈", title:"Developer Docs", desc:"Guides, references, SDKs" },
    { icon:"⬡", title:"Integrations",   desc:"Jira, Slack, ServiceNow & more" },
  ]},
  { label: "Pricing", items: [
    { icon:"○", title:"Free",       desc:"Up to 3 scans/month" },
    { icon:"◈", title:"Pro",        desc:"$49/mo — unlimited scans" },
    { icon:"⬡", title:"Team",       desc:"$199/mo — org-wide coverage" },
    { icon:"⛨", title:"Enterprise", desc:"Custom SLAs & on-prem" },
  ]},
  { label: "Resources", items: [
    { icon:"✍", title:"Blog",           desc:"PQC research & news" },
    { icon:"◈", title:"Documentation",  desc:"Full product reference" },
    { icon:"⬡", title:"PQC Guide",      desc:"Post-quantum explained simply" },
    { icon:"⛨", title:"NIST Standards", desc:"FIPS 203, 204, 205 breakdown" },
    { icon:"◉", title:"Customer Stories",desc:"Real migration case studies" },
  ]},
];

function NavDropdown({ item, isOpen, onToggle }) {
  const ref = useRef(null);
  useEffect(() => {
    if (!isOpen) return;
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) onToggle(null); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [isOpen, onToggle]);

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button onClick={() => onToggle(item.label)} className="qg-nav-link"
        style={{ background:"none", border:"none", cursor:"pointer", display:"flex", alignItems:"center", gap:4,
          fontSize:".875rem", fontWeight:500, color:isOpen?"#22c55e":"#374151", padding:"8px 11px",
          borderRadius:8, fontFamily:"inherit", letterSpacing:"-.01em", transition:"color .15s" }}>
        {item.label} <ChevronDown open={isOpen} />
      </button>
      {isOpen && (
        <div style={{ position:"absolute", top:"calc(100% + 10px)", left:"50%", transform:"translateX(-50%)",
          background:"rgba(255,255,255,.97)", backdropFilter:"blur(20px)",
          border:"1px solid rgba(34,197,94,.15)", borderRadius:16,
          boxShadow:"0 20px 56px rgba(0,0,0,.11),0 4px 16px rgba(34,197,94,.07)",
          padding:8, minWidth:272, zIndex:1000, animation:"dropIn .17s ease-out" }}>
          {item.items.map(sub => (
            <div key={sub.title}
              style={{ display:"flex", alignItems:"flex-start", gap:11, padding:"10px 13px", borderRadius:10, cursor:"pointer", transition:"background .13s" }}
              onMouseEnter={e => e.currentTarget.style.background = "rgba(34,197,94,.07)"}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
              <span style={{ fontSize:17, lineHeight:1, marginTop:2, color:"#22c55e", flexShrink:0 }}>{sub.icon}</span>
              <div>
                <div style={{ fontSize:13, fontWeight:600, color:"#0f1923", letterSpacing:"-.01em" }}>{sub.title}</div>
                <div style={{ fontSize:12, color:"#6b7280", marginTop:2, lineHeight:1.4 }}>{sub.desc}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function LandingPage({ onStart }) {
  const [openNav, setOpenNav]     = useState(null);
  const [scanning, setScanning]   = useState(false);
  const [scanned,  setScanned]    = useState(false);
  const [repoInput, setRepoInput] = useState("github.com/your-org/your-repo");

  function runScan() {
    setScanning(true); setScanned(false);
    setTimeout(() => { setScanning(false); setScanned(true); }, 2200);
  }

  const C = "#22c55e"; // brand green

  return (
    <div style={{ minHeight:"100vh", background:"#f8fafc", fontFamily:"'DM Sans',system-ui,sans-serif", color:"#0f1923", overflowX:"hidden" }}>
      <FontLink />

      {/* ════════════ NAVBAR ════════════ */}
      <nav style={{ position:"sticky", top:0, zIndex:500, background:"rgba(248,250,252,.9)", backdropFilter:"blur(20px)", borderBottom:"1px solid rgba(0,0,0,.07)", padding:"0 32px" }}>
        <div style={{ maxWidth:1200, margin:"0 auto", display:"flex", alignItems:"center", height:60, gap:4 }}>

          {/* Logo */}
          <div style={{ display:"flex", alignItems:"center", gap:8, marginRight:20, flexShrink:0, textDecoration:"none" }}>
            <div style={{ width:30, height:30, background:"linear-gradient(135deg,#22c55e,#15803d)", borderRadius:8, display:"flex", alignItems:"center", justifyContent:"center", boxShadow:"0 4px 12px rgba(34,197,94,.28)" }}>
              <ShieldIcon size={15} />
            </div>
            <span style={{ fontWeight:800, fontSize:"1rem", letterSpacing:"-.03em" }}>
              Quantum<span style={{ color:C }}>Guard</span>
            </span>
          </div>

          {/* Dropdowns */}
          <div className="qg-nav-links" style={{ display:"flex", alignItems:"center", flex:1 }}>
            {NAV_GROUPS.map(g => (
              <NavDropdown key={g.label} item={g} isOpen={openNav === g.label} onToggle={setOpenNav} />
            ))}
          </div>

          {/* Right controls */}
          <div style={{ display:"flex", alignItems:"center", gap:8, flexShrink:0, marginLeft:"auto" }}>
            <div style={{ display:"flex", alignItems:"center", gap:6, fontSize:".7rem", fontWeight:600, color:"#15803d", letterSpacing:".04em", marginRight:4 }}>
              <span style={{ width:7, height:7, borderRadius:"50%", background:C, boxShadow:"0 0 0 3px rgba(34,197,94,.2)", display:"inline-block", animation:"pulse 2s infinite" }} />
              API ONLINE
            </div>
            <button className="qg-btn-outline" onClick={() => window.open("https://github.com/cybersupe/quantumguard","_blank")}>
              <GithubIcon /> GitHub
            </button>
            <button className="qg-btn-primary" onClick={onStart}>Start Free Scan</button>
          </div>
        </div>
      </nav>

      {/* ════════════ HERO ════════════ */}
      <section style={{ background:"linear-gradient(135deg,#f0fdf4 0%,#f8fafc 45%,#eff6ff 100%)", padding:"84px 32px 72px", position:"relative", overflow:"hidden" }}>
        <div style={{ position:"absolute",top:-180,right:-180,width:520,height:520,borderRadius:"50%",background:"radial-gradient(circle,rgba(34,197,94,.07) 0%,transparent 70%)",pointerEvents:"none" }} />
        <div style={{ position:"absolute",bottom:-80,left:-80,width:360,height:360,borderRadius:"50%",background:"radial-gradient(circle,rgba(59,130,246,.05) 0%,transparent 70%)",pointerEvents:"none" }} />

        <div className="qg-hero-grid" style={{ maxWidth:1200, margin:"0 auto", display:"grid", gridTemplateColumns:"1fr 1.05fr", gap:56, alignItems:"center" }}>

          {/* LEFT */}
          <div style={{ animation:"fadeUp .65s ease-out both" }}>
            <div style={{ display:"inline-flex",alignItems:"center",gap:8,background:"rgba(34,197,94,.1)",border:"1px solid rgba(34,197,94,.22)",borderRadius:100,padding:"5px 14px",marginBottom:28 }}>
              <ShieldIcon size={11} color="#15803d" />
              <span style={{ fontSize:".7rem",fontWeight:700,color:"#15803d",letterSpacing:".05em" }}>NIST FIPS 203 / 204 / 205 ALIGNED</span>
            </div>

            <h1 style={{ fontSize:"clamp(2rem,4.2vw,3.2rem)", fontWeight:800, lineHeight:1.1, letterSpacing:"-.04em", marginBottom:20 }}>
              Find weak encryption<br/>before <span style={{ color:C }}>quantum computers</span><br/>break it
            </h1>

            <p style={{ fontSize:"1.05rem", color:"#4b5563", lineHeight:1.68, maxWidth:430, marginBottom:32 }}>
              Scan your codebase for RSA, ECC, MD5, SHA-1, weak TLS, and quantum-vulnerable cryptography.
              Get a Quantum Readiness Score and NIST-aligned migration guidance in seconds.
            </p>

            {/* Scan input */}
            <div style={{ display:"flex", background:"#fff", border:"1.5px solid #e2e8f0", borderRadius:12, overflow:"hidden", boxShadow:"0 4px 20px rgba(0,0,0,.07)", maxWidth:480, marginBottom:22 }}>
              <input value={repoInput} onChange={e => setRepoInput(e.target.value)}
                style={{ flex:1,border:"none",outline:"none",padding:"13px 16px",fontSize:".8rem",fontFamily:"'DM Mono',monospace",color:"#374151",background:"transparent" }} />
              <button className="qg-btn-primary" style={{ borderRadius:0,padding:"13px 20px",fontSize:".8rem" }} onClick={runScan} disabled={scanning}>
                {scanning ? "Scanning…" : "Scan →"}
              </button>
            </div>

            <div style={{ display:"flex",gap:12,flexWrap:"wrap",marginBottom:32 }}>
              <button className="qg-btn-primary" style={{ padding:"12px 24px",fontSize:".93rem" }} onClick={onStart}>
                <ShieldIcon size={14} /> Run a Scan Now
              </button>
              <button className="qg-btn-outline" style={{ padding:"12px 24px",fontSize:".93rem" }}>▷ Try Demo</button>
              <button className="qg-btn-outline" style={{ padding:"12px 24px",fontSize:".93rem" }}>Contact Sales</button>
            </div>

            <div style={{ display:"flex",gap:18,flexWrap:"wrap" }}>
              {["✅ Accurate Results","</> Developer Friendly","🛡 Privacy Focused","⚡ Fast & Reliable"].map(t => (
                <span key={t} style={{ fontSize:".8rem",fontWeight:500,color:"#6b7280" }}>{t}</span>
              ))}
            </div>
          </div>

          {/* RIGHT — original dashboard card, polished */}
          <div style={{ animation:"fadeUp .7s .1s ease-out both" }}>
            <div className="qg-card" style={{ overflow:"hidden", boxShadow:"0 12px 48px rgba(0,0,0,.1),0 2px 8px rgba(0,0,0,.06)", borderRadius:20 }}>

              {/* Window chrome */}
              <div style={{ background:"#f7fbf9",borderBottom:"1px solid #e2ede7",padding:"12px 18px",display:"flex",alignItems:"center",gap:8,fontSize:".8rem",fontWeight:600 }}>
                {["#ff5f57","#febc2e","#28c840"].map(c => <div key={c} style={{ width:8,height:8,borderRadius:"50%",background:c }} />)}
                <div style={{ marginLeft:6,display:"flex",alignItems:"center",gap:6 }}>
                  <ShieldIcon size={13} color={C} />
                  <span>Quantum<span style={{ color:C }}>Guard</span></span>
                </div>
                <span style={{ marginLeft:"auto",color:"#8aa594",fontSize:".78rem",fontWeight:600 }}>Dashboard</span>
              </div>

              <div style={{ display:"grid",gridTemplateColumns:"155px 1fr" }}>
                {/* Sidebar */}
                <div style={{ borderRight:"1px solid #e2ede7",padding:"14px 0" }}>
                  {[{label:"Overview",active:true},{label:"Scans"},{label:"Repositories"},{label:"Agility Checker"},{label:"API Keys"},{label:"Reports"},{label:"Settings"}].map(({label,active}) => (
                    <div key={label} style={{ display:"flex",alignItems:"center",gap:8,padding:"8px 16px",fontSize:".78rem",fontWeight:active?600:500,color:active?"#15803d":"#5a7060",background:active?"#e8f5ee":"transparent",cursor:"pointer" }}>
                      {label}
                    </div>
                  ))}
                </div>

                {/* Dashboard content */}
                <div style={{ padding:18 }}>
                  <div style={{ fontSize:".68rem",fontWeight:700,color:"#8aa594",letterSpacing:".06em",textTransform:"uppercase",marginBottom:12 }}>Security Overview</div>

                  <div style={{ display:"grid",gridTemplateColumns:"125px 1fr",gap:12,marginBottom:16 }}>
                    {/* Score ring */}
                    <div style={{ background:"#f7fbf9",borderRadius:12,padding:12,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center" }}>
                      <div style={{ position:"relative",width:70,height:70 }}>
                        <svg width="70" height="70" viewBox="0 0 70 70" style={{ transform:"rotate(-90deg)" }}>
                          <circle cx="35" cy="35" r="28" fill="none" stroke="#e2ede7" strokeWidth="6" />
                          <circle cx="35" cy="35" r="28" fill="none" stroke="#d97706" strokeWidth="6"
                            strokeDasharray="175.9" strokeDashoffset="47.6" strokeLinecap="round" />
                        </svg>
                        <div style={{ position:"absolute",inset:0,display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center" }}>
                          <span style={{ fontSize:"1.15rem",fontWeight:800,lineHeight:1 }}>72</span>
                          <span style={{ fontSize:".55rem",color:"#8aa594" }}>/100</span>
                        </div>
                      </div>
                      <div style={{ fontSize:".62rem",fontWeight:700,color:"#d97706",marginTop:4 }}>Medium Risk</div>
                    </div>

                    {/* Vuln counts */}
                    <div style={{ background:"#f7fbf9",borderRadius:12,padding:12,display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8 }}>
                      {[{count:12,label:"Critical",color:"#dc2626"},{count:28,label:"High",color:"#d97706"},{count:15,label:"Medium",color:"#ca8a04"},{count:8,label:"Low",color:"#059669"}].map(({count,label,color}) => (
                        <div key={label} style={{ display:"flex",flexDirection:"column",alignItems:"center",gap:3 }}>
                          <span style={{ fontSize:"1rem",fontWeight:800,color }}>{count}</span>
                          <span style={{ fontSize:".58rem",color:"#8aa594",fontWeight:500 }}>{label}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Recent scan */}
                  <div style={{ marginBottom:12 }}>
                    <div style={{ display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8 }}>
                      <span style={{ fontSize:".68rem",fontWeight:700,color:"#8aa594",letterSpacing:".06em",textTransform:"uppercase" }}>Recent Scan</span>
                      <a href="#" style={{ fontSize:".63rem",fontWeight:600,color:C,textDecoration:"none" }}>View All</a>
                    </div>
                    <div style={{ background:"#f7fbf9",borderRadius:10,padding:"10px 12px",display:"flex",alignItems:"center",gap:10 }}>
                      <div style={{ width:26,height:26,borderRadius:6,background:"#0f1923",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0 }}>
                        <GithubIcon size={13} />
                      </div>
                      <div style={{ flex:1 }}>
                        <div style={{ fontSize:".73rem",fontWeight:700 }}>cybersupe/quantumguard</div>
                        <div style={{ fontSize:".63rem",color:"#8aa594" }}>Scan completed 2 minutes ago</div>
                      </div>
                      <div style={{ textAlign:"center",marginRight:8 }}>
                        <div style={{ fontSize:".78rem",fontWeight:700 }}>312</div>
                        <div style={{ fontSize:".58rem",color:"#8aa594" }}>Files</div>
                      </div>
                      <div style={{ textAlign:"center",marginRight:8 }}>
                        <div style={{ fontSize:".78rem",fontWeight:700 }}>1,428</div>
                        <div style={{ fontSize:".58rem",color:"#8aa594" }}>Issues</div>
                      </div>
                      <button style={{ background:"transparent",border:"1.5px solid #e2ede7",color:"#0f1923",borderRadius:7,padding:"5px 9px",fontSize:".66rem",fontWeight:600,cursor:"pointer",whiteSpace:"nowrap",fontFamily:"inherit" }}>
                        View Report →
                      </button>
                    </div>
                  </div>

                  {/* Top issues */}
                  <div>
                    <div style={{ display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8 }}>
                      <span style={{ fontSize:".68rem",fontWeight:700,color:"#8aa594",letterSpacing:".06em",textTransform:"uppercase" }}>Top Issues</span>
                      <a href="#" style={{ fontSize:".63rem",fontWeight:600,color:C,textDecoration:"none" }}>View All</a>
                    </div>
                    {[
                      { type:"critical",label:"CRITICAL",name:"RSA encryption usage detected",         file:"auth/encryption.js:45",lang:"JavaScript" },
                      { type:"high",    label:"HIGH",    name:"SHA-1 hash function detected",          file:"utils/hash.js:12",      lang:"JavaScript" },
                      { type:"medium",  label:"MEDIUM",  name:"Diffie-Hellman key exchange (small key)",file:"secure/dh.js:8",       lang:"JavaScript" },
                    ].map(({type,label,name,file,lang}) => (
                      <div key={label} style={{ display:"flex",alignItems:"center",gap:8,fontSize:".7rem",marginBottom:7 }}>
                        <Chip type={type} label={label} />
                        <span style={{ flex:1,color:"#4b5563",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }}>{name}</span>
                        <span style={{ color:"#9ca3af",fontFamily:"monospace",fontSize:".62rem",flexShrink:0 }}>{file}</span>
                        <span style={{ background:"#f7fbf9",color:"#9ca3af",padding:"1px 5px",borderRadius:4,fontSize:".58rem",flexShrink:0 }}>{lang}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Trust strip */}
        <div style={{ maxWidth:1200,margin:"48px auto 0",display:"flex",justifyContent:"center",gap:36,flexWrap:"wrap",opacity:.4 }}>
          {["SOC 2 Type II","NIST Compliant","GDPR Ready","99.9% Uptime","Zero Data Retention"].map(t => (
            <span key={t} style={{ fontSize:".68rem",fontWeight:700,letterSpacing:".06em",color:"#374151",textTransform:"uppercase" }}>{t}</span>
          ))}
        </div>
      </section>

      {/* ════════════ STATS (original, upgraded) ════════════ */}
      <section style={{ background:"#fff",borderTop:"1px solid #e8edf3",borderBottom:"1px solid #e8edf3",padding:"44px 32px" }}>
        <div className="qg-stats-grid" style={{ maxWidth:1200,margin:"0 auto",display:"grid",gridTemplateColumns:"repeat(5,1fr)",textAlign:"center",gap:24 }}>
          {[
            { val:"50+",   lbl:"Vulnerability Checks" },
            { val:"10+",   lbl:"Supported Languages" },
            { val:"99.9%", lbl:"Uptime" },
            { val:"<30s",  lbl:"Average Scan Time" },
            { val:"100%",  lbl:"Private Scanning" },
          ].map(({val,lbl}) => (
            <div key={lbl}>
              <div style={{ fontSize:"2.1rem",fontWeight:800,color:C,lineHeight:1,letterSpacing:"-.03em" }}>{val}</div>
              <div style={{ fontSize:".82rem",color:"#6b7280",marginTop:7,fontWeight:500 }}>{lbl}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ════════════ PRODUCT DEMO ════════════ */}
      <section style={{ padding:"80px 32px",background:"#f8fafc" }}>
        <div style={{ maxWidth:1100,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:44 }}>
            <div style={{ fontSize:".72rem",fontWeight:700,letterSpacing:".1em",color:C,textTransform:"uppercase",marginBottom:12 }}>Live Demo</div>
            <h2 style={{ fontSize:"clamp(1.5rem,3vw,2.3rem)",fontWeight:800,letterSpacing:"-.03em" }}>See a scan in action</h2>
          </div>
          <div className="qg-card" style={{ overflow:"hidden",boxShadow:"0 8px 40px rgba(0,0,0,.08)" }}>
            <div style={{ background:"#0f1923",padding:"13px 18px",display:"flex",alignItems:"center",gap:8 }}>
              {["#ef4444","#f59e0b","#22c55e"].map(c => <span key={c} style={{ width:11,height:11,borderRadius:"50%",background:c,display:"inline-block" }} />)}
              <span style={{ fontFamily:"DM Mono,monospace",fontSize:".73rem",color:"#4b5563",marginLeft:10 }}>quantumguard scan --repo {repoInput}</span>
            </div>
            <div style={{ background:"#0b1320",padding:28,minHeight:210,position:"relative",overflow:"hidden" }}>
              {scanning && (
                <>
                  <div className="scan-beam" />
                  <div style={{ fontFamily:"DM Mono,monospace",fontSize:".77rem",lineHeight:2.1,color:C }}>
                    <div>▸ Cloning repository… done</div>
                    <div style={{ color:"#4b5563" }}>▸ Parsing files across 12 languages…</div>
                    <div style={{ animation:"pulse 1s infinite" }}>▸ Scanning cryptographic primitives…</div>
                  </div>
                </>
              )}
              {!scanning && !scanned && (
                <div style={{ fontFamily:"DM Mono,monospace",fontSize:".77rem",lineHeight:2,color:"#4b5563" }}>
                  <div style={{ color:C }}>$ quantumguard scan --repo github.com/acme/payments-api</div>
                  <div style={{ marginTop:8 }}>→ Enter a repo above and click Scan →</div>
                </div>
              )}
              {scanned && (
                <div style={{ fontFamily:"DM Mono,monospace",fontSize:".77rem",lineHeight:2.1 }}>
                  <div style={{ color:C }}>✓ Scan complete — 1,847 files analyzed in 18.4s</div>
                  <div style={{ color:"#ef4444" }}>✗ 3 CRITICAL vulnerabilities found</div>
                  <div style={{ color:"#f97316" }}>⚠ 2 HIGH vulnerabilities found</div>
                  <div style={{ color:"#eab308" }}>◈ 1 MEDIUM vulnerability found</div>
                  <div style={{ color:"#4b5563",marginTop:4 }}>Quantum Readiness Score: 38/100 — HIGH RISK</div>
                  <div style={{ color:C,marginTop:4 }}>→ Run `quantumguard report --format pdf` to export</div>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* ════════════ RISK SCORE ════════════ */}
      <section style={{ padding:"80px 32px",background:"#fff" }}>
        <div style={{ maxWidth:1100,margin:"0 auto",display:"flex",gap:60,alignItems:"center",flexWrap:"wrap" }}>
          <div style={{ flex:"1 1 400px" }}>
            <div style={{ fontSize:".72rem",fontWeight:700,letterSpacing:".1em",color:C,textTransform:"uppercase",marginBottom:14 }}>Quantum Risk Score</div>
            <h2 style={{ fontSize:"clamp(1.5rem,3vw,2.2rem)",fontWeight:800,letterSpacing:"-.03em",marginBottom:16,lineHeight:1.2 }}>Know exactly how exposed you are</h2>
            <p style={{ color:"#6b7280",lineHeight:1.7,fontSize:".93rem",marginBottom:26 }}>
              Every scan produces a 0–100 Quantum Readiness Score — a single, board-presentable number that
              translates complex cryptographic risk into actionable NIST-aligned insight.
            </p>
            <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:14 }}>
              {[{label:"Vulnerabilities",val:"6 found"},{label:"Files Scanned",val:"1,847"},{label:"Languages",val:"12"},{label:"NIST Fixes",val:"6 ready"}].map(s => (
                <div key={s.label} className="qg-card" style={{ padding:"16px 18px" }}>
                  <div style={{ fontSize:"1.3rem",fontWeight:800,letterSpacing:"-.03em" }}>{s.val}</div>
                  <div style={{ fontSize:".72rem",color:"#9ca3af",marginTop:4,fontWeight:500 }}>{s.label}</div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ flex:"0 0 auto",display:"flex",flexDirection:"column",alignItems:"center",gap:16 }}>
            <div className="qg-card" style={{ padding:32,textAlign:"center" }}>
              <svg width="140" height="140" viewBox="0 0 140 140">
                <circle cx="70" cy="70" r="54" fill="none" stroke="#f1f5f9" strokeWidth="10" />
                <circle cx="70" cy="70" r="54" fill="none" stroke="#ef4444" strokeWidth="10"
                  strokeDasharray={`${(38/100)*(2*Math.PI*54)} ${2*Math.PI*54}`}
                  strokeDashoffset={(2*Math.PI*54)/4} strokeLinecap="round"
                  style={{ transform:"rotate(-90deg)",transformOrigin:"70px 70px" }} />
                <text x="70" y="65" textAnchor="middle" fontSize="30" fontWeight="800" fill="#0f1923" fontFamily="DM Sans,sans-serif">38</text>
                <text x="70" y="82" textAnchor="middle" fontSize="11" fill="#9ca3af" fontFamily="DM Sans,sans-serif">/ 100</text>
                <text x="70" y="98" textAnchor="middle" fontSize="11" fontWeight="700" fill="#ef4444" fontFamily="DM Sans,sans-serif">HIGH RISK</text>
              </svg>
              <div style={{ marginTop:12,fontSize:".78rem",color:"#9ca3af" }}>payments-api · just scanned</div>
            </div>
            <div style={{ display:"flex",gap:12 }}>
              {[{label:"Low Risk",color:C},{label:"Medium",color:"#eab308"},{label:"High Risk",color:"#ef4444"}].map(l => (
                <div key={l.label} style={{ display:"flex",alignItems:"center",gap:6,fontSize:".7rem",color:"#6b7280",fontWeight:500 }}>
                  <span style={{ width:8,height:8,borderRadius:"50%",background:l.color,display:"inline-block" }} />{l.label}
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ════════════ FINDINGS TABLE ════════════ */}
      <section style={{ padding:"80px 32px",background:"#f8fafc" }}>
        <div style={{ maxWidth:1100,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:44 }}>
            <div style={{ fontSize:".72rem",fontWeight:700,letterSpacing:".1em",color:C,textTransform:"uppercase",marginBottom:12 }}>Findings</div>
            <h2 style={{ fontSize:"clamp(1.5rem,3vw,2.2rem)",fontWeight:800,letterSpacing:"-.03em" }}>Every vulnerability, with a NIST fix</h2>
            <p style={{ color:"#6b7280",marginTop:12,fontSize:".9rem" }}>QuantumGuard maps every finding directly to NIST post-quantum standards.</p>
          </div>
          <div className="qg-card" style={{ overflow:"hidden" }}>
            <table style={{ width:"100%",borderCollapse:"collapse" }}>
              <thead>
                <tr style={{ background:"#f8fafc",borderBottom:"1px solid #e8edf3" }}>
                  {["Severity","Algorithm","Location","NIST Remediation"].map(h => (
                    <th key={h} style={{ textAlign:"left",padding:"13px 18px",fontSize:".66rem",fontWeight:700,color:"#9ca3af",letterSpacing:".07em",textTransform:"uppercase" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[
                  { sev:"CRITICAL",algo:"RSA-1024",    file:"auth/jwt.go:47",        nist:"Replace with ML-KEM-768 (FIPS 203)", color:"#ef4444" },
                  { sev:"CRITICAL",algo:"MD5 Hash",    file:"utils/crypto.py:112",   nist:"Migrate to SHA3-256 per SP 800-107", color:"#ef4444" },
                  { sev:"HIGH",    algo:"ECC P-192",   file:"tls/handshake.ts:89",   nist:"Upgrade to ML-DSA-65 (FIPS 204)",    color:"#f97316" },
                  { sev:"HIGH",    algo:"SHA-1 Sig",   file:"certs/verify.java:203", nist:"Replace with SLH-DSA (FIPS 205)",    color:"#f97316" },
                  { sev:"MEDIUM",  algo:"TLS 1.0",     file:"server/config.yaml:18", nist:"Enforce TLS 1.3 minimum",            color:"#eab308" },
                ].map((f,i) => (
                  <tr key={i} className="qg-hover-row" style={{ borderBottom:"1px solid #f1f5f9" }}>
                    <td style={{ padding:"13px 18px" }}>
                      <span style={{ background:f.color+"18",color:f.color,border:`1px solid ${f.color}38`,borderRadius:6,padding:"3px 9px",fontSize:".63rem",fontWeight:700,letterSpacing:".05em" }}>{f.sev}</span>
                    </td>
                    <td style={{ padding:"13px 18px",fontFamily:"DM Mono,monospace",fontSize:".78rem",fontWeight:500 }}>{f.algo}</td>
                    <td style={{ padding:"13px 18px",fontFamily:"DM Mono,monospace",fontSize:".7rem",color:"#6b7280" }}>{f.file}</td>
                    <td style={{ padding:"13px 18px",fontSize:".8rem",color:"#15803d",fontWeight:500 }}>{f.nist}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ textAlign:"center",marginTop:22 }}>
            <button className="qg-btn-primary">View Full Report Sample →</button>
          </div>
        </div>
      </section>

      {/* ════════════ FEATURES (original 4, upgraded) ════════════ */}
      <section style={{ padding:"80px 32px",background:"#fff" }}>
        <div style={{ maxWidth:1200,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:44 }}>
            <div style={{ fontSize:".72rem",fontWeight:700,letterSpacing:".1em",color:C,textTransform:"uppercase",marginBottom:12 }}>Features</div>
            <h2 style={{ fontSize:"clamp(1.5rem,3vw,2.2rem)",fontWeight:800,letterSpacing:"-.03em" }}>Everything you need to go quantum-safe</h2>
          </div>
          <div className="qg-features-grid" style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:22 }}>
            {[
              { icon:"🛡", title:"Quantum Vulnerability Scanner", desc:"Detects RSA, ECC, DH, DSA, MD5, SHA-1 and more — patterns broken by quantum computer attacks." },
              { icon:"</>",title:"Developer Friendly",            desc:"Easy-to-integrate API, clear reports, and actionable fix recommendations mapped to NIST standards." },
              { icon:"🔒", title:"Private & Secure",              desc:"Your code never leaves your system. Scans are private, secure, and fully confidential by design." },
              { icon:"⚡", title:"Fast & Reliable",               desc:"Get results in seconds with our powerful scanning engine and real-time analysis pipeline." },
            ].map(({icon,title,desc}) => (
              <div key={title} className="qg-card qg-feature-card" style={{ padding:"28px 24px" }}>
                <div style={{ width:44,height:44,borderRadius:11,background:"rgba(34,197,94,.1)",display:"flex",alignItems:"center",justifyContent:"center",marginBottom:16,fontSize:20 }}>{icon}</div>
                <h3 style={{ fontSize:".92rem",fontWeight:700,marginBottom:8,letterSpacing:"-.01em" }}>{title}</h3>
                <p style={{ fontSize:".82rem",color:"#6b7280",lineHeight:1.65 }}>{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════ HOW IT WORKS ════════════ */}
      <section style={{ padding:"80px 32px",background:"#f8fafc" }}>
        <div style={{ maxWidth:1100,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div style={{ fontSize:".72rem",fontWeight:700,letterSpacing:".1em",color:C,textTransform:"uppercase",marginBottom:12 }}>How It Works</div>
            <h2 style={{ fontSize:"clamp(1.5rem,3vw,2.2rem)",fontWeight:800,letterSpacing:"-.03em" }}>Quantum-safe in four steps</h2>
          </div>
          <div className="qg-how-grid" style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:22 }}>
            {[
              { n:"01",title:"Connect your repo",   body:"GitHub, GitLab, Bitbucket or upload a ZIP. Zero config required." },
              { n:"02",title:"Deep crypto scan",    body:"AST-level analysis across 30+ languages detects every vulnerable primitive." },
              { n:"03",title:"Risk score & report", body:"Receive a Quantum Readiness Score with NIST-aligned remediation steps." },
              { n:"04",title:"Enforce in CI/CD",    body:"Block merges that introduce quantum-vulnerable code automatically." },
            ].map(s => (
              <div key={s.n} className="qg-card" style={{ padding:"28px 24px" }}>
                <div style={{ fontSize:".66rem",fontWeight:800,color:C,letterSpacing:".12em",marginBottom:14 }}>{s.n}</div>
                <h3 style={{ fontSize:".92rem",fontWeight:700,letterSpacing:"-.01em",marginBottom:10 }}>{s.title}</h3>
                <p style={{ fontSize:".82rem",color:"#6b7280",lineHeight:1.65 }}>{s.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════ WHY POST-QUANTUM ════════════ */}
      <section style={{ padding:"80px 32px",background:"#fff" }}>
        <div style={{ maxWidth:1100,margin:"0 auto",display:"flex",gap:56,alignItems:"center",flexWrap:"wrap" }}>
          <div style={{ flex:"1 1 420px" }}>
            <div style={{ fontSize:".72rem",fontWeight:700,letterSpacing:".1em",color:C,textTransform:"uppercase",marginBottom:14 }}>The Quantum Threat</div>
            <h2 style={{ fontSize:"clamp(1.5rem,3vw,2.2rem)",fontWeight:800,letterSpacing:"-.03em",lineHeight:1.2,marginBottom:16 }}>
              RSA-2048 breaks in hours.<br/><span style={{ color:C }}>Are you ready?</span>
            </h2>
            <p style={{ color:"#6b7280",lineHeight:1.7,fontSize:".93rem",marginBottom:16 }}>
              A cryptographically relevant quantum computer running Shor's algorithm can break RSA and ECC —
              the backbone of HTTPS, JWT tokens, and TLS — in hours, not millennia.
            </p>
            <p style={{ color:"#6b7280",lineHeight:1.7,fontSize:".93rem",marginBottom:26 }}>
              NIST finalized three post-quantum standards in 2024 (FIPS 203, 204, 205). Harvest-now-decrypt-later
              attacks mean your data is already at risk.
            </p>
            <button className="qg-btn-primary">Read the PQC Guide →</button>
          </div>
          <div style={{ flex:"1 1 280px",display:"grid",gridTemplateColumns:"1fr 1fr",gap:14 }}>
            {[
              { stat:"2030",     label:"Estimated CRQC arrival",                     color:"#ef4444" },
              { stat:"~10M",     label:"Lines of vulnerable code in avg enterprise",  color:"#f97316" },
              { stat:"FIPS 203", label:"ML-KEM replaces RSA/ECC key exchange",        color:C },
              { stat:"FIPS 205", label:"SLH-DSA replaces SHA-1/RSA signatures",       color:"#3b82f6" },
            ].map(s => (
              <div key={s.stat} className="qg-card" style={{ padding:"20px 16px" }}>
                <div style={{ fontSize:"1.2rem",fontWeight:800,color:s.color,letterSpacing:"-.03em" }}>{s.stat}</div>
                <div style={{ fontSize:".72rem",color:"#6b7280",marginTop:6,lineHeight:1.5 }}>{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════ CI/CD GATE ════════════ */}
      <section style={{ padding:"80px 32px",background:"linear-gradient(135deg,#0f1923 0%,#0d2a1a 100%)" }}>
        <div style={{ maxWidth:1100,margin:"0 auto",display:"flex",gap:56,alignItems:"center",flexWrap:"wrap" }}>
          <div style={{ flex:"1 1 380px" }}>
            <div style={{ fontSize:".72rem",fontWeight:700,letterSpacing:".1em",color:"#4ade80",textTransform:"uppercase",marginBottom:14 }}>CI/CD Security Gate</div>
            <h2 style={{ fontSize:"clamp(1.5rem,3vw,2.2rem)",fontWeight:800,letterSpacing:"-.03em",color:"#fff",lineHeight:1.2,marginBottom:16 }}>
              Block weak crypto<br/>before it ships
            </h2>
            <p style={{ color:"#9ca3af",lineHeight:1.7,fontSize:".93rem",marginBottom:26 }}>
              One line in your GitHub Actions workflow. QuantumGuard scans every PR and fails the build
              if quantum-vulnerable cryptography is introduced — before it reaches production.
            </p>
            <div style={{ display:"flex",gap:12,flexWrap:"wrap" }}>
              <button className="qg-btn-primary">View GitHub Action</button>
              <button style={{ background:"transparent",border:"1.5px solid rgba(255,255,255,.18)",color:"#fff",padding:"11px 22px",borderRadius:10,fontSize:".875rem",cursor:"pointer",fontFamily:"inherit",fontWeight:500 }}>
                See all integrations
              </button>
            </div>
          </div>
          <div style={{ flex:"1 1 360px" }}>
            <div style={{ background:"#0b1320",borderRadius:16,border:"1px solid rgba(34,197,94,.15)",overflow:"hidden" }}>
              <div style={{ background:"#111827",padding:"12px 18px",display:"flex",alignItems:"center",gap:8 }}>
                {[0,1,2].map(i => <span key={i} style={{ width:10,height:10,borderRadius:"50%",background:"#374151",display:"inline-block" }} />)}
                <span style={{ fontFamily:"DM Mono,monospace",fontSize:".7rem",color:"#4b5563",marginLeft:10 }}>.github/workflows/security.yml</span>
              </div>
              <div style={{ padding:22,fontFamily:"DM Mono,monospace",fontSize:".73rem",lineHeight:2.1 }}>
                <div style={{ color:"#6b7280" }}># QuantumGuard CI/CD Gate</div>
                <div style={{ color:"#7dd3fc" }}>- name: <span style={{ color:"#a3e635" }}>QuantumGuard Scan</span></div>
                <div style={{ color:"#7dd3fc",paddingLeft:16 }}>uses: <span style={{ color:"#fbbf24" }}>quantumguard-io/action@v2</span></div>
                <div style={{ color:"#7dd3fc",paddingLeft:16 }}>with:</div>
                <div style={{ color:"#94a3b8",paddingLeft:32 }}>fail_on: <span style={{ color:"#f97316" }}>critical,high</span></div>
                <div style={{ color:"#94a3b8",paddingLeft:32 }}>nist_mode: <span style={{ color:C }}>true</span></div>
                <div style={{ color:"#94a3b8",paddingLeft:32 }}>token: <span style={{ color:"#a78bfa" }}>${"{{ secrets.QG_TOKEN }}"}</span></div>
                <div style={{ marginTop:6,color:C }}>✓ Scan passed — 0 critical findings</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ════════════ TRUST / LIMITATIONS ════════════ */}
      <section style={{ padding:"72px 32px",background:"#f8fafc" }}>
        <div style={{ maxWidth:980,margin:"0 auto",textAlign:"center" }}>
          <div style={{ fontSize:".72rem",fontWeight:700,letterSpacing:".1em",color:C,textTransform:"uppercase",marginBottom:14 }}>Transparency</div>
          <h2 style={{ fontSize:"clamp(1.4rem,2.5vw,2rem)",fontWeight:800,letterSpacing:"-.03em",marginBottom:12 }}>Built with honesty about what we can and can't do</h2>
          <p style={{ color:"#6b7280",fontSize:".9rem",lineHeight:1.7,maxWidth:500,margin:"0 auto 44px" }}>We believe security tooling should be transparent about its capabilities.</p>
          <div style={{ display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:18,textAlign:"left" }}>
            {[
              { icon:"✓",title:"What we detect",    color:C,       items:["RSA, DSA, ECC key usage","MD5, SHA-1, weak hashes","Deprecated TLS versions","Hardcoded key material","Weak IV / nonce patterns"] },
              { icon:"⚠",title:"Current limitations",color:"#f97316",items:["Runtime crypto behavior","Encrypted or obfuscated code","Custom crypto libraries","Some C/C++ macros","Binary-only dependencies"] },
              { icon:"◈",title:"Coming soon",        color:"#3b82f6",items:["Binary scanning","Container image analysis","Runtime MTLS inspection","SaaS API scanner","Auto-PR fix suggestions"] },
            ].map(col => (
              <div key={col.title} className="qg-card" style={{ padding:26 }}>
                <div style={{ display:"flex",alignItems:"center",gap:8,marginBottom:16 }}>
                  <span style={{ fontSize:14,color:col.color }}>{col.icon}</span>
                  <span style={{ fontWeight:700,fontSize:".9rem" }}>{col.title}</span>
                </div>
                {col.items.map(item => (
                  <div key={item} style={{ display:"flex",alignItems:"center",gap:9,padding:"6px 0",borderBottom:"1px solid #f1f5f9",fontSize:".79rem",color:"#4b5563" }}>
                    <span style={{ color:col.color,fontSize:8 }}>◆</span>{item}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════ PRICING ════════════ */}
      <section style={{ padding:"80px 32px",background:"#fff" }}>
        <div style={{ maxWidth:1160,margin:"0 auto" }}>
          <div style={{ textAlign:"center",marginBottom:48 }}>
            <div style={{ fontSize:".72rem",fontWeight:700,letterSpacing:".1em",color:C,textTransform:"uppercase",marginBottom:12 }}>Pricing</div>
            <h2 style={{ fontSize:"clamp(1.5rem,3vw,2.3rem)",fontWeight:800,letterSpacing:"-.03em" }}>Start free. Scale when you're ready.</h2>
            <p style={{ color:"#6b7280",marginTop:10,fontSize:".9rem" }}>No credit card required for Free and Pro trials.</p>
          </div>
          <div className="qg-pricing-grid" style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:18 }}>
            {[
              { name:"Free",       price:"$0",    period:"",    desc:"For developers exploring PQC",       features:["3 scans / month","RSA & ECC detection","PDF summary report","Community support"],                                    cta:"Start Free",       highlight:false },
              { name:"Pro",        price:"$49",   period:"/mo", desc:"For security-conscious teams",       features:["Unlimited scans","All 12 vuln types","NIST fix guidance","GitHub Actions gate","API access","Slack alerts"],        cta:"Start Free Trial", highlight:true  },
              { name:"Team",       price:"$199",  period:"/mo", desc:"Org-wide visibility & compliance",   features:["Everything in Pro","Multi-repo dashboard","Executive PDF reports","SSO / SAML","Priority support"],                  cta:"Start Free Trial", highlight:false },
              { name:"Enterprise", price:"Custom",period:"",    desc:"Air-gapped, on-prem or hybrid",      features:["On-premise option","SLA 99.99% uptime","Dedicated CSM","Custom integrations","Pen-test reports","FedRAMP roadmap"],cta:"Contact Sales",    highlight:false },
            ].map(plan => (
              <div key={plan.name} className="qg-card qg-plan-card" style={{ padding:"28px 22px",position:"relative",border:plan.highlight?`2px solid ${C}`:"1px solid #e8edf3",boxShadow:plan.highlight?"0 8px 36px rgba(34,197,94,.13)":undefined,transform:plan.highlight?"scale(1.03)":"none" }}>
                {plan.highlight && (
                  <div style={{ position:"absolute",top:-12,left:"50%",transform:"translateX(-50%)",background:C,color:"#fff",fontSize:".63rem",fontWeight:700,letterSpacing:".06em",padding:"4px 14px",borderRadius:100,whiteSpace:"nowrap" }}>MOST POPULAR</div>
                )}
                <div style={{ fontWeight:700,fontSize:".92rem",marginBottom:4 }}>{plan.name}</div>
                <div style={{ fontSize:".75rem",color:"#9ca3af",marginBottom:16 }}>{plan.desc}</div>
                <div style={{ display:"flex",alignItems:"baseline",gap:2,marginBottom:18 }}>
                  <span style={{ fontSize:"1.9rem",fontWeight:800,letterSpacing:"-.04em" }}>{plan.price}</span>
                  <span style={{ fontSize:".8rem",color:"#9ca3af" }}>{plan.period}</span>
                </div>
                <button className={plan.highlight?"qg-btn-primary":"qg-btn-outline"}
                  onClick={plan.cta !== "Contact Sales" ? onStart : undefined}
                  style={{ width:"100%",justifyContent:"center",marginBottom:18,padding:"11px" }}>
                  {plan.cta}
                </button>
                <div style={{ display:"flex",flexDirection:"column",gap:9 }}>
                  {plan.features.map(f => (
                    <div key={f} style={{ display:"flex",alignItems:"center",gap:9,fontSize:".79rem",color:"#4b5563" }}>
                      <CheckIcon />{f}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ════════════ FINAL CTA (original upgraded) ════════════ */}
      <section style={{ padding:"80px 32px 96px",background:"linear-gradient(135deg,#0f1923 0%,#0d2a1a 60%,#0f1923 100%)",position:"relative",overflow:"hidden" }}>
        <div style={{ position:"absolute",top:"50%",left:"50%",transform:"translate(-50%,-50%)",width:660,height:340,borderRadius:"50%",background:"radial-gradient(circle,rgba(34,197,94,.07) 0%,transparent 70%)",pointerEvents:"none" }} />
        <div style={{ maxWidth:660,margin:"0 auto",textAlign:"center",position:"relative" }}>
          <div style={{ width:52,height:52,background:"linear-gradient(135deg,#22c55e,#15803d)",borderRadius:14,display:"flex",alignItems:"center",justifyContent:"center",margin:"0 auto 20px",boxShadow:"0 8px 24px rgba(34,197,94,.3)" }}>
            <ShieldIcon size={22} />
          </div>
          <div style={{ fontSize:".72rem",fontWeight:700,letterSpacing:".1em",color:"#4ade80",textTransform:"uppercase",marginBottom:16 }}>Get Started Today</div>
          <h2 style={{ fontSize:"clamp(1.8rem,4vw,2.8rem)",fontWeight:800,letterSpacing:"-.04em",color:"#fff",lineHeight:1.1,marginBottom:16 }}>
            Ready to secure your code<br/>for the quantum future?
          </h2>
          <p style={{ color:"#9ca3af",fontSize:".93rem",lineHeight:1.68,marginBottom:36 }}>
            Join developers already using QuantumGuard to protect their applications.
            First scan free. No credit card. Results in 60 seconds.
          </p>
          <div style={{ display:"flex",gap:14,justifyContent:"center",flexWrap:"wrap" }}>
            <button className="qg-btn-primary" style={{ padding:"13px 28px",fontSize:".95rem" }} onClick={onStart}>
              <ShieldIcon size={15} /> Start Scanning Now
            </button>
            <button style={{ background:"transparent",border:"1.5px solid rgba(255,255,255,.18)",color:"#fff",padding:"13px 28px",borderRadius:10,fontSize:".95rem",cursor:"pointer",fontFamily:"inherit",fontWeight:500,transition:"border-color .2s" }}
              onMouseEnter={e => e.currentTarget.style.borderColor=C}
              onMouseLeave={e => e.currentTarget.style.borderColor="rgba(255,255,255,.18)"}>
              Contact Sales
            </button>
          </div>
          <div style={{ marginTop:26,fontSize:".73rem",color:"#374151" }}>
            NIST FIPS 203 · 204 · 205 aligned &nbsp;·&nbsp; SOC 2 Type II &nbsp;·&nbsp; Zero data retention
          </div>
        </div>
      </section>

      {/* ════════════ FOOTER ════════════ */}
      <footer style={{ background:"#0b1117",padding:"48px 32px 28px",color:"#4b5563" }}>
        <div style={{ maxWidth:1200,margin:"0 auto" }}>
          <div style={{ display:"flex",gap:44,flexWrap:"wrap",marginBottom:32 }}>
            <div style={{ flex:"1 1 190px" }}>
              <div style={{ display:"flex",alignItems:"center",gap:8,marginBottom:12 }}>
                <div style={{ width:26,height:26,background:"linear-gradient(135deg,#22c55e,#15803d)",borderRadius:7,display:"flex",alignItems:"center",justifyContent:"center" }}>
                  <ShieldIcon size={13} />
                </div>
                <span style={{ color:"#f8fafc",fontWeight:800,fontSize:".92rem",letterSpacing:"-.02em" }}>
                  Quantum<span style={{ color:C }}>Guard</span>
                </span>
              </div>
              <p style={{ fontSize:".78rem",lineHeight:1.65,maxWidth:185 }}>Post-quantum cryptography scanning for modern engineering teams.</p>
            </div>
            {[
              { title:"Product", links:["Quantum Scanner","CI/CD Gate","TLS Analyzer","Executive Reports"] },
              { title:"Company", links:["About","Blog","Careers","Press"] },
              { title:"Legal",   links:["Privacy","Terms","Security","Cookie Policy"] },
            ].map(col => (
              <div key={col.title} style={{ flex:"1 1 120px" }}>
                <div style={{ fontSize:".66rem",fontWeight:700,color:"#f8fafc",letterSpacing:".07em",textTransform:"uppercase",marginBottom:14 }}>{col.title}</div>
                {col.links.map(l => (
                  <div key={l} style={{ fontSize:".78rem",color:"#4b5563",marginBottom:9,cursor:"pointer",transition:"color .15s" }}
                    onMouseEnter={e => e.currentTarget.style.color=C}
                    onMouseLeave={e => e.currentTarget.style.color="#4b5563"}>
                    {l}
                  </div>
                ))}
              </div>
            ))}
          </div>
          <div style={{ borderTop:"1px solid #1e293b",paddingTop:20,display:"flex",justifyContent:"space-between",flexWrap:"wrap",gap:10,fontSize:".73rem" }}>
            <span>© 2025 QuantumGuard, Inc. All rights reserved.</span>
            <span>Built for the post-quantum era.</span>
          </div>
        </div>
      </footer>

    </div>
  );
}
