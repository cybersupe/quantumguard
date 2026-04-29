import React from "react";

const styles = {
  /* ── Reset & Base ── */
  page: {
    minHeight: "100vh",
    background: "#f4f9f6",
    fontFamily: "'DM Sans', 'Segoe UI', Arial, sans-serif",
    color: "#0f1a14",
    overflowX: "hidden",
  },

  /* ── NAV ── */
  nav: {
    background: "#fff",
    borderBottom: "1px solid #e2ede7",
    position: "sticky",
    top: 0,
    zIndex: 100,
    padding: "0 48px",
    height: "60px",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
  },
  navLogo: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    fontWeight: 800,
    fontSize: "1.1rem",
    color: "#0f1a14",
    textDecoration: "none",
  },
  logoIcon: {
    width: "32px",
    height: "32px",
    background: "#1a6b3a",
    borderRadius: "8px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  },
  navLinks: {
    display: "flex",
    gap: "32px",
    listStyle: "none",
  },
  navLink: {
    textDecoration: "none",
    color: "#5a7060",
    fontSize: "0.92rem",
    fontWeight: 500,
  },
  navRight: {
    display: "flex",
    alignItems: "center",
    gap: "16px",
  },
  apiBadge: {
    display: "flex",
    alignItems: "center",
    gap: "6px",
    fontSize: "0.78rem",
    fontWeight: 600,
    color: "#1a6b3a",
    letterSpacing: "0.04em",
  },
  apiDot: {
    width: "7px",
    height: "7px",
    borderRadius: "50%",
    background: "#22c55e",
    boxShadow: "0 0 0 3px rgba(34,197,94,.2)",
  },
  btnPrimary: {
    background: "#1a6b3a",
    color: "#fff",
    border: "none",
    borderRadius: "8px",
    padding: "9px 20px",
    fontSize: "0.88rem",
    fontWeight: 600,
    cursor: "pointer",
    fontFamily: "inherit",
    display: "flex",
    alignItems: "center",
    gap: "6px",
  },
  btnOutline: {
    background: "transparent",
    color: "#0f1a14",
    border: "1.5px solid #e2ede7",
    borderRadius: "8px",
    padding: "9px 20px",
    fontSize: "0.88rem",
    fontWeight: 600,
    cursor: "pointer",
    fontFamily: "inherit",
    display: "flex",
    alignItems: "center",
    gap: "6px",
  },

  /* ── HERO ── */
  hero: {
    display: "grid",
    gridTemplateColumns: "1fr 1.1fr",
    gap: "48px",
    alignItems: "center",
    maxWidth: "1200px",
    margin: "0 auto",
    padding: "80px 48px 64px",
  },
  heroTag: {
    display: "inline-flex",
    alignItems: "center",
    gap: "7px",
    background: "#e8f5ee",
    color: "#1a6b3a",
    fontSize: "0.78rem",
    fontWeight: 600,
    padding: "5px 12px",
    borderRadius: "20px",
    marginBottom: "20px",
    letterSpacing: "0.02em",
  },
  h1: {
    fontSize: "clamp(2.2rem, 4vw, 3rem)",
    fontWeight: 800,
    lineHeight: 1.12,
    letterSpacing: "-0.02em",
    color: "#0f1a14",
    marginBottom: "18px",
  },
  heroP: {
    color: "#5a7060",
    fontSize: "1.05rem",
    lineHeight: 1.65,
    maxWidth: "420px",
    marginBottom: "32px",
  },
  heroBtns: {
    display: "flex",
    gap: "12px",
    marginBottom: "36px",
  },
  heroTrust: {
    display: "flex",
    gap: "20px",
    flexWrap: "wrap",
  },
  trustItem: {
    display: "flex",
    alignItems: "center",
    gap: "7px",
    fontSize: "0.82rem",
    fontWeight: 500,
    color: "#5a7060",
  },

  /* ── DASHBOARD CARD ── */
  dashCard: {
    background: "#fff",
    borderRadius: "20px",
    boxShadow: "0 8px 32px rgba(0,0,0,.10), 0 2px 8px rgba(0,0,0,.06)",
    overflow: "hidden",
    border: "1px solid #e2ede7",
  },
  dashHeader: {
    background: "#f7fbf9",
    borderBottom: "1px solid #e2ede7",
    padding: "12px 18px",
    display: "flex",
    alignItems: "center",
    gap: "10px",
    fontSize: "0.82rem",
    fontWeight: 600,
  },
  dot: { width: "8px", height: "8px", borderRadius: "50%" },
  dashBody: {
    display: "grid",
    gridTemplateColumns: "160px 1fr",
  },

  /* Sidebar */
  dashSidebar: {
    borderRight: "1px solid #e2ede7",
    padding: "16px 0",
  },
  navItem: {
    display: "flex",
    alignItems: "center",
    gap: "9px",
    padding: "8px 16px",
    fontSize: "0.8rem",
    fontWeight: 500,
    color: "#5a7060",
    cursor: "pointer",
  },
  navItemActive: {
    display: "flex",
    alignItems: "center",
    gap: "9px",
    padding: "8px 16px",
    fontSize: "0.8rem",
    fontWeight: 600,
    color: "#1a6b3a",
    background: "#e8f5ee",
    cursor: "pointer",
  },

  /* Content */
  dashContent: { padding: "18px" },
  sectionTitle: {
    fontSize: "0.72rem",
    fontWeight: 700,
    color: "#8aa594",
    letterSpacing: "0.06em",
    textTransform: "uppercase",
    marginBottom: "12px",
  },
  metricsRow: {
    display: "grid",
    gridTemplateColumns: "130px 1fr",
    gap: "12px",
    marginBottom: "16px",
  },
  scoreRing: {
    background: "#f7fbf9",
    borderRadius: "12px",
    padding: "12px",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    gap: "4px",
  },
  vulnGrid: {
    background: "#f7fbf9",
    borderRadius: "12px",
    padding: "12px",
    display: "grid",
    gridTemplateColumns: "repeat(4,1fr)",
    gap: "8px",
  },
  vulnCell: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: "3px",
  },

  /* Scan row */
  scanRow: {
    background: "#f7fbf9",
    borderRadius: "10px",
    padding: "10px 12px",
    display: "flex",
    alignItems: "center",
    gap: "10px",
  },
  scanAvatar: {
    width: "26px",
    height: "26px",
    borderRadius: "6px",
    background: "#0f1a14",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
  },
  btnReport: {
    background: "transparent",
    border: "1.5px solid #e2ede7",
    color: "#0f1a14",
    borderRadius: "7px",
    padding: "5px 10px",
    fontSize: "0.68rem",
    fontWeight: 600,
    cursor: "pointer",
    whiteSpace: "nowrap",
    fontFamily: "inherit",
  },

  /* Issue rows */
  issueRow: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    fontSize: "0.72rem",
    marginBottom: "6px",
  },
  rowBetween: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    marginBottom: "8px",
  },

  /* ── FEATURES ── */
  features: {
    background: "#fff",
    borderTop: "1px solid #e2ede7",
    padding: "64px 48px",
  },
  featuresGrid: {
    maxWidth: "1200px",
    margin: "0 auto",
    display: "grid",
    gridTemplateColumns: "repeat(4,1fr)",
    gap: "24px",
  },
  featureCard: {
    background: "#f7fbf9",
    borderRadius: "12px",
    padding: "28px 24px",
    border: "1px solid #e2ede7",
  },
  featureIcon: {
    width: "44px",
    height: "44px",
    borderRadius: "10px",
    background: "#e8f5ee",
    color: "#1a6b3a",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    marginBottom: "14px",
  },

  /* ── STATS ── */
  statsBar: {
    background: "#f7fbf9",
    borderTop: "1px solid #e2ede7",
    padding: "40px 48px",
  },
  statsInner: {
    maxWidth: "1200px",
    margin: "0 auto",
    display: "grid",
    gridTemplateColumns: "repeat(5,1fr)",
    textAlign: "center",
    gap: "24px",
  },

  /* ── CTA ── */
  ctaBanner: {
    background: "#fff",
    borderTop: "1px solid #e2ede7",
    padding: "32px 48px 56px",
  },
  ctaInner: {
    maxWidth: "1200px",
    margin: "0 auto",
    background: "#e8f5ee",
    borderRadius: "16px",
    padding: "28px 36px",
    display: "flex",
    alignItems: "center",
    gap: "20px",
    border: "1px solid #d1ead9",
  },
  ctaLogo: {
    width: "48px",
    height: "48px",
    background: "#1a6b3a",
    borderRadius: "12px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
  },
};

/* ── Small reusable SVG icons ── */
const ShieldIcon = ({ size = 16, color = "#fff" }) => (
  <svg width={size} height={size} fill="none" viewBox="0 0 24 24" stroke={color} strokeWidth="2.5">
    <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" />
  </svg>
);

const Chip = ({ type, label }) => {
  const map = {
    critical: { bg: "#fef2f2", color: "#dc2626" },
    high:     { bg: "#fffbeb", color: "#d97706" },
    medium:   { bg: "#fffbeb", color: "#b45309" },
  };
  const s = map[type] || map.medium;
  return (
    <span style={{
      padding: "2px 7px", borderRadius: "5px",
      fontSize: "0.6rem", fontWeight: 700, letterSpacing: "0.04em",
      background: s.bg, color: s.color, flexShrink: 0,
    }}>
      {label}
    </span>
  );
};

export default function LandingPage({ onStart }) {
  return (
    <div style={styles.page}>

      {/* ── NAV ── */}
      <nav style={styles.nav}>
        <div style={styles.navLogo}>
          <div style={styles.logoIcon}><ShieldIcon /></div>
          <span>Quantum<span style={{ color: "#1a6b3a" }}>Guard</span></span>
        </div>

        <ul style={styles.navLinks}>
          {["Features", "How It Works", "Pricing", "Documentation", "About"].map(l => (
            <li key={l}><a href="#" style={styles.navLink}>{l}</a></li>
          ))}
        </ul>

        <div style={styles.navRight}>
          <div style={styles.apiBadge}>
            <div style={styles.apiDot} />
            API ONLINE
          </div>
          <span style={{ fontSize: "1.2rem" }}>☀️</span>
          <button style={styles.btnPrimary} onClick={onStart}>Get Started</button>
        </div>
      </nav>

      {/* ── HERO ── */}
      <section style={styles.hero}>

        {/* Left */}
        <div>
          <div style={styles.heroTag}>
            <ShieldIcon size={12} color="#1a6b3a" />
            Protect Your Code. Secure the Quantum Future.
          </div>

          <h1 style={styles.h1}>
            Find Quantum<br />
            <span style={{ color: "#1a6b3a" }}>Vulnerabilities.</span><br />
            Secure Tomorrow.
          </h1>

          <p style={styles.heroP}>
            QuantumGuard scans your codebase for encryption and cryptographic
            vulnerabilities that could be broken by quantum computers.
          </p>

          <div style={styles.heroBtns}>
            <button style={{ ...styles.btnPrimary, padding: "12px 22px", fontSize: "0.95rem" }} onClick={onStart}>
              <ShieldIcon size={14} />
              Run a Scan Now
            </button>
            <button style={{ ...styles.btnOutline, padding: "12px 22px", fontSize: "0.95rem" }}>
              ▷ See How It Works
            </button>
          </div>

          <div style={styles.heroTrust}>
            {["✅ Accurate Results", "</> Developer Friendly", "🛡 Privacy Focused", "⚡ Fast & Reliable"].map(t => (
              <div key={t} style={styles.trustItem}>{t}</div>
            ))}
          </div>
        </div>

        {/* Right — Dashboard Preview */}
        <div style={styles.dashCard}>

          {/* Window chrome */}
          <div style={styles.dashHeader}>
            <div style={{ ...styles.dot, background: "#ff5f57" }} />
            <div style={{ ...styles.dot, background: "#febc2e" }} />
            <div style={{ ...styles.dot, background: "#28c840" }} />
            <div style={{ marginLeft: "4px", display: "flex", alignItems: "center", gap: "6px" }}>
              <ShieldIcon size={14} color="#1a6b3a" />
              <span>Quantum</span><span style={{ color: "#1a6b3a" }}>Guard</span>
            </div>
            <span style={{ marginLeft: "auto", color: "#8aa594", fontSize: "0.8rem", fontWeight: 600 }}>
              Dashboard
            </span>
          </div>

          <div style={styles.dashBody}>

            {/* Sidebar */}
            <div style={styles.dashSidebar}>
              {[
                { label: "Overview", active: true },
                { label: "Scans" },
                { label: "Repositories" },
                { label: "Agility Checker" },
                { label: "API Keys" },
                { label: "Reports" },
                { label: "Settings" },
              ].map(({ label, active }) => (
                <div key={label} style={active ? styles.navItemActive : styles.navItem}>
                  {label}
                </div>
              ))}
            </div>

            {/* Main content */}
            <div style={styles.dashContent}>

              {/* Security Score + Vuln counts */}
              <div style={styles.sectionTitle}>Security Overview</div>
              <div style={styles.metricsRow}>

                {/* Donut ring */}
                <div style={styles.scoreRing}>
                  <div style={{ position: "relative", width: "70px", height: "70px" }}>
                    <svg width="70" height="70" viewBox="0 0 70 70" style={{ transform: "rotate(-90deg)" }}>
                      <circle cx="35" cy="35" r="28" fill="none" stroke="#e2ede7" strokeWidth="6" />
                      <circle cx="35" cy="35" r="28" fill="none" stroke="#d97706" strokeWidth="6"
                        strokeDasharray="175.9" strokeDashoffset="47.6" strokeLinecap="round" />
                    </svg>
                    <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
                      <span style={{ fontSize: "1.15rem", fontWeight: 800, lineHeight: 1 }}>72</span>
                      <span style={{ fontSize: "0.55rem", color: "#8aa594" }}>/100</span>
                    </div>
                  </div>
                  <div style={{ fontSize: "0.65rem", fontWeight: 700, color: "#d97706", marginTop: "2px" }}>
                    Medium Risk
                  </div>
                </div>

                {/* Vuln counts */}
                <div style={styles.vulnGrid}>
                  {[
                    { count: 12, label: "Critical", color: "#dc2626" },
                    { count: 28, label: "High",     color: "#d97706" },
                    { count: 15, label: "Medium",   color: "#ca8a04" },
                    { count: 8,  label: "Low",      color: "#059669" },
                  ].map(({ count, label, color }) => (
                    <div key={label} style={styles.vulnCell}>
                      <span style={{ fontSize: "1.05rem", fontWeight: 800, color }}>{count}</span>
                      <span style={{ fontSize: "0.6rem", color: "#8aa594", fontWeight: 500 }}>{label}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recent Scan */}
              <div style={{ marginBottom: "12px" }}>
                <div style={styles.rowBetween}>
                  <div style={{ ...styles.sectionTitle, marginBottom: 0 }}>Recent Scan</div>
                  <a href="#" style={{ fontSize: "0.65rem", fontWeight: 600, color: "#1a6b3a", textDecoration: "none" }}>View All</a>
                </div>
                <div style={{ height: "8px" }} />
                <div style={styles.scanRow}>
                  <div style={styles.scanAvatar}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="#fff">
                      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.2 11.38.6.1.82-.26.82-.58v-2.03c-3.34.72-4.04-1.61-4.04-1.61-.54-1.38-1.33-1.75-1.33-1.75-1.09-.74.08-.73.08-.73 1.2.09 1.84 1.24 1.84 1.24 1.07 1.83 2.8 1.3 3.49.99.1-.78.42-1.3.76-1.6-2.67-.3-5.47-1.33-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.13-.3-.54-1.52.12-3.18 0 0 1-.32 3.3 1.23a11.5 11.5 0 0 1 3-.4c1.02.004 2.04.14 3 .4 2.28-1.55 3.29-1.23 3.29-1.23.66 1.66.24 2.88.12 3.18.77.84 1.23 1.91 1.23 3.22 0 4.61-2.81 5.63-5.48 5.92.43.37.81 1.1.81 2.22v3.29c0 .32.22.69.83.57C20.57 21.8 24 17.3 24 12c0-6.63-5.37-12-12-12z"/>
                    </svg>
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: "0.75rem", fontWeight: 700 }}>cybersupe/quantumguard</div>
                    <div style={{ fontSize: "0.65rem", color: "#8aa594" }}>Scan completed 2 minutes ago</div>
                  </div>
                  <div style={{ textAlign: "center", marginRight: "8px" }}>
                    <div style={{ fontSize: "0.8rem", fontWeight: 700 }}>312</div>
                    <div style={{ fontSize: "0.6rem", color: "#8aa594" }}>Files</div>
                  </div>
                  <div style={{ textAlign: "center", marginRight: "8px" }}>
                    <div style={{ fontSize: "0.8rem", fontWeight: 700 }}>1,428</div>
                    <div style={{ fontSize: "0.6rem", color: "#8aa594" }}>Issues</div>
                  </div>
                  <button style={styles.btnReport}>View Report →</button>
                </div>
              </div>

              {/* Top Issues */}
              <div>
                <div style={styles.rowBetween}>
                  <div style={{ ...styles.sectionTitle, marginBottom: 0 }}>Top Issues</div>
                  <a href="#" style={{ fontSize: "0.65rem", fontWeight: 600, color: "#1a6b3a", textDecoration: "none" }}>View All</a>
                </div>
                <div style={{ height: "8px" }} />
                {[
                  { type: "critical", label: "CRITICAL", name: "RSA encryption usage detected",           file: "auth/encryption.js:45", lang: "JavaScript" },
                  { type: "high",     label: "HIGH",     name: "SHA-1 hash function detected",            file: "utils/hash.js:12",      lang: "JavaScript" },
                  { type: "medium",   label: "MEDIUM",   name: "Diffie-Hellman key exchange (small key)", file: "secure/dh.js:8",        lang: "JavaScript" },
                ].map(({ type, label, name, file, lang }) => (
                  <div key={label} style={styles.issueRow}>
                    <Chip type={type} label={label} />
                    <span style={{ flex: 1, color: "#5a7060" }}>{name}</span>
                    <span style={{ color: "#8aa594", fontFamily: "monospace", fontSize: "0.65rem" }}>{file}</span>
                    <span style={{ background: "#f7fbf9", color: "#8aa594", padding: "1px 5px", borderRadius: "4px", fontSize: "0.6rem" }}>{lang}</span>
                  </div>
                ))}
              </div>

            </div>
          </div>
        </div>
      </section>

      {/* ── FEATURES ── */}
      <section style={styles.features}>
        <div style={styles.featuresGrid}>
          {[
            {
              icon: "🛡",
              title: "Quantum Vulnerability Scanner",
              desc: "Detects cryptographic algorithms and patterns that are vulnerable to quantum computer attacks.",
            },
            {
              icon: "</>",
              title: "Developer Friendly",
              desc: "Easy to integrate API, clear reports, and actionable fix recommendations for your code.",
            },
            {
              icon: "🔒",
              title: "Private & Secure",
              desc: "Your code never leaves your system. Scans are private, secure, and fully confidential.",
            },
            {
              icon: "⚡",
              title: "Fast & Reliable",
              desc: "Get results in seconds with our powerful scanning engine and real-time analysis.",
            },
          ].map(({ icon, title, desc }) => (
            <div key={title} style={styles.featureCard}>
              <div style={styles.featureIcon}>{icon}</div>
              <h3 style={{ fontSize: "0.95rem", fontWeight: 700, marginBottom: "8px" }}>{title}</h3>
              <p style={{ fontSize: "0.83rem", color: "#5a7060", lineHeight: 1.6 }}>{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── STATS ── */}
      <section style={styles.statsBar}>
        <div style={styles.statsInner}>
          {[
            { val: "50+",   lbl: "Vulnerability Checks" },
            { val: "10+",   lbl: "Supported Languages" },
            { val: "99.9%", lbl: "Uptime" },
            { val: "<30s",  lbl: "Average Scan Time" },
            { val: "100%",  lbl: "Private Scanning" },
          ].map(({ val, lbl }) => (
            <div key={lbl}>
              <div style={{ fontSize: "2rem", fontWeight: 800, color: "#1a6b3a", lineHeight: 1 }}>{val}</div>
              <div style={{ fontSize: "0.83rem", color: "#5a7060", marginTop: "6px", fontWeight: 500 }}>{lbl}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── CTA ── */}
      <section style={styles.ctaBanner}>
        <div style={styles.ctaInner}>
          <div style={styles.ctaLogo}><ShieldIcon size={22} /></div>
          <div>
            <h3 style={{ fontSize: "1rem", fontWeight: 700 }}>Ready to secure your code for the quantum future?</h3>
            <p style={{ fontSize: "0.85rem", color: "#5a7060", marginTop: "3px" }}>
              Join developers who are already using QuantumGuard to protect their applications.
            </p>
          </div>
          <div style={{ marginLeft: "auto" }}>
            <button
              style={{ ...styles.btnPrimary, padding: "12px 24px", fontSize: "0.9rem" }}
              onClick={onStart}
            >
              <ShieldIcon size={14} />
              Start Scanning Now
            </button>
          </div>
        </div>
      </section>

    </div>
  );
}
