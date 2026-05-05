// ══════════════════════════════════════════════════════════════
// Privacy.jsx — QuantumGuard Privacy Policy
// Replace your existing Privacy.jsx with this file entirely.
// No other files need to change.
// Effective date: May 5, 2026
// ══════════════════════════════════════════════════════════════

export default function Privacy() {
  const C = {
    bg:          "#0a0e1a",
    card:        "#0d1220",
    panel:       "#111827",
    border:      "#1e2d40",
    borderLight: "#263548",
    text:        "#f1f5f9",
    mid:         "#94a3b8",
    muted:       "#4b5563",
    green:       "#22c55e",
    greenDim:    "rgba(34,197,94,0.1)",
    greenBorder: "rgba(34,197,94,0.2)",
    amber:       "#f59e0b",
    amberDim:    "rgba(245,158,11,0.08)",
    amberBorder: "rgba(245,158,11,0.2)",
    red:         "#ef4444",
  };

  const Section = ({ id, title, children }) => (
    <section id={id} style={{ marginBottom: 48 }}>
      <h2 style={{
        fontSize: 20, fontWeight: 800, color: C.text,
        letterSpacing: "-.03em", marginBottom: 16,
        paddingBottom: 12,
        borderBottom: `1px solid ${C.border}`,
        display: "flex", alignItems: "center", gap: 10,
      }}>
        <span style={{
          display: "inline-block", width: 3, height: 20,
          background: C.green, borderRadius: 2,
          boxShadow: `0 0 6px ${C.green}`,
          flexShrink: 0,
        }} />
        {title}
      </h2>
      <div style={{ color: C.mid, fontSize: 14, lineHeight: 1.85 }}>
        {children}
      </div>
    </section>
  );

  const P = ({ children, style = {} }) => (
    <p style={{ marginBottom: 14, ...style }}>{children}</p>
  );

  const Highlight = ({ icon, title, body, color = C.green, bg = C.greenDim, border = C.greenBorder }) => (
    <div style={{
      background: bg, border: `1px solid ${border}`,
      borderLeft: `3px solid ${color}`,
      borderRadius: "0 10px 10px 0",
      padding: "14px 18px", marginBottom: 14,
    }}>
      <div style={{ fontSize: 13, fontWeight: 700, color, marginBottom: 4 }}>
        {icon} {title}
      </div>
      <div style={{ fontSize: 13, color: C.mid, lineHeight: 1.7 }}>{body}</div>
    </div>
  );

  const List = ({ items }) => (
    <ul style={{ paddingLeft: 0, listStyle: "none", marginBottom: 14 }}>
      {items.map((item, i) => (
        <li key={i} style={{
          display: "flex", gap: 10, alignItems: "flex-start",
          fontSize: 13, color: C.mid, marginBottom: 8, lineHeight: 1.65,
        }}>
          <span style={{ color: C.green, flexShrink: 0, marginTop: 2, fontWeight: 700 }}>✓</span>
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );

  const TOC = [
    ["information",   "1. Information We Collect"],
    ["scanning",      "2. How Scanning Works"],
    ["usage",         "3. How We Use Information"],
    ["retention",     "4. Data Retention"],
    ["sharing",       "5. Data Sharing"],
    ["cookies",       "6. Cookies & Analytics"],
    ["security",      "7. Security"],
    ["rights",        "8. Your Rights"],
    ["children",      "9. Children's Privacy"],
    ["changes",       "10. Changes to This Policy"],
    ["contact",       "11. Contact Us"],
  ];

  return (
    <div style={{ background: C.bg, minHeight: "100vh", fontFamily: "'DM Sans','Segoe UI',system-ui,sans-serif" }}>

      {/* ── Hero ── */}
      <div style={{
        background: `linear-gradient(135deg, ${C.card}, #0f1929)`,
        borderBottom: `1px solid ${C.border}`,
        padding: "60px 32px 48px",
        position: "relative", overflow: "hidden",
      }}>
        <div style={{
          position: "absolute", inset: 0,
          backgroundImage: "radial-gradient(rgba(34,197,94,0.05) 1px, transparent 1px)",
          backgroundSize: "28px 28px", pointerEvents: "none",
        }} />
        <div style={{ maxWidth: 760, margin: "0 auto", position: "relative" }}>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 8,
            background: C.greenDim, border: `1px solid ${C.greenBorder}`,
            borderRadius: 100, padding: "5px 14px", marginBottom: 20,
          }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: C.green, letterSpacing: ".05em" }}>
              LEGAL DOCUMENT
            </span>
          </div>
          <h1 style={{
            fontSize: "clamp(28px, 4vw, 44px)", fontWeight: 900,
            letterSpacing: "-.04em", color: C.text, marginBottom: 14, lineHeight: 1.1,
          }}>
            Privacy Policy
          </h1>
          <p style={{ fontSize: 15, color: C.mid, marginBottom: 20, lineHeight: 1.7 }}>
            This policy explains how <strong style={{ color: C.text }}>Mangsri QuantumGuard LLC</strong> collects,
            uses, and protects information when you use QuantumGuard at{" "}
            <a href="https://quantumguard.site" style={{ color: C.green, textDecoration: "none" }}>
              quantumguard.site
            </a>.
          </p>
          <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
            <span style={{ fontSize: 12, color: C.muted }}>
              <strong style={{ color: C.mid }}>Effective date:</strong> May 5, 2026
            </span>
            <span style={{ fontSize: 12, color: C.muted }}>
              <strong style={{ color: C.mid }}>Company:</strong> Mangsri QuantumGuard LLC
            </span>
            <span style={{ fontSize: 12, color: C.muted }}>
              <strong style={{ color: C.mid }}>Location:</strong> Montgomery, Alabama, USA
            </span>
          </div>
        </div>
      </div>

      {/* ── Body ── */}
      <div style={{ maxWidth: 760, margin: "0 auto", padding: "48px 32px 80px" }}>

        {/* Key commitments callout */}
        <div style={{
          background: C.greenDim, border: `1px solid ${C.greenBorder}`,
          borderRadius: 14, padding: "20px 24px", marginBottom: 48,
        }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: C.green, marginBottom: 12 }}>
            Our core commitments — plain English
          </div>
          <List items={[
            "Your source code is never permanently stored. It is scanned in a temporary directory and deleted immediately after the scan completes.",
            "We do not sell your data to anyone, ever.",
            "We do not share your personal information with third parties except as required to operate the service (e.g. payment processing via Stripe).",
            "You can delete your account and all associated data at any time.",
            "The scanner is open source — you can verify exactly what runs on your code at github.com/cybersupe/quantumguard.",
          ]} />
        </div>

        {/* Table of contents */}
        <div style={{
          background: C.card, border: `1px solid ${C.border}`,
          borderRadius: 12, padding: "20px 24px", marginBottom: 48,
        }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: C.muted,
            textTransform: "uppercase", letterSpacing: ".07em", marginBottom: 14 }}>
            Contents
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {TOC.map(([id, label]) => (
              <a key={id} href={`#${id}`} style={{
                fontSize: 13, color: C.mid, textDecoration: "none",
                transition: "color .15s",
              }}
                onMouseEnter={e => e.currentTarget.style.color = C.green}
                onMouseLeave={e => e.currentTarget.style.color = C.mid}>
                {label}
              </a>
            ))}
          </div>
        </div>

        {/* ── 1. Information We Collect ── */}
        <Section id="information" title="Information We Collect">
          <P>We collect the minimum information necessary to operate QuantumGuard. We do not collect more than we need.</P>

          <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 8, marginTop: 20 }}>
            Information you provide directly
          </div>
          <List items={[
            "Account information: email address and password (hashed) if you create an account.",
            "Payment information: processed entirely by Stripe. We never see or store your card number.",
            "GitHub repository URLs you submit for scanning.",
            "Feedback or support messages you send to us.",
          ]} />

          <div style={{ fontSize: 13, fontWeight: 700, color: C.text, marginBottom: 8, marginTop: 20 }}>
            Information collected automatically
          </div>
          <List items={[
            "IP address and general geographic region (country/city level) for rate limiting and abuse prevention.",
            "Browser type and operating system for debugging and compatibility.",
            "Pages visited and features used within the app (aggregated, not tied to individual identity on the free tier).",
            "Scan metadata: repository URL, scan timestamp, score, and finding counts. Not the source code content itself.",
          ]} />

          <Highlight
            icon="🔒"
            title="What we do NOT collect"
            body="We do not collect your source code content. Files are read in memory during scanning and are never written to any database or persistent storage. We do not collect passwords (Stripe handles payment credentials). We do not collect sensitive personal information beyond what is listed above."
          />
        </Section>

        {/* ── 2. How Scanning Works ── */}
        <Section id="scanning" title="How Scanning Works">
          <P>
            This section explains exactly what happens to your code when you submit it for scanning.
            We are transparent about this because we understand that submitting source code to a
            third-party service requires trust.
          </P>

          <Highlight
            icon="⚡"
            title="Public GitHub repository scan"
            body="When you submit a public GitHub URL, we fetch the repository content using the GitHub public API. The code is cloned into a temporary sandboxed directory on our server, analyzed in memory, and the temporary directory is deleted immediately after the scan — whether it succeeds, fails, or times out. The source code is never written to a database."
          />

          <Highlight
            icon="📁"
            title="ZIP file upload"
            body="When you upload a ZIP file, it is received, extracted to a temporary sandboxed directory, analyzed in memory, and the temporary directory is deleted immediately after the scan. The ZIP file and its contents are never written to a database or persistent storage."
          />

          <Highlight
            icon="🔑"
            title="Private repository scan (OAuth token)"
            body="If you provide a GitHub OAuth token to scan a private repository, the token is used only for that single API request and is never stored in our database or logs. It exists in memory for the duration of the scan only."
          />

          <P>
            What IS stored: scan metadata — the repository URL, timestamp, finding counts by severity,
            the Quantum Readiness Score, and your user ID (if authenticated). This metadata is stored
            in our database to power scan history and analytics features.
            The actual source code content is never stored.
          </P>
        </Section>

        {/* ── 3. How We Use Information ── */}
        <Section id="usage" title="How We Use Information">
          <P>We use the information we collect for these specific purposes:</P>
          <List items={[
            "Providing the scanning service — analyzing your code and returning findings.",
            "Authentication — verifying your identity when you log in.",
            "Rate limiting — ensuring fair usage across all users.",
            "Billing — processing payments via Stripe for paid plans.",
            "Scan history — showing you your past scans and scores on authenticated accounts.",
            "Service improvement — understanding which features are used most and where errors occur.",
            "Security — detecting and preventing abuse, fraud, and unauthorized access.",
            "Legal compliance — complying with applicable laws and regulations.",
          ]} />

          <Highlight
            icon="⚠️"
            title="What we do NOT use your information for"
            body="We do not sell your personal information. We do not use your data for advertising. We do not share your scan results with any third party. We do not use your source code to train machine learning models."
            color={C.amber}
            bg={C.amberDim}
            border={C.amberBorder}
          />
        </Section>

        {/* ── 4. Data Retention ── */}
        <Section id="retention" title="Data Retention">
          <P>We retain different types of data for different periods:</P>

          <div style={{
            background: C.card, border: `1px solid ${C.border}`,
            borderRadius: 10, overflow: "hidden", marginBottom: 14,
          }}>
            {[
              ["Source code content",      "Deleted immediately after scan — never persisted"],
              ["Scan metadata",            "Retained while your account is active; deleted on account deletion"],
              ["Account information",      "Retained until you delete your account"],
              ["Payment records",          "Retained as required by law (typically 7 years for financial records)"],
              ["Server logs (IP, etc.)",   "Retained for 30 days for security and debugging purposes"],
              ["Aggregated analytics",     "Retained indefinitely in anonymised, non-identifiable form"],
            ].map(([type, retention], i, arr) => (
              <div key={i} style={{
                display: "flex", justifyContent: "space-between", alignItems: "flex-start",
                padding: "12px 16px", gap: 16, flexWrap: "wrap",
                borderBottom: i < arr.length - 1 ? `1px solid ${C.border}` : "none",
              }}>
                <span style={{ fontSize: 13, color: C.text, fontWeight: 500, flex: 1 }}>{type}</span>
                <span style={{ fontSize: 12, color: C.mid, textAlign: "right", maxWidth: 280 }}>{retention}</span>
              </div>
            ))}
          </div>

          <P>
            You can request deletion of your account and all associated data at any time by
            emailing <a href="mailto:privacy@quantumguard.site"
              style={{ color: C.green, textDecoration: "none" }}>privacy@quantumguard.site</a>.
            We will process deletion requests within 30 days.
          </P>
        </Section>

        {/* ── 5. Data Sharing ── */}
        <Section id="sharing" title="Data Sharing">
          <P>
            We do not sell, trade, or rent your personal information to any third party.
            We share data only in these limited circumstances:
          </P>

          <List items={[
            "Stripe — payment processing for Pro, Team, and Enterprise plans. Stripe's privacy policy applies to payment data. We never see your full card number.",
            "Render.com — our cloud infrastructure provider. Server logs and application data reside on Render's infrastructure. Render's privacy policy applies.",
            "Law enforcement — we may disclose information if required by law, court order, or to protect the rights, property, or safety of QuantumGuard, our users, or the public.",
            "Business transfer — in the event of a merger, acquisition, or sale of assets, your data may be transferred. We will notify you before your data is subject to a different privacy policy.",
          ]} />

          <P>
            We do not share your scan results, source code, or security findings with any
            third party under any circumstances.
          </P>
        </Section>

        {/* ── 6. Cookies & Analytics ── */}
        <Section id="cookies" title="Cookies & Analytics">
          <P>We use a minimal set of cookies necessary to operate the service:</P>
          <List items={[
            "Authentication cookies — keep you logged in between sessions. Session-scoped, deleted on logout.",
            "CSRF protection tokens — prevent cross-site request forgery attacks. Security-essential.",
            "Preference cookies — remember your UI preferences (e.g. theme). Optional.",
          ]} />
          <P>
            We do not use advertising cookies. We do not use third-party tracking pixels.
            If we add analytics in the future, we will update this policy and prefer
            privacy-preserving tools (such as Plausible Analytics) that do not track
            individuals across sites.
          </P>
        </Section>

        {/* ── 7. Security ── */}
        <Section id="security" title="Security">
          <P>We take reasonable technical measures to protect your information:</P>
          <List items={[
            "All data in transit is encrypted via HTTPS/TLS 1.3.",
            "Passwords are hashed using industry-standard algorithms — we cannot recover your password.",
            "The scanner is sandboxed — repository scans run in isolated temporary directories.",
            "SSRF protection prevents the scanner from making requests to internal network resources.",
            "ZIP path traversal prevention stops malicious archives from escaping their sandbox.",
            "JWT authentication tokens expire after 24 hours.",
            "Rate limiting prevents abuse and brute-force attacks.",
            "The scanner source code is open source — security researchers can audit it.",
          ]} />
          <P>
            No system is completely secure. If you discover a security vulnerability in QuantumGuard,
            please report it responsibly to{" "}
            <a href="mailto:security@quantumguard.site" style={{ color: C.green, textDecoration: "none" }}>
              security@quantumguard.site
            </a>.
            We will acknowledge reports within 48 hours.
          </P>
        </Section>

        {/* ── 8. Your Rights ── */}
        <Section id="rights" title="Your Rights">
          <P>
            Depending on your location, you may have the following rights regarding your personal data:
          </P>
          <List items={[
            "Right to access — request a copy of the personal data we hold about you.",
            "Right to correction — request correction of inaccurate personal data.",
            "Right to deletion — request deletion of your account and associated personal data.",
            "Right to portability — request your data in a machine-readable format.",
            "Right to object — object to certain types of processing of your personal data.",
            "Right to withdraw consent — where processing is based on consent, withdraw it at any time.",
          ]} />
          <P>
            To exercise any of these rights, email{" "}
            <a href="mailto:privacy@quantumguard.site" style={{ color: C.green, textDecoration: "none" }}>
              privacy@quantumguard.site
            </a>. We will respond within 30 days.
            We may need to verify your identity before processing certain requests.
          </P>
          <Highlight
            icon="🇪🇺"
            title="EU / EEA users (GDPR)"
            body="If you are located in the European Union or European Economic Area, you have additional rights under the General Data Protection Regulation (GDPR). Our lawful basis for processing is: contract performance (providing the scanning service), legitimate interests (security, fraud prevention), and legal obligation. You have the right to lodge a complaint with your local supervisory authority."
          />
        </Section>

        {/* ── 9. Children's Privacy ── */}
        <Section id="children" title="Children's Privacy">
          <P>
            QuantumGuard is not directed at children under the age of 13 (or 16 in the EU).
            We do not knowingly collect personal information from children.
            If you believe a child has provided us with personal information, please contact us
            at{" "}
            <a href="mailto:privacy@quantumguard.site" style={{ color: C.green, textDecoration: "none" }}>
              privacy@quantumguard.site
            </a>{" "}
            and we will delete it promptly.
          </P>
        </Section>

        {/* ── 10. Changes ── */}
        <Section id="changes" title="Changes to This Policy">
          <P>
            We may update this Privacy Policy from time to time. When we make material changes,
            we will notify you by:
          </P>
          <List items={[
            "Posting the updated policy on this page with a new effective date.",
            "Sending an email to registered users if the changes significantly affect how we handle your data.",
            "Displaying a notice in the application.",
          ]} />
          <P>
            Continued use of QuantumGuard after changes to this policy constitutes acceptance
            of the updated terms. If you disagree with the updated policy, you may delete your
            account at any time.
          </P>
        </Section>

        {/* ── 11. Contact ── */}
        <Section id="contact" title="Contact Us">
          <P>
            If you have questions, concerns, or requests regarding this Privacy Policy or
            how we handle your data, please contact us:
          </P>

          <div style={{
            background: C.card, border: `1px solid ${C.border}`,
            borderRadius: 12, padding: "20px 24px",
          }}>
            {[
              ["Company",   "Mangsri QuantumGuard LLC"],
              ["Address",   "Montgomery, Alabama, USA"],
              ["Email",     "privacy@quantumguard.site"],
              ["Security",  "security@quantumguard.site"],
              ["Website",   "quantumguard.site"],
              ["GitHub",    "github.com/cybersupe/quantumguard"],
            ].map(([label, value], i) => (
              <div key={i} style={{
                display: "flex", gap: 16, padding: "8px 0",
                borderBottom: i < 5 ? `1px solid ${C.border}` : "none",
              }}>
                <span style={{ fontSize: 12, color: C.muted, width: 80, flexShrink: 0, fontWeight: 600, textTransform: "uppercase", letterSpacing: ".05em", paddingTop: 1 }}>{label}</span>
                <span style={{ fontSize: 13, color: C.mid }}>
                  {label === "Email" || label === "Security" ? (
                    <a href={`mailto:${value}`} style={{ color: C.green, textDecoration: "none" }}>{value}</a>
                  ) : label === "Website" ? (
                    <a href="https://quantumguard.site" style={{ color: C.green, textDecoration: "none" }}>{value}</a>
                  ) : label === "GitHub" ? (
                    <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer" style={{ color: C.green, textDecoration: "none" }}>{value}</a>
                  ) : value}
                </span>
              </div>
            ))}
          </div>
        </Section>

        {/* Footer note */}
        <div style={{
          borderTop: `1px solid ${C.border}`, paddingTop: 32,
          fontSize: 12, color: C.muted, lineHeight: 1.7,
        }}>
          This Privacy Policy was last updated on May 5, 2026.
          It applies to all users of quantumguard.site and the QuantumGuard API.
          Mangsri QuantumGuard LLC is a limited liability company registered in Alabama, USA.
        </div>
      </div>
    </div>
  );
}
