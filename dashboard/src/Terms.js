// ══════════════════════════════════════════════════════════════
// Terms.jsx — QuantumGuard Terms of Service
// Replace your existing Terms.jsx with this file entirely.
// No other files need to change.
// Effective date: May 5, 2026
// ══════════════════════════════════════════════════════════════

export default function Terms() {
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
    redDim:      "rgba(239,68,68,0.08)",
    redBorder:   "rgba(239,68,68,0.2)",
    blue:        "#3b82f6",
    blueDim:     "rgba(59,130,246,0.08)",
    blueBorder:  "rgba(59,130,246,0.2)",
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

  const Callout = ({ icon, title, body, color=C.green, bg=C.greenDim, border=C.greenBorder }) => (
    <div style={{
      background: bg, border: `1px solid ${border}`,
      borderLeft: `3px solid ${color}`,
      borderRadius: "0 10px 10px 0",
      padding: "14px 18px", marginBottom: 16,
    }}>
      {title && (
        <div style={{ fontSize: 13, fontWeight: 700, color, marginBottom: 4 }}>
          {icon} {title}
        </div>
      )}
      <div style={{ fontSize: 13, color: C.mid, lineHeight: 1.7 }}>{body}</div>
    </div>
  );

  const List = ({ items, cross = false }) => (
    <ul style={{ paddingLeft: 0, listStyle: "none", marginBottom: 14 }}>
      {items.map((item, i) => (
        <li key={i} style={{
          display: "flex", gap: 10, alignItems: "flex-start",
          fontSize: 13, color: C.mid, marginBottom: 8, lineHeight: 1.65,
        }}>
          <span style={{
            color: cross ? C.red : C.green,
            flexShrink: 0, marginTop: 2, fontWeight: 700,
          }}>
            {cross ? "✕" : "✓"}
          </span>
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );

  const TOC = [
    ["acceptance",     "1. Acceptance of Terms"],
    ["description",    "2. Description of Service"],
    ["eligibility",    "3. Eligibility"],
    ["account",        "4. Account Registration"],
    ["acceptable",     "5. Acceptable Use"],
    ["prohibited",     "6. Prohibited Uses"],
    ["ip",             "7. Intellectual Property"],
    ["disclaimer",     "8. Disclaimers & Limitations"],
    ["liability",      "9. Limitation of Liability"],
    ["indemnification","10. Indemnification"],
    ["payment",        "11. Payment & Billing"],
    ["termination",    "12. Termination"],
    ["governing",      "13. Governing Law"],
    ["changes",        "14. Changes to Terms"],
    ["contact",        "15. Contact"],
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
            Terms of Service
          </h1>
          <p style={{ fontSize: 15, color: C.mid, marginBottom: 20, lineHeight: 1.7 }}>
            These Terms of Service govern your use of QuantumGuard, operated by{" "}
            <strong style={{ color: C.text }}>Mangsri QuantumGuard LLC</strong>.
            By using QuantumGuard, you agree to these terms. Please read them carefully.
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

        {/* Key points summary */}
        <div style={{
          background: C.greenDim, border: `1px solid ${C.greenBorder}`,
          borderRadius: 14, padding: "20px 24px", marginBottom: 48,
        }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: C.green, marginBottom: 12 }}>
            Summary — plain English
          </div>
          <List items={[
            "QuantumGuard is a security scanning tool. Results are guidance — not a guarantee of security.",
            "You must not use QuantumGuard to scan code you do not own or have permission to scan.",
            "Your source code is never permanently stored. See our Privacy Policy for details.",
            "The free tier is provided as-is. Paid plans include the features listed at the time of purchase.",
            "We are not liable for decisions made based on QuantumGuard scan results.",
            "You are responsible for validating results before making production security decisions.",
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
                fontSize: 13, color: C.mid, textDecoration: "none", transition: "color .15s",
              }}
                onMouseEnter={e => e.currentTarget.style.color = C.green}
                onMouseLeave={e => e.currentTarget.style.color = C.mid}>
                {label}
              </a>
            ))}
          </div>
        </div>

        {/* ── 1. Acceptance ── */}
        <Section id="acceptance" title="Acceptance of Terms">
          <P>
            By accessing or using QuantumGuard at quantumguard.site (the "Service"), you agree
            to be bound by these Terms of Service ("Terms"). If you do not agree to these Terms,
            you may not use the Service.
          </P>
          <P>
            These Terms apply to all users of the Service, including free-tier users, registered
            account holders, and paid subscribers. By creating an account or submitting a scan,
            you represent that you have read, understood, and agree to these Terms.
          </P>
          <P>
            If you are using the Service on behalf of an organization, you represent that you
            have the authority to bind that organization to these Terms, and references to "you"
            include both you and that organization.
          </P>
        </Section>

        {/* ── 2. Description ── */}
        <Section id="description" title="Description of Service">
          <P>
            QuantumGuard is a post-quantum cryptography readiness scanning platform that analyzes
            source code, dependency manifests, and TLS configurations to identify
            quantum-vulnerable cryptographic algorithms and provide migration guidance aligned
            with NIST post-quantum cryptography standards (FIPS 203, 204, 205).
          </P>
          <P>The Service includes the following capabilities:</P>
          <List items={[
            "Source code scanning for quantum-vulnerable algorithms (RSA, ECC, DH, DSA, MD5, SHA-1, RC4, DES, and others).",
            "Dependency manifest analysis across Python, JavaScript, Java, Go, Rust, and Ruby ecosystems.",
            "TLS configuration analysis for any domain.",
            "Quantum Readiness Score generation (0–100).",
            "Cryptographic Bill of Materials (CBOM) export.",
            "NIST-aligned migration guidance for each finding.",
            "GitHub Actions CI/CD integration (paid plans).",
            "Organization dashboards and team features (paid plans).",
          ]} />

          <Callout
            icon="⚠️"
            title="Important limitation"
            body="QuantumGuard provides security insights and migration guidance. It is a static analysis tool. It does not guarantee detection of all cryptographic vulnerabilities, does not perform dynamic or runtime analysis, and does not constitute a formal security audit. Results should be reviewed and validated by qualified security professionals before making production security decisions."
            color={C.amber}
            bg={C.amberDim}
            border={C.amberBorder}
          />
        </Section>

        {/* ── 3. Eligibility ── */}
        <Section id="eligibility" title="Eligibility">
          <P>You must meet the following requirements to use the Service:</P>
          <List items={[
            "You must be at least 18 years of age, or the age of legal majority in your jurisdiction.",
            "You must have the legal capacity to enter into a binding agreement.",
            "You must not be located in a country subject to US government embargo or sanctions.",
            "Your use of the Service must comply with all applicable local, national, and international laws.",
          ]} />
          <P>
            If you are under 18, you may only use the Service with the involvement and consent
            of a parent or legal guardian who agrees to be bound by these Terms.
          </P>
        </Section>

        {/* ── 4. Account ── */}
        <Section id="account" title="Account Registration">
          <P>
            Certain features of the Service require you to create an account. When creating
            an account, you agree to:
          </P>
          <List items={[
            "Provide accurate, current, and complete information.",
            "Maintain and promptly update your account information.",
            "Keep your password confidential and not share it with others.",
            "Notify us immediately of any unauthorized access to your account.",
            "Accept responsibility for all activity that occurs under your account.",
          ]} />
          <P>
            You may not create an account using a false identity, impersonate another person
            or entity, or create multiple accounts to circumvent usage limits.
            We reserve the right to suspend or terminate accounts that violate these Terms.
          </P>
          <P>
            The free tier does not require account creation. Scan metadata from unauthenticated
            scans is not associated with any user account.
          </P>
        </Section>

        {/* ── 5. Acceptable Use ── */}
        <Section id="acceptable" title="Acceptable Use">
          <P>You may use QuantumGuard for the following purposes:</P>
          <List items={[
            "Scanning source code repositories that you own or have explicit written permission to scan.",
            "Scanning domains and TLS configurations that you own or administer.",
            "Security research and vulnerability assessment on systems you are authorized to test.",
            "Education and learning about post-quantum cryptography.",
            "Generating cryptographic inventories for your organization's internal use.",
            "Integration into CI/CD pipelines for repositories you control.",
            "Generating CBOM and compliance reports for your organization.",
          ]} />
        </Section>

        {/* ── 6. Prohibited Uses ── */}
        <Section id="prohibited" title="Prohibited Uses">
          <P>You must not use the Service for any of the following:</P>
          <List cross items={[
            "Scanning source code, repositories, or systems you do not own and do not have explicit authorization to scan.",
            "Attempting to circumvent rate limits through automated requests, multiple accounts, or other means.",
            "Using the Service to facilitate unauthorized access to computer systems.",
            "Submitting malicious code, ZIP bombs, or other files designed to disrupt the Service.",
            "Scraping, reverse-engineering, or attempting to extract the underlying scanning logic or pattern database.",
            "Reselling or sublicensing access to the Service without written permission.",
            "Using the Service in any manner that violates applicable law, including computer fraud and abuse laws.",
            "Attempting to overwhelm or disrupt the Service through denial-of-service attacks.",
            "Using the Service to scan competitors' proprietary code obtained without authorization.",
            "Misrepresenting QuantumGuard scan results as a formal security certification or audit.",
          ]} />

          <Callout
            icon="🚨"
            title="Authorization requirement"
            body="Scanning code or systems without authorization may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in other jurisdictions. You are solely responsible for ensuring you have proper authorization before scanning any repository or system. Mangsri QuantumGuard LLC accepts no liability for unauthorized scanning performed using the Service."
            color={C.red}
            bg={C.redDim}
            border={C.redBorder}
          />
        </Section>

        {/* ── 7. IP ── */}
        <Section id="ip" title="Intellectual Property">
          <P>
            <strong style={{ color: C.text }}>Our intellectual property:</strong> The QuantumGuard
            platform, including the web application, API, branding, and documentation, is owned
            by Mangsri QuantumGuard LLC. The QuantumGuard name and logo are trademarks of
            Mangsri QuantumGuard LLC.
          </P>
          <P>
            <strong style={{ color: C.text }}>Open source scanner:</strong> The core scanning
            engine is open source software released under the GNU Affero General Public License
            v3 (AGPL v3). The terms of the AGPL v3 govern your use of that code. You can view
            and audit the source code at{" "}
            <a href="https://github.com/cybersupe/quantumguard" target="_blank" rel="noreferrer"
              style={{ color: C.green, textDecoration: "none" }}>
              github.com/cybersupe/quantumguard
            </a>.
          </P>
          <P>
            <strong style={{ color: C.text }}>Your content:</strong> You retain all rights
            to any source code, repositories, or other content you submit to the Service.
            By submitting content for scanning, you grant us a limited, temporary license to
            process that content solely for the purpose of providing the scanning service.
            This license terminates immediately upon completion of the scan.
          </P>
          <P>
            <strong style={{ color: C.text }}>Scan results:</strong> The scan results, reports,
            and CBOM generated for your repositories are yours. We do not claim any ownership
            over your scan results.
          </P>
        </Section>

        {/* ── 8. Disclaimers ── */}
        <Section id="disclaimer" title="Disclaimers & Limitations">
          <Callout
            icon="⚠️"
            title="Service provided as-is"
            body='THE SERVICE IS PROVIDED "AS IS" AND "AS AVAILABLE" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED. MANGSRI QUANTUMGUARD LLC DISCLAIMS ALL WARRANTIES, INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.'
            color={C.amber}
            bg={C.amberDim}
            border={C.amberBorder}
          />

          <P>Specifically, we do not warrant that:</P>
          <List cross items={[
            "The Service will detect all quantum-vulnerable cryptographic algorithms in your codebase.",
            "The Service will be uninterrupted, error-free, or available at any particular time.",
            "The results produced by the Service are complete, accurate, or suitable for any particular purpose.",
            "The migration guidance provided constitutes professional security advice.",
            "The Service is free from false positives or false negatives.",
            "Following the migration guidance will render your system fully quantum-safe.",
          ]} />

          <P>
            <strong style={{ color: C.text }}>Not a security audit:</strong> QuantumGuard is a
            static analysis tool. It is not a substitute for a professional cryptographic security
            audit. The Service does not perform dynamic analysis, runtime monitoring, or penetration
            testing. Results should be reviewed and validated by qualified security professionals
            before making production security decisions.
          </P>

          <P>
            <strong style={{ color: C.text }}>Not NIST certified:</strong> QuantumGuard provides
            NIST-aligned migration guidance based on NIST FIPS 203, 204, and 205. QuantumGuard
            is not affiliated with, endorsed by, or certified by NIST. The guidance is
            informational and does not constitute NIST certification or compliance attestation.
          </P>
        </Section>

        {/* ── 9. Liability ── */}
        <Section id="liability" title="Limitation of Liability">
          <P>
            TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, MANGSRI QUANTUMGUARD LLC AND ITS
            OFFICERS, DIRECTORS, EMPLOYEES, AND AGENTS SHALL NOT BE LIABLE FOR:
          </P>
          <List cross items={[
            "Any indirect, incidental, special, consequential, or punitive damages.",
            "Loss of profits, revenue, data, goodwill, or other intangible losses.",
            "Damages arising from your reliance on scan results without independent validation.",
            "Security incidents, data breaches, or other harms that occur despite using the Service.",
            "Damages arising from unauthorized use of the Service by third parties.",
            "Costs of procurement of substitute goods or services.",
          ]} />
          <P>
            IN NO EVENT SHALL OUR TOTAL LIABILITY TO YOU FOR ALL CLAIMS ARISING OUT OF OR
            RELATING TO THE SERVICE EXCEED THE GREATER OF: (A) THE AMOUNT YOU PAID TO US IN
            THE 12 MONTHS PRECEDING THE CLAIM, OR (B) ONE HUNDRED US DOLLARS ($100).
          </P>
          <P>
            Some jurisdictions do not allow the exclusion or limitation of certain warranties
            or liability. In such jurisdictions, our liability is limited to the maximum extent
            permitted by law.
          </P>
        </Section>

        {/* ── 10. Indemnification ── */}
        <Section id="indemnification" title="Indemnification">
          <P>
            You agree to indemnify, defend, and hold harmless Mangsri QuantumGuard LLC and its
            officers, directors, employees, and agents from and against any claims, liabilities,
            damages, losses, costs, and expenses (including reasonable legal fees) arising out of:
          </P>
          <List items={[
            "Your use of the Service in violation of these Terms.",
            "Your scanning of repositories or systems without proper authorization.",
            "Your violation of any applicable law or regulation.",
            "Your infringement of any third-party intellectual property rights.",
            "Any content you submit to the Service.",
          ]} />
        </Section>

        {/* ── 11. Payment ── */}
        <Section id="payment" title="Payment & Billing">
          <P>
            <strong style={{ color: C.text }}>Free tier:</strong> The free tier of QuantumGuard
            is provided at no cost and includes 20 scans per day without account registration.
            We reserve the right to modify or discontinue the free tier at any time with
            reasonable notice.
          </P>
          <P>
            <strong style={{ color: C.text }}>Paid plans:</strong> Paid plans (Pro at $49/month,
            Team at $199/month) are billed monthly in advance. Enterprise pricing is custom.
            All payments are processed by Stripe. By subscribing, you authorize us to charge
            your payment method on a recurring basis.
          </P>
          <List items={[
            "Subscriptions automatically renew unless cancelled before the renewal date.",
            "You may cancel your subscription at any time through your account settings.",
            "Cancellation takes effect at the end of the current billing period — no mid-period refunds.",
            "We reserve the right to change pricing with 30 days written notice to active subscribers.",
            "All prices are in US dollars and exclusive of applicable taxes.",
            "You are responsible for any applicable taxes based on your location.",
          ]} />
          <P>
            <strong style={{ color: C.text }}>Refunds:</strong> We do not offer refunds for
            partial billing periods. If you believe you were charged in error, contact us at{" "}
            <a href="mailto:billing@quantumguard.site" style={{ color: C.green, textDecoration: "none" }}>
              billing@quantumguard.site
            </a>{" "}
            within 14 days of the charge and we will review it.
          </P>
        </Section>

        {/* ── 12. Termination ── */}
        <Section id="termination" title="Termination">
          <P>
            <strong style={{ color: C.text }}>Termination by you:</strong> You may stop using
            the Service at any time. To delete your account and associated data, email{" "}
            <a href="mailto:support@quantumguard.site" style={{ color: C.green, textDecoration: "none" }}>
              support@quantumguard.site
            </a>.
            Account deletion requests are processed within 30 days.
          </P>
          <P>
            <strong style={{ color: C.text }}>Termination by us:</strong> We reserve the right
            to suspend or terminate your access to the Service at any time, with or without
            notice, for any of the following reasons:
          </P>
          <List items={[
            "Violation of these Terms of Service.",
            "Conduct that we determine, in our sole discretion, is harmful to the Service or other users.",
            "Non-payment of applicable fees.",
            "Extended periods of account inactivity (we will provide notice before terminating inactive accounts).",
            "If we discontinue the Service.",
          ]} />
          <P>
            Upon termination, your right to use the Service ceases immediately. Provisions of
            these Terms that by their nature should survive termination — including intellectual
            property, disclaimer, limitation of liability, and indemnification sections —
            shall survive.
          </P>
        </Section>

        {/* ── 13. Governing Law ── */}
        <Section id="governing" title="Governing Law">
          <P>
            These Terms shall be governed by and construed in accordance with the laws of the
            State of Alabama, United States, without regard to its conflict of law provisions.
          </P>
          <P>
            Any dispute arising out of or relating to these Terms or the Service shall be
            resolved through binding arbitration in Montgomery, Alabama, USA, in accordance
            with the rules of the American Arbitration Association, except that either party
            may seek injunctive or other equitable relief in any court of competent jurisdiction.
          </P>
          <P>
            You agree that any claim arising out of or related to the Service must be filed
            within one (1) year after such claim arose, or the claim is permanently barred.
          </P>
          <P>
            If you are located in the European Union, you may also have rights under applicable
            EU law that supplement or modify these Terms.
          </P>
        </Section>

        {/* ── 14. Changes ── */}
        <Section id="changes" title="Changes to Terms">
          <P>
            We reserve the right to modify these Terms at any time. When we make material
            changes, we will:
          </P>
          <List items={[
            "Post the updated Terms with a new effective date.",
            "Notify registered users by email at least 14 days before the changes take effect.",
            "Display a prominent notice in the application.",
          ]} />
          <P>
            Your continued use of the Service after the effective date of the updated Terms
            constitutes your acceptance of the changes. If you do not agree to the updated
            Terms, you must stop using the Service before the effective date.
          </P>
        </Section>

        {/* ── 15. Contact ── */}
        <Section id="contact" title="Contact">
          <P>
            If you have questions about these Terms, please contact us:
          </P>
          <div style={{
            background: C.card, border: `1px solid ${C.border}`,
            borderRadius: 12, padding: "20px 24px",
          }}>
            {[
              ["Company",   "Mangsri QuantumGuard LLC"],
              ["Address",   "Montgomery, Alabama, USA"],
              ["General",   "support@quantumguard.site"],
              ["Billing",   "billing@quantumguard.site"],
              ["Legal",     "legal@quantumguard.site"],
              ["Security",  "security@quantumguard.site"],
              ["Website",   "quantumguard.site"],
            ].map(([label, value], i) => (
              <div key={i} style={{
                display: "flex", gap: 16, padding: "8px 0",
                borderBottom: i < 6 ? `1px solid ${C.border}` : "none",
              }}>
                <span style={{ fontSize: 12, color: C.muted, width: 80, flexShrink: 0,
                  fontWeight: 600, textTransform: "uppercase", letterSpacing: ".05em", paddingTop: 1 }}>
                  {label}
                </span>
                <span style={{ fontSize: 13, color: C.mid }}>
                  {["General","Billing","Legal","Security"].includes(label) ? (
                    <a href={`mailto:${value}`} style={{ color: C.green, textDecoration: "none" }}>{value}</a>
                  ) : label === "Website" ? (
                    <a href="https://quantumguard.site" style={{ color: C.green, textDecoration: "none" }}>{value}</a>
                  ) : value}
                </span>
              </div>
            ))}
          </div>
        </Section>

        {/* Footer */}
        <div style={{
          borderTop: `1px solid ${C.border}`, paddingTop: 32,
          fontSize: 12, color: C.muted, lineHeight: 1.7,
        }}>
          These Terms of Service were last updated on May 5, 2026 and are effective immediately.
          They supersede all prior versions of the Terms of Service for QuantumGuard.
          Mangsri QuantumGuard LLC is a limited liability company registered in Alabama, USA.
        </div>
      </div>
    </div>
  );
}
