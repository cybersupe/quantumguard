# ============================================================
# QuantumGuard — Unified Risk Engine v2.0  (Enterprise)
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# ============================================================
#
# v2.0 changes:
#   PHASE 5  Executive risk layer — business_impact, exploitability, priority
#   PHASE 6  Score engine aligned with scan.py v3.0
#   FIX-1    Weights: code=50%, TLS=30%, agility=20% (consistent with api.py)
#   FIX-2    LOW confidence excluded from all score calculations
#   FIX-3    Library findings excluded from score
# ============================================================

from typing import Dict, List, Any, Optional


# ── Severity weights (used in code risk score) ────────────────
SEVERITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH":     12,
    "MEDIUM":    5,
    "LOW":       0,   # LOW confidence = no penalty
}

CONFIDENCE_MULTIPLIERS = {
    "HIGH":   1.0,
    "MEDIUM": 0.6,
    "LOW":    0.0,
}


def _clamp(score: float) -> int:
    return max(0, min(100, int(round(score))))


def _risk_level(score: int) -> str:
    if score >= 85: return "LOW RISK"
    if score >= 70: return "MODERATE RISK"
    if score >= 50: return "HIGH RISK"
    return "CRITICAL RISK"


def _business_summary(score: int, clean: bool) -> str:
    if clean:
        return "Code appears clean. No exploitable crypto risks detected. Continue monitoring NIST PQC updates."
    if score >= 85:
        return "Strong current posture. Continue monitoring post-quantum migration readiness."
    if score >= 70:
        return "Good baseline security, but post-quantum migration planning is recommended."
    if score >= 50:
        return "Several cryptographic risks require remediation before enterprise use."
    return "Critical cryptographic weaknesses detected. Immediate remediation is recommended."


# ══════════════════════════════════════════════════════════════
# PHASE 5: Executive risk aggregation
# ══════════════════════════════════════════════════════════════

def _aggregate_executive_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate priority, business_impact, and exploitability across all findings.
    Returns the worst-case values.
    """
    priority_rank = {"P0":0,"P1":1,"P2":2,"P3":3}
    impact_rank   = {"HIGH":0,"MEDIUM":1,"LOW":2}
    exploit_rank  = {"EASY":0,"MODERATE":1,"HARD":2}

    worst_priority  = "P3"
    worst_impact    = "LOW"
    worst_exploit   = "HARD"
    p0_count        = 0
    p1_count        = 0

    for f in findings:
        if f.get("confidence") == "LOW":
            continue
        if f.get("is_library_file"):
            continue

        pri  = f.get("priority", "P2")
        imp  = f.get("business_impact", "LOW")
        expl = f.get("exploitability", "HARD")

        if priority_rank.get(pri, 3) < priority_rank.get(worst_priority, 3):
            worst_priority = pri
        if impact_rank.get(imp, 2) < impact_rank.get(worst_impact, 2):
            worst_impact = imp
        if exploit_rank.get(expl, 2) < exploit_rank.get(worst_exploit, 2):
            worst_exploit = expl

        if pri == "P0": p0_count += 1
        if pri == "P1": p1_count += 1

    return {
        "overall_priority":    worst_priority,
        "business_impact":     worst_impact,
        "exploitability":      worst_exploit,
        "p0_findings":         p0_count,
        "p1_findings":         p1_count,
        "immediate_action":    worst_priority == "P0",
    }


# ══════════════════════════════════════════════════════════════
# Finding summary
# ══════════════════════════════════════════════════════════════

def summarize_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    severity_summary   = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    confidence_summary = {"HIGH":0,"MEDIUM":0,"LOW":0}
    context_summary: Dict[str,int] = {}
    top_findings: List[Dict] = []

    for f in findings or []:
        sev  = f.get("severity",   "MEDIUM")
        conf = f.get("confidence", "MEDIUM")
        ctx  = f.get("usage_context", "unknown")

        severity_summary[sev]   = severity_summary.get(sev, 0) + 1
        confidence_summary[conf] = confidence_summary.get(conf, 0) + 1
        context_summary[ctx]     = context_summary.get(ctx, 0) + 1

        if len(top_findings) < 10 and conf != "LOW" and not f.get("is_library_file"):
            top_findings.append({
                "file":             f.get("file"),
                "line":             f.get("line"),
                "vulnerability":    f.get("vulnerability"),
                "severity":         sev,
                "confidence":       conf,
                "confidence_score": f.get("confidence_score", 0.5),
                "usage_context":    ctx,
                "priority":         f.get("priority", "P2"),
                "business_impact":  f.get("business_impact", "MEDIUM"),
                "exploitability":   f.get("exploitability", "MODERATE"),
                "recommended_fix":  f.get("recommended_fix") or f.get("replacement"),
            })

    return {
        "severity_summary":   severity_summary,
        "confidence_summary": confidence_summary,
        "context_summary":    context_summary,
        "top_findings":       top_findings,
    }


# ══════════════════════════════════════════════════════════════
# Component scores
# ══════════════════════════════════════════════════════════════

def calculate_code_risk_score(findings: List[Dict[str, Any]]) -> int:
    """
    PHASE 6: Linear deduction model, unique findings only.
    Consistent with scan.py calculate_score().
    """
    real = [
        f for f in (findings or [])
        if f.get("confidence") != "LOW"
        and not f.get("is_library_file", False)
    ]
    if not real:
        return 100

    # Deduplicate by (vuln, file)
    unique: Dict[tuple, Dict] = {}
    for f in real:
        key = (f.get("vulnerability",""), f.get("file",""))
        if key not in unique:
            unique[key] = f
        else:
            sev_rank = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
            if sev_rank.get(f.get("severity",""),0) > sev_rank.get(unique[key].get("severity",""),0):
                unique[key] = f

    deductions = {"CRITICAL":-20,"HIGH":-12,"MEDIUM":-5}
    score = 100.0
    critical_count = 0

    for f in unique.values():
        sev = f.get("severity","MEDIUM")
        score += deductions.get(sev, -5)
        if sev == "CRITICAL":
            critical_count += 1

    if critical_count >= 10:
        score = min(score, 25)
    elif critical_count >= 5:
        score = min(score, 40)

    return max(0, min(100, int(round(score))))


def calculate_agility_risk_score(agility_result: Optional[Dict[str, Any]]) -> int:
    if not agility_result:
        return 50
    score = agility_result.get("agility_score")
    return _clamp(score) if score is not None else 50


def calculate_tls_risk_score(tls_result: Optional[Dict[str, Any]]) -> int:
    if not tls_result:
        return 50
    score = tls_result.get("tls_score")
    return _clamp(score) if score is not None else 50


# ══════════════════════════════════════════════════════════════
# Priority actions
# ══════════════════════════════════════════════════════════════

def generate_priority_actions(
    findings: List[Dict[str, Any]],
    agility_result: Optional[Dict[str, Any]],
    tls_result: Optional[Dict[str, Any]],
) -> List[Dict[str, str]]:
    actions = []

    real = [f for f in (findings or []) if f.get("confidence") != "LOW" and not f.get("is_library_file")]

    p0_count  = sum(1 for f in real if f.get("priority") == "P0")
    crit_count = sum(1 for f in real if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in real if f.get("severity") == "HIGH")

    if p0_count:
        actions.append({
            "priority":    "P0",
            "title":       "Immediate action required — P0 vulnerabilities detected",
            "description": f"{p0_count} P0 findings (RC4, MD4, hardcoded secrets, JWT none algorithm) require immediate remediation.",
            "timeline":    "Within 7 days",
        })
    if crit_count and not p0_count:
        actions.append({
            "priority":    "P1",
            "title":       "Remediate critical cryptographic findings",
            "description": f"{crit_count} critical findings detected. Remove broken or quantum-vulnerable algorithms.",
            "timeline":    "Within 30 days",
        })
    if high_count:
        actions.append({
            "priority":    "P1" if not p0_count else "P2",
            "title":       "Fix high-severity crypto risks",
            "description": f"{high_count} high-severity findings. Prioritize auth, token, key, and encryption files.",
            "timeline":    "Within 90 days",
        })

    if agility_result:
        hardcoded = agility_result.get("hardcoded_count", 0)
        if hardcoded > 0:
            actions.append({
                "priority":    "P2",
                "title":       "Improve crypto agility",
                "description": f"{hardcoded} hardcoded crypto patterns. Move algorithms and key sizes to configuration.",
                "timeline":    "Within 90 days",
            })

    if tls_result:
        if not tls_result.get("quantum_safe", False):
            actions.append({
                "priority":    "P3",
                "title":       "Plan post-quantum TLS migration",
                "description": "TLS is secure today but not post-quantum safe. Monitor hybrid ML-KEM/FIPS 203 TLS adoption.",
                "timeline":    "Before 2028",
            })
        issues = tls_result.get("issues", [])
        if any("expired" in i.lower() or "expir" in i.lower() for i in issues):
            actions.append({
                "priority":    "P1",
                "title":       "Renew TLS certificate",
                "description": "Certificate expiry warning. Renew before expiration to avoid service disruption.",
                "timeline":    "Immediately",
            })

    if not actions:
        actions.append({
            "priority":    "P4",
            "title":       "Maintain monitoring",
            "description": "No major issues detected. Continue periodic scans and track NIST PQC updates.",
            "timeline":    "Ongoing",
        })

    return actions[:6]


# ══════════════════════════════════════════════════════════════
# Main entry point
# ══════════════════════════════════════════════════════════════

def calculate_unified_quantum_risk(
    findings: List[Dict[str, Any]],
    agility_result: Optional[Dict[str, Any]] = None,
    tls_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Weighted unified risk score:
      code=50%, TLS=30%, agility=20%
    Includes Phase 5 executive risk layer.
    """
    # Component scores
    code_score    = calculate_code_risk_score(findings)
    tls_score     = calculate_tls_risk_score(tls_result)
    agility_score = calculate_agility_risk_score(agility_result)

    final_score = _clamp(
        (code_score    * 0.50) +
        (tls_score     * 0.30) +
        (agility_score * 0.20)
    )

    # PHASE 7: clean repo check
    from scanner.scan import is_clean_repo
    clean = is_clean_repo(findings)

    # PHASE 5: executive aggregation
    exec_risk = _aggregate_executive_risk(findings)

    finding_summary = summarize_findings(findings)

    return {
        "quantum_risk_score":  final_score,
        "risk_level":          _risk_level(final_score),
        "clean_repo":          clean,
        "business_summary":    _business_summary(final_score, clean),

        # PHASE 5
        "executive_risk": {
            "overall_priority":  exec_risk["overall_priority"],
            "business_impact":   exec_risk["business_impact"],
            "exploitability":    exec_risk["exploitability"],
            "p0_findings":       exec_risk["p0_findings"],
            "p1_findings":       exec_risk["p1_findings"],
            "immediate_action":  exec_risk["immediate_action"],
        },

        "component_scores": {
            "code_crypto_score":    code_score,
            "tls_score":            tls_score,
            "crypto_agility_score": agility_score,
        },
        "finding_summary":    finding_summary,
        "priority_actions":   generate_priority_actions(findings, agility_result, tls_result),
        "standards_alignment": {
            "NIST_FIPS_203": "ML-KEM for key establishment",
            "NIST_FIPS_204": "ML-DSA for digital signatures",
            "NIST_FIPS_205": "SLH-DSA for stateless hash-based signatures",
            "note":          "Recommendations are migration guidance, not a formal certification.",
        },
        "executive_status": {
            "ready_for_demo":             final_score >= 70,
            "ready_for_enterprise_pilot": (
                final_score >= 80 and
                finding_summary["severity_summary"].get("CRITICAL", 0) == 0 and
                exec_risk["overall_priority"] not in ("P0",)
            ),
        },
    }
