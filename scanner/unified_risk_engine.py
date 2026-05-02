# ============================================================
# QuantumGuard — Unified Risk Engine v1.1
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# ============================================================
#
# v1.1 changes vs v1.0:
#   FIX-1  Weight alignment: api.py uses code=50%, TLS=30%, agility=20%.
#          v1.0 used code=50%, agility=30%, TLS=20% — mismatched.
#          Unified to: code=50%, TLS=30%, agility=20% across both files.
#   FIX-2  Score floor: v1.0 calculate_code_risk_score() could return
#          negative scores on codebases with many CRITICAL findings.
#          Now clamped to minimum 20 (consistent with scan.py calculate_score).
#   FIX-3  LOW confidence findings excluded from score calculation.
#          Previously all findings including LOW confidence were penalised.
# ============================================================

from typing import Dict, List, Any, Optional


SEVERITY_WEIGHTS = {
    "CRITICAL": 12,
    "HIGH":     7,
    "MEDIUM":   3,
    "LOW":      1,
}

CONFIDENCE_MULTIPLIERS = {
    "HIGH":   1.0,
    "MEDIUM": 0.6,
    "LOW":    0.0,   # FIX-3: LOW confidence = no penalty
}


def _clamp_score(score: int | float) -> int:
    return max(0, min(100, int(round(score))))


def _risk_level(score: int) -> str:
    if score >= 85: return "LOW RISK"
    if score >= 70: return "MODERATE RISK"
    if score >= 50: return "HIGH RISK"
    return "CRITICAL RISK"


def _business_summary(score: int) -> str:
    if score >= 85:
        return "Strong current posture. Continue monitoring post-quantum migration readiness."
    if score >= 70:
        return "Good baseline security, but post-quantum migration planning is recommended."
    if score >= 50:
        return "Several cryptographic risks require remediation before enterprise use."
    return "Critical cryptographic weaknesses detected. Immediate remediation is recommended."


def summarize_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    severity_summary   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    confidence_summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    top_findings       = []

    for f in findings or []:
        sev  = f.get("severity",   "MEDIUM")
        conf = f.get("confidence", "MEDIUM")
        severity_summary[sev]   = severity_summary.get(sev, 0) + 1
        confidence_summary[conf] = confidence_summary.get(conf, 0) + 1

        if len(top_findings) < 10 and conf != "LOW":
            top_findings.append({
                "file":           f.get("file"),
                "line":           f.get("line"),
                "vulnerability":  f.get("vulnerability"),
                "severity":       sev,
                "confidence":     conf,
                "recommended_fix": f.get("recommended_fix") or f.get("replacement"),
            })

    return {
        "severity_summary":   severity_summary,
        "confidence_summary": confidence_summary,
        "top_findings":       top_findings,
    }


def calculate_code_risk_score(findings: List[Dict[str, Any]]) -> int:
    """
    Convert scanner findings into a 0-100 code crypto safety score.
    Higher = safer. Minimum 20 (consistent with scan.py calculate_score).
    FIX-2: Floor at 20. FIX-3: LOW confidence excluded.
    """
    if not findings:
        return 100

    penalty = 0.0

    for f in findings:
        sev  = f.get("severity",   "MEDIUM")
        conf = f.get("confidence", "MEDIUM")

        # FIX-3: Skip LOW confidence
        if conf == "LOW":
            continue

        is_test = f.get("is_test_file", False)

        base       = SEVERITY_WEIGHTS.get(sev, 3)
        multiplier = CONFIDENCE_MULTIPLIERS.get(conf, 0.6)

        if is_test:
            multiplier *= 0.25

        # Auth/crypto/config files weighted higher
        file_path = str(f.get("file", "")).lower()
        if any(x in file_path for x in ["auth", "crypto", "security", "jwt", "token", "config", "key"]):
            multiplier *= 1.25

        penalty += base * multiplier

    # FIX-2: Floor at 20, not 0
    return max(20, _clamp_score(100 - penalty))


def calculate_agility_risk_score(agility_result: Optional[Dict[str, Any]]) -> int:
    if not agility_result:
        return 50
    score = agility_result.get("agility_score")
    return _clamp_score(score) if score is not None else 50


def calculate_tls_risk_score(tls_result: Optional[Dict[str, Any]]) -> int:
    if not tls_result:
        return 50
    score = tls_result.get("tls_score")
    return _clamp_score(score) if score is not None else 50


def generate_priority_actions(
    findings: List[Dict[str, Any]],
    agility_result: Optional[Dict[str, Any]],
    tls_result: Optional[Dict[str, Any]],
) -> List[Dict[str, str]]:
    actions = []

    critical_count = sum(1 for f in findings or [] if f.get("severity") == "CRITICAL" and f.get("confidence") != "LOW")
    high_count     = sum(1 for f in findings or [] if f.get("severity") == "HIGH"     and f.get("confidence") != "LOW")

    if critical_count:
        actions.append({
            "priority":    "P1",
            "title":       "Remediate critical cryptographic findings",
            "description": f"{critical_count} critical findings detected. Remove broken or quantum-vulnerable algorithms immediately.",
        })

    if high_count:
        actions.append({
            "priority":    "P2",
            "title":       "Fix high-severity crypto risks",
            "description": f"{high_count} high-severity findings detected. Prioritize auth, token, key, and encryption-related files.",
        })

    if agility_result:
        hardcoded = agility_result.get("hardcoded_count", 0)
        if hardcoded > 0:
            actions.append({
                "priority":    "P2",
                "title":       "Improve crypto agility",
                "description": f"{hardcoded} hardcoded crypto patterns detected. Move algorithms and key sizes into configuration.",
            })

    if tls_result:
        if not tls_result.get("quantum_safe", False):
            actions.append({
                "priority":    "P3",
                "title":       "Plan post-quantum TLS migration",
                "description": "TLS is secure today but not post-quantum safe. Monitor hybrid ML-KEM/FIPS 203 TLS adoption.",
            })

        issues = tls_result.get("issues", [])
        if any("expired" in i.lower() or "expir" in i.lower() for i in issues):
            actions.append({
                "priority":    "P2",
                "title":       "Renew TLS certificate",
                "description": "Certificate expiry warning detected. Renew before expiration to avoid service disruption.",
            })

    if not actions:
        actions.append({
            "priority":    "P4",
            "title":       "Maintain monitoring",
            "description": "No major issues detected. Continue periodic scans and track NIST PQC migration updates.",
        })

    return actions[:6]


def calculate_unified_quantum_risk(
    findings: List[Dict[str, Any]],
    agility_result: Optional[Dict[str, Any]] = None,
    tls_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Main entry point.

    FIX-1: Weight model aligned with api.py:
    - Code scanner: 50%
    - TLS analyzer: 30%
    - Crypto agility: 20%
    """
    code_score    = calculate_code_risk_score(findings)
    tls_score     = calculate_tls_risk_score(tls_result)
    agility_score = calculate_agility_risk_score(agility_result)

    # FIX-1: code=50%, TLS=30%, agility=20% (matches api.py)
    final_score = _clamp_score(
        (code_score    * 0.50) +
        (tls_score     * 0.30) +
        (agility_score * 0.20)
    )

    finding_summary = summarize_findings(findings)

    return {
        "quantum_risk_score": final_score,
        "risk_level":         _risk_level(final_score),
        "business_summary":   _business_summary(final_score),
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
                finding_summary["severity_summary"].get("CRITICAL", 0) == 0
            ),
        },
    }
