# ============================================================
# QuantumGuard — Unified Risk Engine v1.0
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
#
# Purpose:
# Combines Code Scanner + Crypto Agility + TLS Analyzer results
# into one executive-grade Quantum Risk Score.
# ============================================================

from typing import Dict, List, Any, Optional


SEVERITY_WEIGHTS = {
    "CRITICAL": 12,
    "HIGH": 7,
    "MEDIUM": 3,
    "LOW": 1,
}

CONFIDENCE_MULTIPLIERS = {
    "HIGH": 1.0,
    "MEDIUM": 0.6,
    "LOW": 0.25,
}


def _clamp_score(score: int) -> int:
    return max(0, min(100, int(round(score))))


def _risk_level(score: int) -> str:
    if score >= 85:
        return "LOW RISK"
    if score >= 70:
        return "MODERATE RISK"
    if score >= 50:
        return "HIGH RISK"
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
    severity_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    confidence_summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    top_findings = []

    for f in findings or []:
        sev = f.get("severity", "MEDIUM")
        conf = f.get("confidence", "MEDIUM")

        severity_summary[sev] = severity_summary.get(sev, 0) + 1
        confidence_summary[conf] = confidence_summary.get(conf, 0) + 1

        if len(top_findings) < 10:
            top_findings.append({
                "file": f.get("file"),
                "line": f.get("line"),
                "vulnerability": f.get("vulnerability"),
                "severity": sev,
                "confidence": conf,
                "recommended_fix": f.get("recommended_fix") or f.get("replacement"),
            })

    return {
        "severity_summary": severity_summary,
        "confidence_summary": confidence_summary,
        "top_findings": top_findings,
    }


def calculate_code_risk_score(findings: List[Dict[str, Any]]) -> int:
    """
    Converts scanner findings into a 0-100 code crypto safety score.
    Higher = safer.
    """
    if not findings:
        return 100

    penalty = 0.0

    for f in findings:
        sev = f.get("severity", "MEDIUM")
        conf = f.get("confidence", "MEDIUM")
        is_test = f.get("is_test_file", False)

        base = SEVERITY_WEIGHTS.get(sev, 3)
        multiplier = CONFIDENCE_MULTIPLIERS.get(conf, 0.6)

        if is_test:
            multiplier *= 0.25

        # Production/auth/crypto/config files matter more
        file_path = str(f.get("file", "")).lower()
        if any(x in file_path for x in ["auth", "crypto", "security", "jwt", "token", "config"]):
            multiplier *= 1.25

        penalty += base * multiplier

    return _clamp_score(100 - penalty)


def calculate_agility_risk_score(agility_result: Optional[Dict[str, Any]]) -> int:
    """
    Uses existing agility score if available.
    """
    if not agility_result:
        return 50

    score = agility_result.get("agility_score")
    if score is None:
        return 50

    return _clamp_score(score)


def calculate_tls_risk_score(tls_result: Optional[Dict[str, Any]]) -> int:
    """
    Uses existing TLS score if available.
    """
    if not tls_result:
        return 50

    score = tls_result.get("tls_score")
    if score is None:
        return 50

    return _clamp_score(score)


def generate_priority_actions(
    findings: List[Dict[str, Any]],
    agility_result: Optional[Dict[str, Any]],
    tls_result: Optional[Dict[str, Any]],
) -> List[Dict[str, str]]:
    actions = []

    critical_count = sum(1 for f in findings or [] if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings or [] if f.get("severity") == "HIGH")

    if critical_count:
        actions.append({
            "priority": "P1",
            "title": "Remediate critical cryptographic findings",
            "description": f"{critical_count} critical findings detected. Review file/line results and remove broken or quantum-vulnerable algorithms.",
        })

    if high_count:
        actions.append({
            "priority": "P2",
            "title": "Fix high-severity crypto risks",
            "description": f"{high_count} high-severity findings detected. Prioritize auth, token, key, and encryption-related files.",
        })

    if agility_result:
        hardcoded = agility_result.get("hardcoded_count", 0)
        if hardcoded > 0:
            actions.append({
                "priority": "P2",
                "title": "Improve crypto agility",
                "description": f"{hardcoded} hardcoded crypto patterns detected. Move algorithms and key sizes into configuration.",
            })

    if tls_result:
        if not tls_result.get("quantum_safe", False):
            actions.append({
                "priority": "P3",
                "title": "Plan post-quantum TLS migration",
                "description": "TLS may be secure today, but it is not post-quantum safe yet. Monitor hybrid ML-KEM/FIPS 203 TLS adoption.",
            })

        cert_issues = tls_result.get("cert_issues", [])
        if cert_issues:
            actions.append({
                "priority": "P2",
                "title": "Review certificate lifecycle",
                "description": "Certificate expiry warnings detected. Renew certificates before expiration.",
            })

    if not actions:
        actions.append({
            "priority": "P4",
            "title": "Maintain monitoring",
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

    Weighted model:
    - Code scanner: 50%
    - Crypto agility: 30%
    - TLS analyzer: 20%
    """

    code_score = calculate_code_risk_score(findings)
    agility_score = calculate_agility_risk_score(agility_result)
    tls_score = calculate_tls_risk_score(tls_result)

    final_score = _clamp_score(
        (code_score * 0.50) +
        (agility_score * 0.30) +
        (tls_score * 0.20)
    )

    finding_summary = summarize_findings(findings)

    return {
        "quantum_risk_score": final_score,
        "risk_level": _risk_level(final_score),
        "business_summary": _business_summary(final_score),
        "component_scores": {
            "code_crypto_score": code_score,
            "crypto_agility_score": agility_score,
            "tls_score": tls_score,
        },
        "finding_summary": finding_summary,
        "priority_actions": generate_priority_actions(findings, agility_result, tls_result),
        "standards_alignment": {
            "NIST_FIPS_203": "ML-KEM for key establishment",
            "NIST_FIPS_204": "ML-DSA for digital signatures",
            "NIST_FIPS_205": "SLH-DSA for stateless hash-based signatures",
            "note": "Recommendations are migration guidance, not a formal certification.",
        },
        "executive_status": {
            "ready_for_demo": final_score >= 70,
            "ready_for_enterprise_pilot": final_score >= 80 and finding_summary["severity_summary"].get("CRITICAL", 0) == 0,
        }
    }
