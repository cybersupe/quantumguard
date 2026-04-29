# ============================================================
# QuantumGuard — CBOM Export (CycloneDX 1.4)
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# Standards: NIST FIPS 203, FIPS 204, FIPS 205
# ============================================================
#
# Drop this file at: scanner/cbom.py
# ============================================================

import uuid
from datetime import datetime

# ── Algorithm metadata map ───────────────────────────────────
# Maps vulnerability name prefix → CycloneDX crypto component info
ALGO_META = {
    "RSA": {
        "algorithm-type": "asymmetric-encryption",
        "primitive": "rsa",
        "quantum_safe": False,
        "nist_status": "deprecated-by-2030",
        "replacement": "ML-KEM (CRYSTALS-Kyber) — NIST FIPS 203",
    },
    "ECC": {
        "algorithm-type": "signature",
        "primitive": "ecdsa",
        "quantum_safe": False,
        "nist_status": "deprecated-by-2030",
        "replacement": "ML-DSA (CRYSTALS-Dilithium) — NIST FIPS 204",
    },
    "ECDH": {
        "algorithm-type": "key-agreement",
        "primitive": "ecdh",
        "quantum_safe": False,
        "nist_status": "deprecated-by-2030",
        "replacement": "ML-KEM (CRYSTALS-Kyber) — NIST FIPS 203",
    },
    "ECDSA": {
        "algorithm-type": "signature",
        "primitive": "ecdsa",
        "quantum_safe": False,
        "nist_status": "deprecated-by-2030",
        "replacement": "ML-DSA (CRYSTALS-Dilithium) — NIST FIPS 204",
    },
    "DH": {
        "algorithm-type": "key-agreement",
        "primitive": "dh",
        "quantum_safe": False,
        "nist_status": "deprecated-by-2030",
        "replacement": "ML-KEM (CRYSTALS-Kyber) — NIST FIPS 203",
    },
    "DSA": {
        "algorithm-type": "signature",
        "primitive": "dsa",
        "quantum_safe": False,
        "nist_status": "deprecated-by-2030",
        "replacement": "ML-DSA (CRYSTALS-Dilithium) — NIST FIPS 204",
    },
    "MD5": {
        "algorithm-type": "hash",
        "primitive": "md5",
        "quantum_safe": False,
        "nist_status": "broken",
        "replacement": "SHA-3-256 — NIST FIPS 202",
    },
    "SHA1": {
        "algorithm-type": "hash",
        "primitive": "sha1",
        "quantum_safe": False,
        "nist_status": "deprecated",
        "replacement": "SHA-3-256 — NIST FIPS 202",
    },
    "SHA256_SIGNED": {
        "algorithm-type": "hash",
        "primitive": "sha256",
        "quantum_safe": True,
        "nist_status": "acceptable",
        "replacement": "SHA-3-256 preferred for long-term quantum resistance",
    },
    "RC4": {
        "algorithm-type": "stream-cipher",
        "primitive": "rc4",
        "quantum_safe": False,
        "nist_status": "broken",
        "replacement": "AES-256-GCM — NIST SP 800-38D",
    },
    "DES": {
        "algorithm-type": "block-cipher",
        "primitive": "des",
        "quantum_safe": False,
        "nist_status": "broken",
        "replacement": "AES-256-GCM — NIST SP 800-38D",
    },
    "ECB_MODE": {
        "algorithm-type": "block-cipher-mode",
        "primitive": "ecb",
        "quantum_safe": False,
        "nist_status": "forbidden",
        "replacement": "AES-256-GCM — NIST SP 800-38D",
    },
    "WEAK_TLS": {
        "algorithm-type": "protocol",
        "primitive": "tls",
        "quantum_safe": False,
        "nist_status": "deprecated",
        "replacement": "TLS 1.3 with ML-KEM hybrid key exchange",
    },
    "WEAK_KEY_SIZE": {
        "algorithm-type": "key-size",
        "primitive": "rsa",
        "quantum_safe": False,
        "nist_status": "insufficient",
        "replacement": "ML-KEM (CRYSTALS-Kyber) — NIST FIPS 203",
    },
    "HARDCODED_SECRET": {
        "algorithm-type": "secret-management",
        "primitive": "hardcoded-key",
        "quantum_safe": False,
        "nist_status": "non-compliant",
        "replacement": "Use environment variables or secrets manager",
    },
    "WEAK_RANDOM": {
        "algorithm-type": "rng",
        "primitive": "prng",
        "quantum_safe": False,
        "nist_status": "non-compliant",
        "replacement": "NIST SP 800-90A DRBG — crypto.randomBytes() or os.urandom()",
    },
    "JWT_NONE_ALG": {
        "algorithm-type": "signature",
        "primitive": "jwt-none",
        "quantum_safe": False,
        "nist_status": "broken",
        "replacement": "ML-DSA (CRYSTALS-Dilithium) — NIST FIPS 204",
    },
    "BLOWFISH": {
        "algorithm-type": "block-cipher",
        "primitive": "blowfish",
        "quantum_safe": False,
        "nist_status": "deprecated",
        "replacement": "AES-256-GCM — NIST SP 800-38D",
    },
    "MD4": {
        "algorithm-type": "hash",
        "primitive": "md4",
        "quantum_safe": False,
        "nist_status": "broken",
        "replacement": "SHA-3-256 — NIST FIPS 202",
    },
    # JS AST scanner rule IDs
    "JS-RAND-001": {
        "algorithm-type": "rng",
        "primitive": "math-random",
        "quantum_safe": False,
        "nist_status": "non-compliant",
        "replacement": "crypto.getRandomValues() — NIST SP 800-90A",
    },
    "JS-RSA-001": {
        "algorithm-type": "asymmetric-encryption",
        "primitive": "rsa-oaep",
        "quantum_safe": False,
        "nist_status": "deprecated-by-2030",
        "replacement": "ML-KEM (CRYSTALS-Kyber) — NIST FIPS 203",
    },
    "JS-ECC-001": {
        "algorithm-type": "key-agreement",
        "primitive": "ecdh-ecdsa",
        "quantum_safe": False,
        "nist_status": "deprecated-by-2030",
        "replacement": "ML-KEM / ML-DSA — NIST FIPS 203/204",
    },
    "JS-MD5-001": {
        "algorithm-type": "hash",
        "primitive": "md5",
        "quantum_safe": False,
        "nist_status": "broken",
        "replacement": "SHA-3-256 — NIST FIPS 202",
    },
    "JS-SHA1-001": {
        "algorithm-type": "hash",
        "primitive": "sha1",
        "quantum_safe": False,
        "nist_status": "deprecated",
        "replacement": "SHA-3-256 — NIST FIPS 202",
    },
    "JS-DES-001": {
        "algorithm-type": "block-cipher",
        "primitive": "des",
        "quantum_safe": False,
        "nist_status": "broken",
        "replacement": "AES-256-GCM — NIST SP 800-38D",
    },
    "JS-AES-001": {
        "algorithm-type": "block-cipher",
        "primitive": "aes-128",
        "quantum_safe": False,
        "nist_status": "insufficient",
        "replacement": "AES-256-GCM — NIST SP 800-38D",
    },
    "JS-HARDKEY-001": {
        "algorithm-type": "secret-management",
        "primitive": "hardcoded-key",
        "quantum_safe": False,
        "nist_status": "non-compliant",
        "replacement": "Use environment variables or secrets manager",
    },
    "JS-NODE-001": {
        "algorithm-type": "block-cipher",
        "primitive": "deprecated-api",
        "quantum_safe": False,
        "nist_status": "deprecated",
        "replacement": "crypto.createCipheriv() with AES-256-GCM",
    },
    "JS-RC4-001": {
        "algorithm-type": "stream-cipher",
        "primitive": "rc4",
        "quantum_safe": False,
        "nist_status": "broken",
        "replacement": "AES-256-GCM or ChaCha20-Poly1305",
    },
    "JS-JWT-001": {
        "algorithm-type": "signature",
        "primitive": "jwt-none",
        "quantum_safe": False,
        "nist_status": "broken",
        "replacement": "ML-DSA (CRYSTALS-Dilithium) — NIST FIPS 204",
    },
    "JS-JWT-002": {
        "algorithm-type": "signature",
        "primitive": "hmac-sha256",
        "quantum_safe": False,
        "nist_status": "acceptable",
        "replacement": "ML-DSA asymmetric signing — NIST FIPS 204",
    },
    "JS-WEBCRYPTO-001": {
        "algorithm-type": "key-management",
        "primitive": "extractable-key",
        "quantum_safe": False,
        "nist_status": "non-compliant",
        "replacement": "Set extractable: false",
    },
    "JS-EVAL-001": {
        "algorithm-type": "code-injection",
        "primitive": "eval",
        "quantum_safe": False,
        "nist_status": "non-compliant",
        "replacement": "Remove eval(); use JSON.parse()",
    },
}


def _get_algo_meta(finding: dict) -> dict:
    """Match a finding to its algorithm metadata."""
    # Try rule_id first (JS scanner findings)
    rule_id = finding.get("rule_id", "")
    if rule_id and rule_id in ALGO_META:
        return ALGO_META[rule_id]

    # Try vulnerability name prefix (Python scanner findings)
    vuln = finding.get("vulnerability", "")
    for key in ALGO_META:
        if vuln.startswith(key):
            return ALGO_META[key]

    # Generic fallback
    return {
        "algorithm-type": "unknown",
        "primitive": vuln.lower().replace(" ", "-"),
        "quantum_safe": False,
        "nist_status": "unknown",
        "replacement": finding.get("replacement", "See NIST PQC recommendations"),
    }


def _severity_to_cbom(severity: str) -> str:
    return {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }.get(severity, "medium")


def generate_cbom(findings: list, repo: str = "", score: int = 0) -> dict:
    """
    Generate a CycloneDX 1.4 CBOM (Cryptography Bill of Materials).

    Args:
        findings: list of finding dicts from scan_directory()
        repo: repository name (e.g. "owner/repo")
        score: quantum readiness score 0-100

    Returns:
        CycloneDX 1.4 compliant dict
    """
    now = datetime.utcnow().isoformat() + "Z"
    serial = f"urn:uuid:{uuid.uuid4()}"

    # ── Deduplicate by primitive + file ──────────────────────
    seen_components = {}
    for f in findings:
        meta = _get_algo_meta(f)
        primitive = meta["primitive"]
        file_path = f.get("file", "unknown")
        key = f"{primitive}:{file_path}"

        if key not in seen_components:
            seen_components[key] = {
                "finding": f,
                "meta": meta,
                "occurrences": 1,
                "lines": [f.get("line", 0)],
            }
        else:
            seen_components[key]["occurrences"] += 1
            seen_components[key]["lines"].append(f.get("line", 0))

    # ── Build CycloneDX components ────────────────────────────
    components = []
    for key, data in seen_components.items():
        f = data["finding"]
        meta = data["meta"]

        component = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-{uuid.uuid4().hex[:8]}",
            "name": meta["primitive"],
            "cryptoProperties": {
                "assetType": meta["algorithm-type"],
                "algorithmProperties": {
                    "primitive": meta["primitive"],
                    "cryptoFunctions": [meta["algorithm-type"]],
                    "nistQuantumSecurityLevel": 0 if not meta["quantum_safe"] else 3,
                },
                "quantumSafe": meta["quantum_safe"],
                "nistStatus": meta["nist_status"],
            },
            "properties": [
                {"name": "quantumguard:severity", "value": _severity_to_cbom(f.get("severity", "MEDIUM"))},
                {"name": "quantumguard:confidence", "value": f.get("confidence", "MEDIUM").lower()},
                {"name": "quantumguard:file", "value": f.get("file", "unknown")},
                {"name": "quantumguard:lines", "value": ",".join(str(l) for l in data["lines"])},
                {"name": "quantumguard:occurrences", "value": str(data["occurrences"])},
                {"name": "quantumguard:replacement", "value": meta["replacement"]},
                {"name": "quantumguard:risk", "value": f.get("risk_explanation", "")},
                {"name": "quantumguard:scanner", "value": f.get("scanner", f.get("detection_method", "regex"))},
                {"name": "nist:reference", "value": f.get("nist_ref", "NIST PQC Standards")},
            ],
        }
        components.append(component)

    # ── Build vulnerability list ──────────────────────────────
    vulnerabilities = []
    for f in findings:
        if f.get("confidence", "MEDIUM") == "LOW":
            continue  # skip low confidence from vuln list

        meta = _get_algo_meta(f)
        vuln_id = f.get("rule_id") or f.get("vulnerability", "UNKNOWN")

        vulnerabilities.append({
            "bom-ref": f"vuln-{uuid.uuid4().hex[:8]}",
            "id": vuln_id,
            "source": {
                "name": "QuantumGuard",
                "url": "https://quantumguard.site",
            },
            "ratings": [
                {
                    "severity": _severity_to_cbom(f.get("severity", "MEDIUM")),
                    "method": "other",
                }
            ],
            "description": f.get("risk_explanation", ""),
            "recommendation": meta["replacement"],
            "properties": [
                {"name": "quantumguard:file", "value": f.get("file", "unknown")},
                {"name": "quantumguard:line", "value": str(f.get("line", 0))},
                {"name": "quantumguard:code", "value": f.get("code", "")[:200]},
                {"name": "nist:status", "value": meta["nist_status"]},
                {"name": "quantum:safe", "value": str(meta["quantum_safe"]).lower()},
            ],
        })

    # ── Summary stats ─────────────────────────────────────────
    total = len(findings)
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    quantum_unsafe = sum(1 for c in seen_components.values() if not c["meta"]["quantum_safe"])

    # ── Assemble final CBOM ───────────────────────────────────
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "Mangsri QuantumGuard LLC",
                    "name": "QuantumGuard",
                    "version": "2.1",
                    "externalReferences": [
                        {"type": "website", "url": "https://quantumguard.site"},
                        {"type": "vcs", "url": "https://github.com/cybersupe/quantumguard"},
                    ],
                }
            ],
            "component": {
                "type": "application",
                "name": repo or "scanned-repository",
                "bom-ref": f"app-{uuid.uuid4().hex[:8]}",
            },
            "properties": [
                {"name": "quantumguard:score", "value": str(score)},
                {"name": "quantumguard:total_findings", "value": str(total)},
                {"name": "quantumguard:critical", "value": str(critical)},
                {"name": "quantumguard:high", "value": str(high)},
                {"name": "quantumguard:medium", "value": str(medium)},
                {"name": "quantumguard:quantum_unsafe_components", "value": str(quantum_unsafe)},
                {"name": "nist:standards", "value": "FIPS 203, FIPS 204, FIPS 205"},
                {"name": "quantumguard:generated_at", "value": now},
            ],
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }

    return cbom
