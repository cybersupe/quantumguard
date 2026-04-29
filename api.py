# ============================================================
# QuantumGuard — FastAPI Backend
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# Standards: NIST FIPS 203, FIPS 204, FIPS 205
# ============================================================

from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from typing import Optional
from scanner.scan import scan_directory, calculate_score
try:
    from scanner.cbom import generate_cbom
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from scanner.cbom import generate_cbom
import os, shutil, uuid, zipfile, io, requests, ssl, socket
import datetime

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="QuantumGuard API",
    description="Post-quantum cryptography vulnerability scanner — Mangsri QuantumGuard LLC",
    version="2.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS ─────────────────────────────────────────────────────
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response

class CORSMiddlewareCustom(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        if request.method == "OPTIONS":
            return Response(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Max-Age": "86400",
                },
            )
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
        return response

app.add_middleware(CORSMiddlewareCustom)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY", "quantumguard-secret-2026")
MAX_ZIP_SIZE = 10 * 1024 * 1024  # 10 MB


class ScanRequest(BaseModel):
    directory: str


class GitScanRequest(BaseModel):
    github_url: str
    github_token: Optional[str] = None


def verify_key(key: str):
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _download_github_zip(github_url: str, github_token: Optional[str] = None) -> bytes:
    """Download a GitHub repo as ZIP. Tries main then master branch."""
    parts = github_url.rstrip("/").split("/")
    owner = parts[-2]
    repo = parts[-1].replace(".git", "")

    headers = {"Accept": "application/vnd.github+json", "User-Agent": "QuantumGuard/2.0"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    # ── Check repo size before downloading ───────────────
    meta_url = f"https://api.github.com/repos/{owner}/{repo}"
    meta_resp = requests.get(meta_url, headers=headers, timeout=10)
    if meta_resp.status_code == 200:
        repo_size_kb = meta_resp.json().get("size", 0)
        if repo_size_kb > 50000:
            raise HTTPException(
                status_code=400,
                detail=f"Repo is too large ({repo_size_kb // 1024}MB). Maximum supported size is 50MB. "
                       f"Try scanning a specific subdirectory or upload a ZIP of just the src/ folder."
            )

    for branch in ["main", "master"]:
        zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"
        response = requests.get(zip_url, headers=headers, timeout=30, allow_redirects=True)
        if response.status_code == 200:
            if len(response.content) > 15 * 1024 * 1024:
                raise HTTPException(
                    status_code=400,
                    detail="Repo ZIP is too large for the free tier. Please upload a ZIP of just your src/ folder."
                )
            return response.content, owner, repo

    raise HTTPException(status_code=400, detail="Could not download repo. Make sure it is public.")


# ── TLS ANALYZER ─────────────────────────────────────────────

PQC_INDICATORS = [
    "KYBER", "MLKEM", "ML_KEM", "X25519KYBER768",
    "X25519MLKEM768", "P256KYBER768DRAFT00",
    "NTRU", "FRODO", "SABER", "BIKE", "HQC",
]

STRONG_CIPHERS = ["AES_256", "AES-256", "CHACHA20"]
ACCEPTABLE_CIPHERS = ["AES_128", "AES-128"]
FORWARD_SECRECY_KX = ["ECDHE", "DHE", "X25519", "X448"]


def _analyze_tls_score(tls_version: str, cipher_name: str, cipher_bits: int) -> dict:
    score = 0
    issues = []
    strengths = []
    labels = []

    cipher_upper = cipher_name.upper()

    if tls_version == "TLSv1.3":
        score += 30
        strengths.append("TLS 1.3 — latest standard")
    elif tls_version == "TLSv1.2":
        score += 15
        issues.append("TLS 1.2 detected — upgrade to TLS 1.3 recommended")
    elif tls_version in ("TLSv1.1", "TLSv1.0"):
        score += 0
        issues.append(f"{tls_version} is deprecated and insecure — upgrade to TLS 1.3 immediately")
    else:
        score += 0
        issues.append(f"Unknown TLS version: {tls_version}")

    if any(strong in cipher_upper for strong in STRONG_CIPHERS):
        score += 40
        strengths.append("AES-256/ChaCha20 — quantum-resilient symmetric encryption")
    elif any(ok in cipher_upper for ok in ACCEPTABLE_CIPHERS):
        score += 20
        issues.append(
            "AES-128 detected — secure classically, but Grover's algorithm reduces effective "
            "quantum security to ~64 bits. Upgrade to AES-256 for stronger quantum resilience."
        )
    elif cipher_bits and cipher_bits >= 256:
        score += 30
    elif cipher_bits and cipher_bits >= 128:
        score += 15
        issues.append(f"Cipher key size {cipher_bits}-bit — recommend 256-bit minimum for quantum resilience")
    else:
        issues.append("Weak or unknown cipher strength")

    has_pqc_kx = any(pqc in cipher_upper for pqc in PQC_INDICATORS)
    has_forward_secrecy = any(kx in cipher_upper for kx in FORWARD_SECRECY_KX)

    if has_pqc_kx:
        score += 20
        strengths.append("Post-Quantum / Hybrid KEM key exchange detected!")
    elif has_forward_secrecy:
        score += 10
        strengths.append("Forward secrecy via ECDHE/DHE")
        issues.append(
            "ECDHE/DHE key exchange provides forward secrecy but is NOT quantum-safe. "
            "Shor's Algorithm will break ECDH. Upgrade to CRYSTALS-Kyber (ML-KEM FIPS 203) hybrid."
        )
    else:
        issues.append("No forward secrecy detected — static RSA key exchange is quantum-vulnerable")

    quantum_safe = has_pqc_kx

    if quantum_safe:
        labels.append("Post-Quantum Safe")
    elif tls_version == "TLSv1.3" and any(strong in cipher_upper for strong in STRONG_CIPHERS):
        labels.append("Modern TLS Secure")
        labels.append("Not Post-Quantum Safe Yet")
        labels.append("PQC Upgrade Recommended")
    elif tls_version in ("TLSv1.3", "TLSv1.2"):
        labels.append("Not Post-Quantum Safe Yet")
        labels.append("PQC Upgrade Recommended")
    else:
        labels.append("Insecure TLS Configuration")
        labels.append("PQC Upgrade Required")

    score = max(0, min(100, score))

    return {
        "tls_score": score,
        "quantum_safe": quantum_safe,
        "labels": labels,
        "strengths": strengths,
        "issues": issues,
        "has_forward_secrecy": has_forward_secrecy,
        "has_pqc_kex": has_pqc_kx,
    }


def _calculate_tls_grade(score: int, quantum_safe: bool, tls_version: str, issues: list) -> dict:
    critical_keywords = ["expired", "SSLv", "TLSv1.0", "TLSv1.1", "deprecated and insecure"]
    has_critical = any(any(kw.lower() in issue.lower() for kw in critical_keywords) for issue in issues)

    if has_critical or score < 35:
        grade = "F"
        color = "#dc2626"
        description = "Failing — immediate action required"
    elif score < 50:
        grade = "D"
        color = "#dc2626"
        description = "Poor — significant vulnerabilities present"
    elif score < 65:
        grade = "C"
        color = "#d97706"
        description = "Average — several issues need attention"
    elif score < 80:
        grade = "B"
        color = "#f59e0b"
        description = "Good — some improvements recommended"
    elif score >= 95 and quantum_safe and tls_version == "TLSv1.3" and len(issues) == 0:
        grade = "A+"
        color = "#16a34a"
        description = "Exceptional — post-quantum safe with perfect configuration"
    elif score >= 80 and tls_version == "TLSv1.3":
        grade = "A"
        color = "#16a34a"
        description = "Strong — modern TLS configuration"
    else:
        grade = "B"
        color = "#f59e0b"
        description = "Good — upgrade to TLS 1.3 recommended"

    pqc_note = None
    if grade in ("A+", "A") and not quantum_safe:
        pqc_note = "Grade capped at A until PQC key exchange is deployed (CRYSTALS-Kyber FIPS 203)"

    return {
        "grade": grade,
        "grade_color": color,
        "grade_description": description,
        "pqc_note": pqc_note,
        "grade_breakdown": {
            "tls_version_score": 30 if tls_version == "TLSv1.3" else 15 if tls_version == "TLSv1.2" else 0,
            "cipher_score": score - (30 if tls_version == "TLSv1.3" else 15 if tls_version == "TLSv1.2" else 0),
            "quantum_ready": quantum_safe,
        }
    }


def _analyze_certificate(cert: dict) -> dict:
    cert_info = {}
    cert_issues = []

    exp_str = cert.get("notAfter", "")
    cert_info["cert_expires"] = exp_str

    if exp_str:
        try:
            exp_date = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days_remaining = (exp_date - datetime.datetime.utcnow()).days
            cert_info["days_until_expiry"] = days_remaining
            if days_remaining < 0:
                cert_issues.append("CRITICAL: Certificate has already expired!")
            elif days_remaining < 14:
                cert_issues.append(f"URGENT: Certificate expires in {days_remaining} days!")
            elif days_remaining < 30:
                cert_issues.append(f"WARNING: Certificate expires in {days_remaining} days — renew soon")
            elif days_remaining < 60:
                cert_issues.append(f"NOTICE: Certificate expires in {days_remaining} days")
        except ValueError:
            cert_info["days_until_expiry"] = None

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    cert_info["subject_cn"] = subject.get("commonName", "")
    cert_info["issuer_cn"] = issuer.get("commonName", "")

    san = cert.get("subjectAltName", [])
    cert_info["san_count"] = len(san)

    return cert_info, cert_issues


# ── API ROUTES ────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "message": "QuantumGuard API is running!",
        "version": "2.0",
        "company": "Mangsri QuantumGuard LLC",
        "website": "https://quantumguard.site",
        "standards": ["NIST FIPS 203", "NIST FIPS 204", "NIST FIPS 205"],
    }


@app.post("/scan")
@limiter.limit("10/minute")
def scan(request: Request, body: ScanRequest, x_api_key: str = Header(...)):
    verify_key(x_api_key)
    if not os.path.exists(body.directory):
        raise HTTPException(status_code=404, detail="Directory not found")

    findings = scan_directory(body.directory)
    score = calculate_score(findings)
    severity_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        severity_summary[sev] = severity_summary.get(sev, 0) + 1

    return {
        "quantum_readiness_score": score,
        "total_findings": len(findings),
        "severity_summary": severity_summary,
        "findings": findings,
    }


@app.post("/public-scan-zip")
@limiter.limit("3/minute")
async def public_scan_zip(request: Request, file: UploadFile = File(...)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files allowed")

    contents = await file.read()
    if len(contents) > MAX_ZIP_SIZE:
        raise HTTPException(status_code=400, detail="ZIP file too large. Maximum 10MB allowed")

    temp_dir = f"/tmp/qg-{uuid.uuid4().hex[:8]}"
    try:
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(contents)) as z:
            z.extractall(temp_dir)

        findings = scan_directory(temp_dir)
        score = calculate_score(findings)
        severity_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        for f in findings:
            sev = f.get("severity", "MEDIUM")
            severity_summary[sev] = severity_summary.get(sev, 0) + 1

        return {
            "filename": file.filename,
            "quantum_readiness_score": score,
            "total_findings": len(findings),
            "severity_summary": severity_summary,
            "findings": findings,
        }
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


@app.post("/scan-github")
@limiter.limit("20/minute")
async def scan_github(request: Request, body: GitScanRequest):
    if "github.com" not in body.github_url:
        raise HTTPException(status_code=400, detail="Only GitHub URLs allowed")

    temp_dir = None
    try:
        zip_content, owner, repo = _download_github_zip(body.github_url, body.github_token)

        temp_dir = f"/tmp/qg-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
            z.extractall(temp_dir)

        findings = scan_directory(temp_dir)
        score = calculate_score(findings)

        severity_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
        confidence_summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "MEDIUM")
            conf = f.get("confidence", "MEDIUM")
            severity_summary[sev] = severity_summary.get(sev, 0) + 1
            confidence_summary[conf] = confidence_summary.get(conf, 0) + 1

        return {
            "github_url": body.github_url,
            "repo": f"{owner}/{repo}",
            "quantum_readiness_score": score,
            "total_findings": len(findings),
            "severity_summary": severity_summary,
            "confidence_summary": confidence_summary,
            "findings": findings,
            "meta": {
                "tool": "QuantumGuard v2.0",
                "standards": ["NIST FIPS 203", "NIST FIPS 204", "NIST FIPS 205"],
                "company": "Mangsri QuantumGuard LLC",
                "website": "https://quantumguard.site",
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


@app.post("/check-agility")
@limiter.limit("10/minute")
async def check_agility(request: Request, body: GitScanRequest):
    if "github.com" not in body.github_url:
        raise HTTPException(status_code=400, detail="Only GitHub URLs allowed")

    temp_dir = None
    try:
        zip_content, owner, repo = _download_github_zip(body.github_url, body.github_token)

        temp_dir = f"/tmp/qg-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
            z.extractall(temp_dir)

        from scanner.scan import check_crypto_agility
        result = check_crypto_agility(temp_dir)
        result["repo"] = f"{owner}/{repo}"
        result["github_url"] = body.github_url
        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


@app.post("/analyze-tls")
@limiter.limit("10/minute")
async def analyze_tls(request: Request, body: dict):
    raw_domain = body.get("domain", "").strip()
    domain = raw_domain.replace("https://", "").replace("http://", "").split("/")[0]

    if not domain:
        raise HTTPException(status_code=400, detail="Domain required")

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                tls_version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert()

        cipher_name = cipher[0] if cipher else "Unknown"
        cipher_bits = cipher[2] if cipher else 0

        analysis = _analyze_tls_score(tls_version, cipher_name, cipher_bits)
        cert_info, cert_issues = _analyze_certificate(cert)

        if analysis["quantum_safe"]:
            nist_recommendation = "Already using PQC — maintain and monitor NIST updates"
        elif tls_version == "TLSv1.3":
            nist_recommendation = (
                "Upgrade key exchange to CRYSTALS-Kyber hybrid (X25519Kyber768) per NIST FIPS 203. "
                "Google Chrome already supports this as an experiment."
            )
        else:
            nist_recommendation = (
                "Step 1: Upgrade to TLS 1.3. "
                "Step 2: Upgrade cipher to AES-256-GCM. "
                "Step 3: Deploy CRYSTALS-Kyber hybrid KEM per NIST FIPS 203."
            )

        grade_info = _calculate_tls_grade(
            analysis["tls_score"],
            analysis["quantum_safe"],
            tls_version,
            analysis["issues"] + cert_issues
        )

        return {
            "domain": domain,
            "tls_version": tls_version,
            "cipher_suite": cipher_name,
            "cipher_bits": cipher_bits,
            "quantum_safe": analysis["quantum_safe"],
            "tls_score": analysis["tls_score"],
            "grade": grade_info["grade"],
            "grade_color": grade_info["grade_color"],
            "grade_description": grade_info["grade_description"],
            "pqc_note": grade_info["pqc_note"],
            "grade_breakdown": grade_info["grade_breakdown"],
            "labels": analysis["labels"],
            "strengths": analysis["strengths"],
            "issues": analysis["issues"] + cert_issues,
            "crypto_issues": analysis["issues"],
            "cert_issues": cert_issues,
            "certificate": cert_info,
            "has_forward_secrecy": analysis["has_forward_secrecy"],
            "has_pqc_key_exchange": analysis["has_pqc_kex"],
            "nist_recommendation": nist_recommendation,
            "nist_standard": "CRYSTALS-Kyber (ML-KEM) — NIST FIPS 203",
            "meta": {
                "tool": "QuantumGuard TLS Analyzer v2.0",
                "company": "Mangsri QuantumGuard LLC",
                "website": "https://quantumguard.site",
                "note": "quantum_safe=True only when actual PQC/hybrid KEM is detected in cipher suite",
            }
        }

    except ssl.SSLError as e:
        raise HTTPException(status_code=400, detail=f"SSL Error: {str(e)}")
    except socket.timeout:
        raise HTTPException(status_code=408, detail="Connection timed out")
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Cannot resolve domain: {domain}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"TLS analysis error: {str(e)}")


@app.post("/ai-fix")
@limiter.limit("10/minute")
async def ai_fix(request: Request, body: dict):
    """Generate AI-powered fix suggestion for a vulnerability finding."""
    finding = body.get("finding", {})
    if not finding:
        raise HTTPException(status_code=400, detail="Finding required")

    vuln = finding.get("vulnerability", "")
    code = finding.get("code", "")
    replacement = finding.get("replacement", "")
    severity = finding.get("severity", "")
    risk = finding.get("risk_explanation", "")

    fix_map = {
        "RSA": f"""# BEFORE (Quantum-Vulnerable):
{code}

# AFTER (NIST FIPS 203 — CRYSTALS-Kyber ML-KEM):
# Install: pip install liboqs-python
import oqs

# Key Generation
kem = oqs.KeyEncapsulation("Kyber768")
public_key = kem.generate_keypair()

# Encryption
ciphertext, shared_secret = kem.encap_secret(public_key)

# Decryption
shared_secret = kem.decap_secret(ciphertext)

# Why: RSA is broken by Shor's Algorithm on quantum computers.
# CRYSTALS-Kyber (ML-KEM) is NIST FIPS 203 approved — the official replacement.""",

        "ECC": f"""# BEFORE (Quantum-Vulnerable):
{code}

# AFTER (NIST FIPS 204 — CRYSTALS-Dilithium ML-DSA):
# Install: pip install liboqs-python
import oqs

# Signing
signer = oqs.Signature("Dilithium3")
public_key = signer.generate_keypair()
signature = signer.sign(message)

# Verification
verifier = oqs.Signature("Dilithium3")
is_valid = verifier.verify(message, signature, public_key)

# Why: ECC/ECDSA is broken by Shor's Algorithm.
# CRYSTALS-Dilithium (ML-DSA) is NIST FIPS 204 approved.""",

        "MD5": f"""# BEFORE (Broken Hash):
{code}

# AFTER (NIST FIPS 202 — SHA-3):
import hashlib

# Replace md5 with sha3_256
hash_value = hashlib.sha3_256(data).hexdigest()

# Or for higher security:
hash_value = hashlib.sha3_512(data).hexdigest()

# Why: MD5 is cryptographically broken. Grover's algorithm
# further reduces effective security. SHA-3 is quantum-resilient.""",

        "SHA1": f"""# BEFORE (Deprecated Hash):
{code}

# AFTER (NIST FIPS 202 — SHA-3):
import hashlib

# Replace sha1 with sha3_256
hash_value = hashlib.sha3_256(data).hexdigest()

# Why: SHA-1 is deprecated and broken. Grover's algorithm
# halves effective security to ~80 bits. SHA-3 is the standard.""",

        "DH": f"""# BEFORE (Quantum-Vulnerable Key Exchange):
{code}

# AFTER (NIST FIPS 203 — CRYSTALS-Kyber ML-KEM):
import oqs

kem = oqs.KeyEncapsulation("Kyber768")
public_key = kem.generate_keypair()
ciphertext, shared_secret_enc = kem.encap_secret(public_key)
shared_secret_dec = kem.decap_secret(ciphertext)

# Why: Diffie-Hellman is broken by Shor's Algorithm.
# ML-KEM provides quantum-safe key exchange per NIST FIPS 203.""",
    }

    fix_text = None
    for key in fix_map:
        if vuln.startswith(key):
            fix_text = fix_map[key]
            break

    if not fix_text:
        fix_text = f"""# BEFORE (Vulnerable):
{code}

# Recommended replacement: {replacement}

# Risk: {risk}

# Migration Priority: {severity}
# Reference: https://csrc.nist.gov/projects/post-quantum-cryptography"""

    return {"fix": fix_text, "vulnerability": vuln, "replacement": replacement}


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "version": "2.0",
        "tool": "QuantumGuard",
        "company": "Mangsri QuantumGuard LLC",
    }


@app.get("/badge/{owner}/{repo}")
async def get_badge(owner: str, repo: str):
    from fastapi.responses import Response
    try:
        github_url = f"https://github.com/{owner}/{repo}"
        zip_content, owner_, repo_ = _download_github_zip(github_url)
        temp_dir = f"/tmp/qg-badge-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
                z.extractall(temp_dir)
            findings = scan_directory(temp_dir)
            score = calculate_score(findings)
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
        if score >= 80:
            color = "#16a34a"
            left_color = "#15803d"
            right_text = f"{score}/100 safe"
        elif score >= 50:
            color = "#d97706"
            left_color = "#b45309"
            right_text = f"{score}/100 at risk"
        else:
            color = "#dc2626"
            left_color = "#b91c1c"
            right_text = f"{score}/100 vulnerable"
    except Exception:
        color = "#6b7280"
        left_color = "#4b5563"
        right_text = "unknown"

    left_text = "QuantumGuard"
    lw = len(left_text) * 7 + 20
    rw = len(right_text) * 7 + 20
    tw = lw + rw
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{tw}" height="20">'
        f'<defs><linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{tw}" height="20" rx="3"/></clipPath></defs>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{lw}" height="20" fill="{left_color}"/>'
        f'<rect x="{lw}" width="{rw}" height="20" fill="{color}"/>'
        f'<rect width="{tw}" height="20" fill="url(#s)"/></g>'
        f'<g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">'
        f'<text x="{lw//2}" y="15" fill="#010101" fill-opacity=".3">{left_text}</text>'
        f'<text x="{lw//2}" y="14">{left_text}</text>'
        f'<text x="{lw + rw//2}" y="15" fill="#010101" fill-opacity=".3">{right_text}</text>'
        f'<text x="{lw + rw//2}" y="14">{right_text}</text>'
        f'</g></svg>'
    )
    return Response(content=svg, media_type="image/svg+xml",
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"})


# ── CBOM EXPORT ROUTES ────────────────────────────────────────

@app.post("/export-cbom")
@limiter.limit("10/minute")
async def export_cbom(request: Request, body: GitScanRequest):
    """Export a CycloneDX 1.4 CBOM for a GitHub repository."""
    if "github.com" not in body.github_url:
        raise HTTPException(status_code=400, detail="Only GitHub URLs allowed")

    temp_dir = None
    try:
        zip_content, owner, repo = _download_github_zip(body.github_url, body.github_token)

        temp_dir = f"/tmp/qg-cbom-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
            z.extractall(temp_dir)

        findings = scan_directory(temp_dir)
        score = calculate_score(findings)
        cbom = generate_cbom(findings, repo=f"{owner}/{repo}", score=score)

        return cbom

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CBOM export error: {str(e)}")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


@app.post("/export-cbom-zip")
@limiter.limit("5/minute")
async def export_cbom_zip(request: Request, file: UploadFile = File(...)):
    """Export a CycloneDX 1.4 CBOM from an uploaded ZIP file."""
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files allowed")

    contents = await file.read()
    if len(contents) > MAX_ZIP_SIZE:
        raise HTTPException(status_code=400, detail="ZIP file too large. Maximum 10MB allowed")

    temp_dir = f"/tmp/qg-cbom-{uuid.uuid4().hex[:8]}"
    try:
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(contents)) as z:
            z.extractall(temp_dir)

        findings = scan_directory(temp_dir)
        score = calculate_score(findings)
        cbom = generate_cbom(findings, repo=file.filename, score=score)

        return cbom

    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CBOM export error: {str(e)}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
