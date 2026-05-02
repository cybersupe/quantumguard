# ============================================================
# QuantumGuard — FastAPI Backend v2.5
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# Standards: NIST FIPS 203, FIPS 204, FIPS 205
# ============================================================
# v2.5 adds: JWT Auth, Token scrubbing, enhanced rate limits
# ============================================================

import os
import io
import re
import ssl
import time
import uuid
import socket
import shutil
import zipfile
import logging
import datetime
import requests

from typing import Optional
from datetime import timedelta

from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import Response
from pydantic import BaseModel

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest

from jose import JWTError, jwt
from passlib.context import CryptContext

from scanner.scan import (
    scan_directory, calculate_score, check_crypto_agility,
    generate_score_explanation, generate_scan_summary,
)

try:
    from scanner.cbom import generate_cbom
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from scanner.cbom import generate_cbom

try:
    from scanner.unified_risk_engine import calculate_unified_quantum_risk
except ImportError:
    calculate_unified_quantum_risk = None


# ============================================================
# LOGGING — scrub tokens/passwords from all log lines
# ============================================================

class TokenScrubFilter(logging.Filter):
    PATTERNS = [
        (re.compile(r'ghp_[A-Za-z0-9]{36}'),            '[GH_TOKEN_REDACTED]'),
        (re.compile(r'github_pat_[A-Za-z0-9_]+'),       '[GH_TOKEN_REDACTED]'),
        (re.compile(r'x-token:[^@\s]+'),                 'x-token:[REDACTED]'),
        (re.compile(r'Bearer [A-Za-z0-9\-_\.]+'),       'Bearer [REDACTED]'),
        (re.compile(r'password["\s:=]+[^\s,}"]+',
                    re.IGNORECASE),                      'password:[REDACTED]'),
    ]
    def filter(self, record):
        msg = str(record.getMessage())
        for pattern, replacement in self.PATTERNS:
            msg = pattern.sub(replacement, msg)
        record.msg = msg
        record.args = ()
        return True

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("quantumguard")
logger.addFilter(TokenScrubFilter())


# ============================================================
# CONFIG
# ============================================================

API_KEY       = os.getenv("API_KEY", "quantumguard-secret-2026")
MAX_ZIP_SIZE  = 10 * 1024 * 1024

# JWT
SECRET_KEY                  = os.getenv("JWT_SECRET_KEY", "CHANGE_THIS_IN_PRODUCTION")
ALGORITHM                   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
ENVIRONMENT                 = os.getenv("ENVIRONMENT", "production")


# ============================================================
# PASSWORD HASHING
# ============================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ============================================================
# IN-MEMORY USER STORE  (swap for PostgreSQL later)
# ============================================================

USERS_DB: dict[str, dict] = {}


# ============================================================
# JWT HELPERS
# ============================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire    = datetime.datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.datetime.utcnow()})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ============================================================
# AUTH DEPENDENCIES
# ============================================================

security = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> dict:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required — include: Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    email   = payload.get("sub")
    if not email or email not in USERS_DB:
        raise HTTPException(status_code=401, detail="User not found")
    return USERS_DB[email]

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[dict]:
    if not credentials:
        return None
    try:
        payload = decode_token(credentials.credentials)
        return USERS_DB.get(payload.get("sub"))
    except HTTPException:
        return None


# ============================================================
# RATE LIMITER
# ============================================================

limiter = Limiter(key_func=get_remote_address)


# ============================================================
# APP SETUP
# ============================================================

app = FastAPI(
    title="QuantumGuard API",
    description="Post-quantum cryptography vulnerability scanner — Mangsri QuantumGuard LLC",
    version="2.5",
    docs_url="/docs" if ENVIRONMENT == "development" else None,
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


class CORSMiddlewareCustom(BaseHTTPMiddleware):
    async def dispatch(self, request: StarletteRequest, call_next):
        if request.method == "OPTIONS":
            return Response(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin":  "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Max-Age":       "86400",
                },
            )
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"]  = "*"
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


# ============================================================
# MODELS
# ============================================================

class RegisterRequest(BaseModel):
    email:    str
    password: str
    name:     Optional[str] = ""

class LoginRequest(BaseModel):
    email:    str
    password: str

class ScanRequest(BaseModel):
    directory: str

class GitScanRequest(BaseModel):
    github_url:   str
    github_token: Optional[str] = None

class TLSRequest(BaseModel):
    domain: str

class UnifiedRiskRequest(BaseModel):
    github_url:   str
    domain:       Optional[str] = None
    github_token: Optional[str] = None


# ============================================================
# HELPERS  (unchanged from v2.4)
# ============================================================

def verify_key(key: str):
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _parse_github_url(github_url: str):
    parts = github_url.rstrip("/").split("/")
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")
    owner = parts[-2]
    repo  = parts[-1].replace(".git", "")
    if not owner or not repo:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")
    return owner, repo


def _download_github_zip(github_url: str, github_token: Optional[str] = None):
    if "github.com" not in github_url:
        raise HTTPException(status_code=400, detail="Only GitHub URLs allowed")

    owner, repo = _parse_github_url(github_url)
    headers = {
        "Accept":     "application/vnd.github+json",
        "User-Agent": "QuantumGuard/2.5",
    }
    if github_token:
        headers["Authorization"] = f"token {github_token}"

    meta_url  = f"https://api.github.com/repos/{owner}/{repo}"
    meta_resp = requests.get(meta_url, headers=headers, timeout=10)
    if meta_resp.status_code == 200:
        repo_size_kb = meta_resp.json().get("size", 0)
        if repo_size_kb > 50000:
            raise HTTPException(
                status_code=400,
                detail=f"Repo is too large ({repo_size_kb // 1024}MB). Maximum 50MB.",
            )

    for branch in ["main", "master"]:
        zip_url  = f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"
        response = requests.get(zip_url, headers=headers, timeout=30, allow_redirects=True)
        if response.status_code == 200:
            if len(response.content) > 15 * 1024 * 1024:
                raise HTTPException(
                    status_code=400,
                    detail="Repo ZIP too large for free tier. Upload a ZIP of only src/.",
                )
            return response.content, owner, repo

    raise HTTPException(status_code=400, detail="Could not download repo. Make sure it is public.")


def _summarize_findings(findings):
    severity_summary   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    confidence_summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev  = f.get("severity",   "MEDIUM")
        conf = f.get("confidence", "MEDIUM")
        severity_summary[sev]     = severity_summary.get(sev, 0) + 1
        confidence_summary[conf]  = confidence_summary.get(conf, 0) + 1
    return severity_summary, confidence_summary


def _build_priority_actions(findings, severity_summary, score):
    priority_actions = []
    critical = severity_summary.get("CRITICAL", 0)
    high     = severity_summary.get("HIGH", 0)
    medium   = severity_summary.get("MEDIUM", 0)
    if critical > 0:
        priority_actions.append({"priority":"P1","title":"Fix critical cryptographic vulnerabilities immediately","description":f"{critical} critical findings.","timeline":"Within 30 days"})
    if high > 0:
        priority_actions.append({"priority":"P2","title":"Remediate high-severity crypto risks","description":f"{high} high-severity findings.","timeline":"Within 90 days"})
    if medium > 0:
        priority_actions.append({"priority":"P3","title":"Plan migration for medium-severity findings","description":f"{medium} medium findings.","timeline":"Within 6 months"})
    if score < 50:
        priority_actions.append({"priority":"P1","title":"Begin NIST PQC migration planning","description":"Score below 50 — create a formal post-quantum migration plan.","timeline":"Within 60 days"})
    if not priority_actions:
        priority_actions.append({"priority":"P4","title":"Maintain monitoring","description":"No major issues. Run periodic scans.","timeline":"Ongoing"})
    return priority_actions


def _build_top_findings(findings):
    return [
        {"file": f.get("file","").split("/")[-1], "line": f.get("line"),
         "vulnerability": f.get("vulnerability"), "severity": f.get("severity"),
         "confidence": f.get("confidence"),
         "recommended_fix": f.get("recommended_fix") or f.get("replacement")}
        for f in findings[:10]
        if f.get("confidence") != "LOW"
    ]


# ============================================================
# TLS ANALYZER  (unchanged from v2.4)
# ============================================================

PQC_INDICATORS     = ["KYBER","MLKEM","ML_KEM","X25519KYBER768","X25519MLKEM768","P256KYBER768DRAFT00","NTRU","FRODO","SABER","BIKE","HQC"]
STRONG_CIPHERS     = ["AES_256","AES-256","CHACHA20"]
ACCEPTABLE_CIPHERS = ["AES_128","AES-128"]
FORWARD_SECRECY_KX = ["ECDHE","DHE","X25519","X448"]


def _analyze_tls_score(tls_version, cipher_name, cipher_bits):
    score = 0; issues = []; strengths = []; labels = []
    cipher_upper = (cipher_name or "").upper()
    if tls_version == "TLSv1.3":
        score += 30; strengths.append("TLS 1.3 — modern and forward-secure")
    elif tls_version == "TLSv1.2":
        score += 20; issues.append("TLS 1.2 detected — TLS 1.3 recommended")
    else:
        issues.append(f"{tls_version} is deprecated — upgrade to TLS 1.3")
    if any(s in cipher_upper for s in STRONG_CIPHERS):
        score += 35; strengths.append("Strong symmetric encryption detected")
    elif any(s in cipher_upper for s in ACCEPTABLE_CIPHERS):
        score += 20; issues.append("AES-128 detected — AES-256 preferred")
    elif cipher_bits and cipher_bits >= 256:
        score += 30
    elif cipher_bits and cipher_bits >= 128:
        score += 15; issues.append("AES-256 recommended")
    else:
        issues.append("Weak or unknown cipher strength")
    has_pqc_kx         = any(p in cipher_upper for p in PQC_INDICATORS)
    has_forward_secrecy = tls_version == "TLSv1.3" or has_pqc_kx or any(kx in cipher_upper for kx in FORWARD_SECRECY_KX)
    rsa_key_exchange   = "RSA" in cipher_upper and not has_forward_secrecy
    if has_pqc_kx:
        score += 25; strengths.append("Hybrid post-quantum key exchange detected")
    elif tls_version == "TLSv1.3":
        score += 10; issues.append("Not post-quantum safe yet — monitor hybrid PQC TLS adoption")
    elif has_forward_secrecy:
        score += 10; issues.append("Classical ECDHE/DHE — not post-quantum safe")
    else:
        issues.append("No forward secrecy detected")
    quantum_safe = has_pqc_kx
    return {"tls_score": max(0, min(100, score)), "quantum_safe": quantum_safe,
            "labels": labels, "strengths": strengths, "issues": issues,
            "has_forward_secrecy": has_forward_secrecy, "has_pqc_kex": has_pqc_kx,
            "rsa_key_exchange": rsa_key_exchange,
            "quantum_explanation": "Hybrid PQC detected." if quantum_safe else "Not post-quantum safe yet."}


def _calculate_tls_grade(score, quantum_safe, tls_version, issues):
    critical_kw = ["expired","sslv","tlsv1.0","tlsv1.1","deprecated and insecure"]
    has_critical = any(any(kw in i.lower() for kw in critical_kw) for i in issues)
    if has_critical or score < 35:
        grade, color, desc = "F","#dc2626","Failing — immediate action required"
    elif score < 50:
        grade, color, desc = "D","#dc2626","Poor — significant vulnerabilities"
    elif score < 65:
        grade, color, desc = "C","#d97706","Average — improvements recommended"
    elif score < 80:
        grade, color, desc = "B","#f59e0b","Good — some improvements recommended"
    elif quantum_safe and tls_version == "TLSv1.3":
        grade, color, desc = "A+","#16a34a","Excellent — post-quantum/hybrid TLS detected"
    elif tls_version == "TLSv1.3":
        grade, color, desc = "A","#16a34a","Strong — modern TLS configuration"
    else:
        grade, color, desc = "B","#f59e0b","Good — TLS 1.3 upgrade recommended"
    return {"grade": grade, "grade_color": color, "grade_description": desc,
            "pqc_note": None if quantum_safe else "Not post-quantum safe yet.",
            "grade_breakdown": {"tls_version_score": 30 if tls_version=="TLSv1.3" else 20 if tls_version=="TLSv1.2" else 0,
                                "quantum_ready": quantum_safe}}


def _analyze_certificate(cert):
    cert_info = {}; cert_issues = []
    exp_str = cert.get("notAfter","")
    cert_info["cert_expires"] = exp_str
    if exp_str:
        try:
            exp_date      = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days_remaining = (exp_date - datetime.datetime.utcnow()).days
            cert_info["days_until_expiry"] = days_remaining
            if days_remaining < 0:   cert_issues.append("CRITICAL: Certificate has expired")
            elif days_remaining < 14: cert_issues.append(f"URGENT: Expires in {days_remaining} days")
            elif days_remaining < 30: cert_issues.append(f"WARNING: Expires in {days_remaining} days")
        except ValueError:
            cert_info["days_until_expiry"] = None
    subject = dict(x[0] for x in cert.get("subject",[]))
    issuer  = dict(x[0] for x in cert.get("issuer",[]))
    cert_info["subject_cn"] = subject.get("commonName","")
    cert_info["issuer_cn"]  = issuer.get("commonName","")
    cert_info["san_count"]  = len(cert.get("subjectAltName",[]))
    return cert_info, cert_issues


def _analyze_tls_domain(domain: str) -> dict:
    clean = domain.strip().replace("https://","").replace("http://","").split("/")[0]
    if not clean:
        raise HTTPException(status_code=400, detail="Domain required")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean) as ssock:
                tls_version = ssock.version()
                cipher      = ssock.cipher()
                cert        = ssock.getpeercert()
        cipher_name = cipher[0] if cipher else "Unknown"
        cipher_bits = cipher[2] if cipher else 0
        analysis   = _analyze_tls_score(tls_version, cipher_name, cipher_bits)
        cert_info, cert_issues = _analyze_certificate(cert)
        grade_info = _calculate_tls_grade(analysis["tls_score"], analysis["quantum_safe"],
                                          tls_version, analysis["issues"] + cert_issues)
        nist_rec = (
            "Hybrid PQC TLS detected. Continue monitoring NIST updates." if analysis["quantum_safe"]
            else "TLS 1.3 is modern. Monitor hybrid PQC TLS using ML-KEM/FIPS 203." if tls_version == "TLSv1.3"
            else "Upgrade to TLS 1.3 first, then plan hybrid PQC migration."
        )
        return {
            "domain": clean, "tls_version": tls_version,
            "cipher_suite": cipher_name, "cipher_bits": cipher_bits,
            "quantum_safe": analysis["quantum_safe"], "tls_score": analysis["tls_score"],
            "grade": grade_info["grade"], "grade_color": grade_info["grade_color"],
            "grade_description": grade_info["grade_description"],
            "pqc_note": grade_info["pqc_note"],
            "grade_breakdown": grade_info["grade_breakdown"],
            "labels": analysis["labels"], "strengths": analysis["strengths"],
            "issues": analysis["issues"] + cert_issues,
            "certificate": cert_info,
            "has_forward_secrecy": analysis["has_forward_secrecy"],
            "has_pqc_key_exchange": analysis["has_pqc_kex"],
            "rsa_key_exchange": analysis["rsa_key_exchange"],
            "quantum_explanation": analysis["quantum_explanation"],
            "nist_recommendation": nist_rec,
            "nist_standard": "ML-KEM — NIST FIPS 203",
            "key_exchange": "ECDHE / Forward Secrecy" if analysis["has_forward_secrecy"] else "Unknown",
            "meta": {"tool":"QuantumGuard TLS Analyzer v2.5","company":"Mangsri QuantumGuard LLC"},
        }
    except ssl.SSLError as e:
        raise HTTPException(status_code=400, detail=f"SSL Error: {str(e)}")
    except socket.timeout:
        raise HTTPException(status_code=408, detail="Connection timed out")
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Cannot resolve domain: {clean}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"TLS analysis error: {str(e)}")


# ============================================================
# ── AUTH ENDPOINTS ──────────────────────────────────────────
# ============================================================

@app.post("/auth/register", tags=["Auth"])
@limiter.limit("10/hour")
async def register(request: Request, body: RegisterRequest):
    """Register a new account. Returns JWT immediately."""
    email = body.email.lower().strip()
    if email in USERS_DB:
        raise HTTPException(status_code=409, detail="Email already registered")
    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    user = {
        "id":              str(uuid.uuid4()),
        "email":           email,
        "name":            body.name or email.split("@")[0],
        "hashed_password": hash_password(body.password),
        "created_at":      datetime.datetime.utcnow().isoformat(),
        "scan_count":      0,
        "plan":            "free",
    }
    USERS_DB[email] = user
    token = create_access_token({"sub": email})
    logger.info(f"New user registered: {email}")
    return {
        "access_token": token, "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {"id": user["id"], "email": user["email"],
                 "name": user["name"], "plan": user["plan"]},
    }


@app.post("/auth/login", tags=["Auth"])
@limiter.limit("20/hour")
async def login(request: Request, body: LoginRequest):
    """Login with email + password. Returns JWT."""
    email = body.email.lower().strip()
    user  = USERS_DB.get(email)
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": email})
    logger.info(f"User logged in: {email}")
    return {
        "access_token": token, "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {"id": user["id"], "email": user["email"], "name": user["name"],
                 "plan": user["plan"], "scan_count": user["scan_count"]},
    }


@app.get("/auth/me", tags=["Auth"])
async def get_me(current_user: dict = Depends(get_current_user)):
    return {k: current_user[k] for k in ("id","email","name","plan","scan_count","created_at")}


@app.post("/auth/refresh", tags=["Auth"])
async def refresh_token(current_user: dict = Depends(get_current_user)):
    return {"access_token": create_access_token({"sub": current_user["email"]}), "token_type": "bearer"}


# ============================================================
# ROUTES — unchanged logic from v2.4, enhanced rate limits
# ============================================================

@app.get("/")
def root():
    return {"message":"QuantumGuard API is running!","version":"2.5",
            "company":"Mangsri QuantumGuard LLC","website":"https://quantumguard.site",
            "standards":["NIST FIPS 203","NIST FIPS 204","NIST FIPS 205"]}


@app.get("/health")
def health():
    return {"status":"healthy","version":"2.5","tool":"QuantumGuard"}


@app.post("/scan")
@limiter.limit("10/minute")
def scan(request: Request, body: ScanRequest, x_api_key: str = Header(...)):
    verify_key(x_api_key)
    if not os.path.exists(body.directory):
        raise HTTPException(status_code=404, detail="Directory not found")
    start    = time.time()
    findings = scan_directory(body.directory)
    score    = calculate_score(findings)
    severity_summary, confidence_summary = _summarize_findings(findings)
    return {
        "quantum_readiness_score": score,
        "score_explanation":       generate_score_explanation(findings, score),
        "scan_summary":            generate_scan_summary(body.directory, findings, start),
        "total_findings":          len(findings),
        "severity_summary":        severity_summary,
        "confidence_summary":      confidence_summary,
        "top_findings":            _build_top_findings(findings),
        "priority_actions":        _build_priority_actions(findings, severity_summary, score),
        "findings":                findings,
    }


@app.post("/public-scan-zip")
@limiter.limit("3/minute")
async def public_scan_zip(request: Request, file: UploadFile = File(...)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files allowed")
    contents = await file.read()
    if len(contents) > MAX_ZIP_SIZE:
        raise HTTPException(status_code=400, detail="ZIP too large. Max 10MB.")
    temp_dir = f"/tmp/qg-{uuid.uuid4().hex[:8]}"
    start    = time.time()
    try:
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(contents)) as z:
            z.extractall(temp_dir)
        findings = scan_directory(temp_dir)
        score    = calculate_score(findings)
        severity_summary, confidence_summary = _summarize_findings(findings)
        return {
            "filename":                file.filename,
            "quantum_readiness_score": score,
            "score_explanation":       generate_score_explanation(findings, score),
            "scan_summary":            generate_scan_summary(temp_dir, findings, start),
            "total_findings":          len(findings),
            "severity_summary":        severity_summary,
            "confidence_summary":      confidence_summary,
            "top_findings":            _build_top_findings(findings),
            "priority_actions":        _build_priority_actions(findings, severity_summary, score),
            "findings":                findings,
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
async def scan_github(
    request:      Request,
    body:         GitScanRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    temp_dir = None
    start    = time.time()
    try:
        zip_content, owner, repo = _download_github_zip(body.github_url, body.github_token)
        temp_dir = f"/tmp/qg-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
            z.extractall(temp_dir)
        findings = scan_directory(temp_dir)
        score    = calculate_score(findings)
        severity_summary, confidence_summary = _summarize_findings(findings)
        if current_user:
            USERS_DB[current_user["email"]]["scan_count"] += 1
        return {
            "github_url":              body.github_url,
            "repo":                    f"{owner}/{repo}",
            "quantum_readiness_score": score,
            "score_explanation":       generate_score_explanation(findings, score),
            "scan_summary":            generate_scan_summary(temp_dir, findings, start),
            "total_findings":          len(findings),
            "severity_summary":        severity_summary,
            "confidence_summary":      confidence_summary,
            "top_findings":            _build_top_findings(findings),
            "priority_actions":        _build_priority_actions(findings, severity_summary, score),
            "findings":                findings,
            "meta": {"tool":"QuantumGuard v2.5","standards":["NIST FIPS 203","NIST FIPS 204","NIST FIPS 205"],
                     "company":"Mangsri QuantumGuard LLC","website":"https://quantumguard.site"},
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
async def check_agility(
    request:      Request,
    body:         GitScanRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    temp_dir = None
    try:
        zip_content, owner, repo = _download_github_zip(body.github_url, body.github_token)
        temp_dir = f"/tmp/qg-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
            z.extractall(temp_dir)
        result = check_crypto_agility(temp_dir)
        result["repo"]       = f"{owner}/{repo}"
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
async def analyze_tls(
    request:      Request,
    body:         TLSRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    return _analyze_tls_domain(body.domain)


@app.post("/unified-risk")
@limiter.limit("5/minute")
async def unified_risk(
    request:      Request,
    body:         UnifiedRiskRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    if calculate_unified_quantum_risk is None:
        raise HTTPException(status_code=500, detail="unified_risk_engine.py not found")
    temp_dir = None
    start    = time.time()
    try:
        zip_content, owner, repo = _download_github_zip(body.github_url, body.github_token)
        temp_dir = f"/tmp/qg-unified-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
            z.extractall(temp_dir)
        findings     = scan_directory(temp_dir)
        code_score   = calculate_score(findings)
        severity_summary, confidence_summary = _summarize_findings(findings)
        agility_result = check_crypto_agility(temp_dir)
        tls_result = None; tls_error = None
        if body.domain:
            try:
                tls_result = _analyze_tls_domain(body.domain)
            except Exception as e:
                tls_error = str(e)
        unified_result = calculate_unified_quantum_risk(
            findings=findings, agility_result=agility_result, tls_result=tls_result,
        )
        return {
            "repo": f"{owner}/{repo}", "github_url": body.github_url, "domain": body.domain,
            "unified_risk": unified_result,
            "scanner_result": {
                "quantum_readiness_score": code_score,
                "score_explanation":       generate_score_explanation(findings, code_score),
                "scan_summary":            generate_scan_summary(temp_dir, findings, start),
                "total_findings":          len(findings),
                "severity_summary":        severity_summary,
                "confidence_summary":      confidence_summary,
                "top_findings":            _build_top_findings(findings),
                "priority_actions":        _build_priority_actions(findings, severity_summary, code_score),
                "findings":                findings[:100],
            },
            "agility_result": agility_result,
            "tls_result":     tls_result,
            "tls_error":      tls_error,
            "finding_summary": {
                "total": len(findings),
                "severity_summary": {
                    "CRITICAL": len([f for f in findings if f.get("severity")=="CRITICAL"]),
                    "HIGH":     len([f for f in findings if f.get("severity")=="HIGH"]),
                    "MEDIUM":   len([f for f in findings if f.get("severity")=="MEDIUM"]),
                    "LOW":      len([f for f in findings if f.get("severity")=="LOW"]),
                },
            },
            "top_findings": _build_top_findings(findings),
            "meta": {"tool":"QuantumGuard Unified Risk Engine v2.5","company":"Mangsri QuantumGuard LLC"},
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unified risk error: {str(e)}")
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


@app.post("/ai-fix")
@limiter.limit("10/minute")
async def ai_fix(
    request:      Request,
    body:         dict,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    finding = body.get("finding", {})
    if not finding:
        raise HTTPException(status_code=400, detail="Finding required")
    vuln        = finding.get("vulnerability","")
    code        = finding.get("code","")
    replacement = finding.get("replacement","")
    severity    = finding.get("severity","")
    risk        = finding.get("risk_explanation","")
    vu          = vuln.upper()
    if "RSA" in vu:
        fix = f"# BEFORE:\n{code}\n\n# MIGRATION: Replace with ML-KEM hybrid (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures.\n"
    elif "ECC" in vu or "ECDSA" in vu or "ECDH" in vu:
        fix = f"# BEFORE:\n{code}\n\n# MIGRATION:\n- ECDH/key exchange → ML-KEM/FIPS 203\n- ECDSA/signatures → ML-DSA/FIPS 204\n"
    elif "MD5" in vu:
        fix = f"# BEFORE:\n{code}\n\n# AFTER:\nimport hashlib\nhash_value = hashlib.sha3_256(data).hexdigest()\n\n# Why: MD5 is cryptographically broken.\n"
    elif "SHA1" in vu or "SHA-1" in vu:
        fix = f"# BEFORE:\n{code}\n\n# AFTER:\nimport hashlib\nhash_value = hashlib.sha3_256(data).hexdigest()\n\n# Why: SHA-1 is deprecated and collision-broken.\n"
    elif "DES" in vu:
        fix = f"# BEFORE:\n{code}\n\n# AFTER:\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\nimport os\nkey = AESGCM.generate_key(bit_length=256)\nnonce = os.urandom(12)\naesgcm = AESGCM(key)\nciphertext = aesgcm.encrypt(nonce, plaintext, None)\n"
    elif "RC4" in vu:
        fix = f"# BEFORE:\n{code}\n\n# AFTER:\nfrom cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\nimport os\nkey = ChaCha20Poly1305.generate_key()\nnonce = os.urandom(12)\nchacha = ChaCha20Poly1305(key)\nciphertext = chacha.encrypt(nonce, plaintext, None)\n"
    else:
        fix = f"# BEFORE:\n{code}\n\n# RECOMMENDED FIX:\n{replacement}\n\n# RISK: {risk}\n# SEVERITY: {severity}\n"
    return {"fix": fix, "vulnerability": vuln, "replacement": replacement}


@app.get("/badge/{owner}/{repo}")
async def get_badge(owner: str, repo: str):
    try:
        zip_content, o, r = _download_github_zip(f"https://github.com/{owner}/{repo}")
        temp_dir = f"/tmp/qg-badge-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)
        try:
            with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
                z.extractall(temp_dir)
            score = calculate_score(scan_directory(temp_dir))
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
        if score >= 80:   color="#16a34a"; lc="#15803d"; rt=f"{score}/100 safe"
        elif score >= 50: color="#d97706"; lc="#b45309"; rt=f"{score}/100 at risk"
        else:             color="#dc2626"; lc="#b91c1c"; rt=f"{score}/100 vulnerable"
    except Exception:
        color="#6b7280"; lc="#4b5563"; rt="unknown"
    lt="QuantumGuard"; lw=len(lt)*7+20; rw=len(rt)*7+20; tw=lw+rw
    svg=(f'<svg xmlns="http://www.w3.org/2000/svg" width="{tw}" height="20">'
         f'<g><rect width="{lw}" height="20" fill="{lc}"/>'
         f'<rect x="{lw}" width="{rw}" height="20" fill="{color}"/></g>'
         f'<g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,sans-serif" font-size="11">'
         f'<text x="{lw//2}" y="14">{lt}</text>'
         f'<text x="{lw+rw//2}" y="14">{rt}</text>'
         f'</g></svg>')
    return Response(content=svg, media_type="image/svg+xml",
                    headers={"Cache-Control":"no-cache,no-store,must-revalidate"})


@app.post("/export-cbom")
@limiter.limit("10/minute")
async def export_cbom(
    request:      Request,
    body:         GitScanRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    temp_dir = None
    try:
        zip_content, owner, repo = _download_github_zip(body.github_url, body.github_token)
        temp_dir = f"/tmp/qg-cbom-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zip_content)) as z:
            z.extractall(temp_dir)
        findings = scan_directory(temp_dir)
        score    = calculate_score(findings)
        return generate_cbom(findings, repo=f"{owner}/{repo}", score=score)
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
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files allowed")
    contents = await file.read()
    if len(contents) > MAX_ZIP_SIZE:
        raise HTTPException(status_code=400, detail="ZIP too large. Max 10MB.")
    temp_dir = f"/tmp/qg-cbom-{uuid.uuid4().hex[:8]}"
    try:
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(contents)) as z:
            z.extractall(temp_dir)
        findings = scan_directory(temp_dir)
        score    = calculate_score(findings)
        return generate_cbom(findings, repo=file.filename, score=score)
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CBOM export error: {str(e)}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
