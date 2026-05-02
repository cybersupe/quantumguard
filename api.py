# ============================================================
# QuantumGuard — FastAPI Backend v2.6
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# Standards: NIST FIPS 203, FIPS 204, FIPS 205
# ============================================================
# v2.6 adds: PostgreSQL persistent storage (users + scan history)
#            Tables auto-created on startup — no migrations needed
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

import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool

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
# LOGGING — scrub tokens from all log lines
# ============================================================

class TokenScrubFilter(logging.Filter):
    PATTERNS = [
        (re.compile(r'ghp_[A-Za-z0-9]{36}'),       '[GH_TOKEN_REDACTED]'),
        (re.compile(r'github_pat_[A-Za-z0-9_]+'),   '[GH_TOKEN_REDACTED]'),
        (re.compile(r'x-token:[^@\s]+'),             'x-token:[REDACTED]'),
        (re.compile(r'Bearer [A-Za-z0-9\-_\.]+'),   'Bearer [REDACTED]'),
        (re.compile(r'password["\s:=]+[^\s,}"]+',
                    re.IGNORECASE),                  'password:[REDACTED]'),
        (re.compile(r'postgresql://[^\s]+'),         'postgresql://[REDACTED]'),
    ]
    def filter(self, record):
        msg = str(record.getMessage())
        for pattern, replacement in self.PATTERNS:
            msg = pattern.sub(replacement, msg)
        record.msg  = msg
        record.args = ()
        return True

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("quantumguard")
logger.addFilter(TokenScrubFilter())


# ============================================================
# CONFIG
# ============================================================

API_KEY      = os.getenv("API_KEY", "quantumguard-secret-2026")
MAX_ZIP_SIZE = 10 * 1024 * 1024
DATABASE_URL = os.getenv("DATABASE_URL", "")

# JWT
SECRET_KEY                  = os.getenv("JWT_SECRET_KEY", "CHANGE_THIS_IN_PRODUCTION")
ALGORITHM                   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
ENVIRONMENT                 = os.getenv("ENVIRONMENT", "production")


# ============================================================
# DATABASE — connection pool + auto table creation
# ============================================================

db_pool: Optional[ThreadedConnectionPool] = None


def get_db():
    """Get a connection from the pool."""
    if db_pool is None:
        raise HTTPException(status_code=503, detail="Database not available")
    conn = db_pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        db_pool.putconn(conn)


def init_db():
    """Create tables if they don't exist. Called on startup."""
    global db_pool

    if not DATABASE_URL:
        logger.warning("DATABASE_URL not set — using in-memory fallback")
        return

    try:
        # Render PostgreSQL URLs start with postgres:// — psycopg2 needs postgresql://
        url = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        db_pool = ThreadedConnectionPool(minconn=1, maxconn=10, dsn=url)

        conn = db_pool.getconn()
        try:
            cur = conn.cursor()

            # ── users table ──────────────────────────────────
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id            TEXT PRIMARY KEY,
                    email         TEXT UNIQUE NOT NULL,
                    name          TEXT,
                    hashed_password TEXT NOT NULL,
                    plan          TEXT DEFAULT 'free',
                    scan_count    INTEGER DEFAULT 0,
                    created_at    TIMESTAMP DEFAULT NOW()
                );
            """)

            # ── scan_history table ────────────────────────────
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id          TEXT PRIMARY KEY,
                    user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
                    user_email  TEXT,
                    target      TEXT,
                    score       INTEGER,
                    findings    INTEGER,
                    scan_type   TEXT DEFAULT 'github',
                    created_at  TIMESTAMP DEFAULT NOW()
                );
            """)

            conn.commit()
            cur.close()
            logger.info("PostgreSQL connected — tables ready")
        finally:
            db_pool.putconn(conn)

    except Exception as e:
        logger.error(f"Database init failed: {type(e).__name__} — falling back to in-memory")
        db_pool = None


# ── In-memory fallback (used when DATABASE_URL not set) ──────
USERS_MEMORY: dict[str, dict] = {}


# ── User CRUD helpers ─────────────────────────────────────────

def db_get_user(email: str) -> Optional[dict]:
    if db_pool is None:
        return USERS_MEMORY.get(email)
    conn = db_pool.getconn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        cur.close()
        return dict(row) if row else None
    finally:
        db_pool.putconn(conn)


def db_create_user(user: dict) -> dict:
    if db_pool is None:
        USERS_MEMORY[user["email"]] = user
        return user
    conn = db_pool.getconn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO users (id, email, name, hashed_password, plan, scan_count, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            user["id"], user["email"], user["name"],
            user["hashed_password"], user["plan"],
            user["scan_count"], user["created_at"],
        ))
        conn.commit()
        cur.close()
        return user
    finally:
        db_pool.putconn(conn)


def db_increment_scan_count(email: str):
    if db_pool is None:
        if email in USERS_MEMORY:
            USERS_MEMORY[email]["scan_count"] += 1
        return
    conn = db_pool.getconn()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET scan_count = scan_count + 1 WHERE email = %s", (email,)
        )
        conn.commit()
        cur.close()
    finally:
        db_pool.putconn(conn)


def db_save_scan(user_id: str, user_email: str, target: str,
                 score: int, findings: int, scan_type: str = "github"):
    if db_pool is None:
        return  # history not saved in memory mode
    conn = db_pool.getconn()
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO scan_history (id, user_id, user_email, target, score, findings, scan_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (str(uuid.uuid4()), user_id, user_email, target, score, findings, scan_type))
        conn.commit()
        cur.close()
    finally:
        db_pool.putconn(conn)


def db_get_scan_history(user_id: str, limit: int = 50) -> list:
    if db_pool is None:
        return []
    conn = db_pool.getconn()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute("""
            SELECT * FROM scan_history
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT %s
        """, (user_id, limit))
        rows = cur.fetchall()
        cur.close()
        return [dict(r) for r in rows]
    finally:
        db_pool.putconn(conn)


# ============================================================
# PASSWORD HASHING
# ============================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


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
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = db_get_user(email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Optional[dict]:
    if not credentials:
        return None
    try:
        payload = decode_token(credentials.credentials)
        email   = payload.get("sub")
        return db_get_user(email) if email else None
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
    version="2.6",
    docs_url="/docs" if ENVIRONMENT == "development" else None,
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.on_event("startup")
async def startup():
    init_db()
    logger.info("QuantumGuard API v2.6 started")


@app.on_event("shutdown")
async def shutdown():
    global db_pool
    if db_pool:
        db_pool.closeall()
        logger.info("Database pool closed")


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
# HELPERS
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
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "QuantumGuard/2.6"}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    meta_resp = requests.get(
        f"https://api.github.com/repos/{owner}/{repo}", headers=headers, timeout=10
    )
    if meta_resp.status_code == 200:
        if meta_resp.json().get("size", 0) > 50000:
            raise HTTPException(status_code=400, detail="Repo too large. Max 50MB.")
    for branch in ["main", "master"]:
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}",
            headers=headers, timeout=30, allow_redirects=True,
        )
        if resp.status_code == 200:
            if len(resp.content) > 15 * 1024 * 1024:
                raise HTTPException(status_code=400, detail="Repo ZIP too large for free tier.")
            return resp.content, owner, repo
    raise HTTPException(status_code=400, detail="Could not download repo. Make sure it is public.")


def _summarize_findings(findings):
    sev  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    conf = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev[f.get("severity","MEDIUM")]    = sev.get(f.get("severity","MEDIUM"), 0) + 1
        conf[f.get("confidence","MEDIUM")] = conf.get(f.get("confidence","MEDIUM"), 0) + 1
    return sev, conf


def _build_priority_actions(findings, sev, score):
    actions = []
    if sev.get("CRITICAL", 0) > 0:
        actions.append({"priority":"P1","title":"Fix critical vulnerabilities immediately","description":f"{sev['CRITICAL']} critical findings.","timeline":"Within 30 days"})
    if sev.get("HIGH", 0) > 0:
        actions.append({"priority":"P2","title":"Remediate high-severity risks","description":f"{sev['HIGH']} high findings.","timeline":"Within 90 days"})
    if sev.get("MEDIUM", 0) > 0:
        actions.append({"priority":"P3","title":"Plan medium-severity migration","description":f"{sev['MEDIUM']} medium findings.","timeline":"Within 6 months"})
    if score < 50:
        actions.append({"priority":"P1","title":"Begin NIST PQC migration planning","description":"Score below 50.","timeline":"Within 60 days"})
    if not actions:
        actions.append({"priority":"P4","title":"Maintain monitoring","description":"No major issues.","timeline":"Ongoing"})
    return actions


def _build_top_findings(findings):
    return [
        {"file": f.get("file","").split("/")[-1], "line": f.get("line"),
         "vulnerability": f.get("vulnerability"), "severity": f.get("severity"),
         "confidence": f.get("confidence"),
         "recommended_fix": f.get("recommended_fix") or f.get("replacement")}
        for f in findings[:10] if f.get("confidence") != "LOW"
    ]


# ============================================================
# TLS ANALYZER
# ============================================================

PQC_INDICATORS     = ["KYBER","MLKEM","ML_KEM","X25519KYBER768","X25519MLKEM768","NTRU","FRODO","SABER","BIKE","HQC"]
STRONG_CIPHERS     = ["AES_256","AES-256","CHACHA20"]
ACCEPTABLE_CIPHERS = ["AES_128","AES-128"]
FORWARD_SECRECY_KX = ["ECDHE","DHE","X25519","X448"]


def _analyze_tls_score(tls_version, cipher_name, cipher_bits):
    score = 0; issues = []; strengths = []
    cu = (cipher_name or "").upper()
    if tls_version == "TLSv1.3":
        score += 30; strengths.append("TLS 1.3 — modern and forward-secure")
    elif tls_version == "TLSv1.2":
        score += 20; issues.append("TLS 1.2 — upgrade to TLS 1.3 recommended")
    else:
        issues.append(f"{tls_version} is deprecated — upgrade to TLS 1.3 immediately")
    if any(s in cu for s in STRONG_CIPHERS):
        score += 35; strengths.append("Strong symmetric encryption")
    elif any(s in cu for s in ACCEPTABLE_CIPHERS):
        score += 20; issues.append("AES-128 — AES-256 preferred")
    elif cipher_bits and cipher_bits >= 256:
        score += 30
    elif cipher_bits and cipher_bits >= 128:
        score += 15; issues.append("AES-256 recommended")
    else:
        issues.append("Weak or unknown cipher")
    has_pqc         = any(p in cu for p in PQC_INDICATORS)
    has_fs          = tls_version == "TLSv1.3" or has_pqc or any(kx in cu for kx in FORWARD_SECRECY_KX)
    rsa_kx          = "RSA" in cu and not has_fs
    quantum_safe    = has_pqc
    if has_pqc:
        score += 25; strengths.append("Hybrid post-quantum key exchange detected")
    elif tls_version == "TLSv1.3":
        score += 10; issues.append("Not post-quantum safe yet")
    elif has_fs:
        score += 10; issues.append("Classical ECDHE — not post-quantum safe")
    else:
        issues.append("No forward secrecy detected")
    return {"tls_score": max(0, min(100, score)), "quantum_safe": quantum_safe,
            "strengths": strengths, "issues": issues,
            "has_forward_secrecy": has_fs, "has_pqc_kex": has_pqc,
            "rsa_key_exchange": rsa_kx, "labels": [],
            "quantum_explanation": "Hybrid PQC detected." if quantum_safe else "Not post-quantum safe yet."}


def _calculate_tls_grade(score, quantum_safe, tls_version, issues):
    ck = ["expired","sslv","tlsv1.0","tlsv1.1","deprecated"]
    hc = any(any(k in i.lower() for k in ck) for i in issues)
    if hc or score < 35:  g,c,d = "F","#dc2626","Failing — immediate action required"
    elif score < 50:      g,c,d = "D","#dc2626","Poor — significant vulnerabilities"
    elif score < 65:      g,c,d = "C","#d97706","Average — improvements recommended"
    elif score < 80:      g,c,d = "B","#f59e0b","Good — some improvements recommended"
    elif quantum_safe and tls_version == "TLSv1.3": g,c,d = "A+","#16a34a","Excellent — hybrid PQC detected"
    elif tls_version == "TLSv1.3": g,c,d = "A","#16a34a","Strong — modern TLS"
    else:                 g,c,d = "B","#f59e0b","Good — TLS 1.3 upgrade recommended"
    return {"grade":g,"grade_color":c,"grade_description":d,
            "pqc_note": None if quantum_safe else "Not post-quantum safe yet.",
            "grade_breakdown":{"tls_version_score": 30 if tls_version=="TLSv1.3" else 20 if tls_version=="TLSv1.2" else 0,"quantum_ready":quantum_safe}}


def _analyze_certificate(cert):
    ci = {}; ci_issues = []
    exp = cert.get("notAfter","")
    ci["cert_expires"] = exp
    if exp:
        try:
            ed  = datetime.datetime.strptime(exp, "%b %d %H:%M:%S %Y %Z")
            dr  = (ed - datetime.datetime.utcnow()).days
            ci["days_until_expiry"] = dr
            if dr < 0:    ci_issues.append("CRITICAL: Certificate expired")
            elif dr < 14: ci_issues.append(f"URGENT: Expires in {dr} days")
            elif dr < 30: ci_issues.append(f"WARNING: Expires in {dr} days")
        except ValueError:
            ci["days_until_expiry"] = None
    subject = dict(x[0] for x in cert.get("subject",[]))
    issuer  = dict(x[0] for x in cert.get("issuer",[]))
    ci["subject_cn"] = subject.get("commonName","")
    ci["issuer_cn"]  = issuer.get("commonName","")
    ci["san_count"]  = len(cert.get("subjectAltName",[]))
    return ci, ci_issues


def _analyze_tls_domain(domain: str) -> dict:
    clean = domain.strip().replace("https://","").replace("http://","").split("/")[0]
    if not clean:
        raise HTTPException(status_code=400, detail="Domain required")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((clean, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=clean) as ssock:
                tv = ssock.version(); cipher = ssock.cipher(); cert = ssock.getpeercert()
        cn = cipher[0] if cipher else "Unknown"
        cb = cipher[2] if cipher else 0
        a  = _analyze_tls_score(tv, cn, cb)
        ci, ci_issues = _analyze_certificate(cert)
        g  = _calculate_tls_grade(a["tls_score"], a["quantum_safe"], tv, a["issues"]+ci_issues)
        nr = ("Hybrid PQC TLS detected." if a["quantum_safe"]
              else "TLS 1.3 is modern. Monitor hybrid PQC ML-KEM adoption." if tv=="TLSv1.3"
              else "Upgrade to TLS 1.3 first, then plan hybrid PQC migration.")
        return {
            "domain":cn,"tls_version":tv,"cipher_suite":cn,"cipher_bits":cb,
            "quantum_safe":a["quantum_safe"],"tls_score":a["tls_score"],
            "grade":g["grade"],"grade_color":g["grade_color"],
            "grade_description":g["grade_description"],"pqc_note":g["pqc_note"],
            "grade_breakdown":g["grade_breakdown"],"labels":a["labels"],
            "strengths":a["strengths"],"issues":a["issues"]+ci_issues,
            "certificate":ci,"has_forward_secrecy":a["has_forward_secrecy"],
            "has_pqc_key_exchange":a["has_pqc_kex"],"rsa_key_exchange":a["rsa_key_exchange"],
            "quantum_explanation":a["quantum_explanation"],"nist_recommendation":nr,
            "nist_standard":"ML-KEM — NIST FIPS 203",
            "key_exchange":"ECDHE / Forward Secrecy" if a["has_forward_secrecy"] else "Unknown",
            "domain":clean,
        }
    except ssl.SSLError as e:
        raise HTTPException(status_code=400, detail=f"SSL Error: {str(e)}")
    except socket.timeout:
        raise HTTPException(status_code=408, detail="Connection timed out")
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Cannot resolve: {clean}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"TLS error: {str(e)}")


# ============================================================
# ── AUTH ENDPOINTS ──────────────────────────────────────────
# ============================================================

@app.post("/auth/register", tags=["Auth"])
@limiter.limit("10/hour")
async def register(request: Request, body: RegisterRequest):
    """Register a new account. Persisted to PostgreSQL."""
    email = body.email.lower().strip()
    if db_get_user(email):
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
    db_create_user(user)
    token = create_access_token({"sub": email})
    logger.info(f"New user registered: {email}")
    return {
        "access_token": token, "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {"id":user["id"],"email":user["email"],"name":user["name"],"plan":user["plan"]},
    }


@app.post("/auth/login", tags=["Auth"])
@limiter.limit("20/hour")
async def login(request: Request, body: LoginRequest):
    """Login with email + password."""
    email = body.email.lower().strip()
    user  = db_get_user(email)
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": email})
    logger.info(f"User logged in: {email}")
    return {
        "access_token": token, "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {"id":user["id"],"email":user["email"],"name":user["name"],
                 "plan":user["plan"],"scan_count":user["scan_count"]},
    }


@app.get("/auth/me", tags=["Auth"])
async def get_me(current_user: dict = Depends(get_current_user)):
    return {k: current_user[k] for k in ("id","email","name","plan","scan_count","created_at") if k in current_user}


@app.post("/auth/refresh", tags=["Auth"])
async def refresh_token(current_user: dict = Depends(get_current_user)):
    return {"access_token": create_access_token({"sub": current_user["email"]}), "token_type": "bearer"}


@app.get("/auth/history", tags=["Auth"])
async def get_history(current_user: dict = Depends(get_current_user)):
    """Get scan history for the logged-in user."""
    history = db_get_scan_history(current_user["id"])
    return {"history": history, "total": len(history)}


# ============================================================
# ROUTES
# ============================================================

@app.get("/")
def root():
    return {"message":"QuantumGuard API is running!","version":"2.6",
            "company":"Mangsri QuantumGuard LLC","website":"https://quantumguard.site",
            "standards":["NIST FIPS 203","NIST FIPS 204","NIST FIPS 205"],
            "db": "postgresql" if db_pool else "memory"}


@app.get("/health")
def health():
    return {"status":"healthy","version":"2.6","tool":"QuantumGuard",
            "db": "postgresql" if db_pool else "memory (no DATABASE_URL set)"}


@app.post("/scan")
@limiter.limit("10/minute")
def scan(request: Request, body: ScanRequest, x_api_key: str = Header(...)):
    verify_key(x_api_key)
    if not os.path.exists(body.directory):
        raise HTTPException(status_code=404, detail="Directory not found")
    start = time.time()
    findings = scan_directory(body.directory)
    score    = calculate_score(findings)
    sev, conf = _summarize_findings(findings)
    return {
        "quantum_readiness_score": score,
        "score_explanation":       generate_score_explanation(findings, score),
        "scan_summary":            generate_scan_summary(body.directory, findings, start),
        "total_findings":          len(findings),
        "severity_summary":        sev,
        "confidence_summary":      conf,
        "top_findings":            _build_top_findings(findings),
        "priority_actions":        _build_priority_actions(findings, sev, score),
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
        sev, conf = _summarize_findings(findings)
        return {
            "filename": file.filename,
            "quantum_readiness_score": score,
            "score_explanation":       generate_score_explanation(findings, score),
            "scan_summary":            generate_scan_summary(temp_dir, findings, start),
            "total_findings":          len(findings),
            "severity_summary":        sev,
            "confidence_summary":      conf,
            "top_findings":            _build_top_findings(findings),
            "priority_actions":        _build_priority_actions(findings, sev, score),
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
        sev, conf = _summarize_findings(findings)

        # Save to PostgreSQL if user is logged in
        if current_user:
            db_increment_scan_count(current_user["email"])
            db_save_scan(current_user["id"], current_user["email"],
                         body.github_url, score, len(findings), "github")

        return {
            "github_url": body.github_url, "repo": f"{owner}/{repo}",
            "quantum_readiness_score": score,
            "score_explanation":       generate_score_explanation(findings, score),
            "scan_summary":            generate_scan_summary(temp_dir, findings, start),
            "total_findings":          len(findings),
            "severity_summary":        sev,
            "confidence_summary":      conf,
            "top_findings":            _build_top_findings(findings),
            "priority_actions":        _build_priority_actions(findings, sev, score),
            "findings":                findings,
            "meta": {"tool":"QuantumGuard v2.6","standards":["NIST FIPS 203","NIST FIPS 204","NIST FIPS 205"],
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
        findings       = scan_directory(temp_dir)
        code_score     = calculate_score(findings)
        sev, conf      = _summarize_findings(findings)
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
        if current_user:
            db_increment_scan_count(current_user["email"])
            db_save_scan(current_user["id"], current_user["email"],
                         body.github_url, code_score, len(findings), "unified")
        return {
            "repo": f"{owner}/{repo}", "github_url": body.github_url, "domain": body.domain,
            "unified_risk": unified_result,
            "scanner_result": {
                "quantum_readiness_score": code_score,
                "score_explanation":       generate_score_explanation(findings, code_score),
                "scan_summary":            generate_scan_summary(temp_dir, findings, start),
                "total_findings":          len(findings),
                "severity_summary":        sev,
                "confidence_summary":      conf,
                "top_findings":            _build_top_findings(findings),
                "priority_actions":        _build_priority_actions(findings, sev, code_score),
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
            "meta": {"tool":"QuantumGuard Unified Risk Engine v2.6","company":"Mangsri QuantumGuard LLC"},
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
    vuln = finding.get("vulnerability",""); code = finding.get("code","")
    replacement = finding.get("replacement",""); severity = finding.get("severity","")
    vu = vuln.upper()
    if "RSA" in vu:
        fix = f"# BEFORE:\n{code}\n\n# MIGRATION: Replace with ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures.\n"
    elif "ECC" in vu or "ECDSA" in vu or "ECDH" in vu:
        fix = f"# BEFORE:\n{code}\n\n# MIGRATION:\n- ECDH → ML-KEM/FIPS 203\n- ECDSA → ML-DSA/FIPS 204\n"
    elif "MD5" in vu:
        fix = f"# BEFORE:\n{code}\n\n# AFTER:\nimport hashlib\nhash_value = hashlib.sha3_256(data).hexdigest()\n"
    elif "SHA1" in vu or "SHA-1" in vu:
        fix = f"# BEFORE:\n{code}\n\n# AFTER:\nimport hashlib\nhash_value = hashlib.sha3_256(data).hexdigest()\n"
    elif "DES" in vu:
        fix = f"# BEFORE:\n{code}\n\n# AFTER:\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\nimport os\nkey=AESGCM.generate_key(bit_length=256)\nnonce=os.urandom(12)\nct=AESGCM(key).encrypt(nonce,plaintext,None)\n"
    elif "RC4" in vu:
        fix = f"# BEFORE:\n{code}\n\n# AFTER:\nfrom cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305\nimport os\nkey=ChaCha20Poly1305.generate_key()\nnonce=os.urandom(12)\nct=ChaCha20Poly1305(key).encrypt(nonce,plaintext,None)\n"
    else:
        fix = f"# BEFORE:\n{code}\n\n# RECOMMENDED FIX: {replacement}\n# SEVERITY: {severity}\n"
    return {"fix": fix, "vulnerability": vuln, "replacement": replacement}


@app.get("/badge/{owner}/{repo}")
async def get_badge(owner: str, repo: str):
    try:
        zc, o, r = _download_github_zip(f"https://github.com/{owner}/{repo}")
        td = f"/tmp/qg-badge-{uuid.uuid4().hex[:8]}"
        os.makedirs(td, exist_ok=True)
        try:
            with zipfile.ZipFile(io.BytesIO(zc)) as z: z.extractall(td)
            score = calculate_score(scan_directory(td))
        finally:
            shutil.rmtree(td, ignore_errors=True)
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
         f'<text x="{lw//2}" y="14">{lt}</text><text x="{lw+rw//2}" y="14">{rt}</text>'
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
        zc, owner, repo = _download_github_zip(body.github_url, body.github_token)
        temp_dir = f"/tmp/qg-cbom-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(zc)) as z: z.extractall(temp_dir)
        findings = scan_directory(temp_dir)
        return generate_cbom(findings, repo=f"{owner}/{repo}", score=calculate_score(findings))
    except HTTPException: raise
    except Exception as e: raise HTTPException(status_code=500, detail=f"CBOM error: {str(e)}")
    finally:
        if temp_dir and os.path.exists(temp_dir): shutil.rmtree(temp_dir)


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
        with zipfile.ZipFile(io.BytesIO(contents)) as z: z.extractall(temp_dir)
        findings = scan_directory(temp_dir)
        return generate_cbom(findings, repo=file.filename, score=calculate_score(findings))
    except zipfile.BadZipFile: raise HTTPException(status_code=400, detail="Invalid ZIP")
    except Exception as e:     raise HTTPException(status_code=500, detail=f"CBOM error: {str(e)}")
    finally:
        if os.path.exists(temp_dir): shutil.rmtree(temp_dir)
