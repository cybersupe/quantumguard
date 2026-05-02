"""
QuantumGuard API — main_patched.py
Patches applied today (May 2, 2026):
  FIX-1: ZIP path traversal vulnerability (CVE-class) — validate all member paths
  FIX-2: SSRF on /scan-github — URL allowlist, private IP block
  FIX-3: PostgreSQL wired for users + scan_history (replaces USERS_DB dict)
  FIX-4: agility_score=60 hardcode removed — calls real check_crypto_agility()
  FIX-5: CORS allow_methods tightened from ["*"] to explicit list
  FIX-6: /auth/history endpoint added (scan history from DB)

HOW TO DEPLOY:
  1. Set env vars: JWT_SECRET_KEY, DATABASE_URL (postgres://...), OPENAI_API_KEY
  2. Run: python -c "from main_patched import init_db; import asyncio; asyncio.run(init_db())"
     (or just start the app — init_db() runs on startup)
  3. Replace main.py with this file on Render
"""

import os
import re
import uuid
import shutil
import socket
import tempfile
import logging
import subprocess
import ipaddress
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlparse

import asyncpg
import httpx
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from jose import JWTError, jwt
from passlib.context import CryptContext

from scanner.scan import generate_report, check_crypto_agility

# ─────────────────────────────────────────────
# LOGGING — scrub tokens from all log lines
# ─────────────────────────────────────────────
class TokenScrubFilter(logging.Filter):
    PATTERNS = [
        (re.compile(r'ghp_[A-Za-z0-9]{36}'), '[GH_TOKEN_REDACTED]'),
        (re.compile(r'github_pat_[A-Za-z0-9_]+'), '[GH_TOKEN_REDACTED]'),
        (re.compile(r'x-token:[^@\s]+'), 'x-token:[REDACTED]'),
        (re.compile(r'Bearer [A-Za-z0-9\-_\.]+'), 'Bearer [REDACTED]'),
        (re.compile(r'password["\s:=]+[^\s,}"]+', re.IGNORECASE), 'password:[REDACTED]'),
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

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
SECRET_KEY                  = os.getenv("JWT_SECRET_KEY", "CHANGE_THIS_IN_PRODUCTION_USE_ENV_VAR")
ALGORITHM                   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
OPENAI_API_KEY              = os.getenv("OPENAI_API_KEY", "")
ENVIRONMENT                 = os.getenv("ENVIRONMENT", "production")
DATABASE_URL                = os.getenv("DATABASE_URL", "")  # postgres://user:pass@host/db

# ─────────────────────────────────────────────
# FIX-2: SSRF guard — allowed git hosts + private IP ranges
# ─────────────────────────────────────────────
ALLOWED_GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),    # Render internal
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def _validate_github_url(url: str) -> str:
    """
    FIX-2: Validate a git clone URL.
    - Must be https://
    - Host must be in ALLOWED_GIT_HOSTS
    - Resolved IP must not be a private/internal address
    Raises HTTPException(400) on failure. Returns clean URL on success.
    """
    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise HTTPException(status_code=400, detail="Only https:// URLs are supported.")

    host = parsed.hostname or ""
    if host not in ALLOWED_GIT_HOSTS:
        raise HTTPException(
            status_code=400,
            detail=f"Repository host '{host}' is not allowed. Use github.com, gitlab.com, or bitbucket.org."
        )

    # Resolve and check the IP — blocks SSRF via DNS rebinding
    try:
        resolved_ip = socket.gethostbyname(host)
        ip_obj = ipaddress.ip_address(resolved_ip)
        for network in PRIVATE_NETWORKS:
            if ip_obj in network:
                raise HTTPException(status_code=400, detail="URL resolves to a private/internal address.")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail=f"Could not resolve host: {host}")

    return url


# ─────────────────────────────────────────────
# FIX-1: Safe ZIP extraction
# ─────────────────────────────────────────────
def _safe_extract_zip(zf, target_dir: str) -> None:
    """
    FIX-1: Validate every member path before extraction.
    Prevents path traversal attacks (e.g. '../../etc/crontab' in ZIP).
    """
    import zipfile
    target_dir = os.path.realpath(target_dir)

    for member in zf.namelist():
        # Resolve where this member would land
        member_path = os.path.realpath(os.path.join(target_dir, member))

        # It must stay inside target_dir
        if not member_path.startswith(target_dir + os.sep) and member_path != target_dir:
            raise HTTPException(
                status_code=400,
                detail=f"ZIP contains unsafe path: {member!r}. Extraction blocked."
            )

        # Block absolute paths and null bytes
        if os.path.isabs(member) or "\x00" in member:
            raise HTTPException(
                status_code=400,
                detail=f"ZIP contains unsafe path: {member!r}. Extraction blocked."
            )

    # All paths validated — safe to extract
    zf.extractall(target_dir)


# ─────────────────────────────────────────────
# FIX-3: PostgreSQL — connection pool + schema init
# ─────────────────────────────────────────────
_pool: Optional[asyncpg.Pool] = None

async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        if not DATABASE_URL:
            raise HTTPException(status_code=503, detail="Database not configured.")
        _pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=10)
    return _pool

async def init_db():
    """Create tables if they don't exist. Called on startup."""
    if not DATABASE_URL:
        logger.warning("DATABASE_URL not set — running without persistent storage.")
        return
    try:
        pool = await get_pool()
        async with pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    email       TEXT UNIQUE NOT NULL,
                    name        TEXT NOT NULL DEFAULT '',
                    hashed_password TEXT NOT NULL,
                    plan        TEXT NOT NULL DEFAULT 'free',
                    scan_count  INTEGER NOT NULL DEFAULT 0,
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS scan_history (
                    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
                    target      TEXT NOT NULL,
                    score       INTEGER,
                    findings    INTEGER,
                    scan_type   TEXT DEFAULT 'github',
                    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON scan_history(user_id);
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            """)
        logger.info("Database schema initialized.")
    except Exception as e:
        logger.error(f"Database init failed: {e}")

# ─────────────────────────────────────────────
# DB helpers
# ─────────────────────────────────────────────
async def db_get_user(email: str) -> Optional[dict]:
    if not DATABASE_URL:
        return USERS_DB.get(email)
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
        return dict(row) if row else None

async def db_create_user(user: dict) -> dict:
    if not DATABASE_URL:
        USERS_DB[user["email"]] = user
        return user
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow("""
            INSERT INTO users (id, email, name, hashed_password, plan, scan_count)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
        """, uuid.UUID(user["id"]), user["email"], user["name"],
            user["hashed_password"], user["plan"], user["scan_count"])
        return dict(row)

async def db_increment_scan(email: str):
    if not DATABASE_URL:
        if email in USERS_DB:
            USERS_DB[email]["scan_count"] += 1
        return
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET scan_count = scan_count + 1 WHERE email = $1", email
        )

async def db_save_scan(user_id: str, target: str, score: int, findings: int, scan_type: str = "github"):
    if not DATABASE_URL:
        return
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO scan_history (user_id, target, score, findings, scan_type)
            VALUES ($1, $2, $3, $4, $5)
        """, uuid.UUID(user_id), target, score, findings, scan_type)

async def db_get_history(user_id: str) -> list:
    if not DATABASE_URL:
        return []
    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT target, score, findings, scan_type, created_at
            FROM scan_history
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 50
        """, uuid.UUID(user_id))
        return [dict(r) for r in rows]

# ─────────────────────────────────────────────
# Fallback in-memory store (no DB configured)
# ─────────────────────────────────────────────
USERS_DB: dict[str, dict] = {}

# ─────────────────────────────────────────────
# PASSWORD HASHING
# ─────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# ─────────────────────────────────────────────
# JWT HELPERS
# ─────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ─────────────────────────────────────────────
# AUTH DEPENDENCY
# ─────────────────────────────────────────────
security = HTTPBearer(auto_error=False)

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Include: Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_token(credentials.credentials)
    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = await db_get_user(email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[dict]:
    if not credentials:
        return None
    try:
        payload = decode_token(credentials.credentials)
        email = payload.get("sub")
        if not email:
            return None
        return await db_get_user(email)
    except HTTPException:
        return None

# ─────────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/hour"])

# ─────────────────────────────────────────────
# APP — lifespan initializes DB on startup
# ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(
    title="QuantumGuard API",
    description="Post-quantum cryptography vulnerability scanner",
    version="2.1.0",
    docs_url="/docs" if ENVIRONMENT == "development" else None,
    redoc_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# FIX-5: Tightened CORS — removed allow_methods=["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://quantumguard.site",
        "https://www.quantumguard.site",
        "https://quantumguard-one.vercel.app",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],   # FIX-5: explicit, not wildcard
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# ─────────────────────────────────────────────
# PYDANTIC MODELS
# ─────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = ""

class LoginRequest(BaseModel):
    email: str
    password: str

class ScanGithubRequest(BaseModel):
    github_url: str
    github_token: Optional[str] = None

class AgilityRequest(BaseModel):
    github_url: str

class TLSRequest(BaseModel):
    domain: str

class UnifiedRiskRequest(BaseModel):
    github_url: str
    domain: str

class AIFixRequest(BaseModel):
    finding: dict

class ScanDirectoryRequest(BaseModel):
    directory: str

# ─────────────────────────────────────────────
# AUTH ENDPOINTS
# ─────────────────────────────────────────────

@app.post("/auth/register", tags=["Auth"])
@limiter.limit("10/hour")
async def register(request: Request, body: RegisterRequest):
    email = body.email.lower().strip()

    existing = await db_get_user(email)
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user = {
        "id":               str(uuid.uuid4()),
        "email":            email,
        "name":             body.name or email.split("@")[0],
        "hashed_password":  hash_password(body.password),
        "scan_count":       0,
        "plan":             "free",
        "created_at":       datetime.utcnow().isoformat(),
    }
    user = await db_create_user(user)

    token = create_access_token({"sub": email})
    logger.info(f"New user registered: {email}")

    return {
        "access_token": token,
        "token_type":   "bearer",
        "expires_in":   ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id":    str(user["id"]),
            "email": user["email"],
            "name":  user["name"],
            "plan":  user["plan"],
        }
    }


@app.post("/auth/login", tags=["Auth"])
@limiter.limit("20/hour")
async def login(request: Request, body: LoginRequest):
    email = body.email.lower().strip()
    user  = await db_get_user(email)

    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": email})
    logger.info(f"User logged in: {email}")

    return {
        "access_token": token,
        "token_type":   "bearer",
        "expires_in":   ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id":         str(user["id"]),
            "email":      user["email"],
            "name":       user["name"],
            "plan":       user["plan"],
            "scan_count": user["scan_count"],
        }
    }


@app.get("/auth/me", tags=["Auth"])
async def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id":         str(current_user["id"]),
        "email":      current_user["email"],
        "name":       current_user["name"],
        "plan":       current_user["plan"],
        "scan_count": current_user["scan_count"],
        "created_at": str(current_user.get("created_at", "")),
    }


@app.get("/auth/history", tags=["Auth"])
async def get_history(current_user: dict = Depends(get_current_user)):
    """FIX-6: Return scan history from PostgreSQL."""
    history = await db_get_history(str(current_user["id"]))
    return {"history": [
        {
            "target":     h["target"],
            "score":      h["score"],
            "findings":   h["findings"],
            "scan_type":  h["scan_type"],
            "created_at": h["created_at"].isoformat() if hasattr(h["created_at"], "isoformat") else str(h["created_at"]),
        }
        for h in history
    ]}


@app.post("/auth/refresh", tags=["Auth"])
async def refresh_token(current_user: dict = Depends(get_current_user)):
    token = create_access_token({"sub": current_user["email"]})
    return {"access_token": token, "token_type": "bearer"}


# ─────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    db_status = "connected" if DATABASE_URL else "not_configured"
    return {
        "status":    "healthy",
        "version":   "2.1.0",
        "db":        db_status,
        "time":      datetime.utcnow().isoformat(),
    }


# ─────────────────────────────────────────────
# SCAN ENDPOINTS
# ─────────────────────────────────────────────

@app.post("/scan-github", tags=["Scanner"])
@limiter.limit("20/day")
async def scan_github(
    request:      Request,
    body:         ScanGithubRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    if not body.github_url:
        raise HTTPException(status_code=400, detail="github_url is required")

    # FIX-2: Validate URL before touching the network
    clean_url = _validate_github_url(body.github_url)

    logger.info(f"Scan started: {clean_url} | user={current_user['email'] if current_user else 'guest'}")

    # Build authenticated clone URL without logging the token
    clone_url = clean_url
    if body.github_token:
        clone_url = clone_url.replace("https://", f"https://x-token:{body.github_token}@")

    tmpdir = tempfile.mkdtemp()
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", clone_url, tmpdir],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            err = result.stderr
            if body.github_token:
                err = err.replace(body.github_token, "[REDACTED]")
            raise HTTPException(status_code=400, detail=f"Git clone failed: {err[:200]}")

        report = generate_report(tmpdir)

        if current_user:
            await db_increment_scan(current_user["email"])
            await db_save_scan(
                str(current_user["id"]), clean_url,
                report.get("quantum_readiness_score", 0),
                report.get("total_findings", 0),
                "github"
            )

        logger.info(f"Scan complete: {clean_url} | score={report.get('quantum_readiness_score')}")
        return report

    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Repository clone timed out (60s). Try a smaller repo.")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan error: {type(e).__name__}: {str(e)[:200]}")
        raise HTTPException(status_code=500, detail="Scan failed. Please try again.")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.post("/public-scan-zip", tags=["Scanner"])
@limiter.limit("5/hour")
async def scan_zip(request: Request, current_user: Optional[dict] = Depends(get_optional_user)):
    """
    Upload a ZIP file for scanning.
    FIX-1: Path traversal fixed via _safe_extract_zip().
    """
    import zipfile, io

    form     = await request.form()
    zip_file = form.get("file")

    if not zip_file:
        raise HTTPException(status_code=400, detail="No file uploaded. Send as multipart/form-data with key 'file'")

    contents = await zip_file.read()

    if len(contents) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="ZIP file too large. Maximum size is 10MB.")

    tmpdir = tempfile.mkdtemp()
    try:
        try:
            with zipfile.ZipFile(io.BytesIO(contents)) as zf:
                _safe_extract_zip(zf, tmpdir)   # FIX-1: safe extraction
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Invalid ZIP file.")

        report = generate_report(tmpdir)

        if current_user:
            await db_increment_scan(current_user["email"])
            await db_save_scan(
                str(current_user["id"]),
                zip_file.filename or "upload.zip",
                report.get("quantum_readiness_score", 0),
                report.get("total_findings", 0),
                "zip"
            )

        logger.info(f"ZIP scan complete | score={report.get('quantum_readiness_score')} | size={len(contents)}")
        return report

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"ZIP scan error: {type(e).__name__}: {str(e)[:200]}")
        raise HTTPException(status_code=500, detail="ZIP scan failed. Please try again.")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


@app.post("/scan", tags=["Scanner"])
@limiter.limit("10/hour")
async def scan_directory(
    request:      Request,
    body:         ScanDirectoryRequest,
    current_user: dict = Depends(get_current_user),
):
    directory = os.path.realpath(body.directory)
    allowed_prefixes = ["/app", "/tmp", "/home"]
    if not any(directory.startswith(p) for p in allowed_prefixes):
        raise HTTPException(status_code=403, detail="Directory path not allowed.")
    if not os.path.isdir(directory):
        raise HTTPException(status_code=404, detail="Directory not found.")

    try:
        report = generate_report(directory)
        await db_increment_scan(current_user["email"])
        await db_save_scan(
            str(current_user["id"]), directory,
            report.get("quantum_readiness_score", 0),
            report.get("total_findings", 0),
            "path"
        )
        logger.info(f"Dir scan: {directory} | user={current_user['email']} | score={report.get('quantum_readiness_score')}")
        return report
    except Exception as e:
        logger.error(f"Dir scan error: {str(e)[:200]}")
        raise HTTPException(status_code=500, detail="Scan failed.")


# ─────────────────────────────────────────────
# AGILITY CHECKER
# ─────────────────────────────────────────────

@app.post("/check-agility", tags=["Analysis"])
@limiter.limit("15/hour")
async def check_agility_endpoint(
    request:      Request,
    body:         AgilityRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    if not body.github_url:
        raise HTTPException(status_code=400, detail="github_url is required")

    clean_url = _validate_github_url(body.github_url)  # FIX-2 applies here too

    tmpdir = tempfile.mkdtemp()
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", clean_url, tmpdir],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            raise HTTPException(status_code=400, detail="Could not clone repository.")

        # Use the real agility checker from scan.py (not the regex stub)
        agility_result = check_crypto_agility(tmpdir)
        return agility_result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Agility check error: {str(e)[:200]}")
        raise HTTPException(status_code=500, detail="Agility check failed.")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────────────────────────────────────────
# TLS ANALYZER
# ─────────────────────────────────────────────

@app.post("/analyze-tls", tags=["Analysis"])
@limiter.limit("20/hour")
async def analyze_tls(
    request: Request,
    body:    TLSRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    import ssl, socket as sock_module

    domain = body.domain.strip().replace("https://", "").replace("http://", "").split("/")[0]

    if not domain:
        raise HTTPException(status_code=400, detail="domain is required")

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(sock_module.create_connection((domain, 443), timeout=10), server_hostname=domain) as s:
            tls_version  = s.version()
            cipher_suite, _, cipher_bits = s.cipher()
            cert         = s.getpeercert()

        version_scores      = {"TLSv1.3": 100, "TLSv1.2": 70, "TLSv1.1": 20, "TLSv1": 0}
        tls_score           = version_scores.get(tls_version, 30)
        has_forward_secrecy = any(kw in cipher_suite for kw in ["ECDHE", "DHE"])
        quantum_safe        = tls_version == "TLSv1.3" and "X25519" in cipher_suite

        if has_forward_secrecy and tls_score >= 70:
            tls_score = min(100, tls_score + 10)
        if quantum_safe:
            tls_score = min(100, tls_score + 5)

        grade = "A+" if tls_score >= 95 else "A" if tls_score >= 85 else "B" if tls_score >= 70 else "C" if tls_score >= 50 else "D" if tls_score >= 30 else "F"

        nist_rec = (
            "Excellent — TLS 1.3 with forward secrecy. Add hybrid PQC (X25519+ML-KEM) when available."
            if tls_score >= 85 else
            "Upgrade to TLS 1.3 and enable ECDHE cipher suites for forward secrecy."
            if tls_score >= 50 else
            "CRITICAL: Upgrade TLS immediately. Current version is insecure."
        )

        return {
            "domain":              domain,
            "tls_version":         tls_version,
            "cipher_suite":        cipher_suite,
            "cipher_bits":         cipher_bits or 0,
            "tls_score":           tls_score,
            "grade":               grade,
            "grade_description":   f"TLS {tls_version} — {cipher_suite}",
            "has_forward_secrecy": has_forward_secrecy,
            "quantum_safe":        quantum_safe,
            "cert_expires":        cert.get("notAfter", "Unknown"),
            "nist_recommendation": nist_rec,
            "pqc_roadmap":         "Adopt hybrid TLS: X25519 + ML-KEM-768 (NIST FIPS 203)",
            "pqc_note":            None if quantum_safe else "No hybrid PQC detected. Standard TLS 1.3 is safe today but not quantum-resistant.",
            "issues":              [] if tls_score >= 70 else [f"TLS version {tls_version} should be upgraded to TLS 1.3"],
        }

    except ssl.SSLError as e:
        raise HTTPException(status_code=400, detail=f"SSL error: {str(e)[:150]}")
    except sock_module.timeout:
        raise HTTPException(status_code=408, detail="Connection timed out")
    except sock_module.gaierror:
        raise HTTPException(status_code=404, detail=f"Could not resolve domain: {domain}")
    except Exception as e:
        logger.error(f"TLS analysis error for {domain}: {str(e)[:200]}")
        raise HTTPException(status_code=500, detail="TLS analysis failed.")


# ─────────────────────────────────────────────
# UNIFIED RISK — FIX-4: real agility score
# ─────────────────────────────────────────────

@app.post("/unified-risk", tags=["Analysis"])
@limiter.limit("10/hour")
async def unified_risk(
    request:      Request,
    body:         UnifiedRiskRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    try:
        # FIX-2: validate URL
        clean_url = _validate_github_url(body.github_url)

        # Run code scan
        clone_dir = tempfile.mkdtemp()
        try:
            res = subprocess.run(
                ["git", "clone", "--depth=1", clean_url, clone_dir],
                capture_output=True, text=True, timeout=60
            )
            if res.returncode != 0:
                raise HTTPException(status_code=400, detail="Could not clone repository.")

            code_report = generate_report(clone_dir)

            # FIX-4: Run real agility check on the same cloned dir (don't clone twice)
            agility_result = check_crypto_agility(clone_dir)
            agility_score  = agility_result.get("agility_score", 50)

        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)

        # Run TLS scan inline
        tls_body   = TLSRequest(domain=body.domain)
        tls_mock   = Request(scope={"type": "http", "method": "POST", "headers": []})
        tls_report = await analyze_tls(tls_mock, tls_body)

        code_score    = code_report.get("quantum_readiness_score", 50)
        tls_score     = tls_report.get("tls_score", 50)

        unified_score = round(code_score * 0.5 + tls_score * 0.3 + agility_score * 0.2)
        risk_level    = "LOW RISK" if unified_score >= 70 else "MODERATE RISK" if unified_score >= 40 else "CRITICAL RISK"

        findings     = code_report.get("findings", [])
        top_findings = sorted(findings, key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW"].index(f.get("severity","LOW")))[:5]

        return {
            "unified_risk": {
                "quantum_risk_score": unified_score,
                "risk_level":        risk_level,
                "component_scores": {
                    "code_crypto_score":    code_score,
                    "crypto_agility_score": agility_score,   # FIX-4: real value
                    "tls_score":            tls_score,
                },
                "business_summary": (
                    f"Your codebase scored {code_score}/100 on quantum readiness. "
                    f"Crypto agility scored {agility_score}/100. "
                    f"TLS configuration scored {tls_score}/100. "
                    f"Overall quantum risk level: {risk_level}. "
                    f"{'Immediate action required on critical findings.' if unified_score < 40 else 'Migration planning recommended before 2030.'}"
                ),
            },
            "finding_summary": {
                "total": len(findings),
                "severity_summary": {
                    "CRITICAL": len([f for f in findings if f.get("severity") == "CRITICAL"]),
                    "HIGH":     len([f for f in findings if f.get("severity") == "HIGH"]),
                    "MEDIUM":   len([f for f in findings if f.get("severity") == "MEDIUM"]),
                    "LOW":      len([f for f in findings if f.get("severity") == "LOW"]),
                },
            },
            "top_findings":  top_findings,
            "tls_summary":   tls_report,
            "agility_summary": {
                "agility_score":      agility_score,
                "hardcoded_count":    agility_result.get("hardcoded_count", 0),
                "configurable_count": agility_result.get("configurable_count", 0),
                "status":             agility_result.get("status", ""),
                "migration_ease":     agility_result.get("migration_ease", ""),
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unified risk error: {str(e)[:200]}")
        raise HTTPException(status_code=500, detail="Unified risk scan failed.")


# ─────────────────────────────────────────────
# AI FIX
# ─────────────────────────────────────────────

@app.post("/ai-fix", tags=["AI"])
@limiter.limit("30/hour")
async def ai_fix(
    request:      Request,
    body:         AIFixRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    finding = body.finding

    prompt = f"""You are a cryptography migration expert following NIST FIPS 203, 204, and 205.

A developer has this quantum-vulnerable code:
- File: {finding.get('file', 'unknown')}
- Line: {finding.get('line', '?')}
- Code: {finding.get('code', '')}
- Vulnerability: {finding.get('vulnerability', '')} (Severity: {finding.get('severity', '')})
- NIST Replacement: {finding.get('replacement', '')}

Provide:
1. Why this is quantum-vulnerable (1 sentence)
2. The exact replacement code
3. Any imports needed
4. One migration tip

Keep response under 200 words. Be specific and practical."""

    if not OPENAI_API_KEY:
        return {
            "fix": (
                f"Replace {finding.get('vulnerability', 'this algorithm')} with {finding.get('replacement', 'a NIST PQC algorithm')}.\n\n"
                f"NIST Standard: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)\n\n"
                f"AI fix suggestions require an OpenAI API key. Set OPENAI_API_KEY in your environment."
            )
        }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json={
                    "model":       "gpt-4o-mini",
                    "max_tokens":  300,
                    "temperature": 0.3,
                    "messages": [
                        {"role": "system", "content": "You are a post-quantum cryptography migration expert. Be concise and practical."},
                        {"role": "user",   "content": prompt},
                    ],
                },
            )
            data = response.json()
            fix  = data["choices"][0]["message"]["content"]
            return {"fix": fix}

    except Exception as e:
        logger.error(f"AI fix error: {type(e).__name__}")
        return {"fix": f"Could not generate AI fix. Replace {finding.get('vulnerability','')} with {finding.get('replacement','')} per NIST standards."}
