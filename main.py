"""
QuantumGuard API — main.py
Upgraded with:
  - JWT Authentication (register / login / protected routes)
  - Rate limiting (slowapi — per IP)
  - Token scrubbing from logs
  - CORS
  - All existing endpoints preserved
"""

import os
import re
import uuid
import shutil
import tempfile
import logging
import subprocess
from datetime import datetime, timedelta
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from jose import JWTError, jwt
from passlib.context import CryptContext

# ─────────────────────────────────────────────
# Import your existing scanner modules
# ─────────────────────────────────────────────
from scanner.scan import generate_report
# Add any other imports your original main.py had, e.g.:
# from scanner.tls import analyze_tls_domain
# from scanner.agility import check_agility
# from scanner.unified import unified_risk_scan
# from scanner.ai_fix import get_ai_fix

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
# CONFIG — load from environment variables
# ─────────────────────────────────────────────
SECRET_KEY      = os.getenv("JWT_SECRET_KEY", "CHANGE_THIS_IN_PRODUCTION_USE_ENV_VAR")
ALGORITHM       = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
OPENAI_API_KEY  = os.getenv("OPENAI_API_KEY", "")
ENVIRONMENT     = os.getenv("ENVIRONMENT", "production")  # "development" skips auth on some routes

# ─────────────────────────────────────────────
# PASSWORD HASHING
# ─────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# ─────────────────────────────────────────────
# IN-MEMORY USER STORE
# Replace this with PostgreSQL/Firebase when ready
# ─────────────────────────────────────────────
USERS_DB: dict[str, dict] = {}  # { email: { id, email, hashed_password, created_at, scan_count } }

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
    if not email or email not in USERS_DB:
        raise HTTPException(status_code=401, detail="User not found")
    return USERS_DB[email]

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[dict]:
    """Use on endpoints that work for both authed and guest users."""
    if not credentials:
        return None
    try:
        payload = decode_token(credentials.credentials)
        email = payload.get("sub")
        return USERS_DB.get(email)
    except HTTPException:
        return None

# ─────────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=["200/hour"])

# ─────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────
app = FastAPI(
    title="QuantumGuard API",
    description="Post-quantum cryptography vulnerability scanner",
    version="2.0.0",
    docs_url="/docs" if ENVIRONMENT == "development" else None,
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://quantumguard.site",
        "https://www.quantumguard.site",
        "https://quantumguard-one.vercel.app",
        # Add your new Vercel deployment URLs here
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

class ScanZipRequest(BaseModel):
    pass  # handled via UploadFile

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
# ── AUTH ENDPOINTS ────────────────────────────
# ─────────────────────────────────────────────

@app.post("/auth/register", tags=["Auth"])
@limiter.limit("10/hour")
async def register(request: Request, body: RegisterRequest):
    """Register a new account. Returns JWT token immediately."""
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
        "created_at":      datetime.utcnow().isoformat(),
        "scan_count":      0,
        "plan":            "free",
    }
    USERS_DB[email] = user

    token = create_access_token({"sub": email})
    logger.info(f"New user registered: {email}")

    return {
        "access_token": token,
        "token_type":   "bearer",
        "expires_in":   ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id":    user["id"],
            "email": user["email"],
            "name":  user["name"],
            "plan":  user["plan"],
        }
    }


@app.post("/auth/login", tags=["Auth"])
@limiter.limit("20/hour")
async def login(request: Request, body: LoginRequest):
    """Login with email + password. Returns JWT token."""
    email = body.email.lower().strip()
    user  = USERS_DB.get(email)

    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token({"sub": email})
    logger.info(f"User logged in: {email}")

    return {
        "access_token": token,
        "token_type":   "bearer",
        "expires_in":   ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id":         user["id"],
            "email":      user["email"],
            "name":       user["name"],
            "plan":       user["plan"],
            "scan_count": user["scan_count"],
        }
    }


@app.get("/auth/me", tags=["Auth"])
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user profile."""
    return {
        "id":         current_user["id"],
        "email":      current_user["email"],
        "name":       current_user["name"],
        "plan":       current_user["plan"],
        "scan_count": current_user["scan_count"],
        "created_at": current_user["created_at"],
    }


@app.post("/auth/refresh", tags=["Auth"])
async def refresh_token(current_user: dict = Depends(get_current_user)):
    """Refresh JWT token — call this before expiry."""
    token = create_access_token({"sub": current_user["email"]})
    return {"access_token": token, "token_type": "bearer"}


# ─────────────────────────────────────────────
# ── HEALTH ────────────────────────────────────
# ─────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    return {
        "status":  "healthy",
        "version": "2.0.0",
        "time":    datetime.utcnow().isoformat(),
    }


# ─────────────────────────────────────────────
# ── SCAN ENDPOINTS ────────────────────────────
# Public: guests get 3 scans/day by IP
# Authed: 20 scans/day
# ─────────────────────────────────────────────

@app.post("/scan-github", tags=["Scanner"])
@limiter.limit("20/day")
async def scan_github(
    request:      Request,
    body:         ScanGithubRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """
    Scan a public or private GitHub repository.
    - Guest: 20 scans/day per IP
    - Authenticated: tracked per user, saved to history
    """
    if not body.github_url:
        raise HTTPException(status_code=400, detail="github_url is required")

    logger.info(f"Scan started: {body.github_url} | user={current_user['email'] if current_user else 'guest'}")

    # Build authenticated clone URL without logging the token
    clone_url = body.github_url.strip()
    if body.github_token:
        clone_url = clone_url.replace("https://", f"https://x-token:{body.github_token}@")

    tmpdir = tempfile.mkdtemp()
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", clone_url, tmpdir],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            err = result.stderr.replace(body.github_token or "", "[REDACTED]")
            raise HTTPException(status_code=400, detail=f"Git clone failed: {err[:200]}")

        report = generate_report(tmpdir)

        # Track scan count for authed users
        if current_user:
            USERS_DB[current_user["email"]]["scan_count"] += 1

        logger.info(f"Scan complete: {body.github_url} | score={report.get('quantum_readiness_score')}")
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
async def scan_zip(request: Request):
    """
    Upload a ZIP file for scanning.
    Rate limited to 5/hour per IP (ZIP scans are expensive).
    """
    from fastapi import UploadFile, File
    import zipfile, io

    form     = await request.form()
    zip_file = form.get("file")

    if not zip_file:
        raise HTTPException(status_code=400, detail="No file uploaded. Send as multipart/form-data with key 'file'")

    contents = await zip_file.read()

    if len(contents) > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=413, detail="ZIP file too large. Maximum size is 10MB.")

    tmpdir = tempfile.mkdtemp()
    try:
        try:
            with zipfile.ZipFile(io.BytesIO(contents)) as zf:
                zf.extractall(tmpdir)
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Invalid ZIP file.")

        report = generate_report(tmpdir)
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
    current_user: dict = Depends(get_current_user),  # requires auth
):
    """
    Scan a server-side directory path.
    Requires authentication (internal/enterprise use only).
    """
    directory = body.directory

    # Security: block path traversal
    directory = os.path.realpath(directory)
    allowed_prefixes = ["/app", "/tmp", "/home"]
    if not any(directory.startswith(p) for p in allowed_prefixes):
        raise HTTPException(status_code=403, detail="Directory path not allowed.")

    if not os.path.isdir(directory):
        raise HTTPException(status_code=404, detail="Directory not found.")

    try:
        report = generate_report(directory)
        USERS_DB[current_user["email"]]["scan_count"] += 1
        logger.info(f"Dir scan: {directory} | user={current_user['email']} | score={report.get('quantum_readiness_score')}")
        return report
    except Exception as e:
        logger.error(f"Dir scan error: {str(e)[:200]}")
        raise HTTPException(status_code=500, detail="Scan failed.")


# ─────────────────────────────────────────────
# ── AGILITY CHECKER ───────────────────────────
# ─────────────────────────────────────────────

@app.post("/check-agility", tags=["Analysis"])
@limiter.limit("15/hour")
async def check_agility(
    request:      Request,
    body:         AgilityRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """Check crypto agility of a GitHub repository."""
    if not body.github_url:
        raise HTTPException(status_code=400, detail="github_url is required")

    tmpdir = tempfile.mkdtemp()
    try:
        result = subprocess.run(
            ["git", "clone", "--depth=1", body.github_url, tmpdir],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            raise HTTPException(status_code=400, detail="Could not clone repository.")

        hardcoded_count   = 0
        configurable_count = 0
        hardcoded_patterns   = [r'RSA\.generate', r'ECC\.generate', r"createHash\(['\"]md5", r"createHash\(['\"]sha1"]
        configurable_patterns = [r'os\.environ', r'config\[', r'settings\.', r'getenv\(']

        for root, _, files in os.walk(tmpdir):
            for fname in files:
                if not any(fname.endswith(ext) for ext in ['.py', '.js', '.ts', '.java', '.go']):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    code = open(fpath, encoding='utf-8', errors='ignore').read()
                    for p in hardcoded_patterns:
                        hardcoded_count += len(re.findall(p, code, re.IGNORECASE))
                    for p in configurable_patterns:
                        configurable_count += len(re.findall(p, code, re.IGNORECASE))
                except Exception:
                    continue

        total = hardcoded_count + configurable_count
        agility_score = max(0, min(100, int((configurable_count / total * 100) if total > 0 else 75)))

        return {
            "agility_score":      agility_score,
            "hardcoded_count":    hardcoded_count,
            "configurable_count": configurable_count,
            "assessment":         "High Agility" if agility_score >= 70 else "Partial Agility" if agility_score >= 40 else "Low Agility",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Agility check error: {str(e)[:200]}")
        raise HTTPException(status_code=500, detail="Agility check failed.")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ─────────────────────────────────────────────
# ── TLS ANALYZER ──────────────────────────────
# ─────────────────────────────────────────────

@app.post("/analyze-tls", tags=["Analysis"])
@limiter.limit("20/hour")
async def analyze_tls(
    request: Request,
    body:    TLSRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """Analyze TLS configuration for a domain."""
    import ssl, socket

    domain = body.domain.strip().replace("https://", "").replace("http://", "").split("/")[0]

    if not domain:
        raise HTTPException(status_code=400, detail="domain is required")

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, 443), timeout=10), server_hostname=domain) as sock:
            tls_version  = sock.version()
            cipher_suite, _, cipher_bits = sock.cipher()
            cert         = sock.getpeercert()

        # Score logic
        version_scores = {"TLSv1.3": 100, "TLSv1.2": 70, "TLSv1.1": 20, "TLSv1": 0}
        tls_score      = version_scores.get(tls_version, 30)

        has_forward_secrecy = any(kw in cipher_suite for kw in ["ECDHE", "DHE"])
        quantum_safe        = tls_version == "TLSv1.3" and "X25519" in cipher_suite

        if has_forward_secrecy and tls_score >= 70: tls_score = min(100, tls_score + 10)
        if quantum_safe: tls_score = min(100, tls_score + 5)

        grade = "A+" if tls_score >= 95 else "A" if tls_score >= 85 else "B" if tls_score >= 70 else "C" if tls_score >= 50 else "D" if tls_score >= 30 else "F"

        cert_expires = cert.get("notAfter", "Unknown")

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
            "cert_expires":        cert_expires,
            "nist_recommendation": nist_rec,
            "pqc_roadmap":         "Adopt hybrid TLS: X25519 + ML-KEM-768 (NIST FIPS 203)",
            "pqc_note":            None if quantum_safe else "No hybrid PQC detected. Standard TLS 1.3 is safe today but not quantum-resistant.",
            "issues":              [] if tls_score >= 70 else [f"TLS version {tls_version} should be upgraded to TLS 1.3"],
        }

    except ssl.SSLError as e:
        raise HTTPException(status_code=400, detail=f"SSL error: {str(e)[:150]}")
    except socket.timeout:
        raise HTTPException(status_code=408, detail="Connection timed out")
    except socket.gaierror:
        raise HTTPException(status_code=404, detail=f"Could not resolve domain: {domain}")
    except Exception as e:
        logger.error(f"TLS analysis error for {domain}: {str(e)[:200]}")
        raise HTTPException(status_code=500, detail="TLS analysis failed.")


# ─────────────────────────────────────────────
# ── UNIFIED RISK ──────────────────────────────
# ─────────────────────────────────────────────

@app.post("/unified-risk", tags=["Analysis"])
@limiter.limit("10/hour")
async def unified_risk(
    request:      Request,
    body:         UnifiedRiskRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """Run code scan + TLS analysis and return a unified quantum risk score."""
    try:
        # Run code scan
        clone_dir = tempfile.mkdtemp()
        try:
            res = subprocess.run(
                ["git", "clone", "--depth=1", body.github_url, clone_dir],
                capture_output=True, text=True, timeout=60
            )
            if res.returncode != 0:
                raise HTTPException(status_code=400, detail="Could not clone repository.")
            code_report = generate_report(clone_dir)
        finally:
            shutil.rmtree(clone_dir, ignore_errors=True)

        # Run TLS scan inline
        tls_body   = TLSRequest(domain=body.domain)
        tls_mock   = Request(scope={"type": "http", "method": "POST", "headers": []})
        tls_report = await analyze_tls(tls_mock, tls_body)

        # Combine scores
        code_score    = code_report.get("quantum_readiness_score", 50)
        tls_score     = tls_report.get("tls_score", 50)
        agility_score = 60  # default — run agility check separately for accurate value

        unified_score = round(code_score * 0.5 + tls_score * 0.3 + agility_score * 0.2)

        risk_level = "LOW RISK" if unified_score >= 70 else "MODERATE RISK" if unified_score >= 40 else "CRITICAL RISK"

        findings       = code_report.get("findings", [])
        top_findings   = sorted(findings, key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW"].index(f.get("severity","LOW")))[:5]

        return {
            "unified_risk": {
                "quantum_risk_score": unified_score,
                "risk_level":        risk_level,
                "component_scores": {
                    "code_crypto_score":   code_score,
                    "crypto_agility_score": agility_score,
                    "tls_score":            tls_score,
                },
                "business_summary": (
                    f"Your codebase scored {code_score}/100 on quantum readiness. "
                    f"TLS configuration scored {tls_score}/100. "
                    f"Overall quantum risk level: {risk_level}. "
                    f"{'Immediate action required on critical findings.' if unified_score < 40 else 'Migration planning recommended before 2030.'}"
                ),
            },
            "finding_summary": {
                "total":            len(findings),
                "severity_summary": {
                    "CRITICAL": len([f for f in findings if f.get("severity") == "CRITICAL"]),
                    "HIGH":     len([f for f in findings if f.get("severity") == "HIGH"]),
                    "MEDIUM":   len([f for f in findings if f.get("severity") == "MEDIUM"]),
                    "LOW":      len([f for f in findings if f.get("severity") == "LOW"]),
                },
            },
            "top_findings":  top_findings,
            "tls_summary":   tls_report,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unified risk error: {str(e)[:200]}")
        raise HTTPException(status_code=500, detail="Unified risk scan failed.")


# ─────────────────────────────────────────────
# ── AI FIX ────────────────────────────────────
# ─────────────────────────────────────────────

@app.post("/ai-fix", tags=["AI"])
@limiter.limit("30/hour")
async def ai_fix(
    request:      Request,
    body:         AIFixRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """
    Generate an AI-powered fix suggestion for a vulnerability finding.
    Uses OpenAI GPT-4o-mini.
    """
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
