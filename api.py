from fastapi import FastAPI, HTTPException, Header, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
from scanner.scan import scan_directory, calculate_score
import os, shutil, uuid, zipfile, io, requests

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="QuantumGuard API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY", "quantumguard-secret-2026")
MAX_ZIP_SIZE = 10 * 1024 * 1024

class ScanRequest(BaseModel):
    directory: str

class GitScanRequest(BaseModel):
    github_url: str

def verify_key(key: str):
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

@app.get("/")
def root():
    return {"message": "QuantumGuard API is running!"}

@app.post("/scan")
@limiter.limit("10/minute")
def scan(request: Request, body: ScanRequest, x_api_key: str = Header(...)):
    verify_key(x_api_key)
    if not os.path.exists(body.directory):
        raise HTTPException(status_code=404, detail="Directory not found")
    findings = scan_directory(body.directory)
    score = calculate_score(findings)
    return {"quantum_readiness_score": score, "total_findings": len(findings), "findings": findings}

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
        return {"filename": file.filename, "quantum_readiness_score": score, "total_findings": len(findings), "findings": findings}
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

@app.post("/scan-github")
@limiter.limit("2/minute")
async def scan_github(request: Request, body: GitScanRequest):
    if "github.com" not in body.github_url:
        raise HTTPException(status_code=400, detail="Only GitHub URLs allowed")
    try:
        parts = body.github_url.rstrip("/").split("/")
        owner = parts[-2]
        repo = parts[-1].replace(".git", "")
        headers = {"Accept": "application/vnd.github+json", "User-Agent": "QuantumGuard"}

        zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/main"
        response = requests.get(zip_url, headers=headers, timeout=30, allow_redirects=True)

        if response.status_code != 200:
            zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/master"
            response = requests.get(zip_url, headers=headers, timeout=30, allow_redirects=True)

        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Could not download repo. Make sure it is public.")

        temp_dir = f"/tmp/qg-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)

        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            z.extractall(temp_dir)

        findings = scan_directory(temp_dir)
        score = calculate_score(findings)
        return {
            "github_url": body.github_url,
            "repo": f"{owner}/{repo}",
            "quantum_readiness_score": score,
            "total_findings": len(findings),
            "findings": findings
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

@app.get("/health")
def health():
    return {"status": "healthy"}