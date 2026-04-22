from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import subprocess
import shutil
import uuid

app = FastAPI(title="QuantumGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY", "quantumguard-secret-2026")

class ScanRequest(BaseModel):
    directory: str

class GitScanRequest(BaseModel):
    github_url: str

def verify_key(key: str):
    if key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

@app.get("/")
async def root():
    return {"message": "QuantumGuard API is running!"}

@app.post("/scan")
async def scan(request: ScanRequest, x_api_key: str = Header(...)):
    verify_key(x_api_key)
    from scanner.scan import scan_directory, calculate_score
    if not os.path.exists(request.directory):
        raise HTTPException(status_code=404, detail="Directory not found")
    findings = scan_directory(request.directory)
    score = calculate_score(findings)
    return {"quantum_readiness_score": score, "total_findings": len(findings), "findings": findings}

@app.post("/scan-github")
async def scan_github(request: GitScanRequest):
    if "github.com" not in request.github_url:
        raise HTTPException(status_code=400, detail="Only GitHub URLs allowed")
    temp_dir = f"/tmp/qg-{uuid.uuid4().hex[:8]}"
    try:
        from scanner.scan import scan_directory, calculate_score
        subprocess.run(
            ["git", "clone", "--depth", "1", request.github_url, temp_dir],
            check=True, capture_output=True, timeout=60
        )
        findings = scan_directory(temp_dir)
        score = calculate_score(findings)
        return {"github_url": request.github_url, "quantum_readiness_score": score, "total_findings": len(findings), "findings": findings}
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Clone timeout")
    except subprocess.CalledProcessError:
        raise HTTPException(status_code=400, detail="Invalid GitHub URL or clone failed")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

@app.post("/public-scan-zip")
async def public_scan_zip(file: bytes = None):
    raise HTTPException(status_code=501, detail="ZIP scanning coming soon")

@app.get("/health")
async def health():
    return {"status": "healthy"}
