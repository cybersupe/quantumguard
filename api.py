from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner.scan import scan_directory, calculate_score
import os, subprocess, shutil, uuid

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://quantumguard-one.vercel.app", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("API_KEY", "quantumguard-secret-2026")

class ScanRequest(BaseModel):
    directory: str

class GitScanRequest(BaseModel):
    github_url: str

@app.get("/")
def root():
    return {"message": "QuantumGuard API is running!"}

@app.post("/scan")
def scan(request: ScanRequest, x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    findings = scan_directory(request.directory)
    score = calculate_score(findings)
    return {"quantum_readiness_score": score, "total_findings": len(findings), "findings": findings}

@app.post("/scan-github")
def scan_github(request: GitScanRequest, x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if "github.com" not in request.github_url:
        raise HTTPException(status_code=400, detail="Only GitHub URLs allowed")
    temp_dir = f"/tmp/qg-{uuid.uuid4().hex[:8]}"
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", request.github_url, temp_dir],
            capture_output=True,
            timeout=60
        )
        stdout = result.stdout.decode() if result.stdout else ""
        stderr = result.stderr.decode() if result.stderr else ""
        if result.returncode != 0:
            raise HTTPException(
                status_code=400,
                detail=f"Clone failed: stdout={stdout} stderr={stderr} returncode={result.returncode}"
            )
        findings = scan_directory(temp_dir)
        score = calculate_score(findings)
        return {
            "github_url": request.github_url,
            "quantum_readiness_score": score,
            "total_findings": len(findings),
            "findings": findings
        }
    except HTTPException:
        raise
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Clone timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

@app.get("/health")
def health():
    return {"status": "healthy"}