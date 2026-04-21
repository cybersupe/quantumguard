from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner.scan import scan_directory, calculate_score
import os, shutil, uuid, requests, zipfile, io

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
    
    try:
        parts = request.github_url.rstrip("/").split("/")
        owner = parts[-2]
        repo = parts[-1].replace(".git", "")
        zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/main"
        
        response = requests.get(zip_url, timeout=30)
        if response.status_code != 200:
            zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball/master"
            response = requests.get(zip_url, timeout=30)
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Could not download repo")
        
        temp_dir = f"/tmp/qg-{uuid.uuid4().hex[:8]}"
        os.makedirs(temp_dir, exist_ok=True)
        
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            z.extractall(temp_dir)
        
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

@app.get("/health")
def health():
    return {"status": "healthy"}