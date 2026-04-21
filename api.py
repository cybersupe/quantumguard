from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner.scan import scan_directory, calculate_score
import os

app = FastAPI(title="QuantumGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = "quantumguard-secret-2026"

ALLOWED_PATHS = ["/app/tests", "/app/scanner"]

class ScanRequest(BaseModel):
    directory: str

def verify_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

@app.get("/")
def root():
    return {"message": "QuantumGuard API is running!"}

@app.post("/scan")
def scan(request: ScanRequest, x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if request.directory not in ALLOWED_PATHS:
        raise HTTPException(status_code=403, detail="Path not allowed")
    if not os.path.exists(request.directory):
        raise HTTPException(status_code=404, detail="Directory not found")
    findings = scan_directory(request.directory)
    score = calculate_score(findings)
    return {
        "quantum_readiness_score": score,
        "total_findings": len(findings),
        "findings": findings
    }

@app.get("/health")
def health():
    return {"status": "healthy"}