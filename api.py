from fastapi import FastAPI
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

class ScanRequest(BaseModel):
    directory: str

@app.get("/")
def root():
    return {"message": "QuantumGuard API is running!"}

@app.post("/scan")
def scan(request: ScanRequest):
    if not os.path.exists(request.directory):
        return {"error": "Directory not found"}
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