from fastapi import FastAPI, HTTPException, Header, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner.scan import scan_directory, calculate_score
import os, shutil, uuid, zipfile, io

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

@app.post("/scan-zip")
async def scan_zip(file: UploadFile = File(...), x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files allowed")
    temp_dir = f"/tmp/qg-{uuid.uuid4().hex[:8]}"
    try:
        os.makedirs(temp_dir, exist_ok=True)
        contents = await file.read()
        with zipfile.ZipFile(io.BytesIO(contents)) as z:
            z.extractall(temp_dir)
        findings = scan_directory(temp_dir)
        score = calculate_score(findings)
        return {
            "filename": file.filename,
            "quantum_readiness_score": score,
            "total_findings": len(findings),
            "findings": findings
        }
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
    finally:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

@app.get("/health")
def health():
    return {"status": "healthy"}