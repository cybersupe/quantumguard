# 🖥️ Self-Hosting QuantumGuard

Host QuantumGuard entirely on your own infrastructure. Your code never leaves your network.

---

## Why Self-Host?

- **Privacy** — Code stays inside your network. Nothing sent to external servers.
- **Compliance** — Meets strict data residency requirements (HIPAA, SOC2, GDPR)
- **Speed** — No internet latency for scanning large repos
- **Control** — Customize patterns, rate limits, and features
- **Enterprise** — Run behind your firewall with SSO

---

## Requirements

| Tool | Version | Download |
|------|---------|---------|
| Python | 3.10+ | python.org/downloads |
| Node.js | 18+ | nodejs.org |
| Git | Any | git-scm.com |

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/cybersupe/quantumguard.git
cd quantumguard
```

---

## Step 2 — Set Up the Backend (API)

```bash
# Install Python dependencies
pip install -r requirements.txt

# Start the backend server
uvicorn api:app --host 0.0.0.0 --port 8000

# Optional: run in background
uvicorn api:app --host 0.0.0.0 --port 8000 --daemon
```

Backend is now running at: `http://localhost:8000`

API docs available at: `http://localhost:8000/docs`

---

## Step 3 — Set Up the Frontend (Dashboard)

```bash
# Navigate to dashboard folder
cd dashboard

# Install Node dependencies
npm install

# Update API URL to point to your local backend
# Open src/App.js and change line:
# const API = "https://quantumguard-api.onrender.com";
# to:
# const API = "http://localhost:8000";

# Start the frontend
npm start
```

Frontend is now running at: `http://localhost:3000`

---

## Step 4 — Build for Production

```bash
# Build optimized frontend
cd dashboard
npm run build

# Serve the build folder using any web server
# Example with Python:
cd build
python -m http.server 3000

# Example with nginx:
# Copy build/ contents to /var/www/html/
```

---

## Step 5 — Environment Variables (Optional)

Create a `.env` file in the root folder:

```env
# Anthropic API key for AI Fix feature
ANTHROPIC_API_KEY=sk-ant-your-key-here

# Custom API key for /scan endpoint
API_SECRET_KEY=your-custom-secret-key

# Max files to scan per request (default: 200)
MAX_FILES=200
```

---

## Docker Deployment (Recommended for Production)

```dockerfile
# Dockerfile (backend)
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
# Build and run with Docker
docker build -t quantumguard-api .
docker run -p 8000:8000 quantumguard-api

# With environment variables
docker run -p 8000:8000 \
  -e ANTHROPIC_API_KEY=your-key \
  -e MAX_FILES=500 \
  quantumguard-api
```

---

## Docker Compose (Full Stack)

```yaml
# docker-compose.yml
version: '3.8'
services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - MAX_FILES=500
    restart: unless-stopped

  frontend:
    build: ./dashboard
    ports:
      - "3000:80"
    depends_on:
      - api
    restart: unless-stopped
```

```bash
# Start full stack
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

---

## Verify Installation

After setup, test these endpoints:

```bash
# Health check
curl http://localhost:8000/health

# Scan a GitHub repo
curl -X POST http://localhost:8000/scan-github \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/cybersupe/quantumguard"}'

# Check TLS
curl -X POST http://localhost:8000/analyze-tls \
  -H "Content-Type: application/json" \
  -d '{"domain": "google.com"}'
```

---

## API Endpoints Available

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | None | Health check |
| `/health` | GET | None | Detailed status |
| `/scan-github` | POST | None | Scan GitHub repo |
| `/public-scan-zip` | POST | None | Upload ZIP and scan |
| `/check-agility` | POST | None | Crypto agility check |
| `/analyze-tls` | POST | None | TLS domain analysis |
| `/scan` | POST | API key | Scan server path |

---

## Customizing Vulnerability Patterns

Add your own patterns to `scanner/patterns.py`:

```python
# Add custom pattern
VULNERABLE_PATTERNS["MY_CUSTOM_VULN"] = {
    "patterns": [r"your_regex_pattern_here"],
    "severity": "CRITICAL",  # CRITICAL, HIGH, or MEDIUM
    "replacement": "Your recommended fix here"
}
```

---

## Security Considerations

When self-hosting:

- Run behind a reverse proxy (nginx, Caddy) with HTTPS
- Set a strong `API_SECRET_KEY` for the `/scan` endpoint
- Enable firewall rules to restrict access
- Keep dependencies updated: `pip install -r requirements.txt --upgrade`
- Monitor logs regularly for unusual activity

---

## Nginx Configuration (Production)

```nginx
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Frontend
    location / {
        root /var/www/quantumguard/build;
        try_files $uri /index.html;
    }

    # Backend API
    location /api/ {
        proxy_pass http://localhost:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Troubleshooting

**Backend won't start:**
```bash
# Check Python version
python --version  # Must be 3.10+

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

**Frontend can't reach API:**
```bash
# Make sure API is running
curl http://localhost:8000/health

# Check CORS — backend allows all origins by default
# Update API URL in dashboard/src/App.js
```

**Scan times out:**
```bash
# Reduce MAX_FILES in environment variables
MAX_FILES=100
```

---

## Support

- **GitHub Issues:** github.com/cybersupe/quantumguard/issues
- **Email:** thisispayyavula@gmail.com
- **Live Demo:** quantumguard.site

---

## License

QuantumGuard is released under the **GNU Affero General Public License v3 (AGPL v3)**.

Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI

If you modify and run this software as a network service, you must make your modified source code available to users of that service.

Full license: https://www.gnu.org/licenses/agpl-3.0.txt
