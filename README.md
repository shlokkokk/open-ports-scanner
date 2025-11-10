<div align="center">

# **OPEN-PORT REAPER**

*Fast async 1–65535 open-port scanner with instant PDF reports.*

![Python](https://img.shields.io/badge/Python-3.11%2B-0f0?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-00f?style=flat-square&logo=flask)
![Docker](https://img.shields.io/badge/Docker-ready-2496ed?style=flat-square&logo=docker)
[![MIT](https://img.shields.io/badge/license-MIT-fff?style=flat-square)](LICENSE)

</div>

---

## 🚀 About

**OPEN-PORT REAPER** is a lightweight asynchronous TCP port scanner (ports 1–65535) with a clean Flask web interface and instant PDF reporting.  
Designed for speed, simplicity, and easy deployment.

---

## ✨ Features

- Fast asynchronous port scanning (concurrent checks)
- Simple web UI (Flask)
- Instant PDF export of scan results
- CLI mode for quick scans (optional)
- Docker-ready for easy deployment

---

## 🔧 Quick Start

### **Option A — Run locally (Python)**

1. **Clone the repo and enter the directory:**
   ```bash
   git clone https://github.com/shlokkokk/open-ports-scanner.git
   cd open-ports-scanner
  
2. **Create and activate a virtual environment:**

    Windows:

       python -m venv venv
       .\venv\Scripts\activate

    macOS / Linux:
  
       python -m venv venv
       source venv/bin/activate


3. **Install dependencies and run the scanner:**

       pip install -r requirements.txt
       python scanner.py


4. **Open the app in your browser:**

    http://localhost:5000

### **Option B — Run with Docker**

1. **Build the Docker image:**

       docker build -t reaper .

2. **Run the container (maps container port 5000 to host port 5000):**

       docker run -p 5000:5000 reaper


3. **Open the web UI:**

http://localhost:5000


### **⚖️ Legal Notice**

Only scan systems and networks you own or have explicit permission to test.
Unauthorized scanning is illegal and may be treated as malicious activity.

<div align="center">

MIT © 2025 Shlok Shah

</div> 
