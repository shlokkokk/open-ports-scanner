<div align="center">

# **OPEN-PORT REAPER**

*Fast async 1–65535 open-port scanner with instant PDF reports.*
<img width="1050" height="947" alt="image" src="https://github.com/user-attachments/assets/8d0441de-0e28-4106-8549-2d4f77ae3cac" />


![Python](https://img.shields.io/badge/Python-3.11%2B-0f0?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-00f?style=flat-square&logo=flask)
![Docker](https://img.shields.io/badge/Docker-ready-2496ed?style=flat-square&logo=docker)
[![MIT](https://img.shields.io/badge/license-MIT-fff?style=flat-square)](LICENSE)

</div>

---

## 🚀 About

**OPEN-PORT REAPER** is a lightweight asynchronous ethical port scanner that maps open ports, detects services, analyzes attack risks, and recommends security fixes - complete with real-time output and automated PDF reporting.
---

## ✨ Features

* **Full-Range Port Scanning (1–65535):** Fast asynchronous engine that scans all ports with high accuracy.
* **Service Detection:** Automatically identifies common services (SSH, HTTP, FTP, custom ports, malware backdoors).
* **Vulnerability Insights:** Each open port comes with attack risks, explanations, and real-world exploitation possibilities.
* **Recommended Fixes:** Every detection includes actionable security hardening steps.
* **Severity Tagging:** Ports are categorized by severity—Low, Medium, High, Critical.
* **Clean Hacker-UI Dashboard:** Matrix-style terminal interface optimized for clarity and speed.
* **Target Resolver:** Automatically resolves domain to IP before scanning.
* **PDF Report Generator:** One-click export of beautifully formatted, professional security reports.
* **Ethical by Design:** Built for cybersecurity learning, network auditing, and defensive analysis.
* **Optimized for Students & Pentesters:** Simple enough for beginners, powerful enough for pros.
* **Lightweight & Fast:** Uses async architecture to achieve high-speed scanning with minimal system load.
* **Cross-Platform Support:** Works on Linux, Windows, macOS.

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
