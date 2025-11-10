<div align="center">

<h1 style="font-weight:bold;font-size:50px;background:linear-gradient(90deg,#0f0,#f0f);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">OPEN-PORT REAPER</h1>

<i>Fast async 1-65535 open-port scanner with cyberpunk UI + instant PDF reports.</i>

![Python](https://img.shields.io/badge/Python-3.11%2B-0f0?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-00f?style=flat-square&logo=flask)
![Docker](https://img.shields.io/badge/Docker-ready-2496ed?style=flat-square&logo=docker)
[![MIT](https://img.shields.io/badge/license-MIT-fff?style=flat-square)](LICENSE)

<br>

![demo](https://user-images.githubusercontent.com/shlokkokk/REPLACE_WITH_GIF/demo.gif)

</div>

## ⚡ Quick Start (local)
```bash
git clone https://github.com/shlokkokk/open-ports-scanner.git
cd open-ports-scanner
python -m venv venv
.\venv\Scripts\activate   # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
python scanner.py

Open http://localhost:5000 and scan.

## 🐳 One-liner Docker
docker build -t reaper .
docker run -p 5000:5000 reaper

## ⚖️ Legal
Only scan targets you own or have explicit permission to test.
<div align="center">MIT © 2025 Shlok Shah</div>
```
