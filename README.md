# OPEN-PORT REAPER  
*Fast async 1-65535 open-port scanner with instant PDF reports.*

![demo](https://user-images.githubusercontent.com/YOUR_USER/REPLACE_WITH_GIF_LINK/demo.gif)

## Quick Start (local)
```bash
git clone https://github.com/shlokkokk/open-ports-scanner.git
cd open-ports-scanner
python -m venv venv
.\venv\Scripts\activate      # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
python scanner.py
Open http://localhost:5000 and scan.

One-liner Docker
bash
Copy
docker build -t reaper .
docker run -p 5000:5000 reaper
Legal
Only scan targets you own or have explicit permission to test.
MIT © 2025 Shlok Shah
