import asyncio, socket, ipaddress, json, textwrap, io, time
from flask import Flask, request, jsonify, render_template, make_response
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import black, green, red, orange

app = Flask(__name__)

TOP_PORTS = list(range(1, 65536))   # full range

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

async def tcp_check(ip, port, timeout=1):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port, True
    except Exception:
        return port, False

async def full_scan(ip, max_tasks=500):
    semaphore = asyncio.Semaphore(max_tasks)
    async def sem_check(port):
        async with semaphore:
            return await tcp_check(ip, port)
    tasks = [sem_check(p) for p in TOP_PORTS]
    results = await asyncio.gather(*tasks)
    return [p for p, ok in results if ok]

# ---- vuln / fix lookup (same as before) ----
# pure service name
SERVICE = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "Windows RPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle TNS", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt"
}
ATTACK = {
    21: "Anonymous upload / credential sniffing",
    22: "Brute-force login / weak key abuse",
    23: "Credential sniffing (cleartext)",
    25: "Spam relay / header injection",
    53: "Cache poisoning / DNS hijack",
    80: "DoS, XSS, SQLi, data leak",
    110: "Password sniffing",
    135: "RPC exploits (BlueKeep-style)",
    139: "SMBv1 ransomware (WannaCry)",
    143: "Password sniffing",
    443: "Downgrade to weak TLS, POODLE",
    993: "Account lockout (brute)",
    995: "Account lockout (brute)",
    1433: "Data dump, privilege escalation",
    1521: "TNS poison / data leak",
    1723: "MS-CHAPv2 crack → domain creds",
    3306: "Data dump, ransomware",
    3389: "BlueKeep, brute-force → domain",
    5432: "Data dump, privilege escalation",
    5900: "Screen watch, key-log, brute",
    6379: "Data dump, cache poison",
    8080: "Dev panel takeover, data leak"
}

FIX = {21: "Use SFTP; disable anon.", 22: "Key-auth, no root, port-knock.", 23: "Disable; use SSH.", 25: "Auth+TLS, no relay.", 53: "Recursion only trusted.", 80: "Redirect HTTPS, patch.", 110: "Use POP3S.", 135: "Block at firewall.", 139: "Disable NetBIOS.", 143: "Use IMAPS.", 443: "Use TLS 1.3, HSTS.", 993: "Strong pw, 2FA.", 995: "Same as 993.", 1433: "VPN-only, strong sa pw.", 1521: "Encrypt traffic, ACL.", 1723: "Use WireGuard.", 3306: "Bind localhost / VPN.", 3389: "Gateway, NLA, latest.", 5432: "Hostssl, strong auth.", 5900: "Tunnel over SSH.", 6379: "Require auth, bind local.", 8080: "Firewall or reverse-proxy with auth."}

def build_pdf(ip, open_ports):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    title = ParagraphStyle("title", fontSize=18, textColor=green, spaceAfter=12)
    normal = styles["Normal"]
    story = [Paragraph("Ethical Port-Scan Report", title),
             Paragraph(f"Target IP: <b>{ip}</b>", normal),
             Paragraph(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')} UTC", normal)]
    if not open_ports:
        story.append(Paragraph("No open ports found. Nice lockdown!", normal))
    else:
       for port in open_ports:
             svc   = SERVICE.get(port, f"port-{port}")
             atk   = ATTACK.get(port, "Investigate manually.")
             fix   = FIX.get(port, "Restrict to trusted IPs or disable.")
             story.extend([
                Spacer(0.1*inch),
                Paragraph(f"<b>Port {port}</b> ({svc})", normal),
                Paragraph(f"<font color='orange'>Attack:</font> {atk}", normal),
                Paragraph(f"<font color='red'>Fix:</font> {fix}", normal)
    ])
    doc.build(story)
    buffer.seek(0)
    return buffer

@app.route("/")
def boot():
    return render_template("boot.html")
@app.route("/scan")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify(error="No target"), 400
    ip = resolve(target)
    if not ip:
        return jsonify(error="Host unreachable"), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify(error="Invalid IP"), 400
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    open_ports = loop.run_until_complete(full_scan(ip))
    loop.close()
    return jsonify(
    ip=ip,
    open=open_ports,
    service={p: SERVICE.get(p, f"port-{p}") for p in open_ports},
    attack={p: ATTACK.get(p, "Investigate manually.") for p in open_ports},
    fix={p: FIX.get(p, "Restrict to trusted IPs or disable.") for p in open_ports}
)

@app.route("/report", methods=["POST"])
def report():
    data = request.get_json()
    ip = data.get("ip")
    ports = data.get("open", [])
    if not ip:
        return jsonify(error="Missing data"), 400
    pdf_buffer = build_pdf(ip, ports)
    pdf_buffer.seek(0, io.SEEK_END)          # go to end
    if pdf_buffer.tell() == 0:               # 0 bytes → bug
        return jsonify(error="PDF generation failed"), 500
    pdf_buffer.seek(0)                       # rewind
    return make_response(
        pdf_buffer.getvalue(),
        200,
        {
            "Content-Type": "application/pdf",
            "Content-Disposition": f"attachment; filename=scan_{ip}.pdf",
        },
    )

if __name__ == "__main__":
    app.run(debug=True)