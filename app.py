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
VULN = {21: "FTP cleartext / anon login.", 22: "SSH brute-force / weak keys.", 23: "Telnet unencrypted.", 25: "SMTP open-relay risk.", 53: "DNS cache poisoning.", 80: "Web bugs, info leak.", 110: "POP3 cleartext.", 135: "Windows RPC exploits.", 139: "NetBIOS (SMBv1) attacks.", 143: "IMAP cleartext.", 443: "OK if TLS 1.3, else weak.", 993: "Secure IMAP – usually OK.", 995: "Secure POP – usually OK.", 1433: "MSSQL brute / leaks.", 1521: "Oracle TNS poison.", 1723: "PPTP broken crypto.", 3306: "MySQL exposed.", 3389: "RDP – BlueKeep, brute.", 5432: "PostgreSQL leaks.", 5900: "VNC no encryption.", 6379: "Redis unauth.", 8080: "Dev panel weak creds."}
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
            svc = VULN.get(port, f"port-{port}")
            vuln = VULN.get(port, "Investigate service manually.")
            fix  = FIX.get(port, "Restrict to trusted IPs or disable.")
            story.extend([Spacer(0.1*inch),
                          Paragraph(f"<b>Port {port}</b> ({svc})", normal),
                          Paragraph(f"<font color='orange'>Risk:</font> {vuln}", normal),
                          Paragraph(f"<font color='red'>Fix:</font> {fix}", normal)])
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
    return jsonify(ip=ip, open=open_ports)

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