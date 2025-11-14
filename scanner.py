import asyncio, socket, ipaddress, json, textwrap, io, time
from flask import Flask, request, jsonify, render_template, make_response
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import black, green, red, orange
from iana import IANA          # real service names

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
    7:"Echo", 19:"Chargen", 20:"FTP-Data", 21:"FTP", 22:"SSH",
    23:"Telnet", 25:"SMTP", 37:"Time", 42:"WINS", 43:"WHOIS",

    49:"TACACS", 53:"DNS", 67:"DHCP-Server", 68:"DHCP-Client", 69:"TFTP",
    70:"Gopher", 79:"Finger", 80:"HTTP", 88:"Kerberos", 102:"MS-Exchange",

    110:"POP3", 111:"RPCBind", 113:"Ident", 119:"NNTP", 123:"NTP",
    135:"Windows RPC", 137:"NetBIOS Name", 138:"NetBIOS Datagram",
    139:"NetBIOS Session", 143:"IMAP",

    161:"SNMP", 162:"SNMP-Trap", 179:"BGP", 194:"IRC", 201:"AppleTalk",
    389:"LDAP", 427:"SLP", 443:"HTTPS", 445:"SMB", 465:"SMTPS",

    500:"ISAKMP", 512:"rexec", 513:"rlogin", 514:"syslog", 520:"RIP",
    521:"RIPng", 554:"RTSP", 587:"SMTP Submission", 631:"IPP Printing",
    636:"LDAPS",

    873:"RSYNC", 902:"VMware Server", 912:"VMware Auth",
    989:"FTPS-Data", 990:"FTPS",
    993:"IMAPS", 995:"POP3S", 1025:"RPC High", 1026:"RPC High", 1027:"RPC High",

    1080:"SOCKS Proxy", 1194:"OpenVPN", 1352:"Lotus Notes", 1433:"MSSQL",
    1434:"MSSQL Monitor",
    1521:"Oracle TNS", 1701:"L2TP", 1723:"PPTP", 1812:"RADIUS", 1883:"MQTT",

    1900:"UPnP", 2000:"Cisco SCCP", 2049:"NFS", 2082:"cPanel",
    2083:"cPanel SSL",
    2181:"Zookeeper", 2222:"DirectAdmin", 2375:"Docker API",
    2376:"Docker SSL", 2483:"Oracle DB",

    2484:"Oracle DB SSL", 2601:"Zebra", 2604:"Zebra", 2701:"SMSD",
    28017:"Mongo Web",
    3000:"Node Dev", 3050:"Firebird", 3128:"Squid Proxy", 3260:"iSCSI",
    3306:"MySQL",

    3333:"DEC Notes", 3389:"RDP", 3478:"STUN", 3632:"DistCC",
    3690:"SVN",
    4369:"Erlang Mapper", 4486:"FileMaker", 4567:"Apple RemoteMgmt",
    4662:"eMule", 4711:"OBM",

    5000:"UPnP", 5001:"HTTP-Alt", 5060:"SIP", 5061:"SIP-TLS",
    5120:"Barracuda",
    5432:"PostgreSQL", 5500:"VNC", 5601:"Kibana", 5672:"RabbitMQ",
    5800:"VNC Web",

    5900:"VNC", 5984:"CouchDB", 6000:"X11", 6001:"X11", 6002:"X11",
    6379:"Redis", 6667:"IRC", 7000:"IRC Alt", 7001:"WebLogic",
    7002:"WebLogic SSL",

    7199:"Cassandra", 7306:"MySQL-Alt", 7777:"Oracle EPM", 8000:"HTTP-Alt",
    8008:"Proxy",
    8009:"AJP", 8080:"HTTP Proxy", 8081:"HTTP Backup", 8086:"InfluxDB",
    8181:"Node-RED",

    8222:"VMware Console", 8333:"Bitcoin", 8443:"HTTPS-Alt",
    8500:"Consul",
    8530:"WSUS", 8531:"WSUS SSL", 8600:"Consul DNS", 8888:"Alt HTTP",
    9000:"SonarQube",

    9042:"Cassandra", 9060:"IBM WebSphere", 9090:"Prometheus",
    9100:"Printer RAW",
    9200:"Elasticsearch", 9300:"Elastic Transport", 9418:"Git",
    9500:"ISM Server", 9800:"Webmin",

    9999:"Abyss Web", 11211:"Memcached", 15672:"RabbitMQ Admin",
    16080:"Alt HTTP",
    18080:"MinIO", 19000:"SAP Router", 20000:"Usermin", 
    27017:"MongoDB", 27018:"Mongo Node",

    27019:"Mongo Cluster", 28015:"RethinkDB", 29015:"RethinkDB",
    30000:"Kubernetes NodePort",
    30718:"Calico", 31000:"Game Servers", 31337:"BackOrifice",
    32400:"Plex", 34567:"DVR",

    37777:"Dahua DVR", 44818:"EtherNet/IP", 47808:"BACnet",
    50000:"SAP Management",
    50070:"Hadoop NameNode", 50090:"Hadoop Sec NameNode",
    50300:"IBM DB2", 54321:"Backdoor", 64738:"Mumble"
}

# ---- auto-fill missing ports with IANA names (tiny download, once) ----
try:
    import requests, csv, io
    r = requests.get(
        "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv",
        timeout=5
    )
    for row in csv.reader(io.StringIO(r.text)):
        if len(row) >= 3 and row[0] and row[1].isdigit():
            IANA[int(row[1])] = row[0]          # collect IANA names
except Exception:
    IANA = {}   # offline → empty dict

# manual names win → caps stay, IANA fills gaps only
# after IANA collection
SERVICE = {**IANA, **SERVICE}   

FULL = {
    7: "Echo Protocol", 19: "Character Generator Protocol",
    20: "FTP Data Transfer", 21: "File Transfer Protocol",
    22: "Secure Shell Remote Login",

    23: "Teletype Network (Telnet)",
    25: "Simple Mail Transfer Protocol (SMTP)",
    37: "Time Protocol", 42: "WINS Name Service",
    43: "WHOIS Lookup Protocol",

    49: "Terminal Access Controller Access-Control System (TACACS)",
    53: "Domain Name System (DNS)",
    67: "DHCP Server", 68: "DHCP Client",
    69: "Trivial File Transfer Protocol (TFTP)",

    70: "Gopher Protocol", 79: "Finger User Information",
    80: "HyperText Transfer Protocol (HTTP)",
    88: "Kerberos Authentication",
    102: "Microsoft Exchange Messaging",

    110: "Post Office Protocol v3 (POP3)",
    111: "RPC Bind / Portmapper",
    113: "Ident Authentication Service",
    119: "Network News Transfer Protocol (NNTP)",
    123: "Network Time Protocol (NTP)",

    135: "Microsoft Remote Procedure Call (MS-RPC)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "Internet Message Access Protocol (IMAP)",

    161: "Simple Network Management Protocol (SNMP)",
    162: "SNMP Trap Service",
    179: "Border Gateway Protocol (BGP)",
    194: "Internet Relay Chat (IRC)",
    201: "AppleTalk Routing Protocol",

    389: "Lightweight Directory Access Protocol (LDAP)",
    427: "Service Location Protocol (SLP)",
    443: "HyperText Transfer Protocol Secure (HTTPS)",
    445: "SMB File Sharing (Windows)",
    465: "Secure SMTP (SMTPS)",

    500: "IPsec ISAKMP VPN",
    512: "Remote Execution (rexec)",
    513: "rlogin Remote Login",
    514: "Syslog Logging Protocol",
    520: "Routing Information Protocol (RIP)",

    554: "Real Time Streaming Protocol (RTSP)",
    587: "SMTP Mail Submission",
    631: "Internet Printing Protocol (IPP)",
    636: "Secure LDAP (LDAPS)",
    873: "RSYNC File Synchronization",

    902: "VMware Server Console",
    912: "VMware Authentication Daemon",
    989: "FTPS Data Channel",
    990: "FTPS Control Channel",
    993: "Secure IMAP (IMAPS)",

    995: "Secure POP3 (POP3S)",
    1025: "Microsoft RPC Dynamic",
    1080: "SOCKS Proxy Protocol",
    1194: "OpenVPN Encrypted Tunnel",
    1352: "IBM Lotus Domino",

    1433: "Microsoft SQL Server Database",
    1434: "MS SQL Monitor / Browser",
    1521: "Oracle Transparent Network Substrate (TNS)",
    1701: "Layer 2 Tunneling Protocol (L2TP)",
    1723: "Point-to-Point Tunneling Protocol (PPTP)",

    1812: "RADIUS Authentication",
    1883: "MQTT IoT Message Broker",
    1900: "UPnP Discovery Service",
    2000: "Cisco Skinny Client Control Protocol",
    2049: "Network File System (NFS)",

    2181: "Zookeeper Coordination Service",
    2375: "Docker Remote API (Unencrypted)",
    2376: "Docker Remote API (TLS Encrypted)",
    2483: "Oracle Database Listener",
    2484: "Oracle Secure Database Listener",

    27017: "MongoDB Database",
    27018: "MongoDB Cluster Node",
    27019: "MongoDB Replication",
    28017: "MongoDB Web Console",
    3000: "Node.js / Express Dev Server",

    3050: "Firebird SQL Database",
    3128: "Squid Web Proxy",
    3260: "iSCSI Storage Protocol",
    3306: "MySQL / MariaDB Database",
    3333: "DEC Notes Protocol",

    3389: "Microsoft Remote Desktop Protocol (RDP)",
    3478: "STUN NAT Traversal",
    3632: "DistCC Distributed Compiler",
    3690: "Subversion Repository",
    4369: "Erlang Port Mapper Daemon",

    4486: "FileMaker Database Server",
    4567: "Apple Remote Management",
    4662: "eMule Peer File Transfer",
    5000: "UPnP / Flask Development Server",
    5001: "HTTP Alternate / Admin Panel",

    5060: "SIP VoIP Signaling",
    5061: "Secure SIP (TLS)",
    5432: "PostgreSQL Database Server",
    5500: "VNC Remote Control",
    5601: "Kibana Analytics Dashboard",

    5672: "RabbitMQ Messaging Broker",
    5800: "VNC Web Interface",
    5900: "Virtual Network Computing (VNC)",
    5984: "CouchDB HTTP API",
    6000: "X11 Display Server",

    6379: "Remote Dictionary Server (Redis)",
    6667: "IRC Real-Time Chat",
    7001: "Oracle WebLogic Application Server",
    7002: "Oracle WebLogic SSL",
    7199: "Cassandra JMX Monitoring",

    8000: "Alternate HTTP Service / Python HTTP Server",
    8009: "AJP Apache JServ Protocol",
    8080: "HTTP Alternate / Web Proxy",
    8081: "Alternate Web Interface",
    8086: "InfluxDB Time-Series Database",

    8181: "Node-RED Automation Panel",
    8222: "VMware ESXi Management Console",
    8333: "Bitcoin Full Node",
    8443: "Alternate HTTPS (Admin Panels)",
    8500: "HashiCorp Consul",

    8530: "Windows Update Service (WSUS)",
    8531: "WSUS Secure Server",
    8888: "Alternate HTTP / Web Console",
    9000: "SonarQube Static Analysis Dashboard",
    9042: "Cassandra Storage Cluster",

    9090: "Prometheus Metrics System",
    9100: "Raw Printer Protocol",
    9200: "Elasticsearch REST API",
    9300: "Elasticsearch Transport Node",
    9418: "Git Smart Transfer Protocol",

    9999: "Abyss Web Server",
    11211: "Memcached In-Memory Cache",
    15672: "RabbitMQ Management Console",
    16080: "Alternate HTTP",
    18080: "MinIO Object Storage",

    20000: "Usermin Web Interface",
    27000: "FlexLM License Manager",
    30000: "Kubernetes NodePort Range",
    31337: "Back Orifice Malware",
    32400: "Plex Media Server",

    34567: "DVR CCTV Streaming",
    37777: "Dahua CCTV Server",
    44818: "EtherNet/IP Industrial Control",
    47808: "BACnet Building Automation",
    50000: "SAP Management Console"
}


DESC = {
    7: "Echo test; rarely used; simple packet reply",
    19: "Chargen spam generator; used for reflection DDoS",
    20: "FTP data channel; cleartext; legacy",
    21: "FTP control; cleartext logins; brute-force target",
    22: "SSH secure remote shell; encrypted terminal access",

    23: "Telnet remote shell; plaintext; highly insecure",
    25: "SMTP mail relay; moves mail between servers",
    37: "Time protocol; obsolete; spoofable",
    42: "WINS name service; old Windows LAN",
    43: "WHOIS lookup; domain/IP ownership info",

    49: "TACACS+ router/switch authentication (Cisco)",
    53: "DNS name resolution; critical infrastructure",
    67: "DHCP server; assigns IP configs; rogue DHCP = MITM",
    68: "DHCP client; receives IP settings",
    69: "TFTP no-auth file transfer; used in PXE booting",

    70: "Gopher pre-web info system; rare",
    79: "Finger user info service; enumeration-friendly",
    80: "HTTP web traffic; unencrypted",
    88: "Kerberos auth; Active Directory core",
    102: "MS Exchange backend RPC; email infrastructure",

    110: "POP3 mail download; plaintext by default",
    111: "RPCBind/NFS mapper; exposes RPC services",
    113: "Ident auth info; legacy; leaks usernames",
    119: "NNTP newsgroups; legacy",
    123: "NTP time sync; large DDoS reflector",

    135: "MS-RPC endpoint mapper; core Windows service",
    137: "NetBIOS name lookup; LAN discovery",
    138: "NetBIOS datagram; legacy broadcasts",
    139: "NetBIOS session; SMBv1 over NetBIOS",
    143: "IMAP email access; mailbox stays on server",

    161: "SNMP monitoring; default creds common ('public')",
    162: "SNMP trap receiver; device alerts",
    179: "BGP internet routing; ISP backbone",
    194: "IRC chat protocol; common botnet C2 channel",
    201: "AppleTalk routing; obsolete",

    389: "LDAP directory queries; AD user enumeration",
    427: "SLP service discovery; DoS amplifier",
    443: "HTTPS encrypted web traffic",
    445: "SMB file sharing; EternalBlue/PrintNightmare vector",
    465: "SMTPS secure email delivery",

    500: "ISAKMP/IPsec VPN negotiation",
    512: "rexec remote execution; plaintext",
    513: "rlogin remote login; plaintext; insecure",
    514: "Syslog centralized logging; UDP-based",
    520: "RIP routing protocol; old & spoofable",

    554: "RTSP streaming; CCTV/DVR systems",
    587: "SMTP submission; client outbound mail",
    631: "IPP printing; printer recon/injection",
    636: "LDAPS encrypted directory service",
    873: "RSYNC file sync; leaks directories if open",

    902: "VMware server console; VM control",
    912: "VMware auth service",
    989: "FTPS data channel; encrypted FTP",
    990: "FTPS control channel",
    993: "IMAPS secure encrypted email access",

    995: "POP3S secure email download",
    1025: "MS RPC high port; dynamic services",
    1080: "SOCKS proxy; tunneling & anonymity",
    1194: "OpenVPN tunnels; encrypted VPN",
    1352: "Lotus Domino groupware; enterprise legacy",

    1433: "MSSQL database server; high-value target",
    1434: "MSSQL browser/discovery (UDP)",
    1521: "Oracle TNS listener; enterprise DB",
    1701: "L2TP VPN; relies on IPsec for security",
    1723: "PPTP VPN; broken crypto; avoid",

    1812: "RADIUS authentication; Wi-Fi enterprise",
    1883: "MQTT IoT message broker",
    1900: "UPnP discovery; exploited by Mirai",
    2000: "Cisco SCCP VoIP signaling",
    2049: "NFS file shares; exposes whole directories",

    2082: "cPanel login (HTTP); hosting control",
    2083: "cPanel login (HTTPS); secure hosting admin",
    2181: "Zookeeper cluster coordination",
    2375: "Docker API; remote root access if exposed",
    2376: "Docker API over TLS; secured version",

    2483: "Oracle DB (TCP listener)",
    2484: "Oracle DB (SSL listener)",
    2601: "Zebra router service; network control",
    2604: "Zebra routing service; admin plane",
    28017: "MongoDB web status; info disclosure",

    3000: "Node.js dev server; dashboards",
    3050: "Firebird SQL database",
    3128: "Squid proxy; often open to world",
    3260: "iSCSI storage; raw disk access",
    3306: "MySQL/MariaDB database server",

    3333: "DEC Notes; very old enterprise service",
    3389: "RDP remote desktop; brute-force target",
    3478: "STUN NAT traversal; WebRTC/VoIP",
    3632: "DistCC compiler; RCE vulnerable",
    3690: "SVN source control",

    4369: "Erlang port mapper; RabbitMQ/CouchDB",
    4486: "FileMaker database server",
    4567: "Apple Remote Management; remote Mac admin",
    4662: "eMule P2P transfers",
    5000: "UPnP/Flask/IoT dashboards",

    5001: "Alt HTTPS admin interface",
    5060: "SIP VoIP signaling; caller ID spoofing",
    5061: "Secure SIP over TLS",
    5432: "PostgreSQL database",
    5500: "VNC alt port; no encryption",

    5601: "Kibana dashboards; ELK visualizer",
    5672: "RabbitMQ message broker",
    5800: "VNC web interface",
    5900: "VNC remote desktop; plaintext",
    5984: "CouchDB REST API",

    6000: "X11 GUI display; remote Linux desktop",
    6379: "Redis in-memory DB; no auth by default",
    6667: "IRC chat; botnet command channel",
    7001: "WebLogic admin; high-risk exploits",
    7002: "WebLogic SSL admin",

    7199: "Cassandra JMX; cluster control",
    8000: "Python/Dev HTTP server; dashboards",
    8009: "AJP (Tomcat backend); Ghostcat vuln",
    8080: "Alt HTTP; dev servers & proxies",
    8081: "Backup HTTP interface; admin UIs",

    8086: "InfluxDB HTTP API; time-series data",
    8181: "Node-RED automation panel; IoT flows",
    8222: "VMware ESXi old web UI",
    8333: "Bitcoin P2P node",
    8443: "Alt HTTPS; admin portals",

    8500: "Consul service mesh; service discovery",
    8530: "WSUS Windows updates",
    8531: "WSUS over SSL",
    8888: "Alt HTTP; Jupyter dashboards",
    9000: "SonarQube code analysis",

    9042: "Cassandra DB native protocol",
    9090: "Prometheus metrics endpoint",
    9100: "Printer raw socket; direct print injection",
    9200: "Elasticsearch REST API; data leak prone",
    9300: "Elasticsearch node cluster comms",

    9418: "Git smart transfer; bare repo access",
    9999: "Abyss web server; lightweight",
    11211: "Memcached; massive data leak risk",
    15672: "RabbitMQ admin console",
    16080: "Alt HTTP for proxies/load-balancers",

    18080: "MinIO S3-like storage",
    20000: "Usermin web portal for Linux users",
    27000: "FlexLM license manager",
    30000: "Kubernetes NodePort",
    31337: "Back Orifice malware backdoor",

    32400: "Plex media server; streaming backend",
    34567: "CCTV/DVR video transport",
    37777: "Dahua CCTV control",
    44818: "EtherNet/IP industrial PLC control",
    47808: "BACnet building automation (HVAC)",
    
    50000: "SAP management console; enterprise core"
}


ATTACK = {
    # FTP & File Transfer
    20: "FTP data channel hijacking, file interception",
    21: "FTP anonymous access, credential sniffing, bounce attacks",
    22: "SSH brute-force, weak key exchange, session hijacking",
    23: "Telnet credential sniffing (cleartext), brute-force",
    69: "TFTP unauthorized file access, directory traversal",
    115: "SFTP misconfiguration, key theft",
    989: "FTPS data channel hijacking, SSL stripping",
    990: "FTPS control channel exploitation",
    8021: "FTP proxy bounce attacks",
    
    # Email Services
    25: "SMTP open relay, spam propagation, header injection",
    26: "SMTP alternative spam relay, credential theft",
    110: "POP3 credential sniffing, brute-force attacks",
    143: "IMAP credential sniffing, brute-force attacks",
    465: "SMTPS SSL stripping, credential interception",
    587: "SMTP submission auth bypass, spam relay",
    993: "IMAPS account lockout via brute-force",
    995: "POP3S account lockout via brute-force",
    
    # Web Services
    80: "HTTP DoS, XSS, SQL injection, data leakage",
    81: "HTTP alternative admin panel attacks",
    443: "HTTPS TLS downgrade, POODLE, BEAST, heartbleed",
    444: "HTTPS alternative SSL stripping",
    800: "HTTP alternative web app vulnerabilities",
    808: "HTTP alternative proxy misconfiguration",
    8443: "HTTPS alternative SSL stripping, weak ciphers",
    8080: "Web proxy dev panel takeover, data leakage",
    8081: "HTTP proxy cache poisoning, MITM",
    8088: "HTTP alternative SQLi, path traversal",
    8888: "Web management default creds, RCE",
    9080: "WebSphere JNDI injection, deserialization",
    9090: "WebSM default configuration exploits",
    9443: "HTTPS management console default passwords",
    
    # DNS & Network Services
    53: "DNS cache poisoning, DNS hijacking, DDoS amplification",
    67: "DHCP rogue server attacks, IP spoofing, exhaustion",
    68: "DHCP client impersonation, MITM attacks",
    123: "NTP DDoS amplification, time manipulation",
    137: "NetBIOS name service enumeration, zone transfer",
    138: "NetBIOS datagram service exploits",
    139: "NetBIOS session service SMBv1 exploits",
    161: "SNMP community string brute-force, info disclosure",
    162: "SNMP-trap fake trap injection, DDoS",
    389: "LDAP injection attacks, credential harvesting",
    636: "LDAPS SSL stripping, LDAP injection",
    860: "iSCSI unauthorized storage access",
    3268: "Global catalog LDAP enumeration",
    3269: "Global catalog LDAPS attacks",
    
    # Database Services
    1433: "MSSQL data exfiltration, privilege escalation",
    1434: "MSSQL browser service enumeration",
    1521: "Oracle TNS poisoning, data leakage",
    1522: "Oracle TNS listener exploits",
    1527: "Derby database unauthorized access",
    1830: "Oracle listener attacks, buffer overflow",
    2424: "OrientDB code injection",
    2483: "Oracle SSL stripping, TNS attacks",
    2484: "Oracle TNS listener over SSL attacks",
    3050: "Firebird/InterBase database access",
    3306: "MySQL data theft, ransomware deployment",
    3351: "Pervasive SQL injection",
    3389: "RDP BlueKeep exploits, brute-force to domain",
    5432: "PostgreSQL data exfiltration, privilege escalation",
    5984: "CouchDB database injection, unauthorized access",
    6379: "Redis data dumping, cache poisoning, ransomware",
    7001: "WebLogic deserialization attacks",
    7002: "WebLogic cluster attacks",
    7199: "Cassandra JMX exploitation",
    7474: "Neo4j Cypher injection",
    7676: "JBoss JMX console exploits",
    8009: "Apache JServ protocol exploits",
    8089: "Splunk search language injection",
    8090: "Atlassian Confluence RCE",
    8098: "Riak KV unauthorized data access",
    8140: "Puppet master code injection",
    8161: "ActiveMQ admin console default creds",
    8200: "GoCD config information disclosure",
    8333: "Bitcoin JSON-RPC exploitation",
    8484: "Hadoop HDFS unauthorized access",
    8585: "Hadoop MapReduce job submission",
    8629: "MongoDB web interface attacks",
    8675: "Hadoop YARN resource manager exploits",
    8686: "Hadoop YARN node manager",
    8765: "Hadoop HBase master exploits",
    8889: "Hadoop HBase region server",
    9000: "Hadoop HDFS name node, PHP-FPM RCE",
    9001: "Hadoop HDFS data node, Tor control",
    9002: "Hadoop secondary name node",
    9042: "Cassandra CQL injection",
    9092: "Apache Kafka unauthorized message production",
    9160: "Cassandra Thrift interface attacks",
    9200: "Elasticsearch remote code execution",
    9300: "Elasticsearch transport layer exploits",
    9418: "Git daemon unauthorized repo access",
    9999: "Java debug wire protocol RCE",
    10000: "Webmin command injection, backup disclosure",
    11211: "Memcached DDoS amplification, cache poisoning",
    15672: "RabbitMQ management console default creds",
    27017: "MongoDB unauthorized access, data theft",
    27018: "MongoDB sharding commands",
    28017: "MongoDB web interface attacks",
    
    # Remote Access & Management
    512: "rexec remote command execution, credential theft",
    513: "rlogin trust relationship exploitation",
    514: "rsh remote command execution, log injection",
    515: "LPD printer service exploitation, file injection",
    993: "IMAPS brute-force, credential interception",
    1080: "SOCKS proxy abuse, traffic tunneling",
    1194: "OpenVPN configuration theft, MITM",
    1241: "Nessus vulnerability scanner data theft",
    1311: "Dell OpenManage default credentials",
    1352: "Lotus Notes database enumeration",
    1434: "MSSQL resolution service buffer overflow",
    1494: "Citrix ICA session hijacking",
    1500: "NetGuard default admin access",
    1524: "Ingreslock backdoor access",
    1583: "Pervasive SQL buffer overflow",
    1723: "PPTP MS-CHAPv2 cracking, credential theft",
    1812: "RADIUS authentication bypass",
    1813: "RADIUS accounting manipulation",
    1900: "UPnP SSDP DDoS amplification",
    2049: "NFS unauthorized mount, file access",
    2082: "cPanel default credential attacks",
    2083: "cPanel over SSL credential theft",
    2086: "WHM default credential attacks",
    2087: "WHM over SSL attacks",
    2100: "Oracle XDB FTP unauthorized access",
    2222: "DirectAdmin brute-force, ESET admin",
    2375: "Docker unencrypted communication",
    2376: "Docker TLS misconfiguration",
    2381: "HP iLO default credentials",
    2480: "OrientDB studio RCE",
    2601: "Zebra router default passwords",
    2604: "Zebra BGP route injection",
    3128: "Squid proxy cache poisoning, MITM",
    3260: "iSCSI target unauthorized access",
    3300: "MySQL Webmin module attacks",
    3333: "Network Beacon C2 communication",
    3389: "RDP BlueKeep, brute-force, session theft",
    3690: "Subversion repo unauthorized access",
    4440: "IKE VPN PSK brute-force",
    4443: "IKE VPN over SSL attacks",
    4444: "Metasploit listener detection",
    4500: "IPsec NAT-T traversal attacks",
    4567: "Sinatra default configuration",
    4848: "GlassFish admin console default creds",
    4899: "Radmin remote control unauthorized access",
    5000: "UPnP control, Docker registry manipulation",
    5001: "VMware ESXi management exploits",
    5009: "AirPort admin default passwords",
    5060: "SIP registration hijacking, call interception",
    5061: "SIP over TLS MITM attacks",
    5190: "ICQ session hijacking",
    5353: "mDNS service spoofing",
    5357: "WS-Discovery device enumeration",
    5431: "SofaShark database attacks",
    5500: "VNC server unauthorized access",
    5555: "Android debug bridge RCE",
    5601: "Kibana prototype pollution",
    5631: "PCAnywhere data interception",
    5632: "PCAnywhere over SSL attacks",
    5666: "Nagios command injection",
    5800: "VNC over HTTP session hijacking",
    5900: "VNC screen capture, keylogging, brute-force",
    5901: "VNC session hijacking, authentication bypass",
    5984: "CouchDB unauthorized admin access",
    5985: "WinRM credential theft, remote execution",
    5986: "WinRM SSL MITM, credential interception",
    6000: "X11 session hijacking, screen capture",
    6001: "X11 session theft",
    6379: "Redis unauthorized command execution",
    6443: "Kubernetes API server exploits",
    6481: "Sun Management Center attacks",
    6646: "McAfee default credentials",
    6666: "IRC botnet C&C, Voldemort database",
    6667: "IRC channel takeover, DDoS bots",
    6679: "Osiris botnet communication",
    6697: "IRC over SSL credential theft",
    6881: "BitTorrent peer flooding",
    6969: "BitTorrent tracker exploits",
    7000: "Cassandra internode communication",
    7001: "WebLogic deserialization",
    7002: "WebLogic cluster communication",
    7070: "RealServer buffer overflow",
    7210: "MaxDB remote administration",
    7634: "Hardware monitoring default creds",
    7777: "Oracle HTTP server attacks",
    8000: "Web dev XSS, CSRF, framework exploits",
    8005: "Tomcat shutdown command abuse",
    8008: "HTTP alternative SQLi, path traversal",
    8009: "Apache JServ protocol",
    8010: "Wing FTP admin default passwords",
    8069: "Odoo ERP unauthorized access",
    8074: "Gunicorn misconfiguration",
    8080: "Web proxy dev panel takeover",
    8081: "HTTP proxy cache poisoning",
    8082: "HTTP alternative attacks",
    8088: "HTTP alternative SQLi",
    8090: "Atlassian Confluence RCE",
    8091: "Couchbase admin console",
    8098: "Riak KV unauthorized access",
    8140: "Puppet master code injection",
    8180: "HTTP proxy cache deception",
    8222: "VMware VI SOAP API attacks",
    8243: "HTTPS alternative attacks",
    8332: "Bitcoin JSON-RPC wallet theft",
    8333: "Bitcoin mainnet node exploitation",
    8400: "Commvault backup data theft",
    8443: "HTTPS alternative SSL stripping",
    8484: "Hadoop HDFS unauthorized access",
    8585: "Hadoop MapReduce job submission",
    8686: "Hadoop YARN node manager",
    8765: "HBase master exploits",
    8888: "Jupyter notebook code execution",
    9000: "PHP-FPM RCE, Hadoop name node",
    9001: "Tor control port hijacking",
    9042: "Cassandra CQL injection",
    9060: "WebLogic admin console",
    9080: "WebSphere application exploits",
    9090: "Prometheus data scraping",
    9091: "Openfire admin console",
    9092: "Kafka unauthorized access",
    9100: "RAW print server attacks",
    9160: "Cassandra Thrift interface",
    9200: "Elasticsearch RCE",
    9300: "Elasticsearch transport layer",
    9418: "Git daemon repo theft",
    9443: "HTTPS management console",
    9669: "Zabbix agent command injection",
    9876: "TeamViewer unauthorized access",
    9999: "Java debug wire protocol RCE",
    10000: "Webmin command injection",
    10001: "Ubiquiti discovery service",
    10050: "Zabbix agent data theft",
    10051: "Zabbix server spoofing",
    11211: "Memcached DDoS amplification",
    12345: "NetBus trojan backdoor",
    13720: "NetBackup credential theft",
    13721: "NetBackup data access",
    15151: "Bo2k trojan backdoor",
    16992: "Intel AMT default credentials",
    16993: "Intel AMT exploitation",
    20000: "Usermin attacks, DNP3 exploits",
    20720: "Symantec AV data theft",
    27017: "MongoDB unauthorized access",
    27374: "Sub7 trojan backdoor",
    31337: "Back Orifice backdoor",
    32764: "Router backdoor access",
    35871: "Fluxbot trojan",
    37777: "Qakbot trojan",
    44818: "EtherNet/IP exploitation",
    47001: "Windows RPC exploitation",
    47808: "BACnet device spoofing",
    49152: "Windows RPC dynamic port exploits",
    50000: "DB2 database unauthorized access",
    50030: "Hadoop MapReduce job tracker",
    50060: "Hadoop task tracker",
    50070: "Hadoop HDFS name node web UI",
    54311: "BTC miner RPC exploitation"
}

FIX = {
    # FTP & File Transfer
    20: "Use SFTP/SCP; disable FTP data port",
    21: "Use SFTP; disable anonymous access; require TLS",
    22: "Use key-based authentication; disable root login; implement fail2ban",
    23: "Disable Telnet; use SSH exclusively",
    69: "Disable TFTP; use secure file transfer protocols",
    115: "Use SSH-based SFTP with strong authentication",
    989: "Require mutual TLS; validate certificates",
    990: "Enforce strong TLS configurations; disable weak ciphers",
    8021: "Restrict FTP proxy access; use application-layer filtering",
    
    # Email Services
    25: "Require authentication + TLS; disable open relay; use SPF/DKIM/DMARC",
    26: "Same as port 25; monitor for abuse",
    110: "Use POP3S exclusively; disable plain POP3",
    143: "Use IMAPS exclusively; disable plain IMAP",
    465: "Enforce certificate validation; use modern TLS",
    587: "Require authentication; implement rate limiting",
    993: "Enforce strong passwords + 2FA; implement account lockout",
    995: "Same as port 993; monitor authentication attempts",
    
    # Web Services
    80: "Redirect to HTTPS; implement HSTS; keep patched",
    81: "Restrict access; implement authentication; use HTTPS",
    443: "Use TLS 1.3 only; implement HSTS; disable weak ciphers",
    444: "Redirect to standard HTTPS ports; disable unnecessary services",
    800: "Use standard HTTPS; implement WAF; regular security testing",
    808: "Use reverse proxy with authentication; disable if unused",
    8443: "Same as port 443; use standard HTTPS when possible",
    8080: "Firewall restriction; reverse proxy with auth; disable if dev only",
    8081: "Implement access controls; use authentication; monitor traffic",
    8088: "Restrict to internal networks; implement WAF",
    8888: "Change default credentials; restrict network access",
    9080: "Keep WebSphere updated; disable unused services",
    9090: "Implement authentication; restrict network access",
    9443: "Change default passwords; implement certificate authentication",
    
    # DNS & Network Services
    53: "Restrict recursion to trusted networks; use DNSSEC",
    67: "Implement DHCP snooping; use port security",
    68: "Monitor for rogue DHCP clients; network segmentation",
    123: "Use authenticated NTP; restrict client access",
    137: "Disable NetBIOS name service; use DNS",
    138: "Disable NetBIOS datagram service",
    139: "Disable SMBv1; use SMBv3 with encryption",
    161: "Use SNMPv3 with encryption; change community strings",
    162: "Authenticate SNMP traps; monitor for spoofing",
    389: "Implement LDAPS; use strong authentication",
    636: "Validate certificates; enforce encryption",
    860: "Use CHAP authentication; network segmentation",
    3268: "Implement access controls; monitor queries",
    3269: "Require LDAPS; implement account lockout",
    
    # Database Services
    1433: "VPN-only access; strong 'sa' password; network encryption",
    1434: "Disable SQL Browser service; use static ports",
    1521: "Encrypt network traffic; implement ACLs; use VPN",
    1522: "Restrict listener access; implement network encryption",
    1527: "Implement authentication; restrict network access",
    1830: "Keep Oracle updated; restrict listener permissions",
    2424: "Implement authentication; network segmentation",
    2483: "Use TLS; validate certificates; restrict access",
    2484: "Enforce mutual TLS; monitor connection attempts",
    3050: "Implement strong authentication; network encryption",
    3306: "Bind to localhost/VPN; strong passwords; disable remote root",
    3351: "Use parameterized queries; implement access controls",
    3389: "Use RDP Gateway; enable Network Level Authentication; keep patched",
    5432: "Use hostssl in pg_hba.conf; strong authentication; network encryption",
    5984: "Implement authentication; use reverse proxy",
    6379: "Require authentication; bind to localhost; rename dangerous commands",
    7001: "Keep WebLogic patched; disable demo applications",
    7002: "Use SSL between cluster nodes; implement authentication",
    7199: "Secure JMX access; use authentication and SSL",
    7474: "Use parameterized queries; implement authentication",
    7676: "Secure JMX console; change default credentials",
    8009: "Disable if unused; use AJP secret",
    8089: "Implement authentication; restrict search permissions",
    8090: "Keep Confluence updated; implement access controls",
    8098: "Implement authentication; use HTTPS",
    8140: "Use code signing; implement node classification",
    8161: "Change default credentials; restrict network access",
    8200: "Implement authentication; encrypt sensitive data",
    8333: "Use RPC authentication; restrict to localhost",
    8484: "Implement Kerberos authentication; use network encryption",
    8585: "Secure job submission; implement queue authentication",
    8629: "Implement authentication; use TLS",
    8675: "Secure resource manager; implement access controls",
    8686: "Secure node manager; monitor for unauthorized jobs",
    8765: "Implement authentication; encrypt region server traffic",
    8889: "Secure region server; implement access logging",
    9000: "Restrict PHP-FPM access; secure Hadoop name node",
    9001: "Use Tor authentication; restrict control port",
    9002: "Secure secondary name node; network segmentation",
    9042: "Use authentication; implement client-to-node encryption",
    9092: "Implement SASL authentication; use TLS encryption",
    9160: "Use authentication; restrict Thrift interface access",
    9200: "Implement X-Pack security; use TLS encryption",
    9300: "Implement node-to-node encryption; use certificates",
    9418: "Use SSH instead; restrict git daemon access",
    9999: "Disable debug wire protocol in production",
    10000: "Keep Webmin updated; strong passwords; restrict access",
    11211: "Restrict to localhost; use SASL authentication",
    15672: "Change default credentials; restrict network access",
    27017: "Enable authentication; use TLS; network segmentation",
    27018: "Implement sharding security; use keyFile authentication",
    28017: "Disable HTTP interface; use admin database commands",
    
    # Remote Access & Management
    512: "Disable rexec; use SSH key authentication",
    513: "Disable rlogin; use SSH exclusively",
    514: "Disable rsh; use syslog with TLS",
    515: "Disable LPD; use IPP with TLS",
    993: "Enforce strong passwords + 2FA; monitor authentication",
    1080: "Implement SOCKS authentication; restrict allowed destinations",
    1194: "Use certificate authentication; implement TLS crypt",
    1241: "Restrict Nessus access; use strong authentication",
    1311: "Change default credentials; restrict network access",
    1352: "Implement Lotus Notes security; use certificates",
    1434: "Disable SQL Browser; use static port assignment",
    1494: "Use Citrix Gateway; implement session policies",
    1500: "Change default credentials; restrict access",
    1524: "Remove ingreslock; use modern authentication",
    1583: "Keep Pervasive SQL updated; use network encryption",
    1723: "Migrate to WireGuard/OpenVPN; disable PPTP",
    1812: "Use RADIUS with EAP-TLS; implement monitoring",
    1813: "Secure accounting data; use RADIUS over TLS",
    1900: "Disable UPnP on perimeter; use manual port forwarding",
    2049: "Use NFSv4 with Kerberos; implement export restrictions",
    2082: "Change cPanel defaults; use strong passwords",
    2083: "Use TLS; implement certificate pinning",
    2086: "Change WHM defaults; restrict access to trusted IPs",
    2087: "Use TLS; implement strong authentication",
    2100: "Disable Oracle XDB FTP; use secure file transfer",
    2222: "Change DirectAdmin defaults; use key authentication",
    2375: "Use TLS with client certificate authentication",
    2376: "Implement proper TLS configuration; use certificate auth",
    2381: "Change iLO defaults; use dedicated management network",
    2480: "Secure OrientDB studio; implement authentication",
    2601: "Change Zebra defaults; use authentication",
    2604: "Implement BGP MD5 authentication; use route filters",
    3128: "Implement proxy authentication; use access control lists",
    3260: "Use CHAP authentication; implement network segmentation",
    3300: "Secure MySQL Webmin; use strong authentication",
    3333: "Monitor for beaconing; block unauthorized outbound",
    3389: "Use RDP Gateway; enable NLA; keep systems patched",
    3690: "Use SSH for SVN; implement repository permissions",
    4440: "Use certificate-based IKEv2; disable aggressive mode",
    4443: "Implement proper TLS configuration; use strong ciphers",
    4444: "Monitor for Metasploit; block unauthorized listeners",
    4500: "Use strong PSK or certificates; implement perfect forward secrecy",
    4567: "Implement authentication; use framework security features",
    4848: "Change GlassFish defaults; use certificate authentication",
    4899: "Use Radmin encryption; implement access controls",
    5000: "Disable UPnP on perimeter; secure Docker registry",
    5001: "Use vSphere security features; restrict management access",
    5009: "Change AirPort defaults; use WPA3 encryption",
    5060: "Use SIP over TLS; implement authentication",
    5061: "Validate certificates; use SRTP for media",
    5190: "Use modern messaging apps; disable legacy protocols",
    5353: "Implement mDNS filtering; use service discovery controls",
    5357: "Disable WS-Discovery on perimeter; use internal only",
    5431: "Implement authentication; use database security features",
    5500: "Tunnel VNC over SSH; disable direct access",
    5555: "Disable ADB in production; use developer mode only",
    5601: "Keep Kibana updated; implement authentication",
    5631: "Use modern remote access tools; disable PCAnywhere",
    5632: "Same as 5631; migrate to secure alternatives",
    5666: "Secure Nagios; implement command restrictions",
    5800: "Tunnel over SSH; use VNC authentication",
    5900: "Tunnel over SSH; use strong VNC passwords",
    5901: "Same as 5900; consider alternative remote access",
    5984: "Implement CouchDB authentication; use reverse proxy",
    5985: "Use WinRM over HTTPS; implement certificate auth",
    5986: "Validate certificates; use constrained endpoints",
    6000: "Use SSH X11 forwarding; disable direct X11 access",
    6001: "Same as 6000; use secure alternatives",
    6379: "Require Redis AUTH; rename dangerous commands; bind localhost",
    6443: "Use RBAC; implement network policies; enable audit logging",
    6481: "Secure Sun MC; use authentication and encryption",
    6646: "Change McAfee defaults; use ePO management",
    6666: "Monitor for IRC traffic; block unauthorized outbound",
    6667: "Same as 6666; use enterprise messaging solutions",
    6679: "Monitor for botnet C&C; block malicious domains",
    6697: "Use modern chat solutions; disable legacy IRC",
    6881: "Implement traffic shaping; monitor for abuse",
    6969: "Secure tracker; implement access controls",
    7000: "Use node-to-node encryption; implement authentication",
    7001: "Keep WebLogic patched; secure admin console",
    7002: "Use SSL between nodes; implement cluster authentication",
    7070: "Use modern streaming solutions; keep software updated",
    7210: "Implement authentication; restrict admin access",
    7634: "Change hardware monitor defaults; restrict access",
    7777: "Secure Oracle HTTP; use authentication and authorization",
    8000: "Use production web servers; implement security headers",
    8005: "Secure shutdown port; use management interface instead",
    8008: "Redirect to HTTPS; implement security controls",
    8009: "Use AJP secret; restrict connector access",
    8010: "Change Wing FTP defaults; use strong authentication",
    8069: "Implement Odoo authentication; restrict access",
    8074: "Secure Gunicorn; use reverse proxy with SSL",
    8080: "Firewall restriction; use auth reverse proxy; disable if dev",
    8081: "Implement access controls; use authentication",
    8082: "Same as 8080; use standard HTTPS when possible",
    8088: "Restrict access; implement WAF and authentication",
    8090: "Keep Confluence updated; implement security controls",
    8091: "Secure Couchbase; implement authentication",
    8098: "Implement Riak authentication; use HTTPS",
    8140: "Use code signing; implement proper node classification",
    8180: "Implement proxy authentication; use access controls",
    8222: "Secure VMware API; use certificate authentication",
    8243: "Use standard HTTPS; implement proper TLS configuration",
    8332: "Use RPC authentication; restrict to localhost",
    8333: "Secure Bitcoin node; implement peer filtering",
    8400: "Secure Commvault; use authentication and encryption",
    8443: "Use TLS 1.3; implement HSTS; disable weak ciphers",
    8484: "Implement Kerberos; use network encryption",
    8585: "Secure job submission; implement queue authentication",
    8765: "Implement authentication; encrypt region server traffic",
    8888: "Change Jupyter defaults; use token authentication",
    9000: "Secure PHP-FPM; restrict Hadoop name node access",
    9001: "Use Tor authentication; restrict control port access",
    9042: "Use authentication; implement client-to-node encryption",
    9060: "Secure WebLogic admin; use strong authentication",
    9080: "Secure WebSphere; implement proper authorization",
    9090: "Secure Prometheus; use authentication and TLS",
    9091: "Change Openfire defaults; use strong authentication",
    9092: "Implement SASL authentication; use TLS encryption",
    9100: "Use IPP with TLS; implement print job authentication",
    9160: "Use authentication; restrict Thrift interface",
    9200: "Implement X-Pack security; use TLS and role-based access",
    9300: "Implement node-to-node encryption; use certificates",
    9418: "Use SSH for Git; restrict daemon access",
    9443: "Change default passwords; use certificate authentication",
    9669: "Secure Zabbix agent; use PSK authentication",
    9876: "Use TeamViewer accounts; implement access controls",
    9999: "Disable debug wire protocol in production environments",
    10000: "Keep Webmin updated; strong passwords; restrict network access",
    10001: "Change Ubiquiti defaults; use strong authentication",
    10050: "Secure Zabbix agent; use PSK encryption",
    10051: "Authenticate Zabbix server; use TLS communication",
    11211: "Restrict to localhost; use SASL authentication",
    12345: "Monitor for NetBus; block unauthorized applications",
    13720: "Secure NetBackup; use authentication and encryption",
    13721: "Same as 13720; implement access logging",
    15151: "Monitor for Bo2k; use endpoint protection",
    16992: "Change Intel AMT defaults; use dedicated management network",
    16993: "Same as 16992; disable if unused",
    20000: "Secure Usermin; implement DNP3 security controls",
    20720: "Secure Symantec AV; use management console",
    27017: "Enable authentication; use TLS; network segmentation",
    27374: "Monitor for Sub7; use endpoint protection",
    31337: "Monitor for Back Orifice; block unauthorized apps",
    32764: "Update router firmware; change default credentials",
    35871: "Monitor for Fluxbot; use network intrusion detection",
    37777: "Monitor for Qakbot; use endpoint detection and response",
    44818: "Implement EtherNet/IP security; use network segmentation",
    47001: "Secure Windows RPC; use firewall restrictions",
    47808: "Implement BACnet security; use network segmentation",
    49152: "Use Windows firewall; monitor dynamic RPC ports",
    50000: "Secure DB2; use authentication and encryption",
    50030: "Secure job tracker; implement access controls",
    50060: "Secure task tracker; use network encryption",
    50070: "Secure HDFS web UI; implement authentication",
    54311: "Secure BTC miner; restrict RPC access"
}

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
            name, desc = IANA.get(port, (f"Port-{port}", "No IANA entry"))
            atk   = ATTACK.get(port, "Investigate manually.")
            fix   = FIX.get(port, "Restrict to trusted IPs or disable.")
            story.extend([
            Spacer(0.1*inch),
            Paragraph(f"<b>Port {port}</b> ({name})", normal),
            Paragraph(f"<font color='orange'>Description:</font> {desc}", normal),
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
    full={p: FULL.get(p, "Network Service") for p in open_ports},
    desc={p: DESC.get(p, "Common network service") for p in open_ports}, 
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