import os
import platform
import subprocess
import sqlite3
import requests
import logging
import hashlib
import threading
import time
import psutil
from flask import Flask, render_template_string, request, send_file, jsonify, redirect, url_for, flash, session
from flask_httpauth import HTTPBasicAuth
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename
from fpdf import FPDF
from datetime import datetime
import smtplib

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.FileHandler("security_dashboard.log"), logging.StreamHandler()]
)

# --- Configuration via Environment Variables ---
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "securepass")
USER_USER = os.environ.get("USER_USER", "user")
USER_PASS = os.environ.get("USER_PASS", "userpass")
ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "recipient@example.com")
EMAIL_USER = os.environ.get("EMAIL_USER", "your@email.com")
EMAIL_PASS = os.environ.get("EMAIL_PASS", "yourpassword")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "YOUR_VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "YOUR_ABUSEIPDB_API_KEY")
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
auth = HTTPBasicAuth()
socketio = SocketIO(app)

# --- Database setup ---
def init_db():
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS checks
                 (date TEXT, os TEXT, updates TEXT, antivirus TEXT, firewall TEXT, score INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS incidents
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, type TEXT, description TEXT, status TEXT DEFAULT 'open', comments TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logins
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, date TEXT, username TEXT, success INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, password TEXT, role TEXT)''')
    c.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)', (ADMIN_USER, ADMIN_PASS, 'admin'))
    c.execute('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)', (USER_USER, USER_PASS, 'user'))
    conn.commit()
    conn.close()
init_db()

# --- Authentication and RBAC ---
@auth.verify_password
def verify_password(username, password):
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute('SELECT password, role FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    valid = row and row[0] == password
    log_login_attempt(username, valid)
    if valid:
        session['role'] = row[1]
    return valid

def role_required(role):
    def wrapper(fn):
        def decorated(*args, **kwargs):
            if session.get('role') != role:
                flash("Access denied: insufficient privileges.")
                return redirect(url_for('security_dashboard'))
            return fn(*args, **kwargs)
        decorated.__name__ = fn.__name__
        return decorated
    return wrapper

# --- System Update Checks ---
def check_windows_updates():
    try:
        result = subprocess.run(
            ["powershell", "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates | Select-Object -Property Title"],
            capture_output=True,
            text=True
        )
        return result.stdout.strip() or "System is up to date"
    except Exception as e:
        logging.error(f"Windows update check failed: {e}")
        return f"Update check failed: {str(e)}"

def check_linux_updates():
    try:
        result = subprocess.run(
            ["apt-get", "-s", "upgrade"],
            capture_output=True,
            text=True
        )
        if "upgraded" in result.stdout:
            return "Updates available"
        else:
            return "System is up to date"
    except Exception as e:
        logging.error(f"Linux update check failed: {e}")
        return f"Update check failed: {str(e)}"

def check_updates():
    if platform.system() == "Windows":
        return check_windows_updates()
    elif platform.system() == "Linux":
        return check_linux_updates()
    else:
        return "Update check not implemented for this OS"

# --- Antivirus Check ---
def check_antivirus():
    try:
        if platform.system() == "Windows":
            import windows_tools.antivirus
            av_info = windows_tools.antivirus.get_installed_antivirus_software()
            return [f"{av['name']} (Enabled: {av['enabled']}, Up-to-date: {av['up_to_date']})" for av in av_info]
        elif platform.system() == "Linux":
            result = subprocess.run(['clamscan', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                return [result.stdout.strip()]
            else:
                return ["ClamAV not installed"]
        else:
            return ["Antivirus check not implemented for this OS"]
    except Exception as e:
        logging.error(f"Antivirus check failed: {e}")
        return [f"Antivirus check failed: {str(e)}"]

# --- Firewall Check ---
def check_firewall():
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output(['netsh', 'advfirewall', 'show', 'allprofiles'], text=True)
            return "Enabled" if "State ON" in result else "Disabled"
        elif platform.system() == "Linux":
            result = subprocess.check_output(['ufw', 'status'], text=True)
            return "Enabled" if "Status: active" in result else "Disabled"
        else:
            return "Firewall check not implemented for this OS"
    except Exception as e:
        logging.error(f"Firewall check failed: {e}")
        return f"Firewall check failed: {str(e)}"

# --- Security Headers ---
def check_security_headers(url="https://www.google.com"):
    try:
        response = requests.get(url)
        security_headers = {
            "Content-Security-Policy": response.headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": response.headers.get("Strict-Transport-Security"),
            "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
            "X-Frame-Options": response.headers.get("X-Frame-Options"),
            "Referrer-Policy": response.headers.get("Referrer-Policy"),
            "Permissions-Policy": response.headers.get("Permissions-Policy"),
        }
        return security_headers
    except Exception as e:
        logging.error(f"Header check failed: {e}")
        return {"error": f"Header check failed: {str(e)}"}

def check_browser_security():
    return "Browser security check is a stub (not implemented)."

def calculate_security_score(status):
    score = 100
    if "update" in status["update_status"].lower() and "up to date" not in status["update_status"].lower():
        score -= 30
    if not status["antivirus_status"] or any("False" in av for av in status["antivirus_status"]):
        score -= 40
    if "Enabled" not in status["firewall_status"]:
        score -= 30
    return max(score, 0)

# --- Historical Tracking ---
def log_check_results(status, score):
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute('INSERT INTO checks VALUES (?,?,?,?,?,?)',
              (datetime.now().isoformat(), status["os"], status["update_status"],
               str(status["antivirus_status"]), status["firewall_status"], score))
    conn.commit()
    conn.close()

def get_historical_checks():
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute('SELECT * FROM checks ORDER BY date DESC LIMIT 10')
    rows = c.fetchall()
    conn.close()
    return rows

# --- Incident Management ---
def log_incident(inc_type, description):
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute('INSERT INTO incidents (date, type, description) VALUES (?, ?, ?)',
              (datetime.now().isoformat(), inc_type, description))
    conn.commit()
    conn.close()

def get_incidents():
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute('SELECT * FROM incidents ORDER BY date DESC LIMIT 20')
    rows = c.fetchall()
    conn.close()
    return rows

# --- Login Attempt Tracking ---
def log_login_attempt(username, success):
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute('INSERT INTO logins (date, username, success) VALUES (?, ?, ?)',
              (datetime.now().isoformat(), username, int(success)))
    conn.commit()
    conn.close()

def get_login_attempts():
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    c.execute('SELECT * FROM logins ORDER BY date DESC LIMIT 20')
    rows = c.fetchall()
    conn.close()
    return rows

# --- VirusTotal Integration ---
def check_file_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"VirusTotal API error: {response.status_code}"}
    except Exception as e:
        logging.error(f"VirusTotal check failed: {e}")
        return {"error": f"VirusTotal check failed: {str(e)}"}

# --- Threat Intelligence (AbuseIPDB) ---
def check_ip_reputation(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers, timeout=3)
        if response.status_code == 200:
            return response.json()['data']['abuseConfidenceScore']
    except Exception as e:
        logging.error(f"AbuseIPDB check failed for {ip}: {e}")
    return None

# --- Geolocation (ipapi.co) ---
def get_geolocation(ip):
    try:
        url = f"https://ipapi.co/{ip}/json/"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            return {
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country_name"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude")
            }
    except Exception as e:
        logging.error(f"Geolocation lookup failed for {ip}: {e}")
    return {"city": None, "region": None, "country": None, "latitude": None, "longitude": None}

# --- Notification System ---
def send_alert(subject, message, to_email=ALERT_EMAIL):
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        msg = f"Subject: {subject}\n\n{message}"
        server.sendmail(EMAIL_USER, to_email, msg)
        server.quit()
    except Exception as e:
        logging.error(f"Email alert failed: {e}")

# --- PDF Report Generation ---
def generate_pdf_report(status, score):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=14)
    pdf.cell(200, 10, txt="Security Compliance Report", ln=1, align="C")
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Date: {datetime.now().isoformat()}", ln=2)
    pdf.cell(200, 10, txt=f"OS: {status['os']}", ln=3)
    pdf.cell(200, 10, txt=f"Update Status: {status['update_status']}", ln=4)
    pdf.cell(200, 10, txt=f"Antivirus: {', '.join(status['antivirus_status'])}", ln=5)
    pdf.cell(200, 10, txt=f"Firewall: {status['firewall_status']}", ln=6)
    pdf.cell(200, 10, txt=f"Score: {score}/100", ln=7)
    pdf.output("security_report.pdf")
    return "security_report.pdf"

# --- Real-Time Log Monitoring ---
def monitor_logs():
    log_path = "/var/log/auth.log"
    if not os.path.exists(log_path):
        return
    logging.info("Starting log monitoring thread.")
    with open(log_path, "r") as log:
        log.seek(0, os.SEEK_END)
        while True:
            line = log.readline()
            if not line:
                time.sleep(1)
                continue
            if "Failed password" in line or "authentication failure" in line:
                logging.warning(f"Security alert: {line.strip()}")
                socketio.emit('security_alert', {'message': line.strip()})
                send_alert("Security Alert", f"Suspicious login attempt detected:\n{line.strip()}")
                log_incident("Login Failure", line.strip())
if platform.system() == "Linux":
    threading.Thread(target=monitor_logs, daemon=True).start()

# --- Real-Time Network Monitoring ---
def monitor_network():
    prev = psutil.net_io_counters()
    while True:
        time.sleep(1)
        curr = psutil.net_io_counters()
        sent = curr.bytes_sent - prev.bytes_sent
        recv = curr.bytes_recv - prev.bytes_recv
        socketio.emit('network_stats', {'sent': sent, 'recv': recv})
        prev = curr
threading.Thread(target=monitor_network, daemon=True).start()

# --- Top Network Connections with Geolocation and Threat Intelligence ---
def get_top_connections_with_geo(limit=5):
    conns = psutil.net_connections(kind='inet')
    counter = {}
    for c in conns:
        if c.raddr:
            ip = c.raddr.ip
            counter[ip] = counter.get(ip, 0) + 1
    top = sorted(counter.items(), key=lambda x: x[1], reverse=True)[:limit]
    enriched = []
    for ip, count in top:
        geo = get_geolocation(ip)
        abuse_score = check_ip_reputation(ip)
        enriched.append((ip, count, geo, abuse_score))
    return enriched

# --- Main Dashboard Route ---
@app.route('/', methods=['GET', 'POST'])
@auth.login_required
def security_dashboard():
    # Dropdown for number of IPs to show
    num_ips = int(request.form.get('num_ips', 5))
    conn_scores = get_top_connections_with_geo(num_ips)

    system_status = {
        "os": platform.system(),
        "update_status": check_updates(),
        "antivirus_status": check_antivirus(),
        "firewall_status": check_firewall(),
        "security_headers": check_security_headers(),
        "browser_security": check_browser_security()
    }
    score = calculate_security_score(system_status)
    log_check_results(system_status, score)
    history = get_historical_checks()
    incidents = get_incidents()
    logins = get_login_attempts()

    if score < 60:
        send_alert("Security Alert", f"Security score is low: {score}/100\nDetails: {system_status}")

    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Dashboard</title>
        <meta http-equiv="refresh" content="60">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
    </head>
    <body>
    <div class="container mt-4">
        <!-- Real-time Network Monitoring -->
        <div id="network-monitor" class="mb-3"></div>
        <div class="card">
            <div class="card-header bg-primary text-white">
                Security Dashboard
            </div>
            <div class="card-body">
                <h5 class="card-title">System Security Status</h5>
                <p><strong>Operating System:</strong> {{ system_status.os }}</p>
                <p>
                  <strong>System Updates:</strong>
                  <span class="{% if 'up to date' in system_status.update_status.lower() %}text-success{% elif 'update' in system_status.update_status.lower() %}text-danger{% endif %}">
                    {{ system_status.update_status }}
                  </span>
                </p>
                <p><strong>Antivirus Protection:</strong>
                    <ul>
                        {% for av in system_status.antivirus_status %}
                            <li>
                              <span class="{% if 'up-to-date' in av.lower() or 'up_to_date' in av.lower() %}text-success{% elif 'disabled' in av.lower() or 'false' in av.lower() %}text-danger{% endif %}">
                                {{ av }}
                              </span>
                            </li>
                        {% endfor %}
                    </ul>
                </p>
                <p>
                  <strong>Firewall Status:</strong>
                  <span class="{% if system_status.firewall_status == 'Disabled' %}text-danger{% elif system_status.firewall_status == 'Enabled' %}text-success{% endif %}">
                    {{ system_status.firewall_status }}
                  </span>
                </p>
                <p><strong>Browser Security:</strong> {{ system_status.browser_security }}</p>
                <h5>Security Headers (google.com):</h5>
                <table class="table table-bordered">
                    <thead>
                        <tr>
                            <th>Header</th>
                            <th>Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for key, value in system_status.security_headers.items() %}
                        <tr>
                            <td data-bs-toggle="tooltip" title="See Mozilla docs for details">{{ key }}</td>
                            <td>
                              <span class="{% if value is not none %}text-success{% else %}text-danger{% endif %}">
                                {{ value or 'Not present' }}
                              </span>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                <h5>Security Score: <span class="badge bg-success">{{ score }}/100</span></h5>
                <a href="/report" class="btn btn-secondary">Download PDF Report</a>
                <hr>
                <h5>File Upload & VirusTotal Scan</h5>
                <form action="/scan" method="post" enctype="multipart/form-data">
                    <div class="mb-3">
                        <input type="file" name="file" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-warning">Scan File</button>
                </form>
                {% with messages = get_flashed_messages() %}
                  {% if messages %}
                    <ul class="mt-2">
                      {% for message in messages %}
                        <li>{{ message }}</li>
                      {% endfor %}
                    </ul>
                  {% endif %}
                {% endwith %}
                <div id="alerts"></div>
            </div>
        </div>
        <div class="card mt-4">
            <div class="card-header bg-info text-white">
                Historical Checks (Last 10)
            </div>
            <div class="card-body">
                <table class="table table-sm">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>OS</th>
                            <th>Updates</th>
                            <th>Antivirus</th>
                            <th>Firewall</th>
                            <th>Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for row in history %}
                        <tr>
                            <td>{{ row[0] }}</td>
                            <td>{{ row[1] }}</td>
                            <td>
                              <span class="{% if 'up to date' in row[2].lower() %}text-success{% elif 'update' in row[2].lower() %}text-danger{% endif %}">
                                {{ row[2] }}
                              </span>
                            </td>
                            <td>
                              <span class="{% if 'up-to-date' in row[3].lower() or 'up_to_date' in row[3].lower() %}text-success{% elif 'disabled' in row[3].lower() or 'false' in row[3].lower() %}text-danger{% endif %}">
                                {{ row[3] }}
                              </span>
                            </td>
                            <td>
                              <span class="{% if row[4] == 'Disabled' %}text-danger{% elif row[4] == 'Enabled' %}text-success{% endif %}">
                                {{ row[4] }}
                              </span>
                            </td>
                            <td>{{ row[5] }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Incidents -->
        <div class="card mt-4">
            <div class="card-header bg-danger text-white">
                Security Incidents (Last 20)
            </div>
            <div class="card-body">
                <table class="table table-sm">
                    <thead>
                        <tr><th>ID</th><th>Date</th><th>Type</th><th>Description</th><th>Status</th></tr>
                    </thead>
                    <tbody>
                        {% for inc in incidents %}
                        <tr>
                            <td>{{ inc[0] }}</td>
                            <td>{{ inc[1] }}</td>
                            <td>{{ inc[2] }}</td>
                            <td>{{ inc[3] }}</td>
                            <td>{{ inc[4] }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Login Attempts -->
        <div class="card mt-4">
            <div class="card-header bg-secondary text-white">
                Login Attempts (Last 20)
            </div>
            <div class="card-body">
                <table class="table table-sm">
                    <thead>
                        <tr><th>Date/Time</th><th>Username</th><th>Success</th></tr>
                    </thead>
                    <tbody>
                        {% for login in logins %}
                        <tr>
                            <td>{{ login[1] }}</td>
                            <td>{{ login[2] }}</td>
                            <td>
                                <span class="{% if login[3] %}text-success{% else %}text-danger{% endif %}">
                                    {{ 'Yes' if login[3] else 'No' }}
                                </span>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Top Network Connections with Geolocation -->
        <div class="card mt-4">
            <div class="card-header bg-warning text-dark">
                Top Network Connections (by remote IP)
            </div>
            <div class="card-body">
                <form method="post" class="mb-2">
                    <label for="num_ips"><strong>Show top:</strong></label>
                    <select name="num_ips" id="num_ips" onchange="this.form.submit()">
                        {% for n in [5,10,15,20] %}
                            <option value="{{n}}" {% if num_ips == n %}selected{% endif %}>{{n}}</option>
                        {% endfor %}
                    </select>
                    <span>remote IPs</span>
                </form>
                <table class="table table-sm">
                    <thead>
                        <tr>
                            <th>Remote IP</th>
                            <th>Connections</th>
                            <th>Location</th>
                            <th>Country</th>
                            <th>Coordinates</th>
                            <th>AbuseIPDB Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for ip, count, geo, abuse_score in conn_scores %}
                        <tr>
                            <td>{{ ip }}</td>
                            <td>{{ count }}</td>
                            <td>{{ geo.city }}, {{ geo.region }}</td>
                            <td>{{ geo.country }}</td>
                            <td>
                                {% if geo.latitude and geo.longitude %}
                                    {{ geo.latitude }}, {{ geo.longitude }}
                                {% else %}
                                    N/A
                                {% endif %}
                            </td>
                            <td>
                              <span class="{% if abuse_score is not none and abuse_score >= 50 %}text-danger{% elif abuse_score is not none and abuse_score > 0 %}text-warning{% elif abuse_score == 0 %}text-success{% else %}text-muted{% endif %}">
                                {{ abuse_score if abuse_score is not none else 'N/A' }}
                              </span>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    var socket = io();
    // Real-time network stats at top of page
    socket.on('network_stats', function(data) {
        let sentColor = data.sent > 1000000 ? 'red' : 'green';  // >1MB/s
        let recvColor = data.recv > 1000000 ? 'red' : 'green';
        document.getElementById('network-monitor').innerHTML =
            `<b>Network Sent:</b> <span style="color:${sentColor}">${(data.sent/1024).toFixed(1)} KB/s</span> | 
             <b>Received:</b> <span style="color:${recvColor}">${(data.recv/1024).toFixed(1)} KB/s</span>`;
    });
    // Real-time security alerts
    socket.on('security_alert', function(data) {
        var alerts = document.getElementById('alerts');
        var alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-danger mt-3';
        alertDiv.innerText = "Security Alert: " + data.message;
        alerts.appendChild(alertDiv);
    });
    </script>
    </body>
    </html>
    ''',
    system_status=system_status,
    score=score,
    history=history,
    incidents=incidents,
    logins=logins,
    conn_scores=conn_scores,
    num_ips=num_ips)

# --- File Upload & VirusTotal Scan Route ---
@app.route('/scan', methods=['POST'])
@auth.login_required
def scan_file():
    if 'file' not in request.files:
        flash("No file part in request.")
        return redirect(url_for('security_dashboard'))
    file = request.files['file']
    if file.filename == '':
        flash("No selected file.")
        return redirect(url_for('security_dashboard'))
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    try:
        with open(filepath, "rb") as f:
            file_bytes = f.read()
            file_hash = hashlib.sha256(file_bytes).hexdigest()
        vt_result = check_file_hash(file_hash)
        flash(f"SHA256: {file_hash}")
        if "error" in vt_result:
            flash(f"VirusTotal error: {vt_result['error']}")
        else:
            positives = vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            flash(f"VirusTotal scan: {positives}")
    except Exception as e:
        logging.error(f"File scan failed: {e}")
        flash(f"File scan failed: {str(e)}")
    finally:
        os.remove(filepath)
    return redirect(url_for('security_dashboard'))

# --- PDF Report Download Route ---
@app.route('/report')
@auth.login_required
def download_report():
    system_status = {
        "os": platform.system(),
        "update_status": check_updates(),
        "antivirus_status": check_antivirus(),
        "firewall_status": check_firewall(),
        "security_headers": check_security_headers(),
        "browser_security": check_browser_security()
    }
    score = calculate_security_score(system_status)
    pdf_path = generate_pdf_report(system_status, score)
    return send_file(pdf_path, as_attachment=True)

# --- REST API Endpoints ---
@app.route('/api/status')
@auth.login_required
def api_status():
    system_status = {
        "os": platform.system(),
        "update_status": check_updates(),
        "antivirus_status": check_antivirus(),
        "firewall_status": check_firewall(),
        "security_headers": check_security_headers(),
        "browser_security": check_browser_security()
    }
    score = calculate_security_score(system_status)
    return jsonify({"status": system_status, "score": score})

@app.route('/api/incidents')
@auth.login_required
def api_incidents():
    return jsonify({"incidents": get_incidents()})

@app.route('/api/logins')
@auth.login_required
def api_logins():
    return jsonify({"logins": get_login_attempts()})

@app.route('/api/top_connections')
@auth.login_required
def api_top_connections():
    num_ips = int(request.args.get('num_ips', 5))
    return jsonify({"top_connections": get_top_connections_with_geo(num_ips)})

# --- Run the App ---
if __name__ == '__main__':
    socketio.run(app, debug=True)
