Fire Security Dashboard
A real-time, cross-platform security dashboard that monitors system health, network activity (with geolocation), threat intelligence, and user login events, providing actionable insights and compliance reports.

Features
System Security Monitoring: Tracks OS updates, antivirus, and firewall status (Windows and Linux).

Real-Time Network Monitoring: Displays live network throughput and top remote IP connections, including geolocation and threat reputation.

Threat Intelligence: Integrates with AbuseIPDB to check remote IP reputation.

File Upload & VirusTotal Scan: Scan uploaded files against VirusTotal for malware detection.

User Login Tracking: Logs and displays all login attempts with timestamps and success/failure status.

Incident Management: Records and displays security incidents (e.g., failed logins).

Historical Checks: View recent security status checks.

PDF Compliance Reports: Generate and download detailed security reports.

Role-Based Access Control: Supports admin and user roles.

REST API: Access system status, incidents, logins, and top connections programmatically.

Color-Coded UI: Visual cues for security status and alerts.

Real-Time Alerts: Live notifications for suspicious activity.


Requirements
Python 3.7+

Linux or Windows

ClamAV and ufw (Linux, for AV/firewall checks)

windows-tools (Windows, for AV checks)

Python packages:

bash
pip install flask flask-socketio psutil requests fpdf flask_httpauth eventlet
# On Windows, also:
pip install windows-tools
Environment Variables
Set the following environment variables for secure operation:

Variable	Description
ADMIN_USER	Admin username
ADMIN_PASS	Admin password
USER_USER	Regular user username
USER_PASS	Regular user password
ALERT_EMAIL	Email for receiving alerts
EMAIL_USER	SMTP sender email address
EMAIL_PASS	SMTP sender email password
VIRUSTOTAL_API_KEY	VirusTotal API key
ABUSEIPDB_API_KEY	AbuseIPDB API key
SECRET_KEY	Flask session secret key

Set environment variables (see above).

Run the application:

bash
python app.py
Access the dashboard at http://localhost:5000 in your browser.

REST API Endpoints
/api/status - System security status and score

/api/incidents - Recent security incidents

/api/logins - Recent login attempts

/api/top_connections?num_ips=10 - Top remote IP connections (with geolocation and threat score)

Security Notes
Use HTTPS in production.

For best performance, consider caching geolocation and threat lookups.

License
MIT License

Acknowledgments
ipapi.co for geolocation data

AbuseIPDB for threat intelligence

VirusTotal for malware scanning

Questions or suggestions?
Open an issue or submit a pull request!
