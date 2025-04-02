#Blocks bad IPs with ufw and crowdsec, emails the result
#Modify email, excluded IPs, log names and so on, below to your needs. Requires postfix

import re
from collections import defaultdict
import time
import os
import ipaddress
import glob
import smtplib
from email.mime.text import MIMEText
import socket
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/apache_monitor_script2.log'),
        logging.StreamHandler()
    ]
)

# Define patterns for identifying suspicious activities
USER_AGENTS = [
    'python', 'libwww', 'bot', 'spider', 'scraper', 'crawler',
    'bingbot', 'googlebot', 'yandexbot', 'slurp', 'baidu'
]
BLOCKED_PATHS = ['/wp-admin', '/xmlrpc.php', '/cgi-bin', '/admin']
HTTP_METHODS = ['TRACE', 'DELETE', 'CONNECT']  # Removed OPTIONS from blanket suspicion
MAX_REQUESTS_PER_MINUTE = 5000
LOG_FILE_PATTERNS = [
    '/var/log/apache2/access*.log',
    '/var/log/apache2/den-access-ssl.log',
    '/var/log/apache2/johan.log',
  
]
EMAIL_RECIPIENT = 'youremail@yourmail.com'
EMAIL_SENDER = f"{socket.gethostname()}@yourdomain.com"
SMTP_SERVER = 'localhost'
SMTP_PORT = 25

# Suspicious PHP prefixes to monitor
SUSPICIOUS_PHP_PREFIXES = [
    '.tmb', '.fk', '.alf',
    'wp-', 'phpinfo', 'admin', 'bypass', 'alfa',
]

# Updated attack patterns
SQL_INJECTION_PATTERNS = [
    re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE|OR|AND)\b.*['\"-]{2,})", re.I),
    re.compile(r"(\b1\s*=\s*1\b|['\"]\s*OR\s*['\"])", re.I),
    re.compile(r"(\bEXEC\s*\()|(xp_cmdshell)", re.I),
]
XSS_PATTERNS = [
    re.compile(r"(<script\b[^>]*>.*?</script>)", re.I),
    re.compile(r"(javascript:)", re.I),
    re.compile(r"(\bon\w+\s*=)", re.I),
]
COMMAND_INJECTION_PATTERNS = [
    re.compile(r"[;&|]\s*(nc|bash|sh|cmd|perl|wget|curl|whoami|id|cat|ls|dir)\b", re.I),
    re.compile(r"(`[^`]+`)", re.I),
    re.compile(r"\$\([^)]+\)", re.I),
]
DIR_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\%2F|\.\.\%5C)", re.I),
    re.compile(r"(\b/etc/passwd\b|\bwindows/win.ini\b)", re.I),
]

# Trusted IP ranges to exclude
EXCLUDED_SUBNETS = [
    ipaddress.ip_network('127.0.0.1/32'),
    ipaddress.ip_network('172.31.0.0/16'),
    ipaddress.ip_network('66.249.64.0/19'),
    ipaddress.ip_network('64.233.160.0/19'),
    ipaddress.ip_network('40.77.167.0/24'),
    ipaddress.ip_network('207.46.13.0/24'),
    ipaddress.ip_network('157.55.39.0/24'),
    ipaddress.ip_network('52.167.144.0/24'),
    ipaddress.ip_network('54.36.96.140/32'),
    ipaddress.ip_network('5.255.231.0/24'),
    ipaddress.ip_network('213.180.203.0/24'),
    ipaddress.ip_network('77.75.76.0/23'),
    ipaddress.ip_network('17.0.0.0/8'),
    ipaddress.ip_network('141.95.169.192/32'),
    ipaddress.ip_network('52.18.199.206/32'),
    ipaddress.ip_network('146.6.161.103/32'),
    ipaddress.ip_network('52.209.191.79/32'),
    ipaddress.ip_network('213.175.93.181/32'),
    ipaddress.ip_network('193.10.22.0/24'),
]

WHITELISTED_IPS = ['193.10.248.66', '146.6.161.104', '89.45.236.228', '192.168.250.41']

# Store counts and state
ip_requests = defaultdict(list)
user_agents = defaultdict(int)
path_requests = defaultdict(int)
error_codes = defaultdict(int)
attack_patterns = defaultdict(int)
method_counts = defaultdict(int)
suspicious_php_requests = defaultdict(list)
suspicious_findings = []
ips_to_block = {}
file_positions = {}  # Track file positions for continuous monitoring
reported_findings = set()  # Avoid duplicate reports

def is_excluded(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for subnet in EXCLUDED_SUBNETS:
            if ip_obj in subnet:
                return True
    except ValueError:
        return False
    return False

def is_whitelisted(ip):
    return ip in WHITELISTED_IPS

def parse_log_line(line):
    try:
        parts = line.split(' ')
        ip = parts[0]
        method = parts[5][1:]
        url_path = parts[6]
        response_code = parts[8]
        user_agent = ' '.join(parts[11:]).strip('"')  # Fixed typo: ' quels' to ' '
        return ip, method, url_path, response_code, user_agent
    except IndexError:
        logging.error(f"Failed to parse log line: {line}")
        return None, None, None, None, None

def block_ip(ip, reason):
    ufw_cmd = f"ufw insert 1 deny from {ip}"
    try:
        result = subprocess.run(ufw_cmd, shell=True, check=True, capture_output=True, text=True)
        logging.info(f"Blocked {ip} with ufw: {result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block {ip} with ufw: {e.stderr}")

    cscli_cmd = f"cscli decisions add --ip {ip} --reason \"{reason}\" --duration 777h"
    try:
        result = subprocess.run(cscli_cmd, shell=True, check=True, capture_output=True, text=True)
        logging.info(f"Blocked {ip} with CrowdSec: {result.stdout}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block {ip} with CrowdSec: {e.stderr}")

def block_suspicious_ips():
    for ip, reason in ips_to_block.items():
        block_ip(ip, reason)

def is_suspicious_php(url_path):
    if not url_path.endswith('.php'):
        return False
    for prefix in SUSPICIOUS_PHP_PREFIXES:
        if prefix in url_path:
            return True
    return False

def check_attack_patterns(ip, url_path):
    if url_path.startswith(('/matomo.php', '/piwik.php')):
        for pattern in COMMAND_INJECTION_PATTERNS:
            if pattern.search(url_path):
                match = pattern.search(url_path).group(0)
                finding = f"[Command Injection Attempt] IP: {ip} - URL: {url_path} (Matched: {match})"
                if finding not in reported_findings:
                    suspicious_findings.append(finding)
                    attack_patterns[ip] += 1
                    ips_to_block[ip] = "Command Injection Attempt"
                return
        return

    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(url_path):
            finding = f"[SQL Injection Attempt] IP: {ip} - URL: {url_path}"
            if finding not in reported_findings:
                suspicious_findings.append(finding)
                attack_patterns[ip] += 1
                ips_to_block[ip] = "SQL Injection Attempt"
            return
    for pattern in XSS_PATTERNS:
        if pattern.search(url_path):
            finding = f"[XSS Attempt] IP: {ip} - URL: {url_path}"
            if finding not in reported_findings:
                suspicious_findings.append(finding)
                attack_patterns[ip] += 1
                ips_to_block[ip] = "XSS Attempt"
            return
    for pattern in COMMAND_INJECTION_PATTERNS:
        if pattern.search(url_path):
            match = pattern.search(url_path).group(0)
            finding = f"[Command Injection Attempt] IP: {ip} - URL: {url_path} (Matched: {match})"
            if finding not in reported_findings:
                suspicious_findings.append(finding)
                attack_patterns[ip] += 1
                ips_to_block[ip] = "Command Injection Attempt"
            return
    for pattern in DIR_TRAVERSAL_PATTERNS:
        if pattern.search(url_path):
            finding = f"[Directory Traversal Attempt] IP: {ip} - URL: {url_path}"
            if finding not in reported_findings:
                suspicious_findings.append(finding)
                attack_patterns[ip] += 1
                ips_to_block[ip] = "Directory Traversal Attempt"
            return

def analyze_log_lines(log_file):
    if not os.path.exists(log_file):
        logging.warning(f"Log file {log_file} not found!")
        return

    if log_file not in file_positions:
        file_positions[log_file] = 0

    try:
        with open(log_file, 'r') as file:
            file.seek(file_positions[log_file])
            lines = file.readlines()
            if not lines:
                return

            logging.info(f"Analyzing {len(lines)} new lines in {log_file}")
            for line in lines:
                line = line.strip()
                ip, method, url_path, response_code, user_agent = parse_log_line(line)
                if ip is None or is_excluded(ip) or is_whitelisted(ip) or "internal dummy connection" in user_agent.lower():
                    continue
                ip_requests[ip].append(time.time())
                if any(bot in user_agent.lower() for bot in USER_AGENTS):
                    user_agents[ip] += 1
                if any(path in url_path for path in BLOCKED_PATHS):
                    path_requests[ip] += 1
                method_counts[ip] += 1 if method in HTTP_METHODS + ['OPTIONS'] else 0
                if method in HTTP_METHODS:
                    finding = f"[Suspicious] IP: {ip} used HTTP method: {method}"
                    if finding not in reported_findings:
                        suspicious_findings.append(finding)
                        ips_to_block[ip] = f"Suspicious HTTP Method: {method}"
                if method == 'OPTIONS' and method_counts[ip] > 10:
                    finding = f"[Suspicious] IP: {ip} used HTTP method OPTIONS excessively ({method_counts[ip]} times)"
                    if finding not in reported_findings:
                        suspicious_findings.append(finding)
                        ips_to_block[ip] = "Excessive OPTIONS Usage"
                if response_code in ['404', '500']:
                    error_codes[ip] += 1
                if is_suspicious_php(url_path) and response_code == '403':
                    suspicious_php_requests[ip].append(time.time())
                check_attack_patterns(ip, url_path)

            file_positions[log_file] = file.tell()
    except Exception as e:
        logging.error(f"Error analyzing {log_file}: {e}")

def identify_rate_limit_violations():
    for ip, timestamps in ip_requests.items():
        timestamps = [ts for ts in timestamps if ts > time.time() - 60]
        if len(timestamps) > MAX_REQUESTS_PER_MINUTE:
            finding = f"[Rate Limit Violation] IP {ip} made more than {MAX_REQUESTS_PER_MINUTE} requests per minute"
            if finding not in reported_findings:
                suspicious_findings.append(finding)
                ips_to_block[ip] = "Rate Limit Violation"

def identify_user_agent_violations():
    for ip, count in user_agents.items():
        if count > 90:
            finding = f"[Suspicious User-Agent] IP {ip} has suspicious user-agent usage ({count} hits)"
            if finding not in reported_findings:
                suspicious_findings.append(finding)
                ips_to_block[ip] = "Suspicious User-Agent"

def identify_error_code_violations():
    for ip, count in error_codes.items():
        if count > 50:
            finding = f"[Error Code Violation] IP {ip} generated more than 50 errors (404/500) ({count} hits)"
            if finding not in reported_findings:
                suspicious_findings.append(finding)
                ips_to_block[ip] = "Error Code Violation"

def identify_suspicious_paths():
    for ip, count in path_requests.items():
        if count > 20:
            finding = f"[Suspicious Path Access] IP {ip} accessed suspicious paths multiple times ({count} hits)"
            if finding not in reported_findings:
                suspicious_findings.append(finding)
                ips_to_block[ip] = "Suspicious Path Access"

def identify_attack_patterns():
    for ip, count in attack_patterns.items():
        if count > 1:
            finding = f"[Multiple Attack Attempts] IP {ip} triggered attack patterns ({count} hits)"
            if finding not in reported_findings:
                suspicious_findings.append(finding)

def identify_suspicious_php_violations():
    for ip, timestamps in suspicious_php_requests.items():
        recent_timestamps = [ts for ts in timestamps if ts > time.time() - 60]
        if len(recent_timestamps) >= 5:
            finding = f"[Suspicious PHP Requests] IP {ip} made {len(recent_timestamps)} requests to suspicious PHP files (403 errors) in the last minute"
            if finding not in reported_findings:
                suspicious_findings.append(finding)
                ips_to_block[ip] = "Suspicious PHP Requests"

def send_email(subject, body):
    with open('/var/log/suspicious_activity_script2.log', 'a') as f:
        f.write(f"{subject}\n{body}\n\n")
    logging.info("Logged findings to /var/log/suspicious_activity_script2.log")

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECIPIENT
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.sendmail(EMAIL_SENDER, EMAIL_RECIPIENT, msg.as_string())
        logging.info(f"Email sent to {EMAIL_RECIPIENT} from {EMAIL_SENDER}")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

def process_findings(log_files):
    identify_rate_limit_violations()
    identify_user_agent_violations()
    identify_error_code_violations()
    identify_suspicious_paths()
    identify_attack_patterns()
    identify_suspicious_php_violations()

    if suspicious_findings:
        block_suspicious_ips()
        subject = "Suspicious Activity Detected in Apache Logs (Script 2)"
        body = "The following new suspicious activities were detected and blocked:\n\n"
        body += "\n".join(suspicious_findings)
        body += f"\n\nAnalyzed logs: {', '.join(log_files)}"
        body += f"\n\nWhitelisted IPs (ignored): {', '.join(WHITELISTED_IPS)}"
        body += f"\nBlocked IPs: {', '.join(ips_to_block.keys())}"
        body += f"\nTimestamp: {time.ctime()}"
        send_email(subject, body)
        reported_findings.update(suspicious_findings)
        suspicious_findings.clear()
        ips_to_block.clear()

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, log_files):
        self.log_files = log_files

    def on_modified(self, event):
        if not event.is_directory and event.src_path in self.log_files:
            logging.info(f"Detected modification in {event.src_path}")
            analyze_log_lines(event.src_path)
            process_findings(self.log_files)

def main():
    log_files = []
    for pattern in LOG_FILE_PATTERNS:
        log_files.extend(glob.glob(pattern))
    if not log_files:
        logging.error(f"No log files found matching patterns: {', '.join(LOG_FILE_PATTERNS)}!")
        return

    logging.info("Performing initial scan of existing logs")
    for log_file in log_files:
        if os.path.exists(log_file):
            analyze_log_lines(log_file)
    process_findings(log_files)

    try:
        event_handler = LogFileHandler(log_files)
        observer = Observer()
        observer.schedule(event_handler, path='/var/log/apache2', recursive=False)
        observer.start()
        logging.info("Starting continuous monitoring of Apache logs...")
    except Exception as e:
        logging.error(f"Failed to start watchdog observer: {e}")
        return

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Stopping monitoring...")
    observer.join()

if __name__ == "__main__":
    main()
