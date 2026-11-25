from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import re
import socket
import ssl
from urllib.parse import urlparse
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "High",
        "weight": 20,
        "description": "Enforces secure (HTTPS) connections to the server.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
    },
    "Content-Security-Policy": {
        "severity": "High",
        "weight": 20,
        "description": "Helps prevent Cross-Site Scripting (XSS) and data injection attacks.",
        "remediation": "Define a strong Content-Security-Policy restricting trusted script and content sources.",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "weight": 15,
        "description": "Protects against Clickjacking attacks by controlling iframe embedding.",
        "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "weight": 10,
        "description": "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
        "remediation": "Set 'X-Content-Type-Options: nosniff'.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "weight": 5,
        "description": "Controls how much referrer information is included with requests.",
        "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "weight": 5,
        "description": "Controls which browser features and APIs can be used in the browser.",
        "remediation": "Configure Permissions-Policy to disable unused features like camera or microphone.",
    },
}

COMMON_PORTS = {
    21: ("FTP", "High", 15, "Unencrypted file transfer protocol exposed."),
    22: ("SSH", "Low", 5, "Secure Shell exposed; ensure strong authentication."),
    23: ("Telnet", "Critical", 25, "Unencrypted remote login protocol; highly insecure."),
    25: ("SMTP", "Medium", 10, "Mail server port exposed."),
    80: ("HTTP", "Low", 5, "Unencrypted web traffic port open."),
    443: ("HTTPS", "Info", 0, "Encrypted web traffic port open."),
    3306: ("MySQL", "High", 20, "Database port publicly accessible."),
    3389: ("RDP", "High", 20, "Remote Desktop Protocol exposed to internet."),
    8080: ("HTTP-Proxy", "Low", 5, "Alternative HTTP port open."),
}

DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9.-]+$")


def normalize_url(raw_url):
    cleaned = raw_url.strip()
    if not cleaned:
        raise ValueError("Target URL cannot be empty.")

    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned

    parsed = urlparse(cleaned)
    hostname = parsed.hostname

    if not hostname or not DOMAIN_PATTERN.match(hostname):
        raise ValueError("Please enter a valid domain name or URL (e.g., example.com).")

    return cleaned, hostname


def check_http_headers(url):
    findings = []
    penalty = 0
    server_banner = "Hidden"
    status_code = None

    headers_request = {
        "User-Agent": "Mozilla/5.0 (compatible; WebSecAssess/1.0)"
    }

    try:
        response = requests.get(url, headers=headers_request, timeout=8, allow_redirects=True)
        status_code = response.status_code
        resp_headers = response.headers

        if "Server" in resp_headers:
            server_banner = resp_headers["Server"]
            findings.append(
                {
                    "category": "Information Disclosure",
                    "issue": f"Server Banner Exposed ({server_banner})",
                    "severity": "Warning",
                    "status": "Warning",
                    "remediation": "Configure web server to suppress version details in the 'Server' header.",
                }
            )
            penalty += 5

        for header, meta in SECURITY_HEADERS.items():
            if header not in resp_headers:
                findings.append(
                    {
                        "category": "HTTP Security Header",
                        "issue": f"Missing {header}",
                        "severity": meta["severity"],
                        "status": "Vulnerable",
                        "remediation": meta["remediation"],
                    }
                )
                penalty += meta["weight"]
            else:
                findings.append(
                    {
                        "category": "HTTP Security Header",
                        "issue": f"{header} Present",
                        "severity": "Pass",
                        "status": "Secure",
                        "remediation": f"Configured value: {resp_headers[header][:80]}",
                    }
                )

    except requests.RequestException as exc:
        findings.append(
            {
                "category": "Connection",
                "issue": f"Failed to fetch HTTP headers: {exc}",
                "severity": "Error",
                "status": "Error",
                "remediation": "Verify the target URL is reachable and online.",
            }
        )
        penalty += 20

    return {
        "status_code": status_code,
        "server_banner": server_banner,
        "findings": findings,
        "penalty": penalty,
    }


def check_ssl_certificate(domain):
    ssl_info = {
        "valid": False,
        "issuer": "N/A",
        "expiry_date": "N/A",
        "days_remaining": 0,
        "protocol": "N/A",
        "severity": "High",
        "message": "",
        "penalty": 0,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_info["protocol"] = ssock.version() or "TLS"

                issuer_dict = {}
                for item in cert.get("issuer", []):
                    for k, v in item:
                        issuer_dict[k] = v
                ssl_info["issuer"] = issuer_dict.get(
                    "organizationName",
                    issuer_dict.get("commonName", "Unknown CA"),
                )

                not_after = cert.get("notAfter")
                if not not_after:
                    raise ValueError("Missing certificate expiration field.")

                expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                now_utc = datetime.now(timezone.utc)
                days_left = (expiry_dt - now_utc).days

                ssl_info["expiry_date"] = expiry_dt.strftime("%Y-%m-%d")
                ssl_info["days_remaining"] = days_left

                if days_left < 0:
                    ssl_info["message"] = "SSL Certificate has expired."
                    ssl_info["severity"] = "Critical"
                    ssl_info["penalty"] = 30
                elif days_left < 15:
                    ssl_info["valid"] = True
                    ssl_info["message"] = f"SSL Certificate expiring soon ({days_left} days left)."
                    ssl_info["severity"] = "Medium"
                    ssl_info["penalty"] = 10
                else:
                    ssl_info["valid"] = True
                    ssl_info["message"] = "Valid SSL/TLS certificate configured."
                    ssl_info["severity"] = "Pass"
                    ssl_info["penalty"] = 0

    except ssl.SSLCertVerificationError as exc:
        ssl_info["message"] = f"Certificate verification failed: {exc}"
        ssl_info["severity"] = "Critical"
        ssl_info["penalty"] = 30
    except Exception as exc:
        ssl_info["message"] = f"HTTPS/SSL not supported or unreachable: {exc}"
        ssl_info["severity"] = "High"
        ssl_info["penalty"] = 25

    return ssl_info


def _probe_single_port(ip_address, port, meta):
    service, severity, weight, note = meta
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.8)
        if sock.connect_ex((ip_address, port)) == 0:
            return {
                "port": port,
                "service": service,
                "severity": severity,
                "weight": weight,
                "note": note,
            }
    return None


def scan_ports(domain):
    open_ports = []
    penalty = 0

    try:
        ip_address = socket.gethostbyname(domain)
    except socket.gaierror:
        return {"ip_address": "Unresolved", "open_ports": [], "penalty": 0}

    with ThreadPoolExecutor(max_workers=9) as executor:
        futures = [
            executor.submit(_probe_single_port, ip_address, port, meta)
            for port, meta in COMMON_PORTS.items()
        ]
        for future in as_completed(futures):
            result = future.result()
            if result:
                penalty += result.pop("weight")
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])

    return {
        "ip_address": ip_address,
        "open_ports": open_ports,
        "penalty": penalty,
    }


def run_full_assessment(raw_url):
    target_url, domain = normalize_url(raw_url)

    header_results = check_http_headers(target_url)
    ssl_results = check_ssl_certificate(domain)
    port_results = scan_ports(domain)

    total_risk = min(
        100,
        header_results["penalty"] + ssl_results["penalty"] + port_results["penalty"],
    )

    if total_risk >= 70:
        risk_level = "Critical"
    elif total_risk >= 45:
        risk_level = "High"
    elif total_risk >= 20:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "target_url": target_url,
        "domain": domain,
        "ip_address": port_results["ip_address"],
        "status_code": header_results["status_code"],
        "server_banner": header_results["server_banner"],
        "risk_score": total_risk,
        "risk_level": risk_level,
        "headers": header_results["findings"],
        "ssl": ssl_results,
        "ports": port_results["open_ports"],
    }