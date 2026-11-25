# Web Security Scanner

A Python and Flask web application for reviewing common web security
misconfigurations on websites you own or are authorized to assess. It checks
HTTP security headers, inspects SSL/TLS certificates, probes a short list of
common TCP ports, and presents the findings in a risk-scored report.

## Features

- **HTTP security headers:** Checks for Strict-Transport-Security,
  Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, and Permissions-Policy.
- **Server banner disclosure:** Reports when the target's HTTP response exposes
  a `Server` header.
- **SSL/TLS certificate review:** Connects over HTTPS and reports certificate
  validity, issuer, negotiated TLS protocol, expiration date, and days remaining.
- **Common TCP port checks:** Resolves the target hostname and checks ports
  21, 22, 23, 25, 80, 443, 3306, 3389, and 8080 concurrently.
- **Risk scoring:** Combines weighted findings into a score from 0 to 100 and
  assigns a Low, Medium, High, or Critical risk level.
- **Assessment history:** Saves reports in a local SQLite database so you can
  review or delete previous scans.
- **Report exports:** Download an assessment as JSON or CSV.
- **Web interface:** Enter a domain or URL, review recent assessments, and open
  detailed reports in a browser.

## Project structure

```text
.
├── backend/
│   ├── app.py          # Flask routes and application entry point
│   ├── database.py     # SQLite persistence for scan history
│   └── scanner.py      # HTTP, TLS, port checks, and risk scoring
├── frontend/
│   ├── static/
│   │   └── style.css   # Application styles
│   └── templates/
│       ├── index.html  # Scan form and assessment history
│       └── report.html # Detailed assessment report
├── requirements.txt
└── README.md
```

The SQLite database is created automatically at `backend/scanner.db` the first
time the application starts. It is local runtime data and is excluded from Git.

## Requirements

- Python 3.8 or newer
- pip
- Internet access from the machine running the scanner

## Installation

Clone the repository and move into the project directory:

```bash
git clone https://github.com/pratikvalani/Web-Security-Scanner.git
cd Web-Security-Scanner
```

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**macOS / Linux:**

```bash
python3 -m venv venv
source venv/bin/activate
```

Install the required packages:

```bash
python -m pip install -r requirements.txt
```

## Run the application

From the project root, start Flask:

```bash
python -m backend.app
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.
Stop the server with `Ctrl+C`.

## Use

1. Enter a domain (for example, `example.com`) or a full `http://` or `https://`
   URL.
2. Select **Run Assessment** and wait for the checks to finish.
3. Review the risk score, HTTP header findings, SSL/TLS details, and detected
   common open ports.
4. Use the report page to download JSON or CSV, or return to the home page to
   view or delete saved assessment history.

The scanner follows HTTP redirects when checking headers. TLS certificate
inspection and port checks use the hostname derived from the submitted URL.
Port results are limited to the ports listed above; they are not a complete
network inventory.

## Risk score

The application adds the configured weights for missing security headers,
certificate issues, server banner disclosure, and detected ports. The total is
capped at 100 and classified as follows:

| Score | Risk level |
| --- | --- |
| 0–19 | Low |
| 20–44 | Medium |
| 45–69 | High |
| 70–100 | Critical |

This score is an informational summary of the checks implemented by this
project; it is not a substitute for a full security assessment.

## Safety and limitations

- Only scan systems that you own or have explicit permission to assess.
- The scanner makes outbound HTTP(S) requests and TCP connection attempts to
  the target. Port checks are limited to the common ports listed above.
- Results can be affected by firewalls, rate limits, DNS, proxies, and transient
  network errors. A check that cannot connect does not prove a service is safe.
- This project is intended for local development and authorized testing. The
  Flask development server is not intended for public production deployment.

## Dependencies

Runtime dependencies are listed in [`requirements.txt`](requirements.txt):

- Flask
- Requests

## License

No license file is currently included. Contact the repository owner for
permission before redistributing or reusing this project.
