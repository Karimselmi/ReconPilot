# ReconPilot

> Modular reconnaissance toolkit for authorized security assessments and cybersecurity laboratories.

ReconPilot is a Python-based reconnaissance framework designed to automate, organize, and store common reconnaissance activities during authorized security assessments.

The project combines network discovery, DNS enumeration, subdomain discovery, HTTP reconnaissance, passive technology detection, SQLite-based scan storage, and HTML reporting into a single CLI-oriented workflow.

---

## Features

### Network Reconnaissance

* Nmap-based TCP service discovery
* Service and version detection
* Nmap XML output
* Structured Nmap result parsing
* Scan history through unique scan IDs

### DNS Reconnaissance

* A records
* AAAA records
* MX records
* NS records
* TXT records
* CNAME records

### Subdomain Enumeration

Built-in discovery of common subdomains such as:

* `www`
* `mail`
* `ftp`
* `dev`
* `test`
* `staging`
* `api`
* `admin`
* `portal`
* `vpn`
* `blog`
* `app`

### HTTP Reconnaissance

* HTTP/HTTPS probing
* HTTP status codes
* Page titles
* Server headers
* Redirect detection
* Response-time measurement
* Passive technology fingerprinting

### Technology Detection

ReconPilot can passively identify common technologies such as:

* WordPress
* React
* Next.js
* Vue.js
* Angular
* jQuery
* Bootstrap

### Scan Management

Each reconnaissance execution receives a unique scan ID.

This allows multiple assessments of the same target to be stored independently.

Example:

```text
Scan #1 → target.example
Scan #2 → target.example
Scan #3 → target.example
```

Historical scans can be listed and individual scan results can be retrieved.

### Reporting

* Rich terminal output
* SQLite persistence
* HTML report generation
* Structured reconnaissance data

---

## Architecture

```text
                         ReconPilot
                              │
                    ┌─────────┴─────────┐
                    │       CLI         │
                    └─────────┬─────────┘
                              │
                       Recon Pipeline
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
        Nmap                 DNS                HTTP
          │                   │                   │
          ▼                   ▼                   ▼
     XML Parser        Subdomains         Technology Detection
          │                   │                   │
          └───────────────────┼───────────────────┘
                              ▼
                        Scan / Session ID
                              │
                              ▼
                         SQLite Database
                              │
                    ┌─────────┴─────────┐
                    ▼                   ▼
              Terminal Output       HTML Report
```

---

## Project Structure

```text
reconpilot/
│
├── README.md
├── LICENSE
├── pyproject.toml
├── .gitignore
│
├── reconpilot/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── exceptions.py
│   ├── logger.py
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── engine.py
│   │   ├── pipeline.py
│   │   └── target.py
│   │
│   ├── database/
│   │   ├── __init__.py
│   │   ├── database.py
│   │   └── models.py
│   │
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── dns.py
│   │   ├── http.py
│   │   ├── ports.py
│   │   ├── subdomains.py
│   │   └── technology.py
│   │
│   ├── output/
│   │   ├── __init__.py
│   │   └── terminal.py
│   │
│   ├── parsers/
│   │   ├── __init__.py
│   │   └── nmap.py
│   │
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── html.py
│   │   └── templates/
│   │       └── report.html
│   │
│   └── utils/
│       ├── __init__.py
│       ├── commands.py
│       └── validation.py
│
└── tests/
    ├── test_database.py
    ├── test_nmap.py
    └── test_target.py
```

---

# Installation

## Requirements

* Python 3.10+
* Nmap
* Linux recommended
* Python virtual environment recommended

On Kali Linux:

```bash
sudo apt update
sudo apt install nmap python3 python3-venv
```

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/reconpilot.git
cd reconpilot
```

Create the virtual environment:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

If a `requirements.txt` file is not included in the current release, install the current dependencies with:

```bash
pip install typer rich pyyaml dnspython httpx jinja2 pytest
```

---

# Usage

Display the available commands:

```bash
python -m reconpilot.cli --help
```

Example:

```text
Usage: python -m reconpilot.cli [OPTIONS] COMMAND [ARGS]...

Commands:
  scan
  results
  dns
  subdomains
  http
  pipeline
  report
  scans
  version
```

---

## Target Validation

ReconPilot validates targets before reconnaissance begins.

Example:

```bash
python -m reconpilot.cli scan 192.0.2.10
```

or:

```bash
python -m reconpilot.cli scan example.test
```

Targets should only be systems for which you have explicit authorization.

---

# Complete Reconnaissance Pipeline

The pipeline combines the available reconnaissance modules.

```bash
python -m reconpilot.cli pipeline example.test
```

The pipeline performs the applicable reconnaissance stages:

```text
Target validation
       │
       ▼
     Nmap
       │
       ▼
   DNS records
       │
       ▼
   Subdomains
       │
       ▼
  HTTP / HTTPS
       │
       ▼
Technology detection
       │
       ▼
 SQLite storage
       │
       ▼
 Terminal summary
```

For IP targets, DNS and subdomain enumeration are skipped when they are not applicable.

---

# Viewing Results

Retrieve the latest stored reconnaissance results:

```bash
python -m reconpilot.cli results example.test
```

The results include information such as:

```text
Hosts
Ports
Services
DNS records
Subdomains
HTTP endpoints
Technologies
```

---

# Scan History

ReconPilot assigns a unique ID to every pipeline execution.

List stored scans:

```bash
python -m reconpilot.cli scans
```

Example:

```text
 ID   TARGET          TYPE      STATUS       STARTED              COMPLETED
 3    example.test    domain    completed    2026-09-08 15:20     2026-09-08 15:21
 2    example.test    domain    completed    2026-09-08 14:42     2026-09-08 14:43
 1    192.0.2.10      ip        completed    2026-09-08 13:15     2026-09-08 13:16
```

This allows repeated assessments of the same target to remain separated.

---

# HTML Reporting

Generate an HTML report from the latest stored scan:

```bash
python -m reconpilot.cli report example.test
```

Reports are stored under:

```text
results/
└── example.test/
    └── report_<scan_id>.html
```

The generated report contains sections for:

* Target information
* Network services
* DNS records
* Discovered subdomains
* HTTP services
* Technologies
* Response information

---

# Proof of Concept

The following PoC demonstrates ReconPilot against a **local intentionally controlled test environment**.

No third-party or unauthorized infrastructure is required.

## 1. Start a local HTTP server

Create a temporary directory:

```bash
mkdir -p /tmp/reconpilot-poc
cd /tmp/reconpilot-poc
```

Create a simple HTML page:

```bash
cat > index.html <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>ReconPilot PoC</title>
</head>
<body>
    <h1>ReconPilot Test Server</h1>
</body>
</html>
EOF
```

Start the server:

```bash
python3 -m http.server 8080
```

The server will listen locally on:

```text
127.0.0.1:8080
```

## 2. Run ReconPilot

From another terminal:

```bash
cd reconpilot
source .venv/bin/activate
```

Run the HTTP reconnaissance module:

```bash
python -m reconpilot.cli http 127.0.0.1
```

ReconPilot can identify the HTTP endpoint and collect information such as:

```text
URL
STATUS
TITLE
SERVER
REDIRECT
TIME
TECHNOLOGIES
```

## 3. Run the complete pipeline

For a controlled lab target:

```bash
python -m reconpilot.cli pipeline 127.0.0.1
```

The resulting scan is stored in SQLite and assigned a scan ID.

Verify the scan history:

```bash
python -m reconpilot.cli scans
```

Retrieve the stored results:

```bash
python -m reconpilot.cli results 127.0.0.1
```

Generate the report:

```bash
python -m reconpilot.cli report 127.0.0.1
```

This demonstrates the complete workflow:

```text
Local Target
     │
     ▼
ReconPilot
     │
     ├── Nmap
     ├── HTTP
     ├── Technology Detection
     │
     ▼
Scan ID
     │
     ▼
SQLite
     │
     ├── Terminal Results
     │
     └── HTML Report
```

---

# Database

ReconPilot uses SQLite to maintain reconnaissance history.

The current database contains tables for:

```text
scans
hosts
ports
dns_records
subdomains
http_services
```

The relationships are centered around the scan ID:

```text
scans
  │
  ├── hosts
  │     └── ports
  │
  ├── dns_records
  │
  ├── subdomains
  │
  └── http_services
```

This architecture allows multiple scans of the same target to coexist without overwriting previous assessments.

---

# Testing

Run the test suite:

```bash
pytest -v
```

Compile the project:

```bash
python -m compileall reconpilot
```

The project currently contains tests covering core components including:

* Target validation
* Nmap parsing
* Database functionality

---

# Design Goals

ReconPilot is being developed with the following principles:

### Modularity

Reconnaissance capabilities are separated into independent modules.

### Reproducibility

Each assessment receives a unique scan ID and stored results.

### Extensibility

New reconnaissance modules can be added without redesigning the entire application.

### Automation

Common reconnaissance steps can be executed through a single pipeline.

### Reporting

Raw reconnaissance data is transformed into structured terminal and HTML output.

### Professional CLI Design

The long-term goal is to provide a tool that feels like a native security-testing utility rather than a collection of independent scripts.

---

# Roadmap

## Completed

* [x] Project architecture
* [x] CLI foundation
* [x] Target validation
* [x] Nmap integration
* [x] Nmap XML parser
* [x] DNS enumeration
* [x] Subdomain enumeration
* [x] HTTP/HTTPS probing
* [x] Technology detection
* [x] SQLite database
* [x] Scan/session IDs
* [x] Scan history
* [x] Terminal output
* [x] HTML reporting
* [x] Initial automated tests

## In Development

* [ ] Configuration system
* [ ] Custom Nmap options
* [ ] Custom subdomain wordlists
* [ ] HTTP security-header analysis
* [ ] Cookie analysis
* [ ] TLS information
* [ ] `robots.txt` reconnaissance
* [ ] Additional web metadata
* [ ] Improved technology detection
* [ ] Progress indicators
* [ ] Improved terminal dashboard
* [ ] Enhanced HTML reports
* [ ] Expanded test coverage

## Future

* [ ] Plugin/module system
* [ ] Additional reconnaissance modules
* [ ] JSON export
* [ ] CSV export
* [ ] Professional CLI installation
* [ ] PyPI/package distribution
* [ ] Release automation

---

# Security Considerations

ReconPilot executes external reconnaissance tools and performs network requests against supplied targets.

Users should:

* Only scan systems they own or have explicit permission to assess.
* Use isolated laboratories for experimentation.
* Avoid storing credentials or sensitive assessment data in the repository.
* Review generated reconnaissance data before sharing it publicly.
* Keep dependencies updated.

---

# Legal Disclaimer

ReconPilot is developed for **authorized security testing, education, research, and cybersecurity laboratories**.

You are responsible for ensuring that you have appropriate authorization before using ReconPilot against a target.

The developers and contributors are not responsible for unauthorized, illegal, or abusive use of this software.

---

# Contributing

Contributions are welcome.

A typical development workflow is:

```bash
git clone https://github.com/YOUR_USERNAME/reconpilot.git
cd reconpilot

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

pytest -v
```

Before submitting changes:

1. Add or update tests where appropriate.
2. Verify that existing tests still pass.
3. Keep modules focused and maintainable.
4. Do not commit credentials, private data, databases, or reconnaissance results.
5. Document significant new functionality.

---


# Author

**Karim SELMI**

Cybersecurity Engineering Student

GitHub: `https://github.com/Karimselmi`

---

## Project Status

ReconPilot is an actively developed cybersecurity reconnaissance project.

Current focus:

```text
Reconnaissance
      ↓
Data Collection
      ↓
Scan Management
      ↓
Reporting
      ↓
Automation
      ↓
Professional Security Toolkit
```

The project is intended to evolve into a modular reconnaissance platform suitable for authorized penetration-testing engagements and cybersecurity laboratories.
