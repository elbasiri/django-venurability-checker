# Django Vulnerability Checker (Monitoro)

A professional web vulnerability scanner built with Django that detects XSS and SQL Injection vulnerabilities with automated pentester-level detection techniques.

## Features

- **XSS Detection**: Reflected, DOM-based, context-aware payload injection with 15+ advanced payloads
- **SQL Injection Detection**: Error-based, blind time-based, response comparison, and union-based techniques
- **Professional UI**: Beautiful, modern web interface with form submission and results display
- **Database Storage**: All scans saved to SQLite with full vulnerability details
- **API Endpoints**: RESTful API for programmatic scanning and monitoring
- **Scan Management**: View recent scans, monitor multiple sites, track vulnerability history

## Installation

```bash
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

## Usage

1. Visit `http://127.0.0.1:8000/`
2. Enter a target URL (e.g., `https://example.com/search?q=test`)
3. Select scan options:
   - Deep Scan (more payloads, slower)
   - Follow Links (crawl and test linked pages)
   - Blind Detection (time-based SQLi tests)
4. View detailed results with exact vulnerable parameters, payloads, and evidence

## API Endpoints

- `POST /` - Submit a scan
- `GET /` - View scan form
- `GET /result/<id>/` - View scan results
- `GET /detect/?url=...` - Direct detection endpoint
- `GET /monitor/list/` - List monitored sites
- `POST /monitor/start/` - Start monitoring a site
- `POST /monitor/stop/<id>/` - Stop monitoring

## Project Structure

```
monitoro/
├── manage.py
├── monitoro/
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── analyze_detect/
│   ├── models.py (Scan, MonitoredSite)
│   ├── views.py (Index, Results, Detection)
│   ├── utils.py (Detection Logic)
│   ├── urls.py (Routing)
│   ├── admin.py (Django Admin)
│   ├── management/
│   │   └── commands/
│   │       └── run_monitor.py (Background Scanner)
│   └── templates/
│       ├── index.html (Scan Form)
│       └── result.html (Results Display)
└── db.sqlite3
```

## Detection Techniques

### XSS Detection
- Reflected payload injection
- Context-aware escaping bypass
- Event handler payloads
- Data URI schemes
- DOM-based testing

### SQLi Detection
- Error-based detection (MySQL, PostgreSQL, SQLite, MSSQL, Oracle)
- Blind time-based (SLEEP, BENCHMARK)
- Response comparison analysis
- Union-based SQL injection
- Information schema enumeration

## Requirements

- Python 3.8+
- Django 6.0
- requests
- beautifulsoup4

## Warning ⚠️

This tool is designed for authorized security testing only. Only scan systems you own or have explicit permission to test. Unauthorized security testing is illegal.

## Author

Built as a professional vulnerability assessment tool.
