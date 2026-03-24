# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SRE Report Analyzer is a Flask-based web application for analyzing cybersecurity reports sent by the SRE Platform team. It processes Excel files to detect suspicious activities, malicious domains, and access key anomalies within Business Units (BUs).

## Commands

### Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run the Flask development server
python app.py
```

### Docker
```bash
# Build and run with Docker Compose
docker-compose up --build

# Run container directly
docker build -t sre-report-analyzer .
docker run -p 5000:5000 sre-report-analyzer
```

The application runs on port 5000 by default.

## Architecture

### Backend Structure

- **app.py** - Flask application with REST API endpoints and file upload handling
- **main_processor.py** - Orchestrates analysis across all Excel sheet types
- **config.py** - Central configuration for file paths, thresholds, column mappings, and sheet names
- **processors/** - Modular analysis processors, one per Excel sheet type:
  - `user_manager_processor.py` - Analyzes UserManager sheet for suspicious email domains
  - `access_key_processor.py` - Detects tenants with excessive access keys (>10)
  - `suspicious_user_activities_processor.py` - Matches usernames against suspicious patterns
  - `email_domains_update_processor.py` - Monitors CHANGED_TO_VALUE for suspicious domain updates
  - `tenant_exception_processor.py` - Loads tenant exception list for access key analysis

### Frontend

Single-page application in `templates/dashboard.html` using:
- Tailwind CSS for styling
- Grid.js for data tables
- Chart.js for visualizations

### Data Flow

1. User uploads Excel file through the dashboard
2. File is temporarily saved to `uploads/` directory
3. `main_processor.py` reads available sheets and delegates to appropriate processors
4. Each processor loads reference data from CSV files (suspicious_domains.csv, tenant_exceptions.csv, suspicious_usernames.csv)
5. Results returned as JSON with summary statistics and row-level data
6. Uploaded file is cleaned up after processing

### API Endpoints

- `POST /api/analyze` - Combined analysis of all sheets
- `POST /api/analyze/suspicious-domains` - UserManager sheet only
- `POST /api/analyze/access-keys` - AccessKeyManagement sheet only
- `POST /api/analyze/email-domains-update` - EmailDomainsUpd_stats sheet only
- `POST /api/analyze/suspicious-users` - Username pattern matching
- `GET/POST /api/domains` - Manage suspicious domains list
- `GET/POST /api/tenants` - Manage tenant exception list
- `GET/POST /api/usernames` - Manage suspicious usernames list
- `POST /api/export/csv` and `POST /api/export/excel` - Export results

### Reference Data Files

CSV files in project root that control analysis behavior:
- `suspicious_domains.csv` - Domains flagged as suspicious (column: `domain`)
- `tenant_exceptions.csv` - Tenants exempt from access key threshold (column: `tenant_name`)
- `suspicious_usernames.csv` - Username patterns to flag (column: `suspicious_username`)

### Expected Excel Sheets

- **UserManager** - User activity with ACTOR_USER_EMAIL, USER_EMAIL columns
- **AccessKeyManagement** - Access key operations with TENANT_NAME, ACCESS_KEY_ID
- **EmailDomainsUpd_stats** - Email domain changes with CHANGED_TO_VALUE

### Key Constants (config.py)

- `ACCESS_KEY_THRESHOLD = 10` - Tenants with more keys are flagged
- Gmail domains receive special flag: "suspicious - further checks required"
