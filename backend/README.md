# Backend API: Institutional VAPT & Compliance Scanner

Node.js + Express API that validates scan requests, runs the Nmap scanner, and stores results in PostgreSQL.

## Requirements
- Node.js and npm
- Python 3.9+
- Nmap
- PostgreSQL

## Setup
1. Install packages:
```bash
   cd backend
   npm install
```
2. Start PostgreSQL and create the database:
```bash
   sudo service postgresql start
   sudo -u postgres psql -c "CREATE DATABASE vapt_scanner;"
   sudo -u postgres psql -d vapt_scanner -f schema.sql
   sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'yourpassword';"
```
3. Copy `db.example.js` to `db.js` and set your password (`db.js` is not in Git because it holds the password):
```bash
   cp db.example.js db.js
```
   Then edit `db.js` and replace `yourpassword` with the password from step 2.

4. Start the API:
```bash
   node index.js
```
   The API runs on port 3000.

## Configuration
| Setting | Where | Default |
|---|---|---|
| API key | `API_KEY` env variable | `demo-key-123` |
| Allowed targets | `ALLOWED_SUBNETS` in `validation.js` | `192.168.1.0/24`, `10.42.0.0/24`, `127.0.0.1/32` |
| Allowed frontend origin | CORS in `index.js` | `http://localhost:5173` |
| Max concurrent scans | `index.js` | 2 |
| Scan timeout | `index.js` | 80 seconds |
| Rate limit | `index.js` | 10 scan requests per minute |

## Authentication
Every `/api/scans` request needs the header `x-api-key`. `/api/health` is open.

## Endpoints

### GET /api/health
Response: `{"status":"ok"}`

### POST /api/scans
Request: `{"target":"192.168.1.10"}`
Response (202): `{"scan_id":"scan-001","target":"192.168.1.10","status":"running"}`

### GET /api/scans/:id
Returns the scan status and findings. Poll until status is `completed`, `failed` or `timed_out`.

### GET /api/scans
Returns the last 50 saved scans, newest first.

## Statuses
`running`, `completed`, `failed`, `timed_out`

## Finding format
```json
{
  "finding_id": "F001",
  "title": "Detected service: ssh on port 22/tcp",
  "target": "192.168.1.10",
  "port": 22,
  "protocol": "tcp",
  "service": "ssh",
  "version": "OpenSSH",
  "severity": "informational",
  "evidence": "Nmap detected an open TCP port (22)...",
  "confidence": "observed",
  "recommendation": "Confirm that this service is required...",
  "compliance_references": []
}
```
An open port is an observation, not a confirmed vulnerability.

## Errors
Format: `{"error":{"code":"...","message":"..."}}`

| Code | HTTP | Meaning |
|---|---|---|
| INVALID_TARGET | 400 | Target is not a valid IPv4 address |
| INVALID_JSON | 400 | Request body is not valid JSON |
| UNAUTHORIZED | 401 | Missing or wrong API key |
| TARGET_NOT_ALLOWED | 403 | Target is outside the approved scope |
| SCAN_NOT_FOUND | 404 | Scan ID does not exist |
| TOO_MANY_SCANS | 429 | Concurrent scan limit reached |
| RATE_LIMITED | 429 | Too many requests per minute |
| SERVER_ERROR | 500 | Unexpected error |

## Limitations
- Only scans targets inside the approved subnets.
- Scans a limited list of common TCP ports.
- Scanner results are preliminary and need manual verification.
- A completed scan with no findings does not prove the host is unreachable.

Scanning is restricted to approved subnets, because scanning without authorization is illegal. Only scan systems you own or have written permission to test.

## Known Limitations
- The API key is a single shared key. A production system would use proper authentication and user roles.
- Scan history is limited to the last 50 scans.
- `started_at` and `completed_at` are saved at the same time, so scan duration is not recorded.
- Scans are stored in memory while running. If the server restarts mid-scan, that scan is lost.
