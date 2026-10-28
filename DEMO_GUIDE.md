# Demo Guide: Institutional VAPT & Compliance Scanner

This guide runs the whole project on one Linux laptop (Ubuntu, Debian or Kali). It needs no other machine and no network.

## Part 1: Install the tools (once)

```bash
sudo apt update
sudo apt install -y nodejs npm python3 nmap postgresql git
```

## Part 2: Get the project

```bash
git clone https://github.com/hannadesalegn7-pixel/InstitutionalVAPTComplianceScanner.git
cd InstitutionalVAPTComplianceScanner/backend
npm install
```

## Part 3: Set up the database (once)

Run these in the `backend` folder:

```bash
sudo service postgresql start
sudo -u postgres psql -c "CREATE DATABASE vapt_scanner;"
sudo -u postgres psql -d vapt_scanner -f schema.sql
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'yourpassword';"
cp db.example.js db.js
```

`db.js` already uses the password `yourpassword`, so no edit is needed. If you chose another password, open `db.js` and change it.

## Part 4: Start the system

Terminal 1, backend (leave it open):

```bash
cd InstitutionalVAPTComplianceScanner/backend
sudo service postgresql start
node index.js
```

You should see: `API running on port 3000`.

Terminal 2, frontend (leave it open):

```bash
cd InstitutionalVAPTComplianceScanner/frontend
npm install
npm run dev
```

You should see: `Local: http://localhost:5173/`. Open that address in the browser. If it says 5174 instead, another Vite is still running. Stop it and start again.

## Part 5: Demo script (about 5 minutes)

| Step | Action | Expected result | What to say |
|---|---|---|---|
| 1 | Open `http://localhost:3000/api/health` | `{"status":"ok"}` | The backend is running. |
| 2 | In the dashboard, scan `127.0.0.1` | "Scanning...", then findings with `compliance_references` | The full pipeline: browser, API, Nmap, compliance mapping. An open port is an observation, not a confirmed vulnerability. |
| 3 | Scan `abc` | "The submitted target is invalid." | The backend validates all input. |
| 4 | Scan `8.8.8.8` | "The target is outside the approved scope." | Scanning without permission is illegal, so only approved subnets are allowed. |
| 5 | Scan `127.0.0.1; ls` | Rejected as invalid | Input is validated, and the scanner is called without a shell, so injection does not work. |
| 6 | Run `curl -H "x-api-key: demo-key-123" http://localhost:3000/api/scans` | List of saved scans | Results are stored in PostgreSQL. |
| 7 | Run the same `curl` without the `x-api-key` header | `UNAUTHORIZED` | Access control. |

## Part 6: Points to mention

- Safeguards: target allowlist, API key, rate limit (10 per minute), concurrent scan limit (2), 80 second timeout, no shell commands.
- The Ethiopian data protection reference is marked `needs_manual_review` on purpose, because the exact article is not yet confirmed.
- Known limitations: one shared API key, results shown as raw JSON, scan duration not recorded.
- Only scan systems you own or have written permission to test.

## Troubleshooting

| Problem | Fix |
|---|---|
| "Could not reach the backend API" | Check that `node index.js` is running. Check that the dashboard is on port 5173, not 5174. |
| "Could not load counter" when starting the backend | PostgreSQL is not running. Run `sudo service postgresql start`, then restart the backend. |
| `database "vapt_scanner" does not exist` | Repeat Part 3. |
| Collation version mismatch error from PostgreSQL | Run `sudo -u postgres psql -c "ALTER DATABASE template1 REFRESH COLLATION VERSION;"` and the same for `postgres`, then repeat Part 3. |
| Scan returns an error about Nmap | Run `nmap --version`. If it is missing, run `sudo apt install -y nmap`. |
| Port 3000 already in use | Run `sudo ss -ltnp | grep 3000`, then stop that process. |
