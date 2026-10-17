# Scanner Module – VAPT & Compliance Scanner

A reusable Python module that performs a **basic, non-invasive TCP port and
service scan** using [Nmap](https://nmap.org). It is designed to slot into the
FastAPI backend as an importable function.

---

## ⚠️ Authorization Notice

> **You must have explicit written permission from the system owner before
> scanning any target.** Unauthorized port scanning may be illegal in your
> jurisdiction. This module must only be invoked by the application layer
> after verifying the target against an authorized allowlist.

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10 + | Uses `match`-free typing – should work on 3.9 too |
| Nmap | 7.x + | Must be on system `PATH` |
| pytest | 8.x | For running unit tests only |

### Installing Nmap

**Linux (Debian/Ubuntu)**
```bash
sudo apt update && sudo apt install nmap -y
```

**macOS (Homebrew)**
```bash
brew install nmap
```

**Windows**
Download the installer from <https://nmap.org/download.html> and make sure
the install directory is added to your `PATH` (the installer does this by
default).

Verify the installation:
```bash
nmap --version
```

---

## Installation

```bash
# 1. Clone / copy the project
cd cyb/

# 2. (Recommended) create a virtual environment
python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

# 3. Install Python dependencies
pip install -r requirements.txt
```

---

## Usage

### From the FastAPI backend

```python
from scanner.scanner import scan_target

# IMPORTANT: verify `target` is on your authorized allowlist before calling this.
result = scan_target("127.0.0.1")

print(result["status"])    # "completed" or "error"
print(result["findings"])  # list of finding dicts
print(result["error"])     # None on success, message string on failure
```

### Quick test from the Python REPL

```python
# Run from the project root (cyb/)
import sys, os
sys.path.insert(0, os.getcwd())   # only needed outside a proper install

from scanner.scanner import scan_target
result = scan_target("127.0.0.1")

for f in result["findings"]:
    print(f["title"], "–", f["severity"])
```

---

## Response Structure

`scan_target()` always returns a dictionary with **exactly these four keys**:

```json
{
  "target": "127.0.0.1",
  "status": "completed",
  "findings": [
    {
      "id": "F001",
      "title": "Detected service: ssh on port 22/tcp",
      "port": 22,
      "protocol": "tcp",
      "service": "ssh",
      "version": "OpenSSH 8.9 protocol 2.0",
      "severity": "informational",
      "evidence": "Nmap detected an open TCP port (22) running 'ssh'. ...",
      "recommendation": "Confirm that this service is required ..."
    }
  ],
  "error": null
}
```

| Key | Type | Description |
|---|---|---|
| `target` | `str` | The target that was scanned |
| `status` | `str` | `"completed"` or `"error"` |
| `findings` | `list` | Zero or more finding objects (see below) |
| `error` | `str \| null` | `null` on success; plain-English message on failure |

### Finding object keys

| Key | Type | Notes |
|---|---|---|
| `id` | `str` | Sequential identifier (`F001`, `F002`, …) |
| `title` | `str` | Human-readable summary |
| `port` | `int` | Port number |
| `protocol` | `str` | Always `"tcp"` for this scanner |
| `service` | `str` | Service name detected by Nmap |
| `version` | `str \| null` | Version string when available; `null` otherwise |
| `severity` | `str` | Always `"informational"` – see Limitations |
| `evidence` | `str` | Description of what Nmap found |
| `recommendation` | `str` | Suggested action |

---

## What is and is NOT scanned

| Behaviour | Value |
|---|---|
| Scan type | TCP service-version detection (`-sV`) |
| Port range | `21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443` |
| Timing | Normal (`-T3`), host timeout 60 s |
| Version intensity | 2 (light – 0 = lightest, 9 = heaviest) |
| OS detection | ❌ Not enabled |
| Script engine (`-sC`) | ❌ Not enabled |
| Exploit scripts | ❌ Not included |
| Brute-force | ❌ Not included |
| Stealth/evasion (`-sS`) | ❌ Not used |
| DoS tests | ❌ Not included |

---

## Limitations

1. **Open ≠ Vulnerable.** All findings are `severity: informational`. An open
   port only means the service is reachable. A human analyst or a dedicated
   vulnerability scanner must confirm whether the service is misconfigured or
   exploitable.

2. **Limited port range.** Only the 15 ports listed above are checked. Services
   on non-standard ports will not appear in the results.

3. **No CVE correlation.** The scanner does not cross-reference version strings
   against CVE databases. That is a future enhancement.

4. **Preliminary findings only.** Treat results as a starting point for manual
   investigation, not a definitive security assessment.

---

## Running the Tests

```bash
# From the project root (cyb/)

# Run all tests — live scan tests skip automatically if Nmap is absent
pytest -v

# Force-skip live scan tests even if Nmap is present
pytest -v -k "not TestScanTargetLive"
```

Expected output when Nmap is NOT installed:
```
tests/test_scanner.py::TestScanTargetLive::test_localhost_scan_completes SKIPPED
...
X passed, Y skipped
```

---

## Safe Testing Against Localhost

The safest target for manual testing is your own machine (`127.0.0.1`):

```bash
# Quick smoke test from command line (Nmap required)
python -c "
from scanner.scanner import scan_target
import json
print(json.dumps(scan_target('127.0.0.1'), indent=2))
"
```

Do **not** put real IP addresses in test files. Tests are restricted to
`127.0.0.1` in this repository.

---

## Project Structure

```
cyb/
├── scanner/
│   ├── __init__.py        # re-exports scan_target for easy import
│   ├── scanner.py         # main module (this is what you import)
│   └── README.md          # this file
├── tests/
│   ├── __init__.py
│   └── test_scanner.py    # unit tests (all offline / mocked)
├── requirements.txt
└── scanner.py             # placeholder (root level, not the module)
```

---

## Integration with the FastAPI Backend

Your teammate only needs one line:

```python
from scanner.scanner import scan_target
```

The function signature will not change during this sprint. If the backend
runs from the `cyb/` project root, the import works without any path
manipulation as long as the virtual environment is activated and
`requirements.txt` has been installed.
