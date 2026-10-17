"""
scanner.py
==========
Reusable Python module for the Institutional VAPT & Compliance Scanner.

PURPOSE
-------
Performs a basic, non-invasive TCP port and service scan of an explicitly
authorized target using Nmap. Results are returned as a JSON-serializable
Python dictionary so the FastAPI backend can store, display, or forward them.

IMPORTANT – AUTHORIZATION NOTICE
---------------------------------
This scanner MUST only be used against systems you own or have received
explicit written permission to test. Unauthorized scanning may be illegal
in your jurisdiction. The application layer (FastAPI backend) is responsible
for enforcing an allowlist of authorized targets before calling scan_target().

LIMITATIONS
-----------
- This is a preliminary, informational scan (Nmap -sV on a limited port range).
- An open port does NOT mean the service is vulnerable. Findings require
  manual verification by a qualified security professional.
- This scanner does not run exploit scripts, brute-force attacks, or
  stealth/evasion options.
"""

import shutil          # to check whether nmap is on PATH
import subprocess      # to run nmap as a child process (no shell=True)
import ipaddress       # to validate IP addresses
import re              # to validate hostnames
import xml.etree.ElementTree as ET  # standard-library XML parser
from typing import Optional

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

# Ports scanned. Kept narrow for a beginner MVP – common web, SSH, FTP,
# database, and admin ports. Expand after the first sprint if needed.
DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"

# Nmap will give up on a host after this many seconds.
NMAP_TIMEOUT_SECONDS = 60

# Severity is informational for open ports unless specific evidence says otherwise.
INFORMATIONAL = "informational"

# ---------------------------------------------------------------------------
# PUBLIC INTERFACE
# ---------------------------------------------------------------------------


def scan_target(target: str) -> dict:
    """
    Scan a single target host and return findings as a dictionary.

    This is the main entry point. The FastAPI backend should call this
    function after verifying that `target` is on the authorized allowlist.

    Parameters
    ----------
    target : str
        An IPv4 address or hostname, e.g. "127.0.0.1" or "example.internal".

    Returns
    -------
    dict
        Always contains these top-level keys:
          - "target"   : the target that was scanned
          - "status"   : "completed" | "error"
          - "findings" : list of finding dicts (empty list if nothing found)
          - "error"    : None on success, or a plain-English error message

    Example
    -------
    >>> from scanner.scanner import scan_target
    >>> result = scan_target("127.0.0.1")
    >>> print(result["status"])
    'completed'
    """
    # Step 1 – normalise the target string first so the same value is
    # validated, passed to Nmap, and stored in the response.
    # Without this, "  127.0.0.1  " would pass validation (which strips
    # internally) but the raw padded string would reach Nmap and the caller.
    if isinstance(target, str):
        target = target.strip()

    validation_error = _validate_target(target)
    if validation_error:
        return _error_response(target, validation_error)

    # Step 2 – make sure nmap is installed on this machine
    if not _nmap_is_available():
        return _error_response(
            target,
            "Nmap is not installed or not found on PATH. "
            "Install it with: sudo apt install nmap  (Linux) or "
            "download from https://nmap.org/download.html (Windows/macOS)."
        )

    # Step 3 – run nmap and capture its XML output
    xml_output, run_error = _run_nmap(target)
    if run_error:
        return _error_response(target, run_error)

    # Step 4 – parse the XML and build the findings list
    findings, parse_error = _parse_nmap_xml(xml_output)
    if parse_error:
        return _error_response(target, parse_error)

    return {
        "target": target,
        "status": "completed",
        "findings": findings,
        "error": None,
    }


# ---------------------------------------------------------------------------
# STEP 1 – TARGET VALIDATION
# ---------------------------------------------------------------------------


def _validate_target(target: str) -> Optional[str]:
    """
    Check that `target` is a valid IPv4 address or a safe hostname.

    Returns None when the target is valid, or an error string when it is not.

    NOTE: This function only checks *format*. The application layer must
    also check that the target is on the authorized allowlist before calling
    scan_target(). Format validation alone is NOT a security control.
    """
    if not target or not isinstance(target, str):
        return "Target must be a non-empty string."

    # Note: whitespace stripping is done by the caller (scan_target) before
    # this function is called, so `target` is already clean here.

    if len(target) > 253:
        return "Target is too long to be a valid hostname or IP address."

    # Try to parse as an IPv4 address first
    try:
        ipaddress.IPv4Address(target)
        return None  # valid IPv4
    except ValueError:
        pass

    # Fall back to a basic hostname check.
    # Allowed: letters, digits, hyphens, dots. No spaces, slashes, or flags.
    hostname_pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"          # starts with alphanumeric
        r"(?:[a-zA-Z0-9\-]{0,61}"   # middle characters
        r"[a-zA-Z0-9])?"            # ends with alphanumeric
        r"\.)*"                     # each label ends with a dot (optional)
        r"[a-zA-Z0-9]"              # final label starts
        r"(?:[a-zA-Z0-9\-]{0,61}"
        r"[a-zA-Z0-9])?$"
    )
    if hostname_pattern.match(target):
        return None  # valid hostname

    return (
        f"'{target}' is not a valid IPv4 address or hostname. "
        "Provide a plain IP address (e.g. 192.168.1.1) or hostname "
        "(e.g. example.internal)."
    )


# ---------------------------------------------------------------------------
# STEP 2 – NMAP AVAILABILITY CHECK
# ---------------------------------------------------------------------------


def _nmap_is_available() -> bool:
    """
    Return True if the `nmap` binary is found on the system PATH.

    Uses shutil.which(), which is the standard way to locate executables
    without running a shell command.
    """
    return shutil.which("nmap") is not None


# ---------------------------------------------------------------------------
# STEP 3 – RUN NMAP
# ---------------------------------------------------------------------------


def _run_nmap(target: str) -> tuple[Optional[str], Optional[str]]:
    """
    Execute Nmap against `target` and return its XML output.

    Returns a tuple (xml_string, error_message).
    On success  → (xml_string, None)
    On failure  → (None, error_message)

    SECURITY NOTES
    --------------
    - Arguments are passed as a *list*, never through shell=True, to prevent
      command injection via malicious target strings.
    - Only service-version detection (-sV) is used. No scripts (-sC),
      no OS detection (-O), no intrusive probes.
    - A strict timeout prevents the scan from hanging indefinitely.
    """
    # Build the nmap command as a list of strings.
    # Each element is a separate argument – the OS never interprets a shell.
    cmd = [
        "nmap",
        "-sV",                           # detect service versions
        "--version-intensity", "2",      # light probing (0=lightest, 9=heaviest)
        "-p", DEFAULT_PORTS,             # only scan the defined port list
        "--open",                        # only report open ports
        "-T3",                           # normal timing (not aggressive)
        "--host-timeout", f"{NMAP_TIMEOUT_SECONDS}s",
        "-oX", "-",                      # output XML to stdout ("-")
        target,                          # the validated target
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,   # capture stdout and stderr
            text=True,             # decode bytes to str automatically
            timeout=NMAP_TIMEOUT_SECONDS + 10,  # subprocess-level safety net
        )
    except subprocess.TimeoutExpired:
        return None, (
            f"Nmap scan timed out after {NMAP_TIMEOUT_SECONDS} seconds. "
            "The host may be unreachable or blocking probes."
        )
    except FileNotFoundError:
        # Shouldn't happen because we checked _nmap_is_available(), but
        # handle it defensively anyway.
        return None, "Nmap executable not found. Please reinstall Nmap."
    except Exception as exc:  # noqa: BLE001
        # Catch unexpected OS-level errors (permissions, etc.)
        return None, f"Unexpected error while running Nmap: {exc}"

    if result.returncode != 0:
        # Nmap exit code > 0 usually means the host was down or a flag was wrong.
        stderr_snippet = result.stderr[:300] if result.stderr else "(no stderr)"
        return None, (
            f"Nmap exited with code {result.returncode}. "
            f"Stderr: {stderr_snippet}"
        )

    if not result.stdout.strip():
        return None, "Nmap produced no output. The host may be unreachable."

    return result.stdout, None


# ---------------------------------------------------------------------------
# STEP 4 – PARSE NMAP XML
# ---------------------------------------------------------------------------


def _parse_nmap_xml(xml_string: str) -> tuple[list, Optional[str]]:
    """
    Parse the XML that Nmap writes to stdout (-oX -) and extract findings.

    Returns a tuple (findings_list, error_message).
    On success  → (list_of_dicts, None)   — list may be empty (no open ports)
    On failure  → ([], error_message)

    IMPORTANT
    ---------
    An open port is reported as INFORMATIONAL, not as a vulnerability.
    Marking a port vulnerable requires specific supporting evidence (e.g.,
    a known CVE confirmed by version matching) – that is out of scope for
    this basic MVP scanner.
    """
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as exc:
        return [], f"Failed to parse Nmap XML output: {exc}"

    findings = []
    finding_counter = 1  # used to build the unique finding ID (F001, F002, …)

    # Each scanned host lives inside a <host> element.
    for host in root.findall("host"):

        # ---- host state (up / down) ----------------------------------------
        state_elem = host.find("status")
        host_state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
        if host_state != "up":
            # Host is down or filtered – no ports to report.
            continue

        # ---- port findings ---------------------------------------------------
        ports_elem = host.find("ports")
        if ports_elem is None:
            continue  # no port data at all

        for port_elem in ports_elem.findall("port"):

            # Basic port metadata
            protocol = port_elem.get("protocol", "tcp")
            port_number = int(port_elem.get("portid", 0))

            # Port state (open / closed / filtered)
            state_elem = port_elem.find("state")
            if state_elem is None:
                continue
            port_state = state_elem.get("state", "unknown")
            if port_state != "open":
                # We passed --open to nmap, so this shouldn't occur,
                # but guard anyway.
                continue

            # Service and version information (may be absent)
            service_elem = port_elem.find("service")
            service_name = "unknown"
            service_version = None

            if service_elem is not None:
                service_name = service_elem.get("name", "unknown")
                # Build a version string from product + version + extrainfo
                parts = [
                    service_elem.get("product", ""),
                    service_elem.get("version", ""),
                    service_elem.get("extrainfo", ""),
                ]
                version_str = " ".join(p for p in parts if p).strip()
                service_version = version_str if version_str else None

            # Build a human-readable finding ID
            finding_id = f"F{finding_counter:03d}"
            finding_counter += 1

            findings.append({
                "id": finding_id,
                "title": f"Detected service: {service_name} on port {port_number}/{protocol}",
                "port": port_number,
                "protocol": protocol,
                "service": service_name,
                "version": service_version,
                # Open ports are informational – NOT automatically vulnerabilities.
                "severity": INFORMATIONAL,
                "evidence": (
                    f"Nmap detected an open {protocol.upper()} port "
                    f"({port_number}) running '{service_name}'. "
                    "This is a preliminary finding and requires manual verification."
                ),
                "recommendation": (
                    "Confirm that this service is required for business operations. "
                    "Review its configuration, apply available security patches, "
                    "and restrict access to authorised sources where possible."
                ),
            })

    return findings, None


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------


def _error_response(target: str, message: str) -> dict:
    """
    Build a standard error response dictionary.

    Always returns the same top-level keys so callers never need to do
    key-existence checks before reading results.
    """
    return {
        "target": target,
        "status": "error",
        "findings": [],
        "error": message,
    }
# Authorized security scanning module
