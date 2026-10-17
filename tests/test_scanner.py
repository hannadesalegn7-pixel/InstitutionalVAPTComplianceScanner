"""
test_scanner.py
===============
Unit tests for the VAPT scanner module.

All parsing and validation tests use mocked/static XML data so they can run
without Nmap installed or a live network connection.

The live scan tests (TestScanTargetLive) use pytest.mark.skipif, checked at
collection time against shutil.which("nmap"). They are skipped automatically
when Nmap is not found on PATH, and run automatically when it is — no extra
flags needed.

Run all tests:
    pytest -v

Run offline tests explicitly (skip live scans even if Nmap is present):
    pytest -v -k "not TestScanTargetLive"
"""

import pytest
from unittest.mock import patch, MagicMock
import subprocess

# ---- Import the functions we want to test ----------------------------------
# We import the private helpers directly so we can test each piece in isolation
# without needing to go through the full scan_target() pipeline.
from scanner.scanner import (
    scan_target,
    _validate_target,
    _nmap_is_available,
    _parse_nmap_xml,
    _run_nmap,
    _error_response,
)


# ===========================================================================
# FIXTURES – sample Nmap XML strings
# ===========================================================================

# Minimal valid XML for a host with two open ports.
SAMPLE_XML_TWO_PORTS = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9" extrainfo="protocol 2.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.54" extrainfo=""/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# XML where the host is reported as down.
SAMPLE_XML_HOST_DOWN = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports/>
  </host>
</nmaprun>
"""

# XML with no ports element at all.
SAMPLE_XML_NO_PORTS = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

# XML where ports are closed / filtered (not open).
SAMPLE_XML_NO_OPEN_PORTS = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="reset"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# XML where a service has no version details.
SAMPLE_XML_NO_VERSION = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# Intentionally broken XML.
INVALID_XML = "this is not xml at all <<<"


# ===========================================================================
# 1. TARGET VALIDATION TESTS
# ===========================================================================

class TestValidateTarget:
    """Tests for the _validate_target() helper."""

    def test_valid_ipv4_loopback(self):
        assert _validate_target("127.0.0.1") is None

    def test_valid_ipv4_private(self):
        assert _validate_target("192.168.1.100") is None

    def test_valid_simple_hostname(self):
        assert _validate_target("localhost") is None

    def test_valid_hostname_with_dots(self):
        assert _validate_target("example.internal") is None

    def test_valid_hostname_alphanumeric(self):
        assert _validate_target("server01") is None

    def test_empty_string_returns_error(self):
        error = _validate_target("")
        assert error is not None
        assert isinstance(error, str)

    def test_none_returns_error(self):
        error = _validate_target(None)  # type: ignore[arg-type]
        assert error is not None

    def test_ip_with_shell_metachar_returns_error(self):
        # A target that looks like a shell injection attempt.
        error = _validate_target("127.0.0.1; rm -rf /")
        assert error is not None

    def test_ip_with_flag_injection_returns_error(self):
        # Attacker tries to inject nmap flags via the target string.
        error = _validate_target("--script=exploit 127.0.0.1")
        assert error is not None

    def test_url_scheme_returns_error(self):
        # URLs are not valid targets for nmap (no scheme support here).
        error = _validate_target("http://example.com")
        assert error is not None

    def test_too_long_target_returns_error(self):
        error = _validate_target("a" * 300)
        assert error is not None


# ===========================================================================
# 2. NMAP XML PARSING TESTS
# ===========================================================================

class TestParseNmapXml:
    """Tests for the _parse_nmap_xml() helper."""

    def test_two_open_ports_returns_two_findings(self):
        findings, error = _parse_nmap_xml(SAMPLE_XML_TWO_PORTS)
        assert error is None
        assert len(findings) == 2

    def test_finding_ids_are_sequential(self):
        findings, _ = _parse_nmap_xml(SAMPLE_XML_TWO_PORTS)
        assert findings[0]["id"] == "F001"
        assert findings[1]["id"] == "F002"

    def test_ssh_port_parsed_correctly(self):
        findings, _ = _parse_nmap_xml(SAMPLE_XML_TWO_PORTS)
        ssh = findings[0]
        assert ssh["port"] == 22
        assert ssh["protocol"] == "tcp"
        assert ssh["service"] == "ssh"
        assert "OpenSSH" in ssh["version"]

    def test_http_port_parsed_correctly(self):
        findings, _ = _parse_nmap_xml(SAMPLE_XML_TWO_PORTS)
        http = findings[1]
        assert http["port"] == 80
        assert http["service"] == "http"

    def test_severity_is_informational(self):
        """Open ports must NOT be labelled as vulnerabilities."""
        findings, _ = _parse_nmap_xml(SAMPLE_XML_TWO_PORTS)
        for finding in findings:
            assert finding["severity"] == "informational"

    def test_all_required_keys_present(self):
        """Every finding must include the keys the backend contract requires."""
        required_keys = {
            "id", "title", "port", "protocol",
            "service", "version", "severity", "evidence", "recommendation"
        }
        findings, _ = _parse_nmap_xml(SAMPLE_XML_TWO_PORTS)
        for finding in findings:
            assert required_keys.issubset(finding.keys()), (
                f"Finding is missing keys: {required_keys - finding.keys()}"
            )

    def test_host_down_returns_empty_findings(self):
        findings, error = _parse_nmap_xml(SAMPLE_XML_HOST_DOWN)
        assert error is None
        assert findings == []

    def test_no_ports_element_returns_empty_findings(self):
        findings, error = _parse_nmap_xml(SAMPLE_XML_NO_PORTS)
        assert error is None
        assert findings == []

    def test_no_open_ports_returns_empty_findings(self):
        findings, error = _parse_nmap_xml(SAMPLE_XML_NO_OPEN_PORTS)
        assert error is None
        assert findings == []

    def test_no_version_info_sets_version_to_none(self):
        findings, error = _parse_nmap_xml(SAMPLE_XML_NO_VERSION)
        assert error is None
        assert findings[0]["version"] is None

    def test_invalid_xml_returns_error(self):
        findings, error = _parse_nmap_xml(INVALID_XML)
        assert findings == []
        assert error is not None
        assert isinstance(error, str)

    def test_empty_xml_returns_error(self):
        findings, error = _parse_nmap_xml("")
        assert findings == []
        assert error is not None


# ===========================================================================
# 3. ERROR RESPONSE HELPER TESTS
# ===========================================================================

class TestErrorResponse:
    """Tests for the _error_response() helper."""

    def test_error_response_structure(self):
        resp = _error_response("127.0.0.1", "Something went wrong")
        assert resp["target"] == "127.0.0.1"
        assert resp["status"] == "error"
        assert resp["findings"] == []
        assert resp["error"] == "Something went wrong"

    def test_error_response_is_json_serializable(self):
        import json
        resp = _error_response("10.0.0.1", "Test error")
        # If this doesn't raise, the dict is JSON-serializable.
        json.dumps(resp)


# ===========================================================================
# 4. scan_target() INTEGRATION TESTS (mocked subprocess)
# ===========================================================================

class TestScanTargetMocked:
    """
    Tests for scan_target() that mock subprocess.run so no real Nmap call
    is made. This verifies the full pipeline end-to-end without the network.
    """

    def _make_mock_run(self, stdout: str, returncode: int = 0):
        """Helper: return a mock that replaces subprocess.run."""
        mock_result = MagicMock()
        mock_result.stdout = stdout
        mock_result.stderr = ""
        mock_result.returncode = returncode
        return mock_result

    @patch("scanner.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner.scanner.subprocess.run")
    def test_successful_scan_returns_completed_status(self, mock_run, mock_which):
        mock_run.return_value = self._make_mock_run(SAMPLE_XML_TWO_PORTS)
        result = scan_target("127.0.0.1")
        assert result["status"] == "completed"
        assert result["error"] is None
        assert len(result["findings"]) == 2

    @patch("scanner.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner.scanner.subprocess.run")
    def test_scan_returns_target_unchanged(self, mock_run, mock_which):
        mock_run.return_value = self._make_mock_run(SAMPLE_XML_TWO_PORTS)
        result = scan_target("127.0.0.1")
        assert result["target"] == "127.0.0.1"

    @patch("scanner.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner.scanner.subprocess.run")
    def test_scan_empty_findings_when_no_open_ports(self, mock_run, mock_which):
        mock_run.return_value = self._make_mock_run(SAMPLE_XML_NO_OPEN_PORTS)
        result = scan_target("127.0.0.1")
        assert result["status"] == "completed"
        assert result["findings"] == []

    @patch("scanner.scanner.shutil.which", return_value=None)   # nmap not found
    def test_missing_nmap_returns_error(self, mock_which):
        result = scan_target("127.0.0.1")
        assert result["status"] == "error"
        assert result["error"] is not None
        assert "nmap" in result["error"].lower() or "Nmap" in result["error"]

    def test_invalid_target_returns_error(self):
        result = scan_target("not a valid target!!!")
        assert result["status"] == "error"
        assert result["findings"] == []
        assert result["error"] is not None

    def test_empty_target_returns_error(self):
        result = scan_target("")
        assert result["status"] == "error"

    @patch("scanner.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner.scanner.subprocess.run")
    def test_nmap_nonzero_exit_returns_error(self, mock_run, mock_which):
        mock_run.return_value = self._make_mock_run("", returncode=1)
        result = scan_target("127.0.0.1")
        assert result["status"] == "error"
        assert "exit" in result["error"].lower() or "code" in result["error"].lower()

    @patch("scanner.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner.scanner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=60))
    def test_timeout_returns_error(self, mock_run, mock_which):
        result = scan_target("127.0.0.1")
        assert result["status"] == "error"
        assert "timeout" in result["error"].lower() or "timed out" in result["error"].lower()

    @patch("scanner.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner.scanner.subprocess.run")
    def test_invalid_xml_from_nmap_returns_error(self, mock_run, mock_which):
        mock_run.return_value = self._make_mock_run(INVALID_XML)
        result = scan_target("127.0.0.1")
        assert result["status"] == "error"

    @patch("scanner.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner.scanner.subprocess.run")
    def test_result_is_json_serializable(self, mock_run, mock_which):
        import json
        mock_run.return_value = self._make_mock_run(SAMPLE_XML_TWO_PORTS)
        result = scan_target("127.0.0.1")
        # Raises TypeError if any value can't be serialized.
        json.dumps(result)

    @patch("scanner.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner.scanner.subprocess.run")
    def test_result_always_has_four_top_level_keys(self, mock_run, mock_which):
        mock_run.return_value = self._make_mock_run(SAMPLE_XML_TWO_PORTS)
        result = scan_target("127.0.0.1")
        assert set(result.keys()) == {"target", "status", "findings", "error"}


# ===========================================================================
# 5. WHITESPACE NORMALISATION TESTS
# ===========================================================================

class TestWhitespaceNormalisation:
    """
    Verify that scan_target() strips leading/trailing whitespace from the
    target before validation AND before the value is stored in the response.

    The bug this guards against: _validate_target() used to strip internally
    but throw away the stripped value, so "  127.0.0.1  " would pass
    validation but the raw padded string would reach Nmap and appear in the
    returned "target" key.
    """

    @patch("scanner.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner.scanner.subprocess.run")
    def test_padded_target_is_stripped_in_response(self, mock_run, mock_which):
        """The 'target' key in the result must be the stripped value."""
        mock_result = MagicMock()
        mock_result.stdout = SAMPLE_XML_TWO_PORTS
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        result = scan_target("  127.0.0.1  ")
        # The response must contain the clean IP, not the padded string.
        assert result["target"] == "127.0.0.1", (
            f"Expected '127.0.0.1' but got '{result['target']}'"
        )

    @patch("scanner.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner.scanner.subprocess.run")
    def test_padded_target_still_completes_successfully(self, mock_run, mock_which):
        """A target with surrounding spaces must not be rejected as invalid."""
        mock_result = MagicMock()
        mock_result.stdout = SAMPLE_XML_TWO_PORTS
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        result = scan_target("  127.0.0.1  ")
        assert result["status"] == "completed"

    @patch("scanner.scanner.shutil.which", return_value="/usr/bin/nmap")
    @patch("scanner.scanner.subprocess.run")
    def test_tab_and_newline_whitespace_stripped(self, mock_run, mock_which):
        """Tabs and newlines around the target are stripped too."""
        mock_result = MagicMock()
        mock_result.stdout = SAMPLE_XML_TWO_PORTS
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        result = scan_target("\t127.0.0.1\n")
        assert result["target"] == "127.0.0.1"
        assert result["status"] == "completed"

    def test_whitespace_only_target_returns_error(self):
        """A string of only spaces is not a valid target after stripping."""
        result = scan_target("     ")
        assert result["status"] == "error"
        assert result["error"] is not None


# ===========================================================================
# 6. ADDITIONAL VALIDATION EDGE-CASE TESTS
# ===========================================================================
# 6. HOSTNAME REGEX TESTS
# ===========================================================================

class TestHostnameRegex:
    """
    Focused tests for the hostname branch of _validate_target().

    These inputs all fail the IPv4 check first, so they exercise the regex
    directly. Each test has a short comment explaining why that shape matters.
    """

    # ---- common real-world hostnames that MUST be accepted -----------------

    def test_example_com(self):
        # The most typical two-label internet hostname.
        assert _validate_target("example.com") is None

    def test_www_example_com(self):
        # Three-label hostname with a classic www prefix.
        assert _validate_target("www.example.com") is None

    def test_subdomain_example_com(self):
        # Generic subdomain — common in internal networks.
        assert _validate_target("sub.example.com") is None

    def test_deep_subdomain(self):
        # Four labels — realistic for corp environments.
        assert _validate_target("host.region.corp.internal") is None

    def test_two_char_label(self):
        # Two-character labels are valid DNS labels (e.g. "uk" in bbc.co.uk).
        assert _validate_target("ab") is None

    def test_two_char_labels_with_dot(self):
        # Both labels are two characters — e.g. "co.uk" style.
        assert _validate_target("a.b") is None

    def test_numeric_label(self):
        # Labels can be all digits as long as the whole thing isn't an IP.
        assert _validate_target("host1.zone2.internal") is None

    def test_hyphen_in_middle_of_label(self):
        # Hyphens are valid inside a label — common in real hostnames.
        assert _validate_target("my-host.example.com") is None

    def test_multiple_hyphens_in_label(self):
        # More than one hyphen in a label is fine.
        assert _validate_target("web-app-01.example.com") is None

    def test_punycode_style_label(self):
        # Internationalised domain names use xn-- prefixes.
        # The regex allows them because they are valid ASCII hostname chars.
        assert _validate_target("xn--nxasmq6b.com") is None

    def test_max_length_single_label(self):
        # A single DNS label may be up to 63 characters.
        label = "a" * 63
        assert _validate_target(label) is None

    # ---- malformed hostnames that MUST be rejected -------------------------

    def test_leading_dot_rejected(self):
        # A hostname cannot start with a dot.
        assert _validate_target(".example.com") is not None

    def test_trailing_dot_rejected(self):
        # We reject trailing dots (FQDN-style). Nmap does not need them.
        assert _validate_target("example.com.") is not None

    def test_double_dot_rejected(self):
        # Two consecutive dots means an empty label — invalid.
        assert _validate_target("example..com") is not None

    def test_label_starting_with_hyphen_rejected(self):
        # RFC 952 forbids a label that begins with a hyphen.
        assert _validate_target("-example.com") is not None

    def test_label_ending_with_hyphen_rejected(self):
        # RFC 952 forbids a label that ends with a hyphen.
        assert _validate_target("example-.com") is not None

    def test_interior_label_starts_with_hyphen_rejected(self):
        # The second label starts with a hyphen.
        assert _validate_target("host.-bad.com") is not None

    def test_space_in_hostname_rejected(self):
        # Spaces are never valid in a hostname.
        assert _validate_target("my host.com") is not None

    def test_underscore_in_hostname_rejected(self):
        # Underscores are not valid in hostnames per RFC 952/1123,
        # even though some systems tolerate them. We reject them.
        assert _validate_target("my_host.com") is not None

    def test_slash_in_hostname_rejected(self):
        # A slash would indicate a path, not a hostname.
        assert _validate_target("example.com/path") is not None

    def test_question_mark_rejected(self):
        # Query-string character — not a hostname character.
        assert _validate_target("example.com?q=1") is not None

    def test_hash_rejected(self):
        # Fragment character — not a hostname character.
        assert _validate_target("example.com#section") is not None

    def test_label_too_long_rejected(self):
        # A single DNS label longer than 63 characters is invalid.
        label = "a" * 64
        assert _validate_target(label) is not None

    def test_overall_too_long_rejected(self):
        # Total hostname length > 253 characters is invalid.
        long_host = ("a" * 50 + ".") * 5 + "com"   # well over 253 chars
        assert _validate_target(long_host) is not None


# ===========================================================================

class TestValidateTargetEdgeCases:
    """
    Extra boundary tests for _validate_target() to cover inputs that
    could reach the function from an HTTP request or a misconfigured caller.
    """

    # ---- valid inputs -------------------------------------------------------

    def test_valid_all_zeros_ip(self):
        # 0.0.0.0 is a valid IPv4 address (format-wise).
        assert _validate_target("0.0.0.0") is None

    def test_valid_broadcast_ip(self):
        assert _validate_target("255.255.255.255") is None

    def test_valid_hostname_with_hyphen(self):
        assert _validate_target("my-server") is None

    def test_valid_hostname_with_subdomain(self):
        assert _validate_target("web01.corp.internal") is None

    def test_valid_single_char_hostname(self):
        # Single letter is technically a valid DNS label.
        assert _validate_target("a") is None

    # ---- invalid inputs -----------------------------------------------------

    def test_integer_returns_error(self):
        # Callers should never pass a non-string, but be defensive.
        error = _validate_target(127001)  # type: ignore[arg-type]
        assert error is not None

    def test_list_returns_error(self):
        error = _validate_target(["127.0.0.1"])  # type: ignore[arg-type]
        assert error is not None

    def test_ip_with_port_suffix_returns_error(self):
        # "192.168.1.1:8080" looks like a host+port — not a bare hostname/IP.
        error = _validate_target("192.168.1.1:8080")
        assert error is not None

    def test_ip_with_cidr_returns_error(self):
        # CIDR ranges are not supported by this scanner.
        error = _validate_target("192.168.1.0/24")
        assert error is not None

    def test_hostname_starting_with_hyphen_returns_error(self):
        # RFC 952: hostnames must not start with a hyphen.
        error = _validate_target("-badhost")
        assert error is not None

    def test_hostname_ending_with_hyphen_returns_error(self):
        error = _validate_target("badhost-")
        assert error is not None

    def test_hostname_with_space_returns_error(self):
        error = _validate_target("bad host")
        assert error is not None

    def test_hostname_with_at_sign_returns_error(self):
        # Looks like an email address — not a valid hostname.
        error = _validate_target("user@host.com")
        assert error is not None

    def test_newline_in_target_returns_error(self):
        # A newline in the middle of the target is a clear injection attempt.
        error = _validate_target("127.0.0.1\n--script=exploit")
        assert error is not None

    def test_null_byte_in_target_returns_error(self):
        error = _validate_target("127.0.0.1\x00evil")
        assert error is not None


# ===========================================================================
# 7. LIVE SCAN TESTS  (require Nmap; skipped otherwise)
# ===========================================================================

requires_nmap = pytest.mark.skipif(
    not _nmap_is_available(),
    reason="Nmap is not installed – skipping live scan tests."
)


@requires_nmap
class TestScanTargetLive:
    """
    Smoke tests that run a real (but non-invasive) Nmap scan against localhost.

    These tests ARE skipped when Nmap is not on PATH.
    They MUST only target 127.0.0.1 (localhost). Never add public IPs here.
    """

    def test_localhost_scan_completes(self):
        result = scan_target("127.0.0.1")
        # The scan should either complete or return an error (e.g., no ports open).
        # It must never raise an unhandled exception.
        assert result["status"] in ("completed", "error")

    def test_localhost_result_has_required_keys(self):
        result = scan_target("127.0.0.1")
        assert "target" in result
        assert "status" in result
        assert "findings" in result
        assert "error" in result

    def test_localhost_findings_have_correct_structure(self):
        result = scan_target("127.0.0.1")
        if result["status"] == "completed":
            for finding in result["findings"]:
                assert "id" in finding
                assert "severity" in finding
                assert finding["severity"] == "informational"

