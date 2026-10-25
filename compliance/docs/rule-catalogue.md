# Rule Catalogue

| ID | Name | Severity | Evidence required | Cannot prove |
|---|---|---|---|---|
| R-001 | Telnet service exposed | high | Scanner reports 23/tcp open with service telnet | That credentials are weak or the service is exploitable |
| R-002 | FTP service exposed | medium | Scanner reports 21/tcp open with service ftp | That anonymous login is enabled or that data is exposed |
| R-003 | HTTP service without observed HTTPS | low | Scanner reports 80/tcp open with service http | That sensitive data is actually transmitted over HTTP |
| R-004 | SMB service exposed | medium | Scanner reports 445/tcp open | That the SMB version is vulnerable or that shares are open |
| R-005 | RDP service exposed | medium | Scanner reports 3389/tcp open | That authentication is weak or the host is compromised |
| R-006 | SSH service detected | informational | Scanner reports 22/tcp open with service ssh | That the SSH configuration is secure or insecure |
| R-007 | Database service port exposed | medium | Scanner reports a common database port open | That the database is unauthenticated or contains sensitive data |
| R-008 | Legacy r-service exposed (rexec/rlogin/rsh) | high | Scanner reports 512, 513 or 514/tcp open | That the service accepts trusted-host logins or is exploitable |
| R-009 | Service on unexpected port | informational | Scanner identifies a known service on a non-standard port | That the placement is unauthorized or malicious |
| R-010 | Service version banner detected | informational | Scanner reports a service version string | That the version is outdated or vulnerable |
