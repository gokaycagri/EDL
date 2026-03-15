# Security Policy

## Supported Versions

Security updates are provided for the following versions of Threat Feed Aggregator:

| Version | Supported          |
| ------- | ------------------ |
| 1.19.x  | :white_check_mark: |
| 1.18.x  | :white_check_mark: |
| < 1.18  | :x:                |

## Reporting a Vulnerability

We take the security of this project seriously. If you believe you have found a security vulnerability, please report it to us responsibly.

**Please do not report security vulnerabilities via public GitHub issues.**

### How to Report
Please send an email to the project maintainer (see [README.md](README.md) for contact info) or use the GitHub "Private Vulnerability Reporting" feature if enabled.

In your report, please include:
- A description of the vulnerability.
- Steps to reproduce the issue (PoC).
- Potential impact if exploited.

### What to Expect
- **Acknowledgement:** You will receive an acknowledgement of your report within 48 hours.
- **Evaluation:** We will investigate and validate the vulnerability.
- **Fix:** If validated, we will work on a fix and release a new version.
- **Disclosure:** We will coordinate with you on a public disclosure date once the fix is available.

## Built-in Security Features

The Threat Feed Aggregator includes the following security features:

1.  **CSRF Protection:** Global CSRF enforcement via Flask-WTF CSRFProtect. All HTML forms and AJAX calls include CSRF tokens. Machine-to-machine API endpoints are selectively exempted.
2.  **Session Security:** Sessions are regenerated on login to prevent session fixation. Cookie signing via `SESSION_USE_SIGNER`.
3.  **Role-Based Access Control (RBAC):** Granular permissions for Dashboard, System, Tools, and Analysis modules.
4.  **Multi-Factor Authentication (MFA):** TOTP-based 2FA compatible with Google/Microsoft Authenticator.
5.  **Multi-Client API Management:** Unique API keys for different consumers (SOAR, SIEM) with IP allowlist enforcement.
6.  **LDAP Injection Prevention:** All user input is escaped before LDAP filter construction.
7.  **Input Validation:** IP addresses validated with `ipaddress` module. Indicators validated before DB insertion.
8.  **Path Traversal Prevention:** File download endpoint restricts to basename with extension allowlist.
9.  **XXE Protection:** XML file imports use `defusedxml` to prevent entity expansion attacks.
10. **Atomic File Writes:** EDL files and config are written to temp files first, then renamed — prevents serving partial/empty data.
11. **Non-Root Docker:** Container runs as non-privileged user (UID 1001), compatible with OpenShift arbitrary UIDs.
12. **Secure Proxy Support:** Centralized proxy configuration for all outbound traffic.
13. **JWT Token Security:** SSO tokens require `exp` claim. Signature verified with constant-time comparison.
14. **No Sensitive Logging:** API keys, TOTP codes, and request headers are not logged.
