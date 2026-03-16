# Security Policy

## Supported Versions

Security updates are provided for the following versions of Threat Feed Aggregator:

| Version | Supported          |
| ------- | ------------------ |
| 1.9.x   | :white_check_mark: |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

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

The Threat Feed Aggregator includes several enterprise-grade security features:

1.  **Role-Based Access Control (RBAC):** Granular permissions for Dashboard, System, and Tools modules.
2.  **Multi-Client API Management:** Unique API keys for different consumers (SOAR, SIEM) instead of a single global key.
3.  **Trusted Host Enforcement:** Each API client can be restricted to specific source IP addresses.
4.  **CSRF Protection:** All state-changing operations via the web UI are protected by CSRF tokens.
5.  **Non-Root Docker:** The container is designed to run as a non-privileged user (UID 1001) and is compatible with OpenShift arbitrary UIDs.
6.  **Secure Proxy Support:** Centralized proxy configuration ensures all outbound threat intelligence traffic is routed securely.
7.  **Input Validation:** Strict validation for all threat indicators (IP/CIDR/URL) to prevent injection and data corruption.