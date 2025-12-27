# Changelog

## [1.5.1] - 2025-12-27

### Fixed
- **LDAP Syntax Error:** Fixed a critical `SyntaxError` in `auth_manager.py` related to backslash escaping in f-strings that caused the container to crash loop during startup.
- **Active Directory Parsing:** Corrected the username parsing logic for `DOMAIN\User` formats.

### Added
- **Live LDAP Testing:** Updated the System Settings UI and Backend to allow testing LDAP credentials and server configurations instantly, without needing to save them first.
- **Enhanced Debugging:** Added verbose `[v1.5.1]` logging for LDAP connection attempts to aid in troubleshooting authentication issues.

## [1.5.0] - 2025-12-25

### Added
- **Multi-Client API Access:** Replaced single API key with a robust client management system. Supports generating unique keys for multiple clients (SOAR, SIEM, etc.).
- **Trusted Host Restrictions:** Added ability to restrict API access per client to specific IP addresses.
- **Proxy Support:** Implemented system-wide HTTP/HTTPS proxy configuration (Server, Port, Auth) via System Settings.
- **LDAP Group Authorization:** Added "Admin Group DN" setting to restrict login access to specific LDAP groups.
- **Certificate Management UI:** Improved feedback loops for SSL certificate uploads.
- **Data Normalization:** Automatic lowercase normalization for Domains and standardization for IPs/CIDRs to prevent duplicates.

### Changed
- **API Authentication:** Updated `api_key_required` decorator to validate against the new client list and enforce IP restrictions.
- **Data Parsers:** Enhanced CSV, JSON, and Text parsers to normalize data before database insertion.
- **System Settings UI:** Complete overhaul of the "API Access" card and addition of "Proxy Settings" card.

### Fixed
- **Duplicate Prevention:** Implemented stricter normalization logic to ensure the deduplication mechanism (DB constraints + CIDR aggregation) works flawlessly across all feed sources.

### Operations
- **Docker:** Updated Docker build to include all new dependencies and configuration structures.
