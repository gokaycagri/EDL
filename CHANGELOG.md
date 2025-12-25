# Changelog

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
