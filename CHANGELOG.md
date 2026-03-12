# Changelog

## [1.18.21] - 2026-03-12

### Fixed
- **Health Check Fix:** Resolved a NameError by adding the missing `jsonify` import in `app.py`, ensuring the `/health` endpoint works correctly for OpenShift probes.

## [1.18.20] - 2026-03-12

### Fixed
- **Health Check Standardization:** Re-enforced /health endpoint across all configuration files and Docker metadata to resolve persistent pod restarts in OpenShift environments.
- **Connection Verification:** Confirmed successful firewall connectivity (HTTP 304/200) after path and method updates.

## [1.18.19] - 2026-03-12

### Fixed
- **Health Check Optimization:** Finalized the /health endpoint and fixed the Docker metadata healthcheck override in Dockerfile.offline to prevent pod crashes in OpenShift.
- **Firewall EDL Stability:** Added HEAD method support and disabled caching for firewall EDL routes to ensure real-time updates and better connector compatibility.

## [1.18.18] - 2026-03-11

### Fixed
- **PostgreSQL Stability:** Added thread-safe locking (`pg_pool_lock`) to prevent race conditions during connection pool initialization.
- **SQL Robustness:** Improved `PostgresCursorWrapper` to handle `INSERT OR IGNORE` (converted to `ON CONFLICT DO NOTHING`) more gracefully, ensuring duplicate key errors are silenced only when explicitly expected.
- **Dependency Cleanup:** Removed `uvloop` from `requirements.txt` to resolve build failures on Python 3.13, favoring standard `asyncio` for better compatibility.
- **Requirements Optimization:** Eliminated duplicate and inconsistent package definitions in `requirements.txt` for cleaner builds.

## [1.18.17] - 2026-03-11

### Added
- **Session-Free API:** Introduced a new `/api/edl/firewall/<filename>` route that bypasses session/MFA requirements. This allows firewalls (FortiGate, Palo Alto) to fetch EDL files without authenticating via a browser session.
- **UI Update:** Updated the Dashboard's "Copy Link" buttons to point to the new session-free firewall routes.

## [1.18.16] - 2026-03-11

### Added
- **EDL View Support:** Added `view=1` parameter to the EDL download routes, allowing users to view the raw list content directly in the browser instead of downloading it.
- **Enhanced Clipboard Integration:** Integrated "Copy Link" icons in the Dashboard EDL table for easier distribution of feed URLs.

## [1.18.15] - 2026-03-11

### Fixed
- **Proxy Authentication:** Implemented automatic URL-encoding for proxy credentials to handle special characters (e.g. '@' in usernames like `user@domain`), resolving 407 authentication errors.
- **Service Whitelists:** Fixed a 500 error when accessing Microsoft/GitHub/Azure lists by adding the missing `format_generic` import in `api.py`.
- **API Key Parsing:** Further refined the regex-based API key extraction to handle redundant "Bearer" prefixes and joined strings from FortiDeceptor.
- **System Settings:** Ensured the `from_json` filter is correctly registered globally in `app.py`.

## [1.18.12] - 2026-03-11

## [2.0.0] - 2026-03-05

### Added
- **FortiDeceptor Integration:** Full webhook support for automatic IP blocking/unblocking from FortiDeceptor honeypots
  - `/api/deceptor/block` endpoint with multi-IP support and customizable expiration
  - `/api/deceptor/unblock` endpoint for removing blocks
  - Automatic tagging of FortiDeceptor-originated indicators
  - Special badge display in dashboard and internal search for FortiDeceptor blocks
- **API Blacklist Expiration:** Time-based automatic expiration of blacklisted items
  - Configurable expiration duration per item
  - Background cleanup task for expired entries
  - Visual expiry timestamp display in UI
- **System Base URL Configuration:** Optional base URL setting for external link generation
  - Used in FortiDeceptor webhook URLs
  - Configurable via System Settings page
- **OpenShift Deployment:** Production-ready Kubernetes/OpenShift deployment manifests
  - Complete YAML configuration with PostgreSQL, Redis, and App containers
  - PVC definitions for persistent storage
  - Security context configurations
  - Health probes (liveness/readiness)
- **Enhanced Internal Search:** Improved investigate tool with FortiDeceptor metadata
  - Shows blacklist comments and expiry info
  - Visual distinction for manual vs automated blocks
- **Comprehensive Test Suite:** 23+ unit tests covering core functionality
  - Parser tests (5/5 passing)
  - Aggregation tests (5/5 passing)
  - Filter tests (10/10 passing)
  - FortiDeceptor integration tests
  - System settings tests
- **Integrations Tab:** New UI section in System Settings for third-party integrations
  - FortiDeceptor configuration wizard
  - Visual simulation of Deceptor webhook settings
  - Copy-to-clipboard for API keys and URLs

### Improved
- **Authentication Robustness:** Enhanced API key authentication to support multiple header formats
  - Support for `Authorization: Bearer <key>` header
  - Support for traditional `X-API-KEY` header
  - Automatic quote stripping for compatibility
  - Better error logging for unauthorized attempts
- **Proxy Configuration:** Enhanced proxy settings for corporate environments
  - URL-encoded credentials support
  - Internal domain bypass (no_proxy for .mfa.gov.tr, private IPs)
  - HTTP fallback for problematic HTTPS proxies
  - More descriptive error messages
- **2FA User Experience:** Improved MFA code input field
  - Auto-focus on page load
  - Input validation for digits only
  - Support for space-separated format
- **Background EDL Regeneration:** Non-blocking file regeneration after API changes
  - Prevents API response delays
  - Triggered automatically on blacklist/whitelist changes

### Fixed
- **Database Schema:** Fixed `api_blacklist` table initialization in test environments
- **Import Paths:** Resolved circular dependency issues in whitelist logic tests
- **Proxy Authentication:** Fixed 407 errors with special characters in credentials
- **MFA Code Length:** Increased input maxlength to accommodate spaces in 2FA codes
- **2FA Logging:** Added warning logs for failed 2FA attempts

### Technical
- **Database Migrations:** Added `expires_at` column to `api_blacklist` table
- **Repository Pattern:** Introduced `get_api_blacklist_item_by_value()` function
- **Connection Management:** Better database transaction handling in repository layer
- **Postgres Compatibility:** Optimized UPSERT operations for both SQLite and PostgreSQL
- **Test Infrastructure:** Created custom test runners bypassing pytest dependency issues

### Documentation
- **Test Reports:** Generated comprehensive Turkish test reports (TEST_RESULTS_FINAL_TR.md)
- **Unit Test Report:** Detailed English test execution report (UNIT_TEST_REPORT.md)
- **Test Status:** Environment compatibility documentation (TEST_STATUS_REPORT.md)

## [1.15.1] - 2026-01-23

### Added
- **MFA for LDAP:** Enabled Two-Factor Authentication support for LDAP users by automatically syncing LDAP profiles to the local database upon first login.
- **Safe List & Block List Editing:** Added the ability to edit existing entries in the Safe List and Block List directly from the dashboard, including type and description/comment updates.

### Improved
- **MFA Reliability:** Added a time-drift window (valid_window=1) to TOTP verification to handle slight clock discrepancies between the server and user devices.
- **MFA Logging:** Implemented detailed logging for MFA enablement and verification attempts to aid troubleshooting.
- **Feed Error Handling:** Enhanced 404 error detection for threat feeds, providing clearer log warnings when sources are offline.

## [1.15.0] - 2026-01-22

### Added
- **DNS Deduplication V2:** Re-architected for performance using background batch processing and database caching to prevent network floods.
- **UI Improvements:** Modernized DNS Deduplication dashboard with live logs, improved settings layout, and real-time status.
- **Security:** Added "Confirm Password" validation field for local user creation and password changes.

### Fixed
- **Startup:** Resolved container startup hang caused by synchronous DB index creation on large tables; moved index creation to background thread.
- **Azure:** Fixed SSL certificate verification error during Azure feed downloads (bypassed verification for compatibility).
- **LDAP:** Fixed invalid server address error by ensuring container uses internal DNS servers.
- **System:** Fixed CSRF token missing error in Group Mapping forms by implementing global token handling.
- **Core:** Fixed missing imports in API routes causing failures in Microsoft 365 feed updates.

## [1.14.1] - 2026-01-16

### Fixed
- **DataTables Layout:** Reverted the pagination layout to the classic bottom-aligned style based on user feedback.
- **Pagination Logic:** Verified and ensured `full_numbers` pagination is used for better navigation on large datasets.
- **Filter Editing:** Fixed an issue where clicking on a filter chip would not populate the correct values in the dropdown if special characters were present.

## [1.14.0] - 2026-01-16

### Added
- **Threat Analysis Center:** A comprehensive new module (`/analysis`) for deep-diving into threat intelligence data.
    - **Advanced Filtering:** FortiGate-style "Filter Bar" allowing multiple criteria (Source, Tag, Type, Country, Risk Level).
    - **Smart Autocomplete:** Dynamic suggestions for filter values.
    - **Auto-Tagging:** Indicators are automatically tagged based on their source.
    - **Risk Scoring:** Visual progress bars for risk scores.
- **Server-Side Pagination:** Implemented efficient database queries (`LIMIT/OFFSET`).

### Optimized
- **Batch Processing:** Optimized the analysis service to use "Batch Source Fetching", solving the N+1 query problem.
- **Memory Management:** Refactored the Whitelist cleanup process.
- **Dashboard Architecture:** Refactored `index.html` to extend the unified `base.html` template.

### Fixed
- **UI Glitches:** Fixed alignment issues in the DataTables "Show entries" dropdown.
- **Filter Logic:** Improved "Risk Score" filtering to support intuitive operators (>=, <, etc.).
- **Navigation:** Fixed the issue where the "Risk Analysis" sidebar link would disappear.

## [1.13.1] - 2026-01-16
