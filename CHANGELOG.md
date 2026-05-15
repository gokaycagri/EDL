# Changelog

## [2.2.0] - 2026-05-15

### Added
- **API Mode Feed Fetching:** New `fetch_type: api` option for threat sources enables consuming any paginated REST API (e.g. SGB/USOM zararlı bağlantılar) without provider-specific code.
  - Dot-notation `api_response_path` for extracting nested indicator arrays from complex JSON structures.
  - Configurable pagination: `api_page_param`, `api_page_start`, `api_max_pages`; stops automatically on empty response.
  - Per-source custom HTTP headers (`api_headers`) stored in config for Authorization or custom tokens.
  - Inherits global proxy and SSL-bypass settings automatically.
  - Full UI support in Add/Edit Source modal: "API Mode" toggle reveals response path, headers, and pagination controls.
- **Trend Micro DDEI Integration:** `POST /api/ddei/submit` endpoint for ingesting DDEI-detected indicators.
  - HTTP Basic Authentication using local EDL user accounts.
  - Flexible payload: JSON bulk `{ips, urls}`, JSON single `{type, value}`, indicators array `{indicators:[...]}`, plain-text (newline/comma).
  - Automatically triggers background EDL regeneration on successful ingestion.
  - All submissions recorded in audit log under `ddei_api` user.

### Fixed
- **PostgreSQL RETURNING id:** `INSERT INTO users` with `RETURNING id` no longer fails; cursor correctly handles result fetch before rowcount check.
- **Scheduler startup:** Removed call to non-existent `init_scheduler()`; scheduler now starts via `scheduler.start()` + `update_scheduled_jobs()`.
- **API error response:** Corrected `api_error()` argument order — status code was being passed as the error message.
- **XSS in testSource:** Feed preview content is now HTML-escaped before rendering in SweetAlert2 modal.
- **RBAC coverage:** Added `@permission_required` to 12 write routes that were missing access control enforcement.
- **Password change:** `change_password` validates against the requesting user's account, not always admin.
- **JS deduplication:** Removed duplicate modal helper functions from `dashboard.js`; all source management flows through `source_manager.js`.
- **innerHTML → textContent:** Replaced `innerHTML` with `textContent` for LDAP/DNS/proxy status display to prevent XSS.

### Security
- **CSRF cookie hardening:** `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE=Lax` applied when `FORCE_HTTPS` env var is set. Resolves "CSRF session token is missing" errors when running behind OpenShift/ingress HTTPS proxy.

---

## [1.26.1] - 2026-04-01

### Added
- **Bulk Indicator Delete Module:** New in-app UI card on the dashboard (`POST /system/indicators/bulk_delete`) lets administrators paste a list of IPs, CIDRs, domains, or URLs and delete them from the database in one operation. Optionally removes entries from the block list simultaneously. Requires `system:rw` permission.
- **RFC1918 Private IP Guard:** Defense-in-depth enforcement prevents RFC1918 private IPv4 addresses and CIDRs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) from entering the system. Blocked at ingestion (`indicator_repo`), block list (`whitelist_repo`), feed processing (`feed_processor`), and EDL export (`edl_generator`).

### Security
- **Private IP Ingestion Prevention:** External feeds can no longer introduce RFC1918 private addresses into indicators or block list entries. Existing private records are logged and skipped during EDL generation.
- **Database Cleanup:** One-time SQL migration script (`scripts/cleanup_private_ipv4_postgres.sql`) removes any pre-existing private IP entries.

### Changed
- **Port Mapping:** Host port remapped from `8080` to `8787` in `docker-compose.yml` to free port 8080 for other services.
- **EDL Generator:** Now skips and counts private IPv4 entries during file generation with a `skipped_private` log metric.

### Tests
- Added RFC1918 test coverage across `test_indicator_repo.py`, `test_edl_generator.py`, `test_validate_indicator.py`, `test_blacklist_logic.py`.
- Added `TestBulkIndicatorDelete` class (6 test cases) in `test_system_routes.py`.

## [1.20.1] - 2026-03-16

### Added
- **Dependency Resiliency:** Implemented safe fallback mechanisms for `flask_limiter`, `structlog`, and `prometheus_client` to allow the application to run in environments with restricted internet access.
- **Improved Build Process:** Optimized `Dockerfile.offline` for local builds.

## [1.20.0] - 2026-03-15

### Added
- **Login Rate Limiting:** 10 attempts/minute/IP via Flask-Limiter on `/auth/login`.
- **Audit Logging:** `audit_log` table tracking login, user CRUD, backup downloads, config changes with timestamp, username, IP.
- **Password Complexity:** Minimum 8 chars, uppercase, lowercase, digit required for user creation and password changes.
- **Session Timeout:** Configurable via `SESSION_TIMEOUT_MINUTES` env var (default 60 minutes).
- **Enhanced Health Check:** `/health` now reports DB connection status, scheduler state, job count, aggregation status.
- **Prometheus Metrics:** `/metrics` endpoint with `tfa_indicators_total`, per-type counts, disabled feed count.
- **OpenAPI Documentation:** `/api/docs` serves OpenAPI 3.1 JSON spec with all endpoints, auth schemes, and request/response schemas.
- **Indicator Export:** `GET /analysis/export?format=csv|json` downloads filtered indicators with applied filters.
- **Indicator Tags Table:** `indicator_tags` table for custom per-indicator tagging (schema ready).
- **Read-Only DB Context:** `db_readonly()` context manager for queries that don't need write lock (SQLite WAL concurrent reads).
- **Helm Chart:** Kubernetes deployment chart with PostgreSQL, Redis, PVC, liveness/readiness probes.

### Changed
- **Dependencies:** Added `Flask-Limiter`, `prometheus-client`, `pytest-cov`.
- **Docker:** Expanded `.dockerignore` (tests, docs, caches, markdown files excluded from image).
- **CI Pipeline:** Tests now report coverage via `pytest-cov`.
- **API Spec:** `api_spec.py` with full OpenAPI 3.1 definition.

## [1.19.0] - 2026-03-15

### Security
- **CSRF Protection:** Enabled globally via Flask-WTF CSRFProtect. All HTML forms include CSRF tokens. Machine-to-machine API endpoints (firewall EDL, SOAR, deceptor, SSO) are exempted.
- **Session Fixation:** Session is regenerated (`session.clear()`) on all login paths (local, MFA, SSO) to prevent session fixation attacks.
- **Secret Key:** Removed hardcoded `default_secret_key` fallback. Application generates a random key with a warning if `SECRET_KEY` is not set.
- **Path Traversal:** `/data/<filename>` endpoint now restricts to basename + allowed extensions only.
- **LDAP Injection:** User input is escaped with `escape_filter_chars()` before LDAP filter construction.
- **IP Spoofing:** Removed direct `X-Forwarded-For` header trust in `api_key_required`. Use `request.remote_addr` only.
- **XXE Protection:** XML file import uses `defusedxml` (with fallback to standard ET) to prevent entity expansion attacks.
- **IP Validation:** Investigation tool validates IP format with `ipaddress.ip_address()` before external lookups.
- **JWT Expiry Required:** SSO tokens without `exp` claim are now rejected.
- **SSO Permissions:** SSO endpoint reads `permissions` from JWT payload if available instead of always granting Super_User.
- **Backup Access:** `/api/backup` now requires `system:rw` permission instead of any authenticated session.
- **Sensitive Logging:** Removed full header dumps from API key error logs. TOTP codes no longer logged on failure.
- **Hardcoded Credentials:** Removed `secure_password` fallback from PostgreSQL connection defaults.

### Fixed
- **Destructive GET Endpoints:** `remove_source`, `remove_whitelist`, `remove_blacklist` changed from GET to POST with CSRF tokens.
- **Missing Imports:** Added `update_whitelist_item` and `update_api_blacklist_item` to `system.py` imports (was causing NameError at runtime).
- **SQLite INSERT OR REPLACE:** Changed to `INSERT OR IGNORE` + `UPDATE` to preserve `risk_score` and `source_count` on existing indicators.
- **SQLite VACUUM:** Now runs outside `db_transaction` in autocommit mode (was always failing with OperationalError).
- **SQLite Blacklist Upsert:** Fixed unreachable UPDATE fallback after INSERT failure by using `INSERT OR REPLACE`.
- **Double-Commit:** Removed all explicit `db.commit()` calls from repositories — `db_transaction` context manager is the sole commit owner.
- **Commit Inside Lock:** Moved `conn.commit()` inside SQLite `DB_WRITE_LOCK` scope in `db_transaction`.
- **Deprecated asyncio:** Replaced `asyncio.get_event_loop()` with `asyncio.get_running_loop()` (Python 3.12+ compatibility).
- **aiohttp Timeout:** Changed `timeout=30` to `aiohttp.ClientTimeout(total=30)` (aiohttp 3.x compatibility).
- **aiohttp SSL:** Changed deprecated `verify_ssl=` parameter to `ssl=` in `TCPConnector`.
- **EDL Truncation:** EDL files are now written to `.tmp` files first, then atomically renamed with `os.replace()`. Firewalls never receive empty lists on error.
- **Aggregation Race:** Added `threading.Lock` to `/api/run` endpoint to prevent duplicate aggregation jobs.
- **EDL Regen Race:** Removed redundant `_REGEN_ACTIVE` flag, using only `_REGEN_LOCK.acquire(blocking=False)`.
- **Score Before Cleanup:** Swapped order — whitelist cleanup now runs before `recalculate_scores` to avoid wasting time scoring items that will be deleted.
- **Config Atomicity:** `write_config` writes to temp file then `os.replace()`. `read_config` cache check is fully atomic under lock.
- **Docker Healthcheck:** Fixed port from 5000 to 8080, endpoint from `/status` to `/health`.
- **DNS Domain Extract:** `extract_domain()` returns `None` instead of `"http:"` for unparseable URLs.
- **IntegrityError:** Both `sqlite3.IntegrityError` and `psycopg2.IntegrityError` are now caught in all repositories.
- **Thread Safety:** Added `threading.Lock` to config cache and stats cache for Gunicorn gthread workers.

### Changed
- **SSL Bypass:** Moved hardcoded SSL bypass URLs to config-based `ssl_bypass_hosts` list.
- **Debug Mode:** `app.run(debug=True)` changed to read from `FLASK_DEBUG` env var.
- **Bare Excepts:** All `except:` replaced with `except Exception:` or specific types across the codebase.

### Added
- **Feed Health Monitoring:** Tracks consecutive failures per source. Auto-disables after 3 failures. Dashboard shows red "Disabled" badge with re-enable button. New `GET /api/feed_health` endpoint.
- **Webhook Notifications:** Fire-and-forget HTTP POST to configured webhook URLs on `aggregation_complete`, `feed_disabled` events. Configured via `webhooks` list in `config.json`.
- **Config Validation:** Pydantic schema validation on `read_config()` and `write_config()`. Logs warnings for invalid config, never blocks reads.
- **Structured Logging:** `structlog` integration — JSON output in production (`FLASK_ENV=production`), colored console in development. Existing `logger.info()` calls continue working.
- **Test Infrastructure:** Isolated temp DB per test via `conftest.py` fixtures. New route tests verifying auth, CSRF, permissions, and POST-only endpoints.
- **CI Pipeline:** Added `lint` job with `ruff check` + `bandit` security scan before test job.

### Removed
- **Dead Imports:** Removed unused `output_formatter` imports, `get_existing_ips`, `DB_WRITE_LOCK` from repos/services/schema.
- **Dead Code:** Removed `trigger_background_regeneration()` wrapper. Callers use `regenerate_edl_files()` directly.
- **Redundant Locks:** Removed all outer `DB_WRITE_LOCK` wrappers from repositories, job_repo, auth_manager (handled by `db_transaction`).

### Changed
- **Aggregator Split:** `aggregator.py` split into `edl_generator.py` (EDL file generation), `feed_processor.py` (FeedAggregator class, async processing), and `aggregator.py` (orchestration + re-exports).
- **Unified Upsert:** SQLite and PostgreSQL now use identical `INSERT ... ON CONFLICT DO UPDATE` query. Removed divergent code paths.
- **Dependencies:** Added `defusedxml`, `structlog`, `pydantic` to requirements.txt.

## [1.18.26] - 2026-03-12

### Fixed
- **Dashboard Fix:** Corrected a `NameError` in the dashboard index route where an incorrect variable name was used during scheduler job iteration.

## [1.18.25] - 2026-03-12

### Fixed
- **Scheduler Stability:** Implemented defensive attribute checking (`getattr`) for APScheduler `Job` objects to prevent `AttributeError: next_run_time` during initialization or dashboard refresh.

## [1.18.24] - 2026-03-12

### Changed
- **Maintenance Push:** Iterative update to synchronize latest environment stability fixes and UI improvements across all platforms.

## [1.18.23] - 2026-03-12

### Fixed
- **API Mapping:** Finalized consistency fixes for context/comment field mapping in the `/api/indicators` endpoint.

## [1.18.22] - 2026-03-12

### Added
- **Manual Entries with Context:** Added "Description" field to "Add to Safe List" and "Comment" field to "Add to Block List" modals in the Dashboard. This allows users to provide context and reasons when manually adding indicators.
- **API Consistency:** Updated the `/api/indicators` endpoint to correctly handle context/comments for both whitelist and blacklist actions.

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
