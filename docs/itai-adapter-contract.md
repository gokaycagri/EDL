# ITAI Adapter Contract

This document defines the contract between the EDL Flask backend and the ITAI Hub adapter. The adapter is a thin FastAPI proxy in the ITAI repository that maps 28 tools to endpoints in this application.

**If you add or change an API endpoint, the adapter may need updating too.**

## Response Format

The adapter expects this envelope format:
```json
{
  "status": "success",
  "data": { ... },
  "timestamp": "2026-03-16T01:00:00Z"
}
```

The adapter's `_unwrap()` helper extracts the `data` field. If you return a different format, the adapter passes it through as-is.

For errors:
```json
{
  "status": "error",
  "message": "What went wrong"
}
```

## Endpoint → Tool Mapping

### Direct Proxy (adapter passes through without modification)

| Adapter Tool | Method | Your Endpoint | Notes |
|-------------|--------|---------------|-------|
| `get_edl_status` | GET | `/api/status` | Returns aggregation status |
| `get_source_stats` | GET | `/api/source_stats` | Per-source counts |
| `get_trend_data` | GET | `/api/trend_data` | Query param: `days` |
| `get_generic_edl` | GET | `/api/edl/generic` | Query params: `types`, `sources`, `format` |
| `lookup_ip` | POST | `/tools/api/lookup_ip` | JSON body: `{"ip": "..."}` |
| `lookup_internal` | POST | `/tools/api/lookup_internal` | JSON body: `{"indicator": "..."}` |
| `get_job_history` | GET | `/api/history` | Query param: `limit` |
| `get_scheduled_jobs` | GET | `/api/scheduled_jobs` | No params |
| `get_filter_options` | GET | `/analysis/filter-options` | Query param: `column` |
| `test_feed` | POST | `/api/test_feed` | JSON body: `{"url", "format", "name", "key_or_column"}` |
| `get_live_logs` | GET | `/api/live_logs` | No params |

### Custom Handlers (adapter adds logic)

| Adapter Tool | Method | Your Endpoint | Adapter Behavior |
|-------------|--------|---------------|-----------------|
| `search_indicators` | GET | `/analysis/data` | Converts args to DataTables params |
| `run_aggregation` | GET | `/api/run` | Triggers, then polls `/api/status` in background |
| `add_indicator` | POST | `/api/indicators` | Publishes EventBus event after |
| `remove_indicator` | DELETE | `/api/indicators` | Publishes EventBus event after |
| `regenerate_lists` | POST | `/api/regenerate_lists` | Publishes EventBus event after |
| `run_single_source` | GET | `/api/run_single/{source_name}` | Dynamic path segment |
| `update_cloud_feeds` | POST | `/api/update_ms365`, `/api/update_github`, `/api/update_azure` | Parallel calls based on `platform` param |
| `dns_dedup_analyze` | POST | `/tools/api/dns_deduplication/analyze` | Publishes EventBus event after |
| `dns_dedup_schedule` | POST | `/tools/api/dns_deduplication/schedule` | Direct proxy |
| `deceptor_block` | POST | `/api/deceptor/block` | Raw response (no unwrap) |
| `deceptor_unblock` | POST | `/api/deceptor/unblock` | Raw response (no unwrap) |
| `threat_summary` | — | `/api/source_stats` + `/api/trend_data` + `/api/status` | 3 parallel GETs, composed response |
| `risk_assessment` | — | `/tools/api/lookup_internal` + `/tools/api/lookup_ip` | 2 parallel calls |
| `bulk_check` | — | `/tools/api/lookup_internal` (N times) | Up to 20 parallel calls |
| `country_threat_report` | — | `/analysis/data` + `/api/source_stats` | 2 parallel, filtered by country |
| `source_health_report` | — | `/api/history` + `/api/scheduled_jobs` + `/api/source_stats` | 3 parallel GETs |

## Rules for Endpoint Changes

1. **Don't change existing endpoint URLs** — the adapter hardcodes paths
2. **Keep the `{status, data}` envelope** — adapter's `_unwrap()` depends on it
3. **New endpoints must return JSON** — not HTML redirects
4. **API-key-authed endpoints must NOT require CSRF** — they're called by the adapter, not a browser
5. **POST for state changes** — adapter uses GET for reads, POST/DELETE for writes
6. **If adding a new endpoint** that should be exposed as an ITAI tool:
   - Add it here first (this repo)
   - Then update `manifest.json` + `adapter.py` in the ITAI repo
   - Run contract tests: `python -m pytest tests/test_contract.py tests/test_manifest_compat.py -v`

## Authentication

The adapter sends requests with:
- `X-API-KEY` header (from `EDL_API_KEY` env var or Vault)
- `X-ITAI-Trace-ID` header (for distributed tracing)

Your endpoint should authenticate via API key (existing pattern in `routes/api.py`).

## Contract Tests

Run these to verify adapter compatibility:
```bash
# In the EDL repo
python -m pytest tests/test_contract.py tests/test_sso.py tests/test_manifest_compat.py -v
```

These tests verify:
- All endpoints referenced by the manifest exist (not 404)
- SSO JWT verification works correctly
- Response formats match adapter expectations
