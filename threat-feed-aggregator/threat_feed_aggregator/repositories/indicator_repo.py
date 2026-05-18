from datetime import UTC, datetime, timedelta
import logging
import os
import threading
import time

from ..database.connection import DB_TYPE, db_readonly, db_transaction, get_db_connection

logger = logging.getLogger(__name__)

# --- CACHING LOGIC ---

_STATS_CACHE = {}
_STATS_CACHE_TTL = 300  # 5 minutes
_STATS_CACHE_LOCK = threading.Lock()


def invalidate_stats_cache():
    """Invalidates the in-memory stats cache."""
    with _STATS_CACHE_LOCK:
        _STATS_CACHE.clear()
    logger.debug("Stats cache invalidated.")


def _get_cached_stat(key, fetch_func, *args, **kwargs):
    """Helper to get a stat from cache or fetch it."""
    now = time.time()

    with _STATS_CACHE_LOCK:
        if key in _STATS_CACHE:
            val, timestamp = _STATS_CACHE[key]
            if now - timestamp < _STATS_CACHE_TTL:
                return val

    # Cache miss — fetch outside lock to avoid holding it during DB query
    val = fetch_func(*args, **kwargs)
    with _STATS_CACHE_LOCK:
        _STATS_CACHE[key] = (val, now)
    return val


# --- SCORING & UPSERT LOGIC ---


def upsert_indicators_bulk(indicators, source_name="Unknown", conn=None):
    """
    Highly optimized bulk upsert with scoring logic and chunking.
    indicators: list of (indicator, country, type)
    """
    if not indicators:
        return

    # Deduplicate input list
    unique_indicators_map = {item[0]: item for item in indicators}
    deduplicated_indicators = list(unique_indicators_map.values())

    # Safety guard: never ingest RFC1918 private IPv4 IP/CIDR indicators from feeds.
    from ..utils import is_rfc1918_private_ipv4_indicator

    filtered_indicators = [
        item for item in deduplicated_indicators if not is_rfc1918_private_ipv4_indicator(item[0], item[2])
    ]

    private_dropped = len(deduplicated_indicators) - len(filtered_indicators)
    if private_dropped:
        logger.warning(
            "[%s] Skipped %s RFC1918 private IPv4 indicators during bulk upsert.",
            source_name,
            private_dropped,
        )

    if not filtered_indicators:
        return

    CHUNK_SIZE = 5000  # Process in batches
    now_iso = datetime.now(UTC).isoformat()

    with db_transaction(conn) as db:
        try:
            # Create temp table
            db.execute(
                "CREATE TEMPORARY TABLE IF NOT EXISTS temp_bulk_indicators (indicator TEXT, country TEXT, type TEXT)"
            )

            for i in range(0, len(filtered_indicators), CHUNK_SIZE):
                chunk = filtered_indicators[i : i + CHUNK_SIZE]
                db.execute("DELETE FROM temp_bulk_indicators")
                db.executemany("INSERT INTO temp_bulk_indicators VALUES (?, ?, ?)", chunk)

                if DB_TYPE == "postgres":
                    db.execute(
                        """
                        INSERT INTO indicators (indicator, last_seen, country, type, risk_score, source_count)
                        SELECT indicator, %s, country, type, 50, 1 FROM temp_bulk_indicators
                        ON CONFLICT (indicator) DO UPDATE SET last_seen = EXCLUDED.last_seen
                    """,
                        (now_iso,),
                    )
                    db.execute(
                        """
                        INSERT INTO indicator_sources (indicator, source_name, last_seen)
                        SELECT indicator, %s, %s FROM temp_bulk_indicators
                        ON CONFLICT (indicator, source_name) DO UPDATE SET last_seen = EXCLUDED.last_seen
                    """,
                        (source_name, now_iso),
                    )
                else:
                    # SQLite: INSERT OR IGNORE + UPDATE (ON CONFLICT not supported with SELECT subquery)
                    db.execute(
                        """
                        INSERT OR IGNORE INTO indicators (indicator, last_seen, country, type, risk_score, source_count)
                        SELECT indicator, ?, country, type, 50, 1 FROM temp_bulk_indicators
                    """,
                        (now_iso,),
                    )
                    db.execute(
                        """
                        UPDATE indicators SET last_seen = ?
                        WHERE indicator IN (SELECT indicator FROM temp_bulk_indicators)
                    """,
                        (now_iso,),
                    )
                    db.execute(
                        """
                        INSERT OR IGNORE INTO indicator_sources (indicator, source_name, last_seen)
                        SELECT indicator, ?, ? FROM temp_bulk_indicators
                    """,
                        (source_name, now_iso),
                    )
                    db.execute(
                        """
                        UPDATE indicator_sources SET last_seen = ?
                        WHERE source_name = ? AND indicator IN (SELECT indicator FROM temp_bulk_indicators)
                    """,
                        (now_iso, source_name),
                    )

            invalidate_stats_cache()
            logger.info(f"Bulk upsert completed for {source_name}: {len(filtered_indicators)} items.")
        except Exception as e:
            logger.error(f"Error bulk upserting for {source_name}: {e}")
            raise


def recalculate_scores(source_confidence_map=None, conn=None, target_source=None):
    if source_confidence_map is None:
        source_confidence_map = {}
    with db_transaction(conn) as db:
        try:
            count_where = ""
            count_params = []
            if target_source:
                count_where = (
                    "WHERE indicators.indicator IN (SELECT indicator FROM indicator_sources WHERE source_name = ?)"
                )
                count_params = [target_source]

            db.execute(
                f"UPDATE indicators SET source_count = (SELECT COUNT(*) FROM indicator_sources WHERE indicator_sources.indicator = indicators.indicator) {count_where}",
                count_params,
            )
            db.execute("CREATE TEMPORARY TABLE IF NOT EXISTS temp_source_conf (name TEXT PRIMARY KEY, score INTEGER)")
            db.execute("DELETE FROM temp_source_conf")

            conf_data = list(source_confidence_map.items())
            if conf_data:
                db.executemany("INSERT INTO temp_source_conf VALUES (?, ?)", conf_data)

            score_where = "WHERE EXISTS (SELECT 1 FROM indicator_sources WHERE indicator = indicators.indicator)"
            score_params = []
            if target_source:
                score_where = (
                    "WHERE indicators.indicator IN (SELECT indicator FROM indicator_sources WHERE source_name = ?)"
                )
                score_params = [target_source]

            if DB_TYPE == "postgres":
                score_calc = (
                    "LEAST(100, GREATEST(MAX(COALESCE(sc.score, 50)), 0) + ((indicators.source_count - 1) * 5))"
                )
            else:
                score_calc = "MIN(100, MAX(COALESCE(sc.score, 50)) + ((indicators.source_count - 1) * 5))"

            query = f"UPDATE indicators SET risk_score = (SELECT {score_calc} FROM indicator_sources src LEFT JOIN temp_source_conf sc ON src.source_name = sc.name WHERE src.indicator = indicators.indicator) {score_where}"
            db.execute(query, score_params)
            invalidate_stats_cache()
        except Exception as e:
            logger.error(f"Score error: {e}")
            raise


def get_all_indicators(conn=None):
    with db_readonly() as db:
        cursor = db.execute("SELECT indicator, last_seen, country, type, risk_score, source_count FROM indicators")
        return {
            row["indicator"]: {
                "last_seen": row["last_seen"],
                "country": row["country"],
                "type": row["type"],
                "risk_score": row["risk_score"],
                "source_count": row["source_count"],
            }
            for row in cursor.fetchall()
        }


def clean_database_vacuum(conn=None):
    """Performs VACUUM to shrink DB size and optimize indexes."""
    if DB_TYPE == "sqlite":
        # VACUUM cannot run inside a transaction in SQLite — use a raw connection in autocommit
        import sqlite3 as _sqlite3

        from ..config_manager import DATA_DIR
        from ..constants import DB_TIMEOUT

        db_path = os.getenv("TEST_DB_NAME") or os.path.join(DATA_DIR, "threat_feed.db")
        raw_conn = _sqlite3.connect(db_path, timeout=DB_TIMEOUT)
        try:
            raw_conn.isolation_level = None
            raw_conn.execute("VACUUM")
            logger.info("Database vacuumed and optimized.")
        finally:
            raw_conn.close()
    else:
        with db_transaction(conn) as db:
            db.execute("VACUUM")
            logger.info("Database vacuumed and optimized.")


def get_all_indicators_iter(conn=None):
    """Fetches ALL indicators. Uses fetchall() to ensure all rows are loaded
    while the DB connection is still open (critical for PostgreSQL pool + background threads)."""
    db = conn or get_db_connection()
    try:
        cursor = db.execute("SELECT indicator, last_seen, country, type, risk_score, source_count FROM indicators")
        rows = cursor.fetchall()  # Fetch ALL before releasing connection
        logger.debug(f"get_all_indicators_iter: fetched {len(rows)} rows from indicators table.")
    finally:
        if conn is None:
            db.close()
    yield from rows


def get_filtered_indicators_iter(source_names=None, conn=None):
    """Fetches indicators filtered by source names. Uses fetchall() to ensure all rows are loaded
    while the DB connection is still open (critical for PostgreSQL pool + background threads)."""
    db = conn or get_db_connection()
    try:
        if not source_names:
            cursor = db.execute("SELECT indicator, last_seen, country, type, risk_score, source_count FROM indicators")
        else:
            placeholders = ",".join(["?"] * len(source_names))
            # Use explicit columns (not i.*) for PostgreSQL DictCursor compatibility
            cursor = db.execute(
                f"SELECT DISTINCT i.indicator, i.last_seen, i.country, i.type, i.risk_score, i.source_count "
                f"FROM indicators i JOIN indicator_sources s ON i.indicator = s.indicator "
                f"WHERE s.source_name IN ({placeholders})",
                source_names,
            )
        rows = cursor.fetchall()  # Fetch ALL before releasing connection
        logger.debug(f"get_filtered_indicators_iter: fetched {len(rows)} rows (sources={source_names}).")
    finally:
        if conn is None:
            db.close()
    yield from rows


def remove_old_indicators(source_retention_map=None, default_days=30, conn=None):
    if source_retention_map is None:
        source_retention_map = {}
    with db_transaction(conn) as db:
        try:
            now = datetime.now(UTC)
            cursor = db.execute("SELECT DISTINCT source_name FROM indicator_sources")
            for row in cursor.fetchall():
                src = row["source_name"]
                cutoff = now - timedelta(days=source_retention_map.get(src, default_days))
                db.execute(
                    "DELETE FROM indicator_sources WHERE source_name = ? AND last_seen < ?", (src, cutoff.isoformat())
                )

            cur = db.execute(
                "DELETE FROM indicators WHERE indicator NOT IN (SELECT DISTINCT indicator FROM indicator_sources)"
            )
            invalidate_stats_cache()
            return cur.rowcount
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
            return 0


def get_unique_indicator_count(itype=None, conn=None):
    def _fetch(t, c):
        with db_readonly() as db:
            if t:
                return db.execute("SELECT COUNT(*) FROM indicators WHERE type = ?", (t,)).fetchone()[0]
            return db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]

    return _get_cached_stat(f"unique_count_{itype}", _fetch, itype, conn)


def get_indicator_counts_by_type(conn=None):
    def _fetch(c):
        with db_readonly() as db:
            return {
                row["type"]: row["count"]
                for row in db.execute("SELECT type, COUNT(*) as count FROM indicators GROUP BY type").fetchall()
            }

    return _get_cached_stat("counts_by_type", _fetch, conn)


def get_country_stats(conn=None):
    def _fetch(c):
        with db_readonly() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT COALESCE(country, 'Unknown') as country_code, COUNT(*) as count FROM indicators WHERE type = 'ip' GROUP BY country_code ORDER BY count DESC LIMIT 250"
                ).fetchall()
            ]

    return _get_cached_stat("country_stats", _fetch, conn)


def save_historical_stats(conn=None):
    with db_transaction(conn) as db:
        try:
            total = db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            counts = {
                row[0]: row[1] for row in db.execute("SELECT type, COUNT(*) FROM indicators GROUP BY type").fetchall()
            }
            db.execute(
                "INSERT INTO stats_history (timestamp, total_indicators, ip_count, domain_count, url_count) VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.now(UTC).isoformat(),
                    total,
                    counts.get("ip", 0) + counts.get("cidr", 0),
                    counts.get("domain", 0),
                    counts.get("url", 0),
                ),
            )
        except Exception as e:
            logger.error(f"History error: {e}")


def get_historical_stats(days=30, conn=None):
    with db_readonly() as db:
        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        return [
            dict(row)
            for row in db.execute(
                "SELECT * FROM stats_history WHERE timestamp > ? ORDER BY timestamp ASC", (cutoff,)
            ).fetchall()
        ]


def get_source_counts(conn=None):
    def _fetch(c):
        with db_readonly() as db:
            return {
                row["source_name"]: row["count"]
                for row in db.execute(
                    "SELECT source_name, COUNT(*) as count FROM indicator_sources GROUP BY source_name"
                ).fetchall()
            }

    return _get_cached_stat("source_counts", _fetch, conn)


def get_sources_for_indicator(indicator, conn=None):
    with db_readonly() as db:
        return [
            dict(row)
            for row in db.execute(
                "SELECT source_name, last_seen FROM indicator_sources WHERE indicator = ? ORDER BY last_seen DESC",
                (indicator,),
            ).fetchall()
        ]


def get_sources_for_indicators_batch(indicators, conn=None):
    if not indicators:
        return {}
    with db_readonly() as db:
        placeholders = ",".join(["?"] * len(indicators))
        res = {ind: [] for ind in indicators}
        for row in db.execute(
            f"SELECT indicator, source_name, last_seen FROM indicator_sources WHERE indicator IN ({placeholders})",
            indicators,
        ).fetchall():
            res[row["indicator"]].append({"source_name": row["source_name"], "last_seen": row["last_seen"]})
        return res


def get_indicators_paginated(
    start=0, length=10, search_value=None, filters=None, order_col="risk_score", order_dir="desc", conn=None
):
    with db_readonly() as db:
        base_query = (
            "SELECT DISTINCT i.indicator, i.type, i.country, i.risk_score, i.source_count, i.last_seen, "
            "sgb.sgb_desc, sgb.sgb_source, sgb.sgb_date, sgb.sgb_criticality "
            "FROM indicators i LEFT JOIN sgb_metadata sgb ON i.indicator = sgb.indicator"
        )
        count_query = "SELECT COUNT(DISTINCT i.indicator) FROM indicators i"
        joins, conds, params = [], [], []

        if search_value:
            conds.append("(i.indicator LIKE ? OR i.country LIKE ? OR i.type LIKE ?)")
            p = f"%{search_value}%"
            params.extend([p, p, p])

        if filters:
            for col, val in filters.items():
                if not val:
                    continue
                if col == "type":
                    conds.append("i.type = ?")
                    params.append(val)
                elif col == "country":
                    conds.append("i.country LIKE ?")
                    params.append(f"%{val}%")
                elif col == "level":
                    if val == "Critical":
                        conds.append("i.risk_score >= 90")
                    elif val == "High":
                        conds.append("i.risk_score >= 70 AND i.risk_score < 90")
                    elif val == "Medium":
                        conds.append("i.risk_score >= 40 AND i.risk_score < 70")
                    elif val == "Low":
                        conds.append("i.risk_score < 40")
                elif col == "risk_score":
                    v = str(val).strip()
                    op = ">="
                    if v.startswith(">="):
                        op, v = ">=", v[2:]
                    elif v.startswith("<="):
                        op, v = "<=", v[2:]
                    elif v.startswith(">"):
                        op, v = ">", v[1:]
                    elif v.startswith("<"):
                        op, v = "<", v[1:]
                    elif v.startswith("="):
                        op, v = "=", v[1:]
                    try:
                        conds.append(f"i.risk_score {op} ?")
                        params.append(int(v))
                    except (ValueError, TypeError):
                        pass
                elif col == "source":
                    if "JOIN indicator_sources s" not in joins:
                        joins.append("JOIN indicator_sources s ON i.indicator = s.indicator")
                    conds.append("s.source_name LIKE ?")
                    params.append(f"%{val}%")
                elif col == "tag":
                    if "JOIN indicator_sources s" not in joins:
                        joins.append("JOIN indicator_sources s ON i.indicator = s.indicator")
                    vl = val.lower()
                    if "botnet" in vl:
                        conds.append("s.source_name LIKE '%feodo%'")
                    elif "malware" in vl:
                        conds.append("s.source_name LIKE '%urlhaus%'")
                    else:
                        conds.append("s.source_name LIKE ?")
                        params.append(f"%{val}%")
                elif col == "sgb_desc":
                    conds.append("sgb.sgb_desc = ?")
                    params.append(val.upper())
                elif col == "sgb_source":
                    conds.append("sgb.sgb_source = ?")
                    params.append(val.upper())
                elif col == "sgb_criticality":
                    try:
                        conds.append("sgb.sgb_criticality = ?")
                        params.append(int(val))
                    except (ValueError, TypeError):
                        pass

        if joins:
            j = " " + " ".join(joins)
            base_query += j
            count_query += j
        # If any SGB filter is active, count_query also needs the LEFT JOIN
        if any(c.startswith("sgb.") for c in conds) and "LEFT JOIN sgb_metadata" not in count_query:
            count_query += " LEFT JOIN sgb_metadata sgb ON i.indicator = sgb.indicator"
        if conds:
            w = " WHERE " + " AND ".join(conds)
            base_query += w
            count_query += w

        total_records = db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
        filtered_records = db.execute(count_query, params).fetchone()[0] if conds else total_records

        cols = {
            "indicator": "i.indicator",
            "type": "i.type",
            "country": "i.country",
            "risk_score": "i.risk_score",
            "source_count": "i.source_count",
            "last_seen": "i.last_seen",
        }
        safe_dir = "asc" if order_dir.lower() == "asc" else "desc"
        base_query += f" ORDER BY {cols.get(order_col, 'i.risk_score')} {safe_dir} LIMIT ? OFFSET ?"
        params.extend([length, start])

        return total_records, filtered_records, [dict(row) for row in db.execute(base_query, params).fetchall()]


def get_filter_options(column, search_term=None, limit=20, conn=None):
    with db_readonly() as db:
        p = f"%{search_term}%" if search_term else "%"
        if column == "source":
            return [
                row[0]
                for row in db.execute(
                    "SELECT DISTINCT source_name FROM indicator_sources WHERE source_name LIKE ? ORDER BY source_name LIMIT ?",
                    (p, limit),
                ).fetchall()
            ]
        if column == "country":
            return [
                row[0]
                for row in db.execute(
                    "SELECT DISTINCT country FROM indicators WHERE country LIKE ? ORDER BY country LIMIT ?", (p, limit)
                ).fetchall()
                if row[0]
            ]
        if column == "type":
            return [
                row[0]
                for row in db.execute(
                    "SELECT DISTINCT type FROM indicators WHERE type LIKE ? ORDER BY type LIMIT ?", (p, limit)
                ).fetchall()
            ]
        if column in ("sgb_desc", "sgb_source"):
            return [
                row[0]
                for row in db.execute(
                    f"SELECT DISTINCT {column} FROM sgb_metadata WHERE {column} LIKE ? LIMIT ?", (p, limit)
                ).fetchall()
                if row[0]
            ]
        if column == "sgb_criticality":
            return [
                str(row[0])
                for row in db.execute(
                    "SELECT DISTINCT sgb_criticality FROM sgb_metadata WHERE sgb_criticality IS NOT NULL ORDER BY sgb_criticality"
                ).fetchall()
            ]
        return []


def upsert_sgb_metadata(metadata_map: dict, conn=None):
    """Upsert SGB-specific metadata for indicators."""
    if not metadata_map:
        return
    rows = [
        (ind, m.get("sgb_desc"), m.get("sgb_source"), m.get("sgb_date"), m.get("sgb_criticality"))
        for ind, m in metadata_map.items()
        if m
    ]
    if not rows:
        return
    with db_transaction(conn) as db:
        if DB_TYPE == "postgres":
            db.executemany(
                """
                INSERT INTO sgb_metadata (indicator, sgb_desc, sgb_source, sgb_date, sgb_criticality)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (indicator) DO UPDATE SET
                    sgb_desc=EXCLUDED.sgb_desc, sgb_source=EXCLUDED.sgb_source,
                    sgb_date=EXCLUDED.sgb_date, sgb_criticality=EXCLUDED.sgb_criticality
                """,
                rows,
            )
        else:
            db.executemany(
                """
                INSERT OR REPLACE INTO sgb_metadata
                    (indicator, sgb_desc, sgb_source, sgb_date, sgb_criticality)
                VALUES (?, ?, ?, ?, ?)
                """,
                rows,
            )
    logger.info("Saved SGB metadata for %d indicators.", len(rows))


def update_dns_cache_batch(results, conn=None):
    with db_transaction(conn) as db:
        q = "INSERT INTO dns_resolution_cache (domain, resolved_ips, last_resolved) VALUES (?, ?, ?) ON CONFLICT(domain) DO UPDATE SET resolved_ips=EXCLUDED.resolved_ips, last_resolved=EXCLUDED.last_resolved"
        if DB_TYPE == "postgres":
            q = q.replace("?", "%s")
        db.executemany(q, [(r["domain"], r["resolved_ips"], r["last_resolved"]) for r in results])


def get_domains_for_resolution(limit=100, retry_days=7, conn=None):
    with db_readonly() as db:
        cutoff = (datetime.now(UTC) - timedelta(days=retry_days)).isoformat()
        q = "SELECT i.indicator, i.type FROM indicators i LEFT JOIN dns_resolution_cache c ON i.indicator = c.domain WHERE (i.type = 'domain' OR i.type = 'url') AND (c.domain IS NULL OR c.last_resolved < ?) LIMIT ?"
        return [{"indicator": r[0], "type": r[1]} for r in db.execute(q, (cutoff, limit)).fetchall()]


def get_dns_resolution_cache_iter(conn=None):
    db = conn or get_db_connection()
    try:
        cursor = db.execute("SELECT domain, resolved_ips FROM dns_resolution_cache")
        yield from cursor
    finally:
        if conn is None:
            db.close()


def delete_indicators(indicators_list, conn=None):
    if not indicators_list:
        return 0
    with db_transaction(conn) as db:
        p = ",".join(["?"] * len(indicators_list))
        db.execute(f"DELETE FROM indicator_sources WHERE indicator IN ({p})", indicators_list)
        cur = db.execute(f"DELETE FROM indicators WHERE indicator IN ({p})", indicators_list)
        invalidate_stats_cache()
        return cur.rowcount


def get_existing_ips(ip_list, conn=None):
    if not ip_list:
        return set()
    with db_readonly() as db:
        existing = set()
        for i in range(0, len(ip_list), 900):
            chunk = ip_list[i : i + 900]
            p = ",".join(["?"] * len(chunk))
            existing.update(
                row[0]
                for row in db.execute(
                    f"SELECT indicator FROM indicators WHERE type='ip' AND indicator IN ({p})", chunk
                ).fetchall()
            )
        return existing
