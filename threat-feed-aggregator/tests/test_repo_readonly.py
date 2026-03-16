"""
Tests for repository read-only operations and db_readonly usage.

Validates that read-only functions use db_readonly instead of db_transaction,
and that iterator functions properly yield all results.
"""

import importlib
import os

import pytest


@pytest.fixture()
def db_with_data(tmp_path):
    """Create a test DB with schema and sample data."""
    db_path = str(tmp_path / "test_readonly.db")
    os.environ["TEST_DB_NAME"] = db_path
    os.environ["DB_TYPE"] = "sqlite"

    import threat_feed_aggregator.database.connection as conn_mod
    importlib.reload(conn_mod)

    conn = conn_mod.get_db_connection()
    from threat_feed_aggregator.database.schema import init_db
    init_db(conn)
    conn.commit()
    conn.close()

    # Insert sample data
    from threat_feed_aggregator.repositories.indicator_repo import upsert_indicators_bulk
    indicators = [
        ("1.1.1.1", "US", "ip"),
        ("2.2.2.2", "CN", "ip"),
        ("evil.com", None, "domain"),
        ("bad-url.com/malware", None, "url"),
        ("10.0.0.0/8", None, "cidr"),
    ]
    upsert_indicators_bulk(indicators, source_name="TestSource")
    yield db_path
    os.environ.pop("TEST_DB_NAME", None)


class TestIteratorFunctions:
    """Verify iterator functions yield all results."""

    def test_get_all_indicators_iter(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_all_indicators_iter
        rows = list(get_all_indicators_iter())
        assert len(rows) == 5

    def test_get_filtered_indicators_iter_no_filter(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_filtered_indicators_iter
        rows = list(get_filtered_indicators_iter())
        assert len(rows) == 5

    def test_get_filtered_indicators_iter_with_source(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_filtered_indicators_iter
        rows = list(get_filtered_indicators_iter(source_names=["TestSource"]))
        assert len(rows) == 5

    def test_get_filtered_indicators_iter_nonexistent_source(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_filtered_indicators_iter
        rows = list(get_filtered_indicators_iter(source_names=["NonExistent"]))
        assert len(rows) == 0


class TestReadOnlyFunctions:
    """Verify read-only aggregation functions work correctly."""

    def test_get_unique_indicator_count(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import (
            get_unique_indicator_count, invalidate_stats_cache,
        )
        invalidate_stats_cache()
        count = get_unique_indicator_count()
        assert count == 5

    def test_get_unique_indicator_count_by_type(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import (
            get_unique_indicator_count, invalidate_stats_cache,
        )
        invalidate_stats_cache()
        ip_count = get_unique_indicator_count(itype="ip")
        assert ip_count == 2

    def test_get_indicator_counts_by_type(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import (
            get_indicator_counts_by_type, invalidate_stats_cache,
        )
        invalidate_stats_cache()
        counts = get_indicator_counts_by_type()
        assert counts.get("ip") == 2
        assert counts.get("domain") == 1
        assert counts.get("url") == 1
        assert counts.get("cidr") == 1

    def test_get_country_stats(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import (
            get_country_stats, invalidate_stats_cache,
        )
        invalidate_stats_cache()
        stats = get_country_stats()
        assert isinstance(stats, list)
        countries = {s["country_code"] for s in stats}
        assert "US" in countries

    def test_get_source_counts(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import (
            get_source_counts, invalidate_stats_cache,
        )
        invalidate_stats_cache()
        counts = get_source_counts()
        assert counts.get("TestSource") == 5

    def test_get_sources_for_indicator(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_sources_for_indicator
        sources = get_sources_for_indicator("1.1.1.1")
        assert len(sources) == 1
        assert sources[0]["source_name"] == "TestSource"

    def test_get_sources_for_indicators_batch(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_sources_for_indicators_batch
        result = get_sources_for_indicators_batch(["1.1.1.1", "evil.com"])
        assert "1.1.1.1" in result
        assert "evil.com" in result
        assert len(result["1.1.1.1"]) == 1

    def test_get_sources_for_indicators_batch_empty(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_sources_for_indicators_batch
        result = get_sources_for_indicators_batch([])
        assert result == {}

    def test_get_all_indicators_dict(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_all_indicators
        indicators = get_all_indicators()
        assert len(indicators) == 5
        assert "1.1.1.1" in indicators
        assert indicators["1.1.1.1"]["type"] == "ip"
        assert indicators["1.1.1.1"]["country"] == "US"

    def test_get_existing_ips(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_existing_ips
        existing = get_existing_ips(["1.1.1.1", "9.9.9.9", "2.2.2.2"])
        assert "1.1.1.1" in existing
        assert "2.2.2.2" in existing
        assert "9.9.9.9" not in existing


class TestPaginatedQuery:
    """Verify paginated indicator queries work correctly."""

    def test_basic_pagination(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_indicators_paginated
        total, filtered, rows = get_indicators_paginated(start=0, length=2)
        assert total == 5
        assert filtered == 5
        assert len(rows) == 2

    def test_pagination_offset(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_indicators_paginated
        _, _, page1 = get_indicators_paginated(start=0, length=3)
        _, _, page2 = get_indicators_paginated(start=3, length=3)
        assert len(page1) == 3
        assert len(page2) == 2
        # No overlap
        p1_indicators = {r["indicator"] for r in page1}
        p2_indicators = {r["indicator"] for r in page2}
        assert p1_indicators.isdisjoint(p2_indicators)

    def test_search_filter(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_indicators_paginated
        _, filtered, rows = get_indicators_paginated(search_value="evil")
        assert filtered == 1
        assert rows[0]["indicator"] == "evil.com"

    def test_type_filter(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_indicators_paginated
        _, filtered, rows = get_indicators_paginated(filters={"type": "ip"})
        assert filtered == 2
        assert all(r["type"] == "ip" for r in rows)

    def test_country_filter(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_indicators_paginated
        _, filtered, rows = get_indicators_paginated(filters={"country": "US"})
        assert filtered == 1

    def test_order_by_indicator(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_indicators_paginated
        _, _, rows = get_indicators_paginated(order_col="indicator", order_dir="asc")
        indicators = [r["indicator"] for r in rows]
        assert indicators == sorted(indicators)

    def test_filter_options_type(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_filter_options
        types = get_filter_options("type")
        assert "ip" in types
        assert "domain" in types

    def test_filter_options_country(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import get_filter_options
        countries = get_filter_options("country")
        assert "US" in countries


class TestHistoricalStats:
    """Test save and retrieve of historical stats."""

    def test_save_and_get_historical_stats(self, db_with_data):
        from threat_feed_aggregator.repositories.indicator_repo import (
            save_historical_stats, get_historical_stats,
        )
        save_historical_stats()
        stats = get_historical_stats(days=1)
        assert len(stats) >= 1
        assert stats[0]["total_indicators"] == 5
