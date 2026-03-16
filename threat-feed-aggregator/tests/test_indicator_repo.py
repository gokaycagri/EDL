"""Tests for indicator repository — upsert, scoring, cleanup."""
import importlib
import os
import pytest


@pytest.fixture()
def db_with_schema(tmp_path):
    """Create a test DB with full schema."""
    db_path = str(tmp_path / "test_indicators.db")
    os.environ["TEST_DB_NAME"] = db_path
    os.environ["DB_TYPE"] = "sqlite"

    import threat_feed_aggregator.database.connection as conn_mod
    importlib.reload(conn_mod)

    conn = conn_mod.get_db_connection()
    from threat_feed_aggregator.database.schema import init_db
    init_db(conn)
    conn.commit()
    conn.close()
    yield db_path
    os.environ.pop("TEST_DB_NAME", None)


class TestUpsertIndicatorsBulk:
    def test_insert_new_indicators(self, db_with_schema):
        from threat_feed_aggregator.repositories.indicator_repo import upsert_indicators_bulk
        import threat_feed_aggregator.database.connection as conn_mod
        importlib.reload(conn_mod)
        db_transaction = conn_mod.db_transaction

        indicators = [
            ("1.2.3.4", "US", "ip"),
            ("evil.com", None, "domain"),
            ("10.0.0.0/8", None, "cidr"),
        ]
        upsert_indicators_bulk(indicators, source_name="TestSource")

        with db_transaction() as db:
            count = db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            assert count == 3

            sources = db.execute("SELECT COUNT(*) FROM indicator_sources").fetchone()[0]
            assert sources == 3

    def test_upsert_preserves_existing_score(self, db_with_schema):
        from threat_feed_aggregator.repositories.indicator_repo import upsert_indicators_bulk
        import threat_feed_aggregator.database.connection as conn_mod
        importlib.reload(conn_mod)
        db_transaction = conn_mod.db_transaction

        # First insert
        upsert_indicators_bulk([("1.2.3.4", "US", "ip")], source_name="Source1")

        # Manually set a custom score
        with db_transaction() as db:
            db.execute("UPDATE indicators SET risk_score = 90 WHERE indicator = '1.2.3.4'")

        # Second insert (same indicator, different source)
        upsert_indicators_bulk([("1.2.3.4", "US", "ip")], source_name="Source2")

        # Score should be preserved (not reset to 50)
        with db_transaction() as db:
            row = db.execute("SELECT risk_score FROM indicators WHERE indicator = '1.2.3.4'").fetchone()
            assert row[0] == 90

    def test_deduplicates_input(self, db_with_schema):
        from threat_feed_aggregator.repositories.indicator_repo import upsert_indicators_bulk
        import threat_feed_aggregator.database.connection as conn_mod
        importlib.reload(conn_mod)
        db_transaction = conn_mod.db_transaction

        indicators = [
            ("1.2.3.4", "US", "ip"),
            ("1.2.3.4", "US", "ip"),
            ("1.2.3.4", "US", "ip"),
        ]
        upsert_indicators_bulk(indicators, source_name="DupSource")

        with db_transaction() as db:
            count = db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            assert count == 1

    def test_empty_list_noop(self, db_with_schema):
        from threat_feed_aggregator.repositories.indicator_repo import upsert_indicators_bulk
        # Should not raise
        upsert_indicators_bulk([], source_name="Empty")


class TestRecalculateScores:
    def test_score_increases_with_multiple_sources(self, db_with_schema):
        from threat_feed_aggregator.repositories.indicator_repo import upsert_indicators_bulk, recalculate_scores
        import threat_feed_aggregator.database.connection as conn_mod
        importlib.reload(conn_mod)
        db_transaction = conn_mod.db_transaction

        upsert_indicators_bulk([("1.2.3.4", "US", "ip")], source_name="Source1")
        upsert_indicators_bulk([("1.2.3.4", "US", "ip")], source_name="Source2")

        recalculate_scores({"Source1": 80, "Source2": 70})

        with db_transaction() as db:
            row = db.execute("SELECT risk_score, source_count FROM indicators WHERE indicator = '1.2.3.4'").fetchone()
            assert row["source_count"] == 2
            assert row["risk_score"] > 50  # Should be boosted


class TestRemoveOldIndicators:
    def test_removes_expired_indicators(self, db_with_schema):
        from threat_feed_aggregator.repositories.indicator_repo import upsert_indicators_bulk, remove_old_indicators
        import threat_feed_aggregator.database.connection as conn_mod
        importlib.reload(conn_mod)
        db_transaction = conn_mod.db_transaction
        from datetime import datetime, UTC, timedelta

        upsert_indicators_bulk([("old.com", None, "domain")], source_name="OldSource")

        # Manually set last_seen to 60 days ago
        old_date = (datetime.now(UTC) - timedelta(days=60)).isoformat()
        with db_transaction() as db:
            db.execute("UPDATE indicator_sources SET last_seen = ? WHERE source_name = 'OldSource'", (old_date,))

        removed = remove_old_indicators(default_days=30)
        assert removed >= 1

        with db_transaction() as db:
            count = db.execute("SELECT COUNT(*) FROM indicators WHERE indicator = 'old.com'").fetchone()[0]
            assert count == 0


class TestStatsCache:
    def test_cache_invalidation(self, db_with_schema):
        from threat_feed_aggregator.repositories.indicator_repo import (
            get_unique_indicator_count, invalidate_stats_cache, upsert_indicators_bulk
        )

        count1 = get_unique_indicator_count()
        assert count1 == 0

        upsert_indicators_bulk([("test.com", None, "domain")], source_name="CacheTest")
        invalidate_stats_cache()

        count2 = get_unique_indicator_count()
        assert count2 == 1
