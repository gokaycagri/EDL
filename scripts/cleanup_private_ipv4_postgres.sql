-- Cleanup script for RFC1918 private IPv4 indicators in PostgreSQL.
-- Removes private IPv4 IP/CIDR entries from indicators and api_blacklist.
-- Safe to run multiple times.

-- Preview current counts before cleanup.
SELECT
  (SELECT COUNT(*) FROM indicators i
   WHERE i.type IN ('ip', 'cidr')
     AND family(i.indicator::inet) = 4
     AND (
       i.indicator::inet <<= inet '10.0.0.0/8'
       OR i.indicator::inet <<= inet '172.16.0.0/12'
       OR i.indicator::inet <<= inet '192.168.0.0/16'
     )) AS private_indicators_before,
  (SELECT COUNT(*) FROM api_blacklist b
   WHERE b.type IN ('ip', 'cidr')
     AND family(b.item::inet) = 4
     AND (
       b.item::inet <<= inet '10.0.0.0/8'
       OR b.item::inet <<= inet '172.16.0.0/12'
       OR b.item::inet <<= inet '192.168.0.0/16'
     )) AS private_blacklist_before;

BEGIN;

CREATE TEMP TABLE tmp_private_indicators ON COMMIT DROP AS
SELECT i.indicator
FROM indicators i
WHERE i.type IN ('ip', 'cidr')
  AND family(i.indicator::inet) = 4
  AND (
    i.indicator::inet <<= inet '10.0.0.0/8'
    OR i.indicator::inet <<= inet '172.16.0.0/12'
    OR i.indicator::inet <<= inet '192.168.0.0/16'
  );

CREATE TEMP TABLE tmp_private_blacklist ON COMMIT DROP AS
SELECT b.item
FROM api_blacklist b
WHERE b.type IN ('ip', 'cidr')
  AND family(b.item::inet) = 4
  AND (
    b.item::inet <<= inet '10.0.0.0/8'
    OR b.item::inet <<= inet '172.16.0.0/12'
    OR b.item::inet <<= inet '192.168.0.0/16'
  );

DELETE FROM indicator_sources s
USING tmp_private_indicators p
WHERE s.indicator = p.indicator;

DELETE FROM indicators i
USING tmp_private_indicators p
WHERE i.indicator = p.indicator;

DELETE FROM api_blacklist b
USING tmp_private_blacklist p
WHERE b.item = p.item;

COMMIT;

-- Verify counts after cleanup.
SELECT
  (SELECT COUNT(*) FROM indicators i
   WHERE i.type IN ('ip', 'cidr')
     AND family(i.indicator::inet) = 4
     AND (
       i.indicator::inet <<= inet '10.0.0.0/8'
       OR i.indicator::inet <<= inet '172.16.0.0/12'
       OR i.indicator::inet <<= inet '192.168.0.0/16'
     )) AS private_indicators_after,
  (SELECT COUNT(*) FROM api_blacklist b
   WHERE b.type IN ('ip', 'cidr')
     AND family(b.item::inet) = 4
     AND (
       b.item::inet <<= inet '10.0.0.0/8'
       OR b.item::inet <<= inet '172.16.0.0/12'
       OR b.item::inet <<= inet '192.168.0.0/16'
     )) AS private_blacklist_after;
