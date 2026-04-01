"""Tests for EDL file generation."""
import os
import pytest
from unittest.mock import patch, MagicMock


class TestRegenerateEdlFiles:
    @patch("threat_feed_aggregator.edl_generator.get_api_blacklist_items")
    @patch("threat_feed_aggregator.edl_generator.get_all_indicators_iter")
    def test_creates_all_files(self, mock_iter, mock_blacklist, tmp_path, monkeypatch):
        """Verify all 5 EDL files + 2 legacy files are created."""
        monkeypatch.setattr("threat_feed_aggregator.edl_generator.DATA_DIR", str(tmp_path))

        mock_iter.return_value = iter([
            {"indicator": "1.2.3.4", "type": "ip"},
            {"indicator": "evil.com", "type": "domain"},
            {"indicator": "http://bad.com/malware", "type": "url"},
            {"indicator": "10.0.0.0/8", "type": "cidr"},
        ])
        mock_blacklist.return_value = [
            {"item": "5.6.7.8", "type": "ip"},
            {"item": "blocked.com", "type": "domain"},
        ]

        from threat_feed_aggregator.edl_generator import regenerate_edl_files, _REGEN_LOCK
        # Ensure lock is free
        if _REGEN_LOCK.locked():
            _REGEN_LOCK.release()

        regenerate_edl_files()

        import time
        time.sleep(0.5)  # Wait for background thread

        # Check files exist
        assert os.path.exists(tmp_path / "palo_alto_ip.txt")
        assert os.path.exists(tmp_path / "palo_alto_domain.txt")
        assert os.path.exists(tmp_path / "fortinet_ip.txt")
        assert os.path.exists(tmp_path / "fortinet_domain.txt")
        assert os.path.exists(tmp_path / "url_list.txt")
        assert os.path.exists(tmp_path / "palo_alto_edl.txt")  # legacy
        assert os.path.exists(tmp_path / "fortinet_edl.txt")  # legacy

    @patch("threat_feed_aggregator.edl_generator.get_api_blacklist_items")
    @patch("threat_feed_aggregator.edl_generator.get_all_indicators_iter")
    def test_ip_written_to_correct_files(self, mock_iter, mock_blacklist, tmp_path, monkeypatch):
        monkeypatch.setattr("threat_feed_aggregator.edl_generator.DATA_DIR", str(tmp_path))
        mock_iter.return_value = iter([{"indicator": "1.2.3.4", "type": "ip"}])
        mock_blacklist.return_value = []

        from threat_feed_aggregator.edl_generator import regenerate_edl_files, _REGEN_LOCK
        if _REGEN_LOCK.locked():
            _REGEN_LOCK.release()

        regenerate_edl_files()

        import time
        time.sleep(0.5)

        pa = (tmp_path / "palo_alto_ip.txt").read_text()
        fn = (tmp_path / "fortinet_ip.txt").read_text()
        dom = (tmp_path / "palo_alto_domain.txt").read_text()

        assert "1.2.3.4" in pa
        assert "1.2.3.4" in fn
        assert "1.2.3.4" not in dom

    @patch("threat_feed_aggregator.edl_generator.get_api_blacklist_items")
    @patch("threat_feed_aggregator.edl_generator.get_all_indicators_iter")
    def test_private_ipv4_not_written_to_ip_lists(self, mock_iter, mock_blacklist, tmp_path, monkeypatch):
        monkeypatch.setattr("threat_feed_aggregator.edl_generator.DATA_DIR", str(tmp_path))
        mock_iter.return_value = iter([
            {"indicator": "10.1.2.3", "type": "ip"},
            {"indicator": "1.2.3.4", "type": "ip"},
            {"indicator": "172.16.10.0/24", "type": "cidr"},
        ])
        mock_blacklist.return_value = [
            {"item": "192.168.1.1", "type": "ip"},
            {"item": "5.6.7.8", "type": "ip"},
        ]

        from threat_feed_aggregator.edl_generator import regenerate_edl_files, _REGEN_LOCK
        if _REGEN_LOCK.locked():
            _REGEN_LOCK.release()

        regenerate_edl_files()

        import time
        time.sleep(0.5)

        pa = (tmp_path / "palo_alto_ip.txt").read_text()
        fn = (tmp_path / "fortinet_ip.txt").read_text()

        assert "1.2.3.4" in pa
        assert "5.6.7.8" in pa
        assert "10.1.2.3" not in pa
        assert "172.16.10.0/24" not in pa
        assert "192.168.1.1" not in pa

        assert "1.2.3.4" in fn
        assert "5.6.7.8" in fn
        assert "10.1.2.3" not in fn
        assert "172.16.10.0/24" not in fn
        assert "192.168.1.1" not in fn

    @patch("threat_feed_aggregator.edl_generator.get_api_blacklist_items")
    @patch("threat_feed_aggregator.edl_generator.get_all_indicators_iter")
    def test_no_temp_files_on_success(self, mock_iter, mock_blacklist, tmp_path, monkeypatch):
        monkeypatch.setattr("threat_feed_aggregator.edl_generator.DATA_DIR", str(tmp_path))
        mock_iter.return_value = iter([])
        mock_blacklist.return_value = []

        from threat_feed_aggregator.edl_generator import regenerate_edl_files, _REGEN_LOCK
        if _REGEN_LOCK.locked():
            _REGEN_LOCK.release()

        regenerate_edl_files()

        import time
        time.sleep(0.5)

        tmp_files = [f for f in os.listdir(tmp_path) if f.endswith(".tmp")]
        assert len(tmp_files) == 0

    @patch("threat_feed_aggregator.edl_generator.get_api_blacklist_items")
    @patch("threat_feed_aggregator.edl_generator.get_all_indicators_iter")
    def test_concurrent_calls_skipped(self, mock_iter, mock_blacklist, tmp_path, monkeypatch):
        """Second call while first is running should be skipped."""
        monkeypatch.setattr("threat_feed_aggregator.edl_generator.DATA_DIR", str(tmp_path))
        mock_iter.return_value = iter([])
        mock_blacklist.return_value = []

        from threat_feed_aggregator.edl_generator import regenerate_edl_files, _REGEN_LOCK

        if _REGEN_LOCK.locked():
            _REGEN_LOCK.release()

        # Acquire lock manually to simulate running regeneration
        _REGEN_LOCK.acquire()
        try:
            result = regenerate_edl_files()
            assert result == (False, "Regeneration already in progress.")
        finally:
            _REGEN_LOCK.release()
