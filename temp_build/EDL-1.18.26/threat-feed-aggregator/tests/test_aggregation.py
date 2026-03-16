import unittest
import sys
import os

# Add module to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from threat_feed_aggregator.utils import aggregate_ips

class TestAggregation(unittest.TestCase):

    def test_basic_aggregation(self):
        # Two /25s that make a /24
        inputs = ["192.168.1.0/25", "192.168.1.128/25"]
        expected = ["192.168.1.0/24"]
        result = aggregate_ips(inputs)
        self.assertEqual(result, expected)

    def test_single_ips_to_cidr(self):
        # 4 IPs that make a /30
        inputs = ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]
        expected = ["10.0.0.0/30"]
        result = aggregate_ips(inputs)
        self.assertEqual(result, expected)

    def test_mixed_inputs(self):
        # A mix of IPs and CIDRs
        inputs = ["10.0.0.0/30", "10.0.0.4"]
        # Can't merge /30 (0-3) with .4, so they stay separate
        expected = ["10.0.0.0/30", "10.0.0.4/32"] 
        result = aggregate_ips(inputs)
        
        # Note: ipaddress module might output single IPs as /32 or just IP string depending on version, 
        # but collapse_addresses returns network objects. Our wrapper converts to str. 
        # By default ip_network('1.1.1.1') is a /32.
        self.assertEqual(set(result), set(expected))

    def test_overlap(self):
        # A small subnet inside a larger one
        inputs = ["192.168.0.0/16", "192.168.1.0/24"]
        expected = ["192.168.0.0/16"]
        result = aggregate_ips(inputs)
        self.assertEqual(result, expected)

    def test_invalid_input(self):
        inputs = ["1.1.1.1", "invalid_ip", "google.com"]
        expected = ["1.1.1.1/32"]
        result = aggregate_ips(inputs)
        self.assertEqual(result, expected)

if __name__ == '__main__':
    unittest.main()
