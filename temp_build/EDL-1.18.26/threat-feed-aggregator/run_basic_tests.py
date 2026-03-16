#!/usr/bin/env python
"""
Minimal test runner for threat-feed-aggregator project
This script runs basic syntax checks and imports without full dependencies
"""
import sys
import os

# Add the project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that critical modules can be imported"""
    print("=" * 60)
    print("STARTING IMPORT TESTS")
    print("=" * 60)
    
    tests_passed = 0
    tests_failed = 0
    
    modules_to_test = [
        ('threat_feed_aggregator', 'Main package'),
        ('threat_feed_aggregator.constants', 'Constants module'),
        ('threat_feed_aggregator.config_manager', 'Config manager'),
    ]
    
    for module_name, description in modules_to_test:
        try:
            __import__(module_name)
            print(f"✓ {description} ({module_name}): OK")
            tests_passed += 1
        except ImportError as e:
            print(f"✗ {description} ({module_name}): FAILED")
            print(f"  Error: {e}")
            tests_failed += 1
        except Exception as e:
            print(f"✗ {description} ({module_name}): ERROR")
            print(f"  Error: {e}")
            tests_failed += 1
    
    print("\n" + "=" * 60)
    print(f"Results: {tests_passed} passed, {tests_failed} failed")
    print("=" * 60)
    
    return tests_failed == 0

def test_files_exist():
    """Check that all test files exist"""
    print("\n" + "=" * 60)
    print("CHECKING TEST FILES")
    print("=" * 60)
    
    test_dir = os.path.join(os.path.dirname(__file__), 'tests')
    test_files = [
        'conftest.py',
        'test_aggregation.py',
        'test_auth_manager.py',
        'test_app_integration.py',
        'test_analysis_module.py',
        'test_data_collector.py',
        'test_parsers.py',
        'test_whitelist_logic.py',
        'test_blacklist_logic.py',
    ]
    
    missing = []
    for test_file in test_files:
        file_path = os.path.join(test_dir, test_file)
        if os.path.exists(file_path):
            print(f"✓ {test_file}: Found")
        else:
            print(f"✗ {test_file}: MISSING")
            missing.append(test_file)
    
    print("\n" + "=" * 60)
    total_files = len(test_files)
    found_files = total_files - len(missing)
    print (f"Result: {found_files}/{total_files} test files found")
    print("=" * 60)
    
    return len(missing) == 0

if __name__ == '__main__':
    results = []
    
    # Test 1: Files exist
    results.append(("Test Files Check", test_files_exist()))
    
    # Test 2: Imports work
    results.append(("Import Tests", test_imports()))
    
    # Summary
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    for test_name, passed in results:
        status = "PASSED" if passed else "FAILED"
        print(f"{test_name}: {status}")
    
    all_passed = all(result for _, result in results)
    print("=" * 60)
    
    sys.exit(0 if all_passed else 1)
