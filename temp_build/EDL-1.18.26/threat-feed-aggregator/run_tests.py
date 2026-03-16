#!/usr/bin/env python
"""
Unit Test Execution Report for Threat Feed Aggregator
Runs available tests and documents results
"""
import sys
import os
import unittest
from io import StringIO

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_unit_test(test_module_name, test_file_path):
    """Run a single unit test file and return results"""
    results = {
        'name': test_module_name,
        'file': test_file_path,
        'status': 'UNKNOWN',
        'error': None,
        'tests_run': 0,
        'failures': 0,
        'errors': 0
    }
    
    try:
        # Import test module dynamically
        loader = unittest.TestLoader()
        suite = loader.discover(
            start_dir=os.path.dirname(test_file_path),
            pattern=os.path.basename(test_file_path),
            top_level_dir=os.path.dirname(os.path.dirname(test_file_path))
        )
        
        # Run tests
        stream = StringIO()
        runner = unittest.TextTestRunner(stream=stream, verbosity=2)
        test_result = runner.run(suite)
        
        results['tests_run'] = test_result.testsRun
        results['failures'] = len(test_result.failures)
        results['errors'] = len(test_result.errors)
        
        if test_result.wasSuccessful():
            results['status'] = 'PASSED'
        elif test_result.errors:
            results['status'] = 'ERROR'
            results['error'] = str(test_result.errors[0][1]) if test_result.errors else None
        else:
            results['status'] = 'FAILED'
            results['error'] = str(test_result.failures[0][1]) if test_result.failures else None
            
    except ImportError as e:
        results['status'] = 'IMPORT_ERROR'
        results['error'] = str(e)
    except Exception as e:
        results['status'] = 'EXCEPTION'
        results['error'] = str(e)
    
    return results

def main():
    tests_dir = os.path.join(os.path.dirname(__file__), 'tests')
    
    # Find all test files
    test_files = [
        'test_regex.py',
        'test_parsers.py',
        'test_aggregation.py',
        'test_blacklist_logic.py',
        'test_whitelist_logic.py',
        'test_output_formatter.py',
        'test_all_filters.py',
        'test_advanced_filtering.py',
    ]
    
    print("=" * 80)
    print("THREAT FEED AGGREGATOR - UNIT TEST EXECUTION")
    print("=" * 80)
    print()
    
    all_results = []
    passed = 0
    failed = 0
    errors = 0
    
    for test_file in test_files:
        test_path = os.path.join(tests_dir, test_file)
        
        if not os.path.exists(test_path):
            print(f"⚠️  {test_file}: NOT FOUND")
            continue
        
        print(f"▶️  Running {test_file}...", end=" ", flush=True)
        
        result = run_unit_test(test_file, test_path)
        all_results.append(result)
        
        if result['status'] == 'PASSED':
            print(f"✓ PASSED ({result['tests_run']} tests)")
            passed += 1
        elif result['status'] in ['FAILED', 'IMPORT_ERROR', 'EXCEPTION']:
            print(f"✗ {result['status']}")
            if result['error']:
                print(f"   Error: {result['error'][:100]}")
            if result['status'] == 'FAILED':
                failed += 1
            else:
                errors += 1
        else:
            print(f"? {result['status']}")
    
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total Test Files: {len(test_files)}")
    print(f"Passed: {passed} ✓")
    print(f"Failed: {failed} ✗")
    print(f"Errors: {errors} ⚠️")
    print()
    
    # Detailed results
    print("DETAILED RESULTS:")
    print()
    for result in all_results:
        status_symbol = "✓" if result['status'] == 'PASSED' else "✗" if result['status'] in ['FAILED', 'IMPORT_ERROR'] else "?"
        print(f"{status_symbol} {result['name']}")
        print(f"  Status: {result['status']}")
        if result['tests_run'] > 0:
            print(f"  Tests Run: {result['tests_run']}")
            print(f"  Failures: {result['failures']}")
            print(f"  Errors: {result['errors']}")
        if result['error']:
            lines = result['error'].split('\n')[:3]
            for line in lines:
                if line.strip():
                    print(f"  → {line[:75]}")
        print()
    
    print("=" * 80)
    return 0 if (failed == 0 and errors == 0) else 1

if __name__ == '__main__':
    sys.exit(main())
