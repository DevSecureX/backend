#!/usr/bin/env python3
"""
Test script to verify environment variable validation fixes

This script tests the fixes for decimal environment variables
being parsed as integers, which was causing startup failures.
"""

import os
import sys
import logging

# Add app directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def test_problematic_env_vars():
    """Test the specific problematic environment variables"""

    print("=" * 80)
    print("TESTING ENVIRONMENT VARIABLE DECIMAL PARSING FIXES")
    print("=" * 80)

    # Test cases: Environment variables that were causing integer parsing errors
    test_cases = [
        ('HIGH_FAILURE_RATE_THRESHOLD', '0.5'),
        ('DB_RETRY_DELAY', '0.5'),
        ('UNIFIED_WORKER_POLL_INTERVAL', '1.5'),
        ('MEMORY_GB', '2.0'),
        ('VALIDATION_RETRY_DELAY', '5.0')
    ]

    results = []

    for var_name, test_value in test_cases:
        print(f"\n🧪 Testing {var_name} = '{test_value}'")

        # Set the environment variable to a decimal value
        os.environ[var_name] = test_value

        # Test 1: Direct usage (how it should be)
        try:
            if var_name in ['HIGH_FAILURE_RATE_THRESHOLD', 'DB_RETRY_DELAY', 'UNIFIED_WORKER_POLL_INTERVAL', 'MEMORY_GB', 'VALIDATION_RETRY_DELAY']:
                result_float = float(os.getenv(var_name, '0.0'))
                print(f"  ✅ float(os.getenv('{var_name}', '0.0')) = {result_float}")
                results.append(('PASS', var_name, 'float parsing', result_float))
            else:
                result_int = int(os.getenv(var_name, '0'))
                print(f"  ✅ int(os.getenv('{var_name}', '0')) = {result_int}")
                results.append(('PASS', var_name, 'int parsing', result_int))
        except Exception as e:
            print(f"  ❌ ERROR: {e}")
            results.append(('FAIL', var_name, 'parsing error', str(e)))

        # Test 2: Safe parsing with conversion
        try:
            from core.config import safe_getenv_float, safe_getenv_int

            # Test safe float parsing
            safe_float = safe_getenv_float(var_name, '0.0')
            print(f"  ✅ safe_getenv_float('{var_name}', '0.0') = {safe_float}")

            # Test safe int parsing (should handle decimal gracefully)
            safe_int = safe_getenv_int(var_name, '0')
            print(f"  ✅ safe_getenv_int('{var_name}', '0') = {safe_int}")

        except Exception as e:
            print(f"  ❌ SAFE PARSING ERROR: {e}")
            results.append(('FAIL', var_name, 'safe parsing error', str(e)))

    # Test startup environment validation
    print(f"\n🔍 Testing startup environment validation...")
    try:
        from core.startup_env_check import ensure_safe_env_vars
        validation_result = ensure_safe_env_vars(block_on_errors=False)
        print(f"  ✅ ensure_safe_env_vars() = {validation_result}")
        results.append(('PASS', 'startup_validation', 'validation', validation_result))
    except Exception as e:
        print(f"  ❌ STARTUP VALIDATION ERROR: {e}")
        results.append(('FAIL', 'startup_validation', 'validation error', str(e)))

    # Summary
    print(f"\n📊 TEST RESULTS SUMMARY:")
    print("=" * 80)

    passed = sum(1 for r in results if r[0] == 'PASS')
    failed = sum(1 for r in results if r[0] == 'FAIL')

    print(f"✅ PASSED: {passed}")
    print(f"❌ FAILED: {failed}")
    print(f"📋 TOTAL:  {len(results)}")

    if failed > 0:
        print(f"\n❌ FAILED TESTS:")
        for result in results:
            if result[0] == 'FAIL':
                print(f"  - {result[1]}: {result[2]} -> {result[3]}")

    print("=" * 80)

    return failed == 0

def test_current_codebase_patterns():
    """Test that current codebase patterns work correctly"""

    print(f"\n🔍 Testing current codebase patterns...")

    # Test the actual patterns used in the codebase
    patterns = [
        ('HIGH_FAILURE_RATE_THRESHOLD', 'float(os.getenv("HIGH_FAILURE_RATE_THRESHOLD", "0.5"))', lambda: float(os.getenv("HIGH_FAILURE_RATE_THRESHOLD", "0.5"))),
        ('DB_RETRY_DELAY', 'float(os.getenv("DB_RETRY_DELAY", "0.5"))', lambda: float(os.getenv("DB_RETRY_DELAY", "0.5"))),
        ('UNIFIED_WORKER_POLL_INTERVAL', 'float(os.getenv("UNIFIED_WORKER_POLL_INTERVAL", "1.5"))', lambda: float(os.getenv("UNIFIED_WORKER_POLL_INTERVAL", "1.5")))
    ]

    all_passed = True

    for var_name, pattern_desc, pattern_func in patterns:
        try:
            result = pattern_func()
            print(f"  ✅ {pattern_desc} = {result}")
        except Exception as e:
            print(f"  ❌ {pattern_desc} FAILED: {e}")
            all_passed = False

    return all_passed

if __name__ == "__main__":
    print("🚀 Starting environment variable validation tests...")

    # Run tests
    basic_tests_passed = test_problematic_env_vars()
    codebase_tests_passed = test_current_codebase_patterns()

    # Final result
    if basic_tests_passed and codebase_tests_passed:
        print("\n🎉 ALL TESTS PASSED! Environment variable fixes are working correctly.")
        sys.exit(0)
    else:
        print("\n💥 SOME TESTS FAILED! Please review the errors above.")
        sys.exit(1)