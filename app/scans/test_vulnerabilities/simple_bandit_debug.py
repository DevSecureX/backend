#!/usr/bin/env python3
"""
Simple Bandit Debug Test
Debug why Bandit finds issues directly but not through scanner engine
"""

import asyncio
import logging
import os
import sys
import tempfile
import json

# Add app root to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from app.scans.tools.bandit_runner import BanditRunner

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def debug_bandit_execution():
    """Debug Bandit execution with target files"""
    
    # Create test directory with vulnerable Python code
    test_dir = tempfile.mkdtemp(prefix="bandit_debug_")
    logger.info(f"Test directory: {test_dir}")
    
    # Create vulnerable Python file
    vulnerable_code = '''
import pickle
import subprocess

PASSWORD = "admin123"

def execute_command(cmd):
    subprocess.call(cmd, shell=True)

def load_data(data):
    return pickle.loads(data)
'''
    
    test_file = os.path.join(test_dir, 'vulnerable.py')
    with open(test_file, 'w') as f:
        f.write(vulnerable_code)
    
    logger.info(f"Created test file: {test_file}")
    
    bandit_runner = BanditRunner()
    
    try:
        # Test 1: Direct execution without target files (like direct test)
        logger.info("\n=== TEST 1: Direct execution (no target_files) ===")
        result1 = await bandit_runner.run(test_dir)
        logger.info(f"Result 1 - Issues found: {len(result1.get('issues', []))}")
        logger.info(f"Result 1 - Error: {result1.get('error')}")
        logger.info(f"Result 1 - Skipped: {result1.get('skipped')}")
        
        # Test 2: Execution with target files (like scanner engine)
        logger.info("\n=== TEST 2: Execution with target_files (like scanner engine) ===")
        result2 = await bandit_runner.run(
            test_dir, 
            target_files=[test_file],
            focus_on_changed_files=True
        )
        logger.info(f"Result 2 - Issues found: {len(result2.get('issues', []))}")
        logger.info(f"Result 2 - Error: {result2.get('error')}")
        logger.info(f"Result 2 - Skipped: {result2.get('skipped')}")
        
        # Test 3: Execution with relative path target files
        logger.info("\n=== TEST 3: Execution with relative target_files ===")
        relative_file = os.path.relpath(test_file, test_dir)
        result3 = await bandit_runner.run(
            test_dir, 
            target_files=[relative_file],
            focus_on_changed_files=True
        )
        logger.info(f"Result 3 - Issues found: {len(result3.get('issues', []))}")
        logger.info(f"Result 3 - Error: {result3.get('error')}")
        logger.info(f"Result 3 - Skipped: {result3.get('skipped')}")
        
        # Test 4: Check what files exist
        logger.info(f"\n=== FILE SYSTEM DEBUG ===")
        logger.info(f"Test dir: {test_dir}")
        logger.info(f"Test file: {test_file}")
        logger.info(f"Test file exists: {os.path.exists(test_file)}")
        logger.info(f"Test dir contents: {os.listdir(test_dir)}")
        
    finally:
        # Cleanup
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == "__main__":
    asyncio.run(debug_bandit_execution())