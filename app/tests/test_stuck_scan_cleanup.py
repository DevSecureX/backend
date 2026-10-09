#!/usr/bin/env python3
"""
Test script for stuck scan cleanup implementation.

This script tests the stuck scan detection and cleanup functionality
to ensure accurate queue statistics.

Usage:
    python test_stuck_scan_cleanup.py

Date: 2025-01-09
"""

import asyncio
import asyncpg
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import List

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database connection string
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://devsecurex:devsecurex_secure_2024@localhost:5432/devsecurex_db")

async def create_test_data(conn):
    """Create test scan jobs to simulate stuck scans"""
    logger.info("Creating test data...")

    # Current time
    now = datetime.now(timezone.utc)

    # Create stuck scans (processing for > 30 minutes)
    stuck_time = now - timedelta(minutes=45)

    test_jobs = [
        {
            'id': 'test-stuck-1',
            'repo_full_name': 'test/repo1',
            'user_id': 1,
            'scan_type': 'manual',
            'priority': 2,
            'job_data': '{"test": true}',
            'status': 'processing',
            'started_at': stuck_time,
            'created_at': stuck_time,
        },
        {
            'id': 'test-stuck-2',
            'repo_full_name': 'test/repo2',
            'user_id': 1,
            'scan_type': 'manual',
            'priority': 2,
            'job_data': '{"test": true}',
            'status': 'processing',
            'started_at': stuck_time,
            'created_at': stuck_time,
        },
        {
            'id': 'test-active',
            'repo_full_name': 'test/repo3',
            'user_id': 1,
            'scan_type': 'manual',
            'priority': 2,
            'job_data': '{"test": true}',
            'status': 'processing',
            'started_at': now - timedelta(minutes=5),  # Recent, not stuck
            'created_at': now - timedelta(minutes=5),
        },
        {
            'id': 'test-queued',
            'repo_full_name': 'test/repo4',
            'user_id': 1,
            'scan_type': 'manual',
            'priority': 2,
            'job_data': '{"test": true}',
            'status': 'queued',
            'created_at': now,
        }
    ]

    for job in test_jobs:
        await conn.execute("""
            INSERT INTO scan_jobs (id, repo_full_name, user_id, scan_type, priority, job_data, status, started_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (id) DO NOTHING
        """, job['id'], job['repo_full_name'], job['user_id'], job['scan_type'],
             job['priority'], job['job_data'], job['status'],
             job.get('started_at'), job['created_at'])

    logger.info("Test data created successfully")

async def test_stuck_scan_detection(conn):
    """Test the stuck scan detection logic"""
    logger.info("Testing stuck scan detection...")

    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=30)

    # Find stuck scans
    stuck_scans = await conn.fetch("""
        SELECT id, repo_full_name, status, started_at, created_at
        FROM scan_jobs
        WHERE status = 'processing'
          AND started_at IS NOT NULL
          AND started_at < $1
          AND id LIKE 'test-%'
    """, cutoff_time)

    logger.info(f"Found {len(stuck_scans)} stuck scans:")
    for scan in stuck_scans:
        duration = (datetime.now(timezone.utc) - scan['started_at']).total_seconds() / 60
        logger.info(f"  - ID: {scan['id']}, Duration: {duration:.1f} minutes")

    return len(stuck_scans)

async def test_cleanup_operation(conn):
    """Test the cleanup operation"""
    logger.info("Testing cleanup operation...")

    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=30)

    # Update stuck scans to failed
    result = await conn.execute("""
        UPDATE scan_jobs
        SET status = 'failed',
            completed_at = $1,
            error_message = 'Scan timed out after 30 minutes - marked as failed during queue cleanup'
        WHERE status = 'processing'
          AND started_at IS NOT NULL
          AND started_at < $2
          AND id LIKE 'test-%'
    """, datetime.now(timezone.utc), cutoff_time)

    # Extract number of updated rows from result
    updated_count = int(result.split()[-1])
    logger.info(f"Cleaned up {updated_count} stuck scans")

    return updated_count

async def test_queue_stats(conn):
    """Test queue statistics after cleanup"""
    logger.info("Testing queue statistics...")

    user_repos = ['test/repo1', 'test/repo2', 'test/repo3', 'test/repo4']

    # Count by status
    queued = await conn.fetchval("""
        SELECT COUNT(*) FROM scan_jobs
        WHERE status = 'queued' AND repo_full_name = ANY($1) AND id LIKE 'test-%'
    """, user_repos)

    processing = await conn.fetchval("""
        SELECT COUNT(*) FROM scan_jobs
        WHERE status = 'processing' AND repo_full_name = ANY($1) AND id LIKE 'test-%'
    """, user_repos)

    failed = await conn.fetchval("""
        SELECT COUNT(*) FROM scan_jobs
        WHERE status = 'failed' AND repo_full_name = ANY($1) AND id LIKE 'test-%'
    """, user_repos)

    logger.info(f"Queue statistics:")
    logger.info(f"  - Queued: {queued}")
    logger.info(f"  - Processing: {processing}")
    logger.info(f"  - Failed: {failed}")

    return {"queued": queued, "processing": processing, "failed": failed}

async def cleanup_test_data(conn):
    """Clean up test data"""
    logger.info("Cleaning up test data...")

    await conn.execute("DELETE FROM scan_jobs WHERE id LIKE 'test-%'")
    logger.info("Test data cleaned up")

async def run_tests():
    """Run all tests"""
    logger.info("Starting stuck scan cleanup tests...")

    conn = await asyncpg.connect(DATABASE_URL)
    try:
        # Step 1: Create test data
        await create_test_data(conn)

        # Step 2: Test stuck scan detection
        stuck_count_before = await test_stuck_scan_detection(conn)

        # Step 3: Test cleanup operation
        cleaned_count = await test_cleanup_operation(conn)

        # Step 4: Test queue stats after cleanup
        stats = await test_queue_stats(conn)

        # Step 5: Validate results
        logger.info("\n=== Test Results ===")
        logger.info(f"Stuck scans detected: {stuck_count_before}")
        logger.info(f"Scans cleaned up: {cleaned_count}")
        logger.info(f"Final processing count: {stats['processing']}")

        # Assertions
        assert stuck_count_before == 2, f"Expected 2 stuck scans, found {stuck_count_before}"
        assert cleaned_count == 2, f"Expected to clean 2 scans, cleaned {cleaned_count}"
        assert stats['processing'] == 1, f"Expected 1 active processing scan, found {stats['processing']}"
        assert stats['queued'] == 1, f"Expected 1 queued scan, found {stats['queued']}"
        assert stats['failed'] == 2, f"Expected 2 failed scans, found {stats['failed']}"

        logger.info("✅ All tests passed!")

    except Exception as e:
        logger.error(f"❌ Test failed: {e}")
        raise
    finally:
        # Clean up test data
        await cleanup_test_data(conn)
        await conn.close()

if __name__ == "__main__":
    asyncio.run(run_tests())