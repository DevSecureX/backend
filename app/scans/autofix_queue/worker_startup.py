#!/usr/bin/env python3
"""
Autofix Worker Startup Script
Production-ready autofix worker startup with signal handling and health monitoring
"""

import asyncio
import argparse
import logging
import os
import sys
from pathlib import Path

# Add app directory to Python path
app_dir = Path(__file__).parent.parent.parent
sys.path.insert(0, str(app_dir))

from core.signal_handlers import GracefulShutdownHandler
from scans.autofix_queue.autofix_worker import AutofixWorker

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    """Main autofix worker startup function"""
    parser = argparse.ArgumentParser(description='Start DevSecureX Autofix Worker')
    parser.add_argument('--worker-id', required=True, help='Worker ID')
    
    args = parser.parse_args()
    worker_id = args.worker_id
    
    # Setup shutdown handler
    shutdown_handler = GracefulShutdownHandler(f"autofix_worker_{worker_id}")
    shutdown_handler.setup_signal_handlers()
    
    worker = None
    try:
        logger.info(f"Starting autofix worker {worker_id}")
        
        # Create and start the worker
        worker = AutofixWorker(worker_id)
        
        # Add cleanup callback
        shutdown_handler.add_cleanup_callback(worker.stop)
        
        # Start the worker
        await worker.start()
        
        # Wait for shutdown signal
        await shutdown_handler.wait_for_shutdown()
        
        logger.info(f"Autofix worker {worker_id} shutdown signal received")
        
    except Exception as e:
        logger.error(f"Error in autofix worker {worker_id}: {e}")
        sys.exit(1)
    finally:
        if worker:
            try:
                await worker.stop()
            except Exception as e:
                logger.error(f"Error stopping autofix worker {worker_id}: {e}")
        
        shutdown_handler.restore_signal_handlers()
        logger.info(f"Autofix worker {worker_id} stopped")


if __name__ == "__main__":
    asyncio.run(main())