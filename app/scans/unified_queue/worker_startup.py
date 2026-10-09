#!/usr/bin/env python3
"""
Unified Worker Startup Script
Production-ready worker startup with signal handling and health monitoring
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
from scans.unified_queue.unified_worker import start_unified_worker

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    """Main worker startup function"""
    parser = argparse.ArgumentParser(description='Start DevSecureX Unified Worker')
    parser.add_argument('--worker-id', required=True, help='Worker ID')
    parser.add_argument('--openai-key', help='OpenAI API Key (or use OPENAI_API_KEY env var)')
    
    args = parser.parse_args()
    worker_id = args.worker_id
    
    # Get OpenAI API key
    openai_api_key = args.openai_key or os.getenv('OPENAI_API_KEY')
    if not openai_api_key:
        logger.error("OpenAI API key is required (--openai-key or OPENAI_API_KEY env var)")
        sys.exit(1)
    
    # Setup shutdown handler
    shutdown_handler = GracefulShutdownHandler(f"unified_worker_{worker_id}")
    shutdown_handler.setup_signal_handlers()
    
    worker = None
    try:
        logger.info(f"Starting unified worker {worker_id}")
        
        # Start the worker
        worker = await start_unified_worker(worker_id, openai_api_key)
        
        # Add cleanup callback
        if worker:
            shutdown_handler.add_cleanup_callback(worker.stop)
        
        # Wait for shutdown signal
        await shutdown_handler.wait_for_shutdown()
        
        logger.info(f"Unified worker {worker_id} shutdown signal received")
        
    except Exception as e:
        logger.error(f"Error in unified worker {worker_id}: {e}")
        sys.exit(1)
    finally:
        if worker:
            try:
                await worker.stop()
            except Exception as e:
                logger.error(f"Error stopping worker {worker_id}: {e}")
        
        shutdown_handler.restore_signal_handlers()
        logger.info(f"Unified worker {worker_id} stopped")


if __name__ == "__main__":
    asyncio.run(main())