"""
Event-driven system monitoring and diagnostics API routes
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
import logging

from .health_check import (
    check_event_system_health,
    diagnose_event_system_issues,
    test_event_delivery
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans/events", tags=["Event System"])

@router.get("/health", response_model=Dict[str, Any])
async def get_event_system_health():
    """
    Get comprehensive health status of the event-driven worker system
    """
    try:
        health_status = await check_event_system_health()
        return health_status
    except Exception as e:
        logger.error(f"Event system health check failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@router.get("/diagnosis", response_model=Dict[str, Any])
async def get_event_system_diagnosis():
    """
    Diagnose common issues with the event-driven system
    """
    try:
        diagnosis = await diagnose_event_system_issues()
        return diagnosis
    except Exception as e:
        logger.error(f"Event system diagnosis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Diagnosis failed: {str(e)}")

@router.post("/test-delivery", response_model=Dict[str, Any])
async def test_event_system_delivery():
    """
    Test event delivery end-to-end to measure performance
    """
    try:
        test_result = await test_event_delivery()
        return test_result
    except Exception as e:
        logger.error(f"Event delivery test failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Delivery test failed: {str(e)}")

@router.get("/stats", response_model=Dict[str, Any])
async def get_event_system_stats():
    """
    Get event system statistics and metrics
    """
    try:
        from .worker_events import event_system
        stats = await event_system.get_system_stats()
        return stats
    except Exception as e:
        logger.error(f"Failed to get event system stats: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Stats retrieval failed: {str(e)}")