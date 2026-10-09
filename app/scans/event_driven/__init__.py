"""
Event-driven worker system for DevSecureX
Reduces Redis polling from 80k+ requests per day to under 1k requests per day
"""

from .worker_events import event_system, EventDrivenWorkerSystem, WorkerEventType

__all__ = ["event_system", "EventDrivenWorkerSystem", "WorkerEventType"]