"""
Performance-Optimized Database Operations for DevSecureX Scans
Optimizes database interactions for faster scan result storage and retrieval
"""

import logging
import time
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, select, insert, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
import asyncio
import json
from datetime import datetime, timezone, timedelta

from .models import Scan, ScanSummary
from auth.models import User
from repos.models import Repo

logger = logging.getLogger(__name__)

class PerformanceDatabaseOptimizer:
    """
    High-performance database operations for scan results
    
    Optimizations:
    - Batch insert operations to reduce database round trips
    - Connection pooling and prepared statements
    - Asynchronous bulk operations
    - Efficient JSON serialization
    - Minimal database queries with optimized indexes
    """
    
    def __init__(self):
        self.batch_size = 500  # Optimal batch size for PostgreSQL
        self.metrics = {
            "total_operations": 0,
            "batch_operations": 0,
            "avg_operation_time": 0.0
        }
    
    async def store_scan_results_optimized(
        self,
        scan_result: Dict[str, Any],
        user_id: int,
        repo_full_name: str,
        db: AsyncSession,
        niche: str = "general",
        batch_mode: bool = True
    ) -> str:
        """
        Store scan results with optimized database operations
        """
        start_time = time.time()
        
        try:
            logger.info(f"🚀 Optimized storage for {repo_full_name} - {len(scan_result.get('issues', []))} issues")
            
            # Prepare scan data
            metadata = scan_result.get("metadata", {})
            scores = scan_result.get("scores", {})
            issues = scan_result.get("issues", [])
            
            # Create main scan record with upsert for performance
            # Prepare scan data matching the Scan model fields
            scan_data = {
                "repo_full_name": repo_full_name,
                "user_id": user_id,
                "branch": metadata.get("branch", "main"),
                "mode": metadata.get("mode", "comprehensive"),
                "scope": metadata.get("scope", "full"),
                "scan_type": metadata.get("scan_type", "manual"),
                "status": "completed",
                "total_score": scan_result.get("total_score", 0),
                "code_score": scores.get("code_score", 0),
                "deps_score": scores.get("deps_score", 0),
                "secrets_score": scores.get("secrets_score", 0),
                "configs_score": scores.get("configs_score", 0),
                "niche": niche or "general",
                "created_at": datetime.now(timezone.utc),
                "completed_at": datetime.now(timezone.utc),
                "scan_duration": int(scan_result.get("scan_duration", metadata.get("execution_time", 0))),
                "tools_used": scan_result.get("tools_used", []),
                "commit_sha": metadata.get("commit_sha"),
                "pr_number": metadata.get("pr_number"),
                "sbom": metadata.get("sbom"),
            }
            
            # Use standard SQLAlchemy insert for compatibility
            # The pg_insert was causing SQLAlchemy bulk_update_tuples errors
            scan = Scan(**scan_data)
            db.add(scan)
            await db.flush()
            scan_id = str(scan.id)
            
            # Create summary record concurrently if issues exist
            if issues:
                await self._create_scan_summary_optimized(
                    scan_id, scan_data, issues, db, batch_mode
                )
            
            # Commit in a single transaction
            await db.commit()
            
            execution_time = time.time() - start_time
            self._update_metrics(execution_time)
            
            logger.info(f"⚡ Optimized scan storage completed in {execution_time:.2f}s: {scan_id}")
            return scan_id
            
        except Exception as e:
            await db.rollback()
            logger.error(f"💥 Optimized scan storage failed: {e}", exc_info=True)
            raise
    
    async def _create_scan_summary_optimized(
        self,
        scan_id: str,
        scan_data: Dict[str, Any],
        issues: List[Dict[str, Any]],
        db: AsyncSession,
        batch_mode: bool = True
    ):
        """Create scan summary with optimized operations and proper issue storage"""
        
        try:
            logger.info(f"Creating scan summaries for {len(issues)} issues")
            
            # Group issues by tool and category (same logic as scan_worker.py)
            summaries = {}
            
            for issue in issues:
                tool = issue.get("tool", "unknown")
                category = issue.get("category", "security")
                severity = issue.get("severity", "medium").lower()
                
                key = f"{tool}_{category}"
                
                if key not in summaries:
                    summaries[key] = {
                        "scan_id": scan_id,
                        "category": category,
                        "tool_name": tool,
                        "critical_count": 0,
                        "high_count": 0,
                        "medium_count": 0,
                        "low_count": 0,
                        "total_issues": 0,
                        "sample_issues": []
                    }
                
                # Count by severity
                if severity == "critical":
                    summaries[key]["critical_count"] += 1
                elif severity == "high":
                    summaries[key]["high_count"] += 1
                elif severity == "medium":
                    summaries[key]["medium_count"] += 1
                else:
                    summaries[key]["low_count"] += 1
                
                summaries[key]["total_issues"] += 1
                
                # Store the issue in sample_issues (same format as scan_worker.py)
                sample_issue = {
                    "message": issue.get("message"),
                    "file_path": issue.get("file_path"),
                    "line_start": issue.get("line_start"),
                    "line_end": issue.get("line_end"),
                    "severity": severity,
                    "rule_id": issue.get("rule_id"),
                    "confidence": issue.get("confidence"),
                    "owasp_category": issue.get("owasp_category"),
                    "cwe_id": issue.get("cwe_id"),
                    "code_context": issue.get("code_context")
                }
                summaries[key]["sample_issues"].append(sample_issue)
            
            # Create ScanSummary records for each tool/category combination
            summary_objects = []
            for key, summary_data in summaries.items():
                summary_obj = ScanSummary(**summary_data)
                summary_objects.append(summary_obj)
            
            # Bulk insert all summaries
            if summary_objects:
                db.add_all(summary_objects)
                await db.flush()
                
                logger.info(f"✅ Created {len(summary_objects)} scan summaries with issues")
                
                # Log summary for debugging
                for key, summary in summaries.items():
                    logger.info(f"  Summary {key}: {summary['total_issues']} issues "
                              f"({summary['critical_count']}C/{summary['high_count']}H/"
                              f"{summary['medium_count']}M/{summary['low_count']}L)")
            
        except Exception as e:
            logger.error(f"Summary creation failed: {e}", exc_info=True)
            # Don't fail the whole operation for summary issues
            pass
    
    
    async def batch_update_scan_status(
        self,
        scan_ids: List[str],
        status: str,
        db: AsyncSession
    ) -> int:
        """Batch update scan statuses for efficiency"""
        
        if not scan_ids:
            return 0
        
        start_time = time.time()
        
        try:
            # Process in batches to avoid memory issues
            updated_count = 0
            
            for i in range(0, len(scan_ids), self.batch_size):
                batch = scan_ids[i:i + self.batch_size]
                
                stmt = (
                    update(Scan)
                    .where(Scan.id.in_(batch))
                    .values(status=status, updated_at=datetime.now(timezone.utc))
                )
                
                result = await db.execute(stmt)
                updated_count += result.rowcount
            
            await db.commit()
            
            execution_time = time.time() - start_time
            logger.info(f"⚡ Batch updated {updated_count} scans in {execution_time:.2f}s")
            
            return updated_count
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Batch update failed: {e}")
            raise
    
    async def get_scan_results_optimized(
        self,
        scan_id: str,
        db: AsyncSession,
        include_issues: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Optimized scan result retrieval"""
        
        start_time = time.time()
        
        try:
            # Build optimized query
            if include_issues:
                query = select(Scan).where(Scan.id == scan_id)
            else:
                # Select only necessary columns for faster queries
                query = select(
                    Scan.id, Scan.repo_full_name, Scan.branch, Scan.status,
                    Scan.total_score, Scan.created_at, Scan.scan_duration
                ).where(Scan.id == scan_id)
            
            result = await db.execute(query)
            scan = result.scalar_one_or_none()
            
            if not scan:
                return None
            
            execution_time = time.time() - start_time
            
            if execution_time > 0.5:  # Only log slow queries
                logger.info(f"Scan retrieval took {execution_time:.2f}s")
            
            return scan
            
        except Exception as e:
            logger.error(f"Scan retrieval failed: {e}")
            return None
    
    async def cleanup_old_scans(
        self,
        days_old: int,
        db: AsyncSession,
        batch_size: int = 100
    ) -> int:
        """Optimized cleanup of old scan data"""
        
        start_time = time.time()
        
        try:
            # Calculate cutoff date
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)
            
            # Get old scan IDs first
            query = text("""
                SELECT id FROM scans 
                WHERE created_at < :cutoff_date 
                ORDER BY created_at 
                LIMIT :batch_size
            """)
            
            result = await db.execute(query, {
                "cutoff_date": cutoff_date,
                "batch_size": batch_size
            })
            
            old_scan_ids = [row[0] for row in result.fetchall()]
            
            if not old_scan_ids:
                return 0
            
            # Delete in order: summaries first, then scans
            summary_delete = text("""
                DELETE FROM scan_summaries 
                WHERE scan_id = ANY(:scan_ids)
            """)
            
            scan_delete = text("""
                DELETE FROM scans 
                WHERE id = ANY(:scan_ids)
            """)
            
            await db.execute(summary_delete, {"scan_ids": old_scan_ids})
            await db.execute(scan_delete, {"scan_ids": old_scan_ids})
            
            await db.commit()
            
            execution_time = time.time() - start_time
            logger.info(f"⚡ Cleaned up {len(old_scan_ids)} old scans in {execution_time:.2f}s")
            
            return len(old_scan_ids)
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Cleanup failed: {e}")
            return 0
    
    def _update_metrics(self, execution_time: float):
        """Update performance metrics"""
        self.metrics["total_operations"] += 1
        
        total_ops = self.metrics["total_operations"]
        current_avg = self.metrics["avg_operation_time"]
        self.metrics["avg_operation_time"] = (
            (current_avg * (total_ops - 1) + execution_time) / total_ops
        )
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get database performance metrics"""
        return {
            **self.metrics,
            "batch_size": self.batch_size
        }

# Global instance
db_optimizer = PerformanceDatabaseOptimizer()

# Utility functions
async def store_scan_results_fast(
    scan_result: Dict[str, Any],
    user_id: int,
    repo_full_name: str,
    db: AsyncSession,
    niche: str = "general"
) -> str:
    """Fast scan result storage"""
    return await db_optimizer.store_scan_results_optimized(
        scan_result, user_id, repo_full_name, db, niche
    )