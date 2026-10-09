"""
Safe Database Operations Utilities for DevSecureX
Prevents memory issues from unbounded queries and provides circuit breaker protection
"""

import logging
from typing import List, Dict, Any, Optional, Type, TypeVar
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.exc import SQLAlchemyError
from core.circuit_breaker import get_circuit_breaker, CircuitBreakerConfig, CircuitBreakerOpenError

logger = logging.getLogger(__name__)

T = TypeVar('T')

# Configuration constants
MAX_BATCH_SIZE = 1000
DEFAULT_LIMIT = 100
MAX_SAFE_LIMIT = 10000

class SafeQueryError(Exception):
    """Custom exception for safe query operations"""
    pass


class SafeDatabaseOperations:
    """
    Safe database operations with built-in limits and circuit breaker protection
    to prevent resource exhaustion and infinite result sets
    """
    
    def __init__(self, db: AsyncSession, circuit_breaker_name: str = "safe_db_operations"):
        self.db = db
        self.circuit_breaker = get_circuit_breaker(
            circuit_breaker_name,
            config=CircuitBreakerConfig(
                failure_threshold=5,
                success_threshold=2,
                timeout=30.0,
                max_timeout=300.0
            )
        )
    
    async def safe_fetch_all(
        self,
        query: Any,
        limit: Optional[int] = None,
        max_limit: int = MAX_SAFE_LIMIT,
        warn_threshold: int = 1000
    ) -> List[Any]:
        """
        Safely fetch all results with automatic limits to prevent memory issues
        
        Args:
            query: SQLAlchemy query to execute
            limit: Optional limit to apply (default: DEFAULT_LIMIT)
            max_limit: Maximum allowed limit for safety (default: MAX_SAFE_LIMIT)
            warn_threshold: Log warning if results exceed this number
        
        Returns:
            List of query results
            
        Raises:
            SafeQueryError: If limits are exceeded or circuit breaker is open
        """
        if limit is None:
            limit = DEFAULT_LIMIT
        
        # Validate limits
        if limit > max_limit:
            raise SafeQueryError(f"Query limit {limit} exceeds maximum safe limit {max_limit}")
        
        try:
            async with self.circuit_breaker:
                # Apply limit to query
                limited_query = query.limit(limit)
                
                # Execute query
                result = await self.db.execute(limited_query)
                
                # Extract results safely
                if hasattr(result, 'scalars'):
                    items = result.scalars().all()
                else:
                    items = result.fetchall()
                
                # Log warning if approaching limits
                if len(items) >= warn_threshold:
                    logger.warning(
                        f"Query returned {len(items)} results, approaching limit of {limit}. "
                        "Consider using pagination."
                    )
                
                return items
                
        except CircuitBreakerOpenError as e:
            logger.error(f"Database circuit breaker is open: {e}")
            raise SafeQueryError("Database operations temporarily unavailable") from e
        except SQLAlchemyError as e:
            logger.error(f"Database error in safe_fetch_all: {e}", exc_info=True)
            raise SafeQueryError("Database query failed") from e
        except Exception as e:
            logger.error(f"Unexpected error in safe_fetch_all: {e}", exc_info=True)
            raise SafeQueryError("Query execution failed") from e
    
    async def safe_count(self, query: Any) -> int:
        """
        Safely count query results with circuit breaker protection
        
        Args:
            query: SQLAlchemy query to count
            
        Returns:
            Number of matching records
            
        Raises:
            SafeQueryError: If circuit breaker is open or query fails
        """
        try:
            async with self.circuit_breaker:
                # Create count query from the base query
                count_query = select(func.count()).select_from(query.subquery())
                result = await self.db.execute(count_query)
                count = result.scalar()
                
                return count if count is not None else 0
                
        except CircuitBreakerOpenError as e:
            logger.error(f"Database circuit breaker is open: {e}")
            raise SafeQueryError("Database operations temporarily unavailable") from e
        except SQLAlchemyError as e:
            logger.error(f"Database error in safe_count: {e}", exc_info=True)
            raise SafeQueryError("Count query failed") from e
        except Exception as e:
            logger.error(f"Unexpected error in safe_count: {e}", exc_info=True)
            raise SafeQueryError("Count operation failed") from e
    
    async def safe_batch_fetch(
        self,
        query: Any,
        batch_size: int = MAX_BATCH_SIZE,
        max_total: int = MAX_SAFE_LIMIT
    ) -> List[Any]:
        """
        Safely fetch results in batches to handle large datasets
        
        Args:
            query: SQLAlchemy query to execute
            batch_size: Size of each batch (default: MAX_BATCH_SIZE)
            max_total: Maximum total results to fetch (default: MAX_SAFE_LIMIT)
            
        Returns:
            List of all results from batches
            
        Raises:
            SafeQueryError: If limits are exceeded or circuit breaker issues
        """
        if batch_size > MAX_BATCH_SIZE:
            raise SafeQueryError(f"Batch size {batch_size} exceeds maximum {MAX_BATCH_SIZE}")
        
        all_results = []
        offset = 0
        
        try:
            while len(all_results) < max_total:
                async with self.circuit_breaker:
                    # Fetch batch with limit and offset
                    batch_query = query.limit(batch_size).offset(offset)
                    result = await self.db.execute(batch_query)
                    
                    # Extract batch results
                    if hasattr(result, 'scalars'):
                        batch_items = result.scalars().all()
                    else:
                        batch_items = result.fetchall()
                    
                    # Break if no more results
                    if not batch_items:
                        break
                    
                    all_results.extend(batch_items)
                    offset += batch_size
                    
                    # Stop if batch was smaller than batch_size (last batch)
                    if len(batch_items) < batch_size:
                        break
                    
                    # Safety check for max_total
                    if len(all_results) >= max_total:
                        logger.warning(f"Reached maximum result limit of {max_total}, truncating results")
                        all_results = all_results[:max_total]
                        break
            
            return all_results
            
        except CircuitBreakerOpenError as e:
            logger.error(f"Database circuit breaker is open during batch fetch: {e}")
            raise SafeQueryError("Database operations temporarily unavailable") from e
        except SQLAlchemyError as e:
            logger.error(f"Database error in safe_batch_fetch: {e}", exc_info=True)
            raise SafeQueryError("Batch query failed") from e
        except Exception as e:
            logger.error(f"Unexpected error in safe_batch_fetch: {e}", exc_info=True)
            raise SafeQueryError("Batch fetch operation failed") from e
    
    async def safe_exists(self, query: Any) -> bool:
        """
        Safely check if query has any results without fetching all data
        
        Args:
            query: SQLAlchemy query to check
            
        Returns:
            True if query has results, False otherwise
            
        Raises:
            SafeQueryError: If circuit breaker is open or query fails
        """
        try:
            async with self.circuit_breaker:
                # Use exists() for efficient checking
                exists_query = select(query.exists())
                result = await self.db.execute(exists_query)
                return result.scalar()
                
        except CircuitBreakerOpenError as e:
            logger.error(f"Database circuit breaker is open: {e}")
            raise SafeQueryError("Database operations temporarily unavailable") from e
        except SQLAlchemyError as e:
            logger.error(f"Database error in safe_exists: {e}", exc_info=True)
            raise SafeQueryError("Exists query failed") from e
        except Exception as e:
            logger.error(f"Unexpected error in safe_exists: {e}", exc_info=True)
            raise SafeQueryError("Exists operation failed") from e


# Convenience functions
async def safe_query_all(
    db: AsyncSession,
    query: Any,
    limit: int = DEFAULT_LIMIT,
    circuit_breaker_name: str = "default_safe_query"
) -> List[Any]:
    """
    Convenience function for safe query execution
    
    Args:
        db: Database session
        query: SQLAlchemy query
        limit: Maximum results to return
        circuit_breaker_name: Name for circuit breaker instance
        
    Returns:
        List of query results
    """
    safe_ops = SafeDatabaseOperations(db, circuit_breaker_name)
    return await safe_ops.safe_fetch_all(query, limit=limit)


async def safe_query_count(
    db: AsyncSession,
    query: Any,
    circuit_breaker_name: str = "default_safe_count"
) -> int:
    """
    Convenience function for safe count operations
    
    Args:
        db: Database session
        query: SQLAlchemy query
        circuit_breaker_name: Name for circuit breaker instance
        
    Returns:
        Count of matching records
    """
    safe_ops = SafeDatabaseOperations(db, circuit_breaker_name)
    return await safe_ops.safe_count(query)


async def safe_query_exists(
    db: AsyncSession,
    query: Any,
    circuit_breaker_name: str = "default_safe_exists"
) -> bool:
    """
    Convenience function for safe exists checks
    
    Args:
        db: Database session
        query: SQLAlchemy query
        circuit_breaker_name: Name for circuit breaker instance
        
    Returns:
        True if records exist, False otherwise
    """
    safe_ops = SafeDatabaseOperations(db, circuit_breaker_name)
    return await safe_ops.safe_exists(query)


# Decorator for automatic query safety
def safe_query(limit: int = DEFAULT_LIMIT, circuit_breaker_name: str = "decorated_query"):
    """
    Decorator to automatically apply safe query limits
    
    Args:
        limit: Default limit to apply
        circuit_breaker_name: Circuit breaker name
        
    Returns:
        Decorated function that applies safe query patterns
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Extract db session if it's in args or kwargs
            db = None
            for arg in args:
                if isinstance(arg, AsyncSession):
                    db = arg
                    break
            
            if db is None:
                db = kwargs.get('db')
            
            if db is None:
                raise SafeQueryError("No database session found in function arguments")
            
            # Apply safe operations to the function
            safe_ops = SafeDatabaseOperations(db, circuit_breaker_name)
            
            # Call original function
            result = await func(*args, **kwargs)
            
            # If result is a query, apply safe limits
            if hasattr(result, 'limit'):  # It's a SQLAlchemy query
                return await safe_ops.safe_fetch_all(result, limit=limit)
            
            return result
        
        return wrapper
    return decorator


# Global circuit breaker metrics
def get_database_circuit_breaker_metrics() -> Dict[str, Any]:
    """Get metrics for all database circuit breakers"""
    from core.circuit_breaker import get_all_circuit_breaker_metrics
    
    # Filter for database-related circuit breakers
    all_metrics = get_all_circuit_breaker_metrics()
    db_metrics = {
        name: metrics 
        for name, metrics in all_metrics.items() 
        if 'db' in name.lower() or 'database' in name.lower() or 'safe' in name.lower()
    }
    
    return db_metrics