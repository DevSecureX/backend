"""
Advanced Pagination Utilities
Provides consistent, high-performance pagination across all endpoints
"""

from typing import Dict, List, Any, Optional, Type, TypeVar, Generic
from pydantic import BaseModel, Field, validator
from fastapi import Query, HTTPException, status
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Query as SQLQuery
from math import ceil
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')

class PaginationParams(BaseModel):
    """Standard pagination parameters with validation"""
    page: int = Field(default=1, ge=1, le=10000, description="Page number (1-based)")
    per_page: int = Field(default=20, ge=1, le=100, description="Items per page (max 100)")
    
    @validator('page')
    def validate_page(cls, v):
        if v < 1:
            raise ValueError("Page must be at least 1")
        if v > 10000:
            raise ValueError("Page cannot exceed 10000 for performance reasons")
        return v
    
    @validator('per_page')
    def validate_per_page(cls, v):
        if v < 1:
            raise ValueError("Per page must be at least 1")
        if v > 100:
            raise ValueError("Per page cannot exceed 100 for performance reasons")
        return v
    
    @property
    def offset(self) -> int:
        """Calculate offset for database queries"""
        return (self.page - 1) * self.per_page
    
    @property
    def limit(self) -> int:
        """Get limit for database queries"""
        return self.per_page

class PaginationMeta(BaseModel):
    """Pagination metadata"""
    page: int
    per_page: int
    total_items: int
    total_pages: int
    has_next: bool
    has_prev: bool
    next_page: Optional[int] = None
    prev_page: Optional[int] = None
    offset: int

class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response"""
    items: List[T]
    meta: PaginationMeta
    
    class Config:
        arbitrary_types_allowed = True

class AdvancedPaginationParams(PaginationParams):
    """Advanced pagination with sorting and filtering"""
    sort_by: Optional[str] = Field(default=None, description="Field to sort by")
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$", description="Sort order")
    search: Optional[str] = Field(default=None, max_length=255, description="Search query")
    
    # Common filters
    created_after: Optional[str] = Field(default=None, description="Filter by creation date (ISO format)")
    created_before: Optional[str] = Field(default=None, description="Filter by creation date (ISO format)")
    
    @validator('search')
    def validate_search(cls, v):
        if v is not None and len(v.strip()) == 0:
            return None
        return v

class PaginationService:
    """Service for handling pagination logic"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def paginate_query(
        self,
        query: Any,  # SQLAlchemy query
        params: PaginationParams,
        count_query: Optional[Any] = None
    ) -> Dict[str, Any]:
        """
        Paginate a SQLAlchemy query efficiently
        
        Args:
            query: The main query to paginate
            params: Pagination parameters
            count_query: Optional separate count query for better performance
            
        Returns:
            Dict with items, total_count, and pagination metadata
        """
        
        # Get total count
        if count_query is not None:
            total_result = await self.db.execute(count_query)
            total_count = total_result.scalar()
        else:
            # Use the main query with count()
            count_query_derived = select(func.count()).select_from(query.subquery())
            total_result = await self.db.execute(count_query_derived)
            total_count = total_result.scalar()
        
        # Calculate pagination metadata
        total_pages = ceil(total_count / params.per_page) if total_count > 0 else 0
        has_next = params.page < total_pages
        has_prev = params.page > 1
        
        # Apply pagination to main query
        paginated_query = query.offset(params.offset).limit(params.limit)
        
        # Execute paginated query
        result = await self.db.execute(paginated_query)
        items = result.scalars().all() if hasattr(result, 'scalars') else result.fetchall()
        
        # Build pagination metadata
        meta = PaginationMeta(
            page=params.page,
            per_page=params.per_page,
            total_items=total_count,
            total_pages=total_pages,
            has_next=has_next,
            has_prev=has_prev,
            next_page=params.page + 1 if has_next else None,
            prev_page=params.page - 1 if has_prev else None,
            offset=params.offset
        )
        
        return {
            'items': items,
            'meta': meta,
            'total': total_count,  # Legacy compatibility
            'skip': params.offset,  # Legacy compatibility
            'limit': params.limit,  # Legacy compatibility
            'has_more': has_next    # Legacy compatibility
        }
    
    async def paginate_list(
        self,
        items: List[Any],
        params: PaginationParams
    ) -> Dict[str, Any]:
        """
        Paginate an in-memory list (use sparingly for small datasets)
        
        Args:
            items: List of items to paginate
            params: Pagination parameters
            
        Returns:
            Dict with paginated items and metadata
        """
        
        total_count = len(items)
        total_pages = ceil(total_count / params.per_page) if total_count > 0 else 0
        has_next = params.page < total_pages
        has_prev = params.page > 1
        
        # Slice the list
        start_idx = params.offset
        end_idx = start_idx + params.per_page
        paginated_items = items[start_idx:end_idx]
        
        # Build pagination metadata
        meta = PaginationMeta(
            page=params.page,
            per_page=params.per_page,
            total_items=total_count,
            total_pages=total_pages,
            has_next=has_next,
            has_prev=has_prev,
            next_page=params.page + 1 if has_next else None,
            prev_page=params.page - 1 if has_prev else None,
            offset=params.offset
        )
        
        return {
            'items': paginated_items,
            'meta': meta,
            'total': total_count,
            'skip': params.offset,
            'limit': params.per_page,
            'has_more': has_next
        }
    
    def validate_sort_field(self, sort_by: str, allowed_fields: List[str]) -> str:
        """Validate and sanitize sort field to prevent SQL injection"""
        if not sort_by:
            return allowed_fields[0] if allowed_fields else 'id'
        
        # Convert snake_case to actual column names if needed
        field_mapping = {
            'created_at': 'created_at',
            'updated_at': 'updated_at',
            'rule_name': 'rule_name',
            'upvotes': 'upvotes',
            'usage_count': 'usage_count',
            'severity': 'severity',
            'tool': 'tool',
            'language': 'language'
        }
        
        mapped_field = field_mapping.get(sort_by, sort_by)
        
        if mapped_field not in allowed_fields:
            logger.warning(f"Invalid sort field '{sort_by}', using default")
            return allowed_fields[0] if allowed_fields else 'id'
        
        return mapped_field
    
    def build_search_filter(self, search_query: str, search_fields: List[str]) -> Any:
        """Build search filter for text fields"""
        if not search_query or not search_fields:
            return None
        
        # Sanitize search query
        sanitized_query = search_query.strip().replace('%', '\\%').replace('_', '\\_')
        search_pattern = f"%{sanitized_query}%"
        
        # Build OR conditions for search fields
        from sqlalchemy import or_
        
        conditions = []
        for field in search_fields:
            # Assuming the field supports ilike (case-insensitive search)
            conditions.append(field.ilike(search_pattern))
        
        return or_(*conditions) if conditions else None

# Dependency functions for FastAPI
def get_pagination_params(
    page: int = Query(1, ge=1, le=10000, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page")
) -> PaginationParams:
    """FastAPI dependency for basic pagination parameters"""
    return PaginationParams(page=page, per_page=per_page)

def get_advanced_pagination_params(
    page: int = Query(1, ge=1, le=10000, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    sort_by: Optional[str] = Query(None, description="Field to sort by"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    search: Optional[str] = Query(None, max_length=255, description="Search query"),
    created_after: Optional[str] = Query(None, description="Filter by creation date (ISO format)"),
    created_before: Optional[str] = Query(None, description="Filter by creation date (ISO format)")
) -> AdvancedPaginationParams:
    """FastAPI dependency for advanced pagination parameters"""
    return AdvancedPaginationParams(
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
        search=search,
        created_after=created_after,
        created_before=created_before
    )

# Utility functions
def create_pagination_links(base_url: str, params: PaginationParams, meta: PaginationMeta) -> Dict[str, Optional[str]]:
    """Create pagination links for API responses"""
    links = {
        'self': f"{base_url}?page={params.page}&per_page={params.per_page}",
        'first': f"{base_url}?page=1&per_page={params.per_page}",
        'last': f"{base_url}?page={meta.total_pages}&per_page={params.per_page}" if meta.total_pages > 0 else None,
        'next': f"{base_url}?page={meta.next_page}&per_page={params.per_page}" if meta.next_page else None,
        'prev': f"{base_url}?page={meta.prev_page}&per_page={params.per_page}" if meta.prev_page else None
    }
    
    return links

def validate_pagination_params(page: int, per_page: int) -> tuple[int, int]:
    """Validate and normalize pagination parameters"""
    # Ensure page is at least 1
    if page < 1:
        page = 1
    elif page > 10000:  # Reasonable upper limit
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Page number too large (max: 10000)"
        )
    
    # Ensure per_page is within reasonable bounds
    if per_page < 1:
        per_page = 20  # Default
    elif per_page > 100:  # Reasonable upper limit
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Per page limit too large (max: 100)"
        )
    
    return page, per_page