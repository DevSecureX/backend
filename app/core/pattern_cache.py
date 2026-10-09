"""
Pattern Cache Service
High-performance caching for validated patterns, compiled regex, and rule metadata
"""

import re
import hashlib
import time
import logging
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from threading import RLock
import yaml
import asyncio
from functools import lru_cache

logger = logging.getLogger(__name__)

@dataclass
class CachedPattern:
    """Cached pattern with metadata"""
    pattern_hash: str
    compiled_regex: Optional[re.Pattern]
    validation_result: bool
    validation_errors: List[str]
    pattern_type: str
    tool: str
    timestamp: float
    access_count: int
    last_accessed: float

@dataclass
class CachedRule:
    """Cached rule with validation results"""
    rule_hash: str
    validated_rule: Dict[str, Any]
    is_valid: bool
    validation_errors: List[str]
    tool: str
    timestamp: float
    access_count: int
    last_accessed: float

class PatternCache:
    """High-performance pattern and rule cache with LRU eviction"""
    
    def __init__(self, max_patterns: int = 10000, max_rules: int = 5000, ttl_seconds: int = 3600):
        self.max_patterns = max_patterns
        self.max_rules = max_rules
        self.ttl_seconds = ttl_seconds
        
        # Thread-safe storage
        self._pattern_cache: Dict[str, CachedPattern] = {}
        self._rule_cache: Dict[str, CachedRule] = {}
        self._lock = RLock()
        
        # Cache statistics
        self.stats = {
            'pattern_hits': 0,
            'pattern_misses': 0,
            'rule_hits': 0,
            'rule_misses': 0,
            'evictions': 0,
            'validation_time_saved': 0.0
        }
        
        logger.info(f"PatternCache initialized: max_patterns={max_patterns}, max_rules={max_rules}, ttl={ttl_seconds}s")
    
    def _generate_pattern_hash(self, pattern: str, tool: str = "semgrep") -> str:
        """Generate unique hash for pattern + tool combination"""
        content = f"{tool}:{pattern}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _generate_rule_hash(self, rule_data: Dict[str, Any], tool: str = "semgrep") -> str:
        """Generate unique hash for rule data + tool combination"""
        # Normalize rule data for consistent hashing
        normalized = {
            'tool': tool,
            'pattern': rule_data.get('pattern', ''),
            'patterns': rule_data.get('patterns', []),
            'pattern-either': rule_data.get('pattern-either', []),
            'pattern-regex': rule_data.get('pattern-regex', ''),
            'message': rule_data.get('message', ''),
            'severity': rule_data.get('severity', ''),
            'languages': sorted(rule_data.get('languages', []) if isinstance(rule_data.get('languages'), list) else [])
        }
        content = str(normalized)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _is_expired(self, timestamp: float) -> bool:
        """Check if cache entry is expired"""
        return (time.time() - timestamp) > self.ttl_seconds
    
    def _evict_expired(self):
        """Remove expired entries"""
        current_time = time.time()
        
        # Evict expired patterns
        expired_patterns = [
            key for key, cached in self._pattern_cache.items()
            if self._is_expired(cached.timestamp)
        ]
        for key in expired_patterns:
            del self._pattern_cache[key]
            self.stats['evictions'] += 1
        
        # Evict expired rules
        expired_rules = [
            key for key, cached in self._rule_cache.items()
            if self._is_expired(cached.timestamp)
        ]
        for key in expired_rules:
            del self._rule_cache[key]
            self.stats['evictions'] += 1
        
        if expired_patterns or expired_rules:
            logger.debug(f"Evicted {len(expired_patterns)} patterns and {len(expired_rules)} rules")
    
    def _evict_lru(self):
        """Evict least recently used entries when cache is full"""
        # Evict LRU patterns if over limit
        if len(self._pattern_cache) >= self.max_patterns:
            # Sort by last_accessed and remove oldest
            sorted_patterns = sorted(
                self._pattern_cache.items(),
                key=lambda x: x[1].last_accessed
            )
            num_to_evict = len(sorted_patterns) - self.max_patterns + 100  # Evict extra for buffer
            for key, _ in sorted_patterns[:num_to_evict]:
                del self._pattern_cache[key]
                self.stats['evictions'] += 1
        
        # Evict LRU rules if over limit
        if len(self._rule_cache) >= self.max_rules:
            # Sort by last_accessed and remove oldest
            sorted_rules = sorted(
                self._rule_cache.items(),
                key=lambda x: x[1].last_accessed
            )
            num_to_evict = len(sorted_rules) - self.max_rules + 50  # Evict extra for buffer
            for key, _ in sorted_rules[:num_to_evict]:
                del self._rule_cache[key]
                self.stats['evictions'] += 1
    
    def get_compiled_pattern(self, pattern: str, tool: str = "semgrep") -> Optional[Tuple[re.Pattern, bool, List[str]]]:
        """Get compiled regex pattern from cache"""
        pattern_hash = self._generate_pattern_hash(pattern, tool)
        
        with self._lock:
            cached = self._pattern_cache.get(pattern_hash)
            
            if cached and not self._is_expired(cached.timestamp):
                # Cache hit
                cached.access_count += 1
                cached.last_accessed = time.time()
                self.stats['pattern_hits'] += 1
                
                return cached.compiled_regex, cached.validation_result, cached.validation_errors
            else:
                # Cache miss
                self.stats['pattern_misses'] += 1
                return None
    
    def cache_compiled_pattern(
        self, 
        pattern: str, 
        compiled_regex: Optional[re.Pattern], 
        is_valid: bool, 
        errors: List[str], 
        pattern_type: str = "regex",
        tool: str = "semgrep"
    ):
        """Cache compiled regex pattern with validation results"""
        pattern_hash = self._generate_pattern_hash(pattern, tool)
        current_time = time.time()
        
        with self._lock:
            # Clean up expired entries and enforce size limits
            self._evict_expired()
            self._evict_lru()
            
            cached_pattern = CachedPattern(
                pattern_hash=pattern_hash,
                compiled_regex=compiled_regex,
                validation_result=is_valid,
                validation_errors=errors,
                pattern_type=pattern_type,
                tool=tool,
                timestamp=current_time,
                access_count=1,
                last_accessed=current_time
            )
            
            self._pattern_cache[pattern_hash] = cached_pattern
            logger.debug(f"Cached pattern {pattern_hash} for tool {tool}")
    
    def get_validated_rule(self, rule_data: Dict[str, Any], tool: str = "semgrep") -> Optional[Tuple[Dict[str, Any], bool, List[str]]]:
        """Get validated rule from cache"""
        rule_hash = self._generate_rule_hash(rule_data, tool)
        
        with self._lock:
            cached = self._rule_cache.get(rule_hash)
            
            if cached and not self._is_expired(cached.timestamp):
                # Cache hit
                cached.access_count += 1
                cached.last_accessed = time.time()
                self.stats['rule_hits'] += 1
                
                return cached.validated_rule, cached.is_valid, cached.validation_errors
            else:
                # Cache miss
                self.stats['rule_misses'] += 1
                return None
    
    def cache_validated_rule(
        self, 
        rule_data: Dict[str, Any], 
        validated_rule: Dict[str, Any], 
        is_valid: bool, 
        errors: List[str], 
        tool: str = "semgrep"
    ):
        """Cache validated rule with results"""
        rule_hash = self._generate_rule_hash(rule_data, tool)
        current_time = time.time()
        
        with self._lock:
            # Clean up expired entries and enforce size limits
            self._evict_expired()
            self._evict_lru()
            
            cached_rule = CachedRule(
                rule_hash=rule_hash,
                validated_rule=validated_rule,
                is_valid=is_valid,
                validation_errors=errors,
                tool=tool,
                timestamp=current_time,
                access_count=1,
                last_accessed=current_time
            )
            
            self._rule_cache[rule_hash] = cached_rule
            logger.debug(f"Cached rule {rule_hash} for tool {tool}")
    
    @lru_cache(maxsize=1000)
    def validate_yaml_pattern(self, pattern: str) -> Tuple[bool, List[str]]:
        """Cache YAML pattern validation using LRU cache"""
        errors = []
        try:
            parsed = yaml.safe_load(pattern)
            if not isinstance(parsed, dict):
                errors.append("Pattern must be a YAML dictionary")
                return False, errors
            return True, []
        except yaml.YAMLError as e:
            errors.append(f"Invalid YAML: {str(e)}")
            return False, errors
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get detailed cache statistics"""
        with self._lock:
            pattern_hit_rate = (
                self.stats['pattern_hits'] / (self.stats['pattern_hits'] + self.stats['pattern_misses'])
                if (self.stats['pattern_hits'] + self.stats['pattern_misses']) > 0 else 0
            )
            
            rule_hit_rate = (
                self.stats['rule_hits'] / (self.stats['rule_hits'] + self.stats['rule_misses'])
                if (self.stats['rule_hits'] + self.stats['rule_misses']) > 0 else 0
            )
            
            return {
                'pattern_cache_size': len(self._pattern_cache),
                'rule_cache_size': len(self._rule_cache),
                'pattern_hit_rate': round(pattern_hit_rate * 100, 2),
                'rule_hit_rate': round(rule_hit_rate * 100, 2),
                'total_evictions': self.stats['evictions'],
                'validation_time_saved_ms': round(self.stats['validation_time_saved'] * 1000, 2),
                'max_patterns': self.max_patterns,
                'max_rules': self.max_rules,
                'ttl_seconds': self.ttl_seconds
            }
    
    def clear_cache(self):
        """Clear all cached data"""
        with self._lock:
            self._pattern_cache.clear()
            self._rule_cache.clear()
            self.stats = {
                'pattern_hits': 0,
                'pattern_misses': 0,
                'rule_hits': 0,
                'rule_misses': 0,
                'evictions': 0,
                'validation_time_saved': 0.0
            }
        logger.info("Pattern cache cleared")
    
    def warm_cache(self, common_patterns: List[Tuple[str, str]]):
        """Warm cache with commonly used patterns"""
        logger.info(f"Warming cache with {len(common_patterns)} patterns")
        
        for pattern, tool in common_patterns:
            try:
                # Pre-validate and cache common patterns
                start_time = time.time()
                
                # Try to compile as regex
                compiled_regex = None
                errors = []
                is_valid = True
                
                try:
                    compiled_regex = re.compile(pattern)
                except re.error as e:
                    errors.append(f"Regex compilation failed: {str(e)}")
                    is_valid = False
                
                # Also validate as YAML
                yaml_valid, yaml_errors = self.validate_yaml_pattern(pattern)
                if not yaml_valid:
                    errors.extend(yaml_errors)
                
                self.cache_compiled_pattern(
                    pattern, compiled_regex, is_valid, errors, "regex", tool
                )
                
                validation_time = time.time() - start_time
                self.stats['validation_time_saved'] += validation_time
                
            except Exception as e:
                logger.warning(f"Failed to warm cache for pattern {pattern[:50]}...: {e}")
        
        logger.info(f"Cache warming completed. Stats: {self.get_cache_stats()}")

# Global cache instance
_pattern_cache = None

def get_pattern_cache() -> PatternCache:
    """Get global pattern cache instance"""
    global _pattern_cache
    if _pattern_cache is None:
        _pattern_cache = PatternCache()
    return _pattern_cache

async def init_pattern_cache():
    """Initialize pattern cache with common patterns"""
    cache = get_pattern_cache()
    
    # Common security patterns to warm the cache
    common_patterns = [
        (r'password\s*=\s*["\'][^"\']+["\']', 'semgrep'),
        (r'api[_-]?key\s*[=:]\s*["\'][^"\']+["\']', 'semgrep'),
        (r'secret\s*[=:]\s*["\'][^"\']+["\']', 'semgrep'),
        (r'eval\s*\(', 'semgrep'),
        (r'exec\s*\(', 'semgrep'),
        (r'subprocess\.call', 'semgrep'),
        (r'os\.system', 'semgrep'),
        (r'sql\s*=\s*["\'].*\+.*["\']', 'semgrep'),
        (r'SELECT\s+.*\s+FROM\s+.*WHERE\s+.*=\s*\$', 'semgrep'),
        (r'document\.createElement\s*\(', 'semgrep'),
    ]
    
    # Warm cache in thread pool to avoid blocking
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, cache.warm_cache, common_patterns)
    
    logger.info("Pattern cache initialization completed")