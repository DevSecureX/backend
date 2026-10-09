"""
Rule Deduplication Service
Advanced pattern-based deduplication for security rules with similarity detection
"""

import re
import hashlib
import difflib
import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass
from datetime import datetime
import yaml
import asyncio
from concurrent.futures import ThreadPoolExecutor
import Levenshtein  # For fuzzy string matching

logger = logging.getLogger(__name__)

@dataclass
class DuplicateResult:
    """Result of duplicate detection"""
    is_duplicate: bool
    similarity_score: float
    duplicate_rule_id: Optional[str] = None
    duplicate_rule_name: Optional[str] = None
    similarity_type: Optional[str] = None  # 'exact', 'pattern', 'semantic'
    confidence: float = 0.0

@dataclass
class RuleFingerprint:
    """Normalized fingerprint of a rule for comparison"""
    pattern_hash: str
    normalized_pattern: str
    keywords: Set[str]
    pattern_type: str
    complexity_score: float
    rule_id: str
    rule_name: str

class RuleDeduplicator:
    """Advanced rule deduplication with pattern analysis"""
    
    def __init__(self, similarity_threshold: float = 0.85):
        self.similarity_threshold = similarity_threshold
        self.pattern_cache: Dict[str, RuleFingerprint] = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Compiled regex patterns for common rule patterns
        self.security_patterns = {
            'sql_injection': re.compile(r'(select|insert|update|delete|union|exec|drop)\s+', re.IGNORECASE),
            'xss': re.compile(r'(script|javascript|onerror|onload|alert|eval)', re.IGNORECASE),
            'path_traversal': re.compile(r'(\.\./|\\\.\\\.\\|path|traversal)', re.IGNORECASE),
            'command_injection': re.compile(r'(exec|system|shell|command|subprocess)', re.IGNORECASE),
            'hardcoded_secrets': re.compile(r'(password|secret|api[_-]?key|token)', re.IGNORECASE),
            'crypto_issues': re.compile(r'(md5|sha1|des|rc4|weak|crypto)', re.IGNORECASE),
        }
        
        logger.info(f"Rule deduplicator initialized with threshold {similarity_threshold}")
    
    def _normalize_pattern(self, pattern: str) -> str:
        """Normalize pattern for comparison"""
        try:
            # Parse YAML if possible
            if pattern.strip().startswith('{') or 'pattern' in pattern:
                try:
                    parsed = yaml.safe_load(pattern)
                    if isinstance(parsed, dict):
                        # Extract the actual pattern content
                        if 'pattern' in parsed:
                            pattern = str(parsed['pattern'])
                        elif 'patterns' in parsed:
                            pattern = str(parsed['patterns'])
                        elif 'pattern-either' in parsed:
                            pattern = str(parsed['pattern-either'])
                        elif 'pattern-regex' in parsed:
                            pattern = str(parsed['pattern-regex'])
                        else:
                            # If it's a rules array, extract first rule's pattern
                            if 'rules' in parsed and parsed['rules']:
                                first_rule = parsed['rules'][0]
                                if 'pattern' in first_rule:
                                    pattern = str(first_rule['pattern'])
                                elif 'patterns' in first_rule:
                                    pattern = str(first_rule['patterns'])
                except yaml.YAMLError:
                    pass
            
            # Normalize whitespace and remove comments
            normalized = re.sub(r'\\s+', ' ', pattern)
            normalized = re.sub(r'#.*$', '', normalized, flags=re.MULTILINE)
            
            # Remove extra whitespace
            normalized = ' '.join(normalized.split())
            
            # Convert to lowercase for comparison
            normalized = normalized.lower()
            
            return normalized.strip()
            
        except Exception as e:
            logger.warning(f"Failed to normalize pattern: {e}")
            return pattern.lower().strip()
    
    def _extract_keywords(self, pattern: str) -> Set[str]:
        """Extract meaningful keywords from pattern"""
        keywords = set()
        
        # Extract quoted strings
        quoted_strings = re.findall(r'["\']([^"\']+)["\']', pattern)
        for s in quoted_strings:
            if len(s) > 2:  # Ignore very short strings
                keywords.add(s.lower())
        
        # Extract function/method names
        functions = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)(\s*\()', pattern)
        for func, _ in functions:
            keywords.add(func.lower())
        
        # Extract variable patterns
        variables = re.findall(r'\$([a-zA-Z_][a-zA-Z0-9_]*)', pattern)
        for var in variables:
            keywords.add(var.lower())
        
        # Security-specific keywords
        for category, regex in self.security_patterns.items():
            if regex.search(pattern):
                keywords.add(category)
        
        return keywords
    
    def _calculate_complexity_score(self, pattern: str) -> float:
        """Calculate pattern complexity score"""
        complexity = 0.0
        
        # Count regex metacharacters
        metacharacters = r'\\[\\](){}.*+?^$|'
        complexity += sum(1 for char in pattern if char in metacharacters) * 0.1
        
        # Count nested structures
        nesting_depth = 0
        max_depth = 0
        for char in pattern:
            if char in '([{':
                nesting_depth += 1
                max_depth = max(max_depth, nesting_depth)
            elif char in ')]}':
                nesting_depth -= 1
        
        complexity += max_depth * 0.2
        
        # Count unique keywords
        keywords = self._extract_keywords(pattern)
        complexity += len(keywords) * 0.05
        
        # Pattern length factor
        complexity += len(pattern) * 0.001
        
        return min(complexity, 10.0)  # Cap at 10.0
    
    def _generate_fingerprint(self, rule_data: Dict[str, Any]) -> RuleFingerprint:
        """Generate fingerprint for a rule"""
        pattern = rule_data.get('pattern', '')
        rule_id = rule_data.get('id', rule_data.get('rule_id', ''))
        rule_name = rule_data.get('rule_name', rule_data.get('name', ''))
        
        normalized_pattern = self._normalize_pattern(pattern)
        pattern_hash = hashlib.sha256(normalized_pattern.encode()).hexdigest()[:16]
        keywords = self._extract_keywords(pattern)
        complexity_score = self._calculate_complexity_score(pattern)
        
        # Determine pattern type
        pattern_type = 'generic'
        if 'pattern-regex' in pattern or re.search(r'\\\\[a-zA-Z]', pattern):
            pattern_type = 'regex'
        elif 'patterns:' in pattern or isinstance(rule_data.get('patterns'), list):
            pattern_type = 'multi_pattern'
        elif 'pattern-either' in pattern:
            pattern_type = 'either_pattern'
        
        return RuleFingerprint(
            pattern_hash=pattern_hash,
            normalized_pattern=normalized_pattern,
            keywords=keywords,
            pattern_type=pattern_type,
            complexity_score=complexity_score,
            rule_id=rule_id,
            rule_name=rule_name
        )
    
    def _calculate_pattern_similarity(self, pattern1: str, pattern2: str) -> float:
        """Calculate similarity between two patterns using multiple methods"""
        if not pattern1 or not pattern2:
            return 0.0
        
        # Exact match
        if pattern1 == pattern2:
            return 1.0
        
        # Levenshtein similarity
        levenshtein_similarity = 1 - (Levenshtein.distance(pattern1, pattern2) / max(len(pattern1), len(pattern2)))
        
        # Sequence matcher similarity
        sequence_similarity = difflib.SequenceMatcher(None, pattern1, pattern2).ratio()
        
        # Token-based similarity (split by whitespace and special chars)
        tokens1 = set(re.split(r'[\\s\\W]+', pattern1))
        tokens2 = set(re.split(r'[\\s\\W]+', pattern2))
        
        if tokens1 or tokens2:
            token_similarity = len(tokens1 & tokens2) / len(tokens1 | tokens2)
        else:
            token_similarity = 0.0
        
        # Combined score with weights
        combined_similarity = (
            levenshtein_similarity * 0.4 +
            sequence_similarity * 0.4 +
            token_similarity * 0.2
        )
        
        return combined_similarity
    
    def _calculate_keyword_similarity(self, keywords1: Set[str], keywords2: Set[str]) -> float:
        """Calculate similarity based on keywords"""
        if not keywords1 and not keywords2:
            return 1.0
        if not keywords1 or not keywords2:
            return 0.0
        
        intersection = keywords1 & keywords2
        union = keywords1 | keywords2
        
        return len(intersection) / len(union) if union else 0.0
    
    async def check_for_duplicates(
        self, 
        new_rule: Dict[str, Any], 
        existing_rules: List[Dict[str, Any]]
    ) -> DuplicateResult:
        """Check if a new rule is a duplicate of existing rules"""
        
        if not existing_rules:
            return DuplicateResult(is_duplicate=False, similarity_score=0.0)
        
        # Generate fingerprint for new rule
        new_fingerprint = self._generate_fingerprint(new_rule)
        
        # Check against existing rules
        max_similarity = 0.0
        best_match = None
        best_match_type = None
        
        for existing_rule in existing_rules:
            existing_fingerprint = self._generate_fingerprint(existing_rule)
            
            # Quick hash check for exact duplicates
            if new_fingerprint.pattern_hash == existing_fingerprint.pattern_hash:
                return DuplicateResult(
                    is_duplicate=True,
                    similarity_score=1.0,
                    duplicate_rule_id=existing_fingerprint.rule_id,
                    duplicate_rule_name=existing_fingerprint.rule_name,
                    similarity_type='exact',
                    confidence=1.0
                )
            
            # Pattern similarity check
            pattern_similarity = self._calculate_pattern_similarity(
                new_fingerprint.normalized_pattern,
                existing_fingerprint.normalized_pattern
            )
            
            # Keyword similarity check
            keyword_similarity = self._calculate_keyword_similarity(
                new_fingerprint.keywords,
                existing_fingerprint.keywords
            )
            
            # Combined similarity score
            combined_similarity = (
                pattern_similarity * 0.7 +
                keyword_similarity * 0.3
            )
            
            # Bonus for same pattern type
            if new_fingerprint.pattern_type == existing_fingerprint.pattern_type:
                combined_similarity += 0.05
            
            # Penalty for very different complexity
            complexity_diff = abs(new_fingerprint.complexity_score - existing_fingerprint.complexity_score)
            if complexity_diff > 2.0:
                combined_similarity -= 0.1
            
            if combined_similarity > max_similarity:
                max_similarity = combined_similarity
                best_match = existing_fingerprint
                
                # Determine similarity type
                if combined_similarity >= 0.95:
                    best_match_type = 'exact'
                elif pattern_similarity >= 0.8:
                    best_match_type = 'pattern'
                elif keyword_similarity >= 0.8:
                    best_match_type = 'semantic'
                else:
                    best_match_type = 'partial'
        
        # Calculate confidence based on similarity score and match quality
        confidence = max_similarity
        if best_match_type == 'exact':
            confidence = min(confidence + 0.1, 1.0)
        elif best_match_type == 'pattern':
            confidence = min(confidence + 0.05, 1.0)
        
        is_duplicate = max_similarity >= self.similarity_threshold
        
        return DuplicateResult(
            is_duplicate=is_duplicate,
            similarity_score=max_similarity,
            duplicate_rule_id=best_match.rule_id if best_match else None,
            duplicate_rule_name=best_match.rule_name if best_match else None,
            similarity_type=best_match_type,
            confidence=confidence
        )
    
    async def find_similar_rules(
        self, 
        target_rule: Dict[str, Any], 
        rule_pool: List[Dict[str, Any]], 
        min_similarity: float = 0.5
    ) -> List[Tuple[Dict[str, Any], float]]:
        """Find all rules similar to target rule above minimum similarity"""
        
        target_fingerprint = self._generate_fingerprint(target_rule)
        similar_rules = []
        
        for rule in rule_pool:
            rule_fingerprint = self._generate_fingerprint(rule)
            
            pattern_similarity = self._calculate_pattern_similarity(
                target_fingerprint.normalized_pattern,
                rule_fingerprint.normalized_pattern
            )
            
            keyword_similarity = self._calculate_keyword_similarity(
                target_fingerprint.keywords,
                rule_fingerprint.keywords
            )
            
            combined_similarity = (
                pattern_similarity * 0.7 +
                keyword_similarity * 0.3
            )
            
            if combined_similarity >= min_similarity:
                similar_rules.append((rule, combined_similarity))
        
        # Sort by similarity score descending
        similar_rules.sort(key=lambda x: x[1], reverse=True)
        
        return similar_rules
    
    async def deduplicate_rule_set(
        self, 
        rules: List[Dict[str, Any]], 
        keep_strategy: str = 'first'  # 'first', 'highest_quality', 'most_recent'
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Deduplicate a set of rules, returning kept and removed rules"""
        
        if not rules:
            return [], []
        
        kept_rules = []
        removed_rules = []
        processed_hashes = set()
        
        for rule in rules:
            fingerprint = self._generate_fingerprint(rule)
            
            # Check if we've seen this exact pattern before
            if fingerprint.pattern_hash in processed_hashes:
                removed_rules.append(rule)
                continue
            
            # Check for similar rules in kept_rules
            duplicate_result = await self.check_for_duplicates(rule, kept_rules)
            
            if duplicate_result.is_duplicate:
                if keep_strategy == 'first':
                    removed_rules.append(rule)
                elif keep_strategy == 'highest_quality':
                    # Replace if this rule has higher complexity/quality
                    if fingerprint.complexity_score > self._generate_fingerprint(
                        next(r for r in kept_rules if r.get('id') == duplicate_result.duplicate_rule_id)
                    ).complexity_score:
                        # Remove the existing rule and add this one
                        kept_rules = [r for r in kept_rules if r.get('id') != duplicate_result.duplicate_rule_id]
                        removed_rules.extend([r for r in kept_rules if r.get('id') == duplicate_result.duplicate_rule_id])
                        kept_rules.append(rule)
                        processed_hashes.add(fingerprint.pattern_hash)
                    else:
                        removed_rules.append(rule)
                elif keep_strategy == 'most_recent':
                    # Compare creation dates if available
                    rule_date = rule.get('created_at', rule.get('updated_at', ''))
                    existing_rule = next(r for r in kept_rules if r.get('id') == duplicate_result.duplicate_rule_id)
                    existing_date = existing_rule.get('created_at', existing_rule.get('updated_at', ''))
                    
                    if rule_date > existing_date:
                        kept_rules = [r for r in kept_rules if r.get('id') != duplicate_result.duplicate_rule_id]
                        removed_rules.extend([r for r in kept_rules if r.get('id') == duplicate_result.duplicate_rule_id])
                        kept_rules.append(rule)
                        processed_hashes.add(fingerprint.pattern_hash)
                    else:
                        removed_rules.append(rule)
                else:
                    removed_rules.append(rule)
            else:
                kept_rules.append(rule)
                processed_hashes.add(fingerprint.pattern_hash)
        
        logger.info(f"Deduplication complete: {len(kept_rules)} kept, {len(removed_rules)} removed")
        
        return kept_rules, removed_rules
    
    def get_deduplication_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics"""
        return {
            'cached_fingerprints': len(self.pattern_cache),
            'similarity_threshold': self.similarity_threshold,
            'pattern_types_supported': list(self.security_patterns.keys()),
            'executor_threads': self.executor._max_workers
        }

# Global deduplicator instance
_deduplicator = None

def get_rule_deduplicator() -> RuleDeduplicator:
    """Get global rule deduplicator instance"""
    global _deduplicator
    if _deduplicator is None:
        _deduplicator = RuleDeduplicator()
    return _deduplicator