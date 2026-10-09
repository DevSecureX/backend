"""
Custom Rules Integration Service
Seamlessly integrates user-created custom rules with the existing scan engine
"""

import os
import yaml
import tempfile
import uuid
import logging
import asyncio
import contextlib
import time
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, update, func
from sqlalchemy.orm import selectinload

from custom_rules.models import CommunityRules
from custom_rules.config.rules_config import RulesConfig
from custom_rules.services.rules_service import CustomRulesService
from core.pattern_cache import get_pattern_cache

logger = logging.getLogger(__name__)

class CustomRulesIntegration:
    """Service for integrating custom rules with the scan engine"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.rules_service = CustomRulesService(db)
        self.pattern_cache = get_pattern_cache()
    
    async def prepare_custom_rules_for_scan(
        self,
        user_id: int,
        niche: str,
        tool: str = 'semgrep',
        include_community: bool = False,
        temp_dir: Optional[str] = None,
        selected_custom_rule_ids: Optional[List[str]] = None,
        selected_community_rule_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Prepare custom rules for integration with scan engine
        
        Args:
            user_id: User whose custom rules to include
            niche: Security niche (ai, blockchain, iot, etc.)
            tool: Security tool name (default: semgrep)
            include_community: Whether to include popular community rules
            temp_dir: Temporary directory for rule files (optional)
            selected_custom_rule_ids: Specific custom rule IDs to include (optional)
            selected_community_rule_ids: Specific community rule IDs to include (optional)
            
        Returns:
            Dict containing rule files paths and metadata
        """
        
        # Input validation and security checks
        if user_id <= 0:
            raise ValueError("Invalid user_id")
        
        # Validate and sanitize tool parameter (all tools that support custom rules)
        from custom_rules.utils.security_validator import SecurityValidator
        allowed_tools = SecurityValidator.ALLOWED_TOOLS
        if tool.lower() not in allowed_tools:
            raise ValueError(f"Unsupported tool: {tool}")
        tool = tool.lower()
        
        # Validate niche parameter
        allowed_niches = {'all', 'ai', 'blockchain', 'iot', 'web', 'cloud', 'api'}
        if niche.lower() not in allowed_niches:
            raise ValueError(f"Unsupported niche: {niche}")
        
        # Validate rule IDs (UUID format check)
        import re
        uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
        
        if selected_custom_rule_ids:
            # Limit number of custom rules per scan
            if len(selected_custom_rule_ids) > 100:
                raise ValueError("Too many custom rules selected (max: 100)")
            for rule_id in selected_custom_rule_ids:
                if not uuid_pattern.match(rule_id):
                    raise ValueError(f"Invalid rule ID format: {rule_id}")
        
        if selected_community_rule_ids:
            # Limit number of community rules per scan  
            if len(selected_community_rule_ids) > 50:
                raise ValueError("Too many community rules selected (max: 50)")
            for rule_id in selected_community_rule_ids:
                if not uuid_pattern.match(rule_id):
                    raise ValueError(f"Invalid community rule ID format: {rule_id}")
        
        # Use context manager for proper temp directory cleanup
        @contextlib.asynccontextmanager
        async def managed_temp_dir():
            if temp_dir:
                # Use provided temp directory
                yield temp_dir
            else:
                # Create and manage our own temp directory
                created_temp_dir = tempfile.mkdtemp(prefix=f'custom_rules_{user_id}_')
                try:
                    yield created_temp_dir
                finally:
                    # Always cleanup temp directory we created
                    if os.path.exists(created_temp_dir):
                        import shutil
                        logger.info(f"Cleaning up custom rules temp directory: {created_temp_dir}")
                        shutil.rmtree(created_temp_dir, ignore_errors=True)
        
        async with managed_temp_dir() as work_temp_dir:
        
            result = {
                'temp_dir': work_temp_dir,
                'rule_files': [],
                'user_rules_count': 0,
                'community_rules_count': 0,
                'total_rules': 0,
                'rule_categories': []
            }
            # Parallel execution: Get both user and community rules concurrently
            tasks = []
            
            # 1. Get user's custom rules (async task)
            if selected_custom_rule_ids:
                user_rules_task = self._get_specific_user_rules(user_id, selected_custom_rule_ids, tool)
            else:
                user_rules_task = self._get_user_rules_for_scan(user_id, tool, niche)
            tasks.append(('user', user_rules_task))
            
            # 2. Get community rules if requested (async task)
            community_rules_task = None
            if include_community:
                if selected_community_rule_ids:
                    community_rules_task = self._get_specific_community_rules(selected_community_rule_ids, tool)
                else:
                    community_rules_task = self._get_popular_community_rules(tool, niche)
                tasks.append(('community', community_rules_task))
            
            # Execute all rule fetching tasks concurrently
            results_data = await asyncio.gather(*[task[1] for task in tasks], return_exceptions=True)
            
            # Process results and create rule files in parallel
            rule_file_tasks = []
            
            for i, (rule_type, _) in enumerate(tasks):
                rules_data = results_data[i]
                if isinstance(rules_data, Exception):
                    logger.error(f"Error fetching {rule_type} rules: {rules_data}")
                    continue
                    
                if rules_data:
                    if rule_type == 'user':
                        file_path = os.path.join(work_temp_dir, f'user_custom_rules_{tool}.yaml')
                        description = f"Custom rules for user {user_id}"
                        rule_file_tasks.append((
                            rule_type, 
                            self._create_rule_file(rules_data, file_path, description),
                            len(rules_data)
                        ))
                    elif rule_type == 'community':
                        file_path = os.path.join(work_temp_dir, f'community_rules_{tool}.yaml')
                        description = f"Community rules for {niche}"
                        rule_file_tasks.append((
                            rule_type,
                            self._create_rule_file(rules_data, file_path, description),
                            len(rules_data)
                        ))
            
            # Execute rule file creation tasks in parallel
            if rule_file_tasks:
                file_results = await asyncio.gather(
                    *[task[1] for task in rule_file_tasks], 
                    return_exceptions=True
                )
                
                # Process file creation results
                for i, (rule_type, _, rule_count) in enumerate(rule_file_tasks):
                    file_result = file_results[i]
                    if isinstance(file_result, Exception):
                        logger.error(f"Error creating {rule_type} rule file: {file_result}")
                        continue
                        
                    result['rule_files'].append(file_result)
                    if rule_type == 'user':
                        result['user_rules_count'] = rule_count
                        result['rule_categories'].append('user_custom')
                    elif rule_type == 'community':
                        result['community_rules_count'] = rule_count
                        result['rule_categories'].append('community')
            
            # 3. Update total count
            result['total_rules'] = result['user_rules_count'] + result['community_rules_count']
            
            # 4. Log rule preparation
            logger.info(
                f"Custom rules prepared for user {user_id}: "
                f"{result['user_rules_count']} user rules, "
                f"{result['community_rules_count']} community rules "
                f"(parallel processing)"
            )
            
            return result
    
    async def get_enhanced_rules_config(
        self,
        user_id: int,
        niche: str,
        include_custom: bool = True,
        include_community: bool = False
    ) -> Dict[str, Any]:
        """
        Get enhanced rules configuration including custom rules
        
        Args:
            user_id: User ID for custom rules
            niche: Security niche
            include_custom: Whether to include user's custom rules
            include_community: Whether to include community rules
            
        Returns:
            Enhanced rules configuration
        """
        
        # Start with base configuration
        base_config = RulesConfig.get_rules_for_niche(niche)
        
        # Initialize enhanced config
        enhanced_config = {
            'base_config': base_config,
            'custom_rules_enabled': include_custom,
            'community_rules_enabled': include_community,
            'total_rules': base_config.get('total_rules', 0),
            'rule_sources': ['builtin'],
            'custom_rules_count': 0,
            'community_rules_count': 0
        }
        
        if include_custom:
            # Count user's custom rules
            user_rules_count = await self._count_user_rules(user_id, niche)
            enhanced_config['custom_rules_count'] = user_rules_count
            enhanced_config['total_rules'] += user_rules_count
            if user_rules_count > 0:
                enhanced_config['rule_sources'].append('custom')
        
        if include_community:
            # Count popular community rules
            community_rules_count = await self._count_community_rules(niche)
            enhanced_config['community_rules_count'] = community_rules_count
            enhanced_config['total_rules'] += community_rules_count
            if community_rules_count > 0:
                enhanced_config['rule_sources'].append('community')
        
        return enhanced_config
    
    async def update_rule_usage_stats(self, user_id: int, tool: str = 'semgrep') -> None:
        """Update usage statistics for user's custom rules after scan"""
        
        try:
            # Update usage count for all of user's rules used in scan
            await self.db.execute(
                update(CommunityRules)
                .where(and_(
                    CommunityRules.author_id == user_id,
                    CommunityRules.tool == tool
                ))
                .values(usage_count=CommunityRules.usage_count + 1)
            )
            await self.db.commit()
            
            logger.info(f"Updated usage stats for user {user_id} custom rules")
            
        except Exception as e:
            logger.error(f"Error updating rule usage stats: {str(e)}")
    
    # Private helper methods
    
    async def _get_user_rules_for_scan(
        self, 
        user_id: int, 
        tool: str, 
        niche: str
    ) -> List[Dict[str, Any]]:
        """Get user's custom rules that match the scan parameters with optimized loading"""
        
        # Use eager loading to prevent N+1 queries
        query = select(CommunityRules).options(
            selectinload(CommunityRules.votes) if hasattr(CommunityRules, 'votes') else selectinload('*')
        ).where(
            and_(
                CommunityRules.author_id == user_id,
                CommunityRules.tool == tool.lower()
            )
        )
        
        # Filter by niche/language if applicable
        if niche != 'all':
            # Get supported languages for the niche
            niche_config = RulesConfig.get_rules_for_niche(niche)
            if niche_config:
                supported_languages = niche_config.get('languages', [])
                if supported_languages:
                    query = query.where(
                        or_(
                            CommunityRules.language.in_(supported_languages),
                            CommunityRules.language.is_(None)  # Include language-agnostic rules
                        )
                    )
        
        result = await self.db.execute(query)
        rules = result.scalars().all()
        
        # Convert rules with validation - skip invalid ones
        validated_rules = []
        for rule in rules:
            try:
                scan_rule = self._rule_model_to_scan_format(rule)
                validated_rules.append(scan_rule)
            except (ValueError, yaml.YAMLError) as e:
                logger.warning(f"Skipping invalid user rule {rule.id}: {str(e)}")
                # Continue to next rule instead of failing entire scan
                continue
        
        if len(validated_rules) < len(rules):
            logger.info(f"Filtered {len(rules) - len(validated_rules)} invalid user rules from scan")
        
        return validated_rules
    
    async def _get_specific_user_rules(
        self,
        user_id: int,
        rule_ids: List[str],
        tool: str
    ) -> List[Dict[str, Any]]:
        """Get specific user rules by their IDs with optimized loading"""
        
        if not rule_ids:
            return []
        
        # Use eager loading to prevent N+1 queries
        query = select(CommunityRules).options(
            selectinload(CommunityRules.votes) if hasattr(CommunityRules, 'votes') else selectinload('*')
        ).where(
            and_(
                CommunityRules.author_id == user_id,
                CommunityRules.tool == tool.lower(),
                CommunityRules.id.in_(rule_ids)
            )
        )
        
        result = await self.db.execute(query)
        rules = result.scalars().all()
        
        # Convert rules with validation - skip invalid ones
        validated_rules = []
        for rule in rules:
            try:
                scan_rule = self._rule_model_to_scan_format(rule)
                validated_rules.append(scan_rule)
            except (ValueError, yaml.YAMLError) as e:
                logger.warning(f"Skipping invalid specific user rule {rule.id}: {str(e)}")
                continue
        
        if len(validated_rules) < len(rules):
            logger.info(f"Filtered {len(rules) - len(validated_rules)} invalid specific user rules")
        
        return validated_rules
    
    async def _get_specific_community_rules(
        self,
        rule_ids: List[str],
        tool: str
    ) -> List[Dict[str, Any]]:
        """Get specific community rules by their IDs with optimized loading"""
        
        if not rule_ids:
            return []
        
        # Use eager loading to prevent N+1 queries
        query = select(CommunityRules).options(
            selectinload(CommunityRules.votes) if hasattr(CommunityRules, 'votes') else selectinload('*')
        ).where(
            and_(
                CommunityRules.tool == tool.lower(),
                CommunityRules.is_public == True,
                CommunityRules.id.in_(rule_ids)
            )
        )
        
        result = await self.db.execute(query)
        rules = result.scalars().all()
        
        # Convert rules with validation - skip invalid ones
        validated_rules = []
        for rule in rules:
            try:
                scan_rule = self._rule_model_to_scan_format(rule)
                validated_rules.append(scan_rule)
            except (ValueError, yaml.YAMLError) as e:
                logger.warning(f"Skipping invalid community rule {rule.id}: {str(e)}")
                continue
        
        if len(validated_rules) < len(rules):
            logger.info(f"Filtered {len(rules) - len(validated_rules)} invalid community rules")
        
        return validated_rules
    
    async def _get_popular_community_rules(
        self, 
        tool: str, 
        niche: str,
        min_upvotes: int = 5,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Get popular community rules for the scan with optimized loading"""
        
        # Use eager loading to prevent N+1 queries
        query = select(CommunityRules).options(
            selectinload(CommunityRules.votes) if hasattr(CommunityRules, 'votes') else selectinload('*')
        ).where(
            and_(
                CommunityRules.tool == tool.lower(),
                CommunityRules.is_public == True,
                CommunityRules.upvotes >= min_upvotes
            )
        )
        
        # Filter by niche if applicable
        if niche != 'all':
            niche_config = RulesConfig.get_rules_for_niche(niche)
            if niche_config:
                supported_languages = niche_config.get('languages', [])
                if supported_languages:
                    query = query.where(
                        or_(
                            CommunityRules.language.in_(supported_languages),
                            CommunityRules.language.is_(None)
                        )
                    )
        
        # Order by popularity (combination of upvotes and usage)
        query = query.order_by(
            (CommunityRules.upvotes + CommunityRules.usage_count * 0.1).desc()
        ).limit(limit)
        
        result = await self.db.execute(query)
        rules = result.scalars().all()
        
        # Convert rules with validation - skip invalid ones
        validated_rules = []
        for rule in rules:
            try:
                scan_rule = self._rule_model_to_scan_format(rule)
                validated_rules.append(scan_rule)
            except (ValueError, yaml.YAMLError) as e:
                logger.warning(f"Skipping invalid popular community rule {rule.id}: {str(e)}")
                continue
        
        if len(validated_rules) < len(rules):
            logger.info(f"Filtered {len(rules) - len(validated_rules)} invalid popular community rules")
        
        return validated_rules
    
    async def _count_user_rules(self, user_id: int, niche: str) -> int:
        """Count user's custom rules for a specific niche"""
        
        query = select(func.count(CommunityRules.id)).where(
            CommunityRules.author_id == user_id
        )
        
        if niche != 'all':
            niche_config = RulesConfig.get_rules_for_niche(niche)
            if niche_config:
                supported_languages = niche_config.get('languages', [])
                if supported_languages:
                    query = query.where(
                        or_(
                            CommunityRules.language.in_(supported_languages),
                            CommunityRules.language.is_(None)
                        )
                    )
        
        result = await self.db.execute(query)
        return result.scalar() or 0
    
    async def _count_community_rules(self, niche: str, min_upvotes: int = 5) -> int:
        """Count popular community rules for a specific niche"""
        
        query = select(func.count(CommunityRules.id)).where(
            and_(
                CommunityRules.is_public == True,
                CommunityRules.upvotes >= min_upvotes
            )
        )
        
        if niche != 'all':
            niche_config = RulesConfig.get_rules_for_niche(niche)
            if niche_config:
                supported_languages = niche_config.get('languages', [])
                if supported_languages:
                    query = query.where(
                        or_(
                            CommunityRules.language.in_(supported_languages),
                            CommunityRules.language.is_(None)
                        )
                    )
        
        result = await self.db.execute(query)
        return result.scalar() or 0
    
    def _rule_model_to_scan_format(self, rule: CommunityRules) -> Dict[str, Any]:
        """Convert database rule model to scan engine format with caching support"""
        
        try:
            # Validate pattern size first
            if len(rule.pattern) > 10000:  # 10KB limit
                raise ValueError("Rule pattern exceeds maximum size limit")
            
            # Check cache for validated rule first
            rule_data_for_cache = {
                'pattern': rule.pattern,
                'rule_name': rule.rule_name,
                'tool': rule.tool,
                'language': rule.language
            }
            
            cached_result = self.pattern_cache.get_validated_rule(rule_data_for_cache, rule.tool)
            if cached_result is not None:
                validated_rule, is_valid, errors = cached_result
                if not is_valid:
                    raise ValueError(f"Cached validation failed: {'; '.join(errors)}")
                return validated_rule
            
            # Parse the pattern YAML with restricted loader
            start_time = time.time()
            try:
                pattern_data = yaml.safe_load(rule.pattern)
            except yaml.YAMLError as e:
                errors = [f"Invalid YAML pattern: {str(e)}"]
                # Cache the validation failure
                self.pattern_cache.cache_validated_rule(
                    rule_data_for_cache, {}, False, errors, rule.tool
                )
                raise ValueError(f"Invalid YAML pattern: {str(e)}")
            
            # Validate pattern structure
            if not isinstance(pattern_data, dict):
                raise ValueError("Pattern must be a valid YAML dictionary")
            
            # Security validation - block dangerous keys
            dangerous_keys = {'!!python', '__import__', 'eval', 'exec', 'compile'}
            pattern_str = str(pattern_data)
            if any(dangerous in pattern_str for dangerous in dangerous_keys):
                raise ValueError("Pattern contains potentially dangerous content")
            
            # Create rule in semgrep format with unique ID (no collision)
            unique_rule_id = f'custom-{rule.id.replace("-", "")[:16]}'  # Use more characters
            scan_rule = {
                'id': unique_rule_id,
                'message': (rule.description or f'Custom rule: {rule.rule_name}')[:200],  # Limit message length
                'severity': rule.severity.upper() if rule.severity.upper() in ['ERROR', 'WARNING', 'INFO'] else 'WARNING',
                'languages': [rule.language] if rule.language else ['generic'],
                'metadata': {
                    'custom_rule': True,
                    'rule_id': rule.id,
                    'rule_name': rule.rule_name[:100],  # Limit name length
                    'author_id': rule.author_id,
                    'upvotes': rule.upvotes,
                    'downvotes': getattr(rule, 'downvotes', 0),
                    'net_votes': rule.upvotes - getattr(rule, 'downvotes', 0),
                    'usage_count': rule.usage_count,
                    'is_public': rule.is_public,
                    'is_verified': getattr(rule, 'is_verified', False),
                    'rule_source': 'community' if rule.is_public else 'user_custom'
                }
            }
            
            # Add pattern data
            if isinstance(pattern_data, dict):
                # Check if this is a full rule format with 'rules' key
                if 'rules' in pattern_data and isinstance(pattern_data['rules'], list) and len(pattern_data['rules']) > 0:
                    # Extract the first rule's pattern fields
                    first_rule = pattern_data['rules'][0]
                    if 'patterns' in first_rule:
                        scan_rule['patterns'] = first_rule['patterns']
                    elif 'pattern' in first_rule:
                        scan_rule['pattern'] = first_rule['pattern']
                    elif 'pattern-either' in first_rule:
                        scan_rule['pattern-either'] = first_rule['pattern-either']
                    elif 'pattern-regex' in first_rule:
                        scan_rule['pattern-regex'] = first_rule['pattern-regex']
                    # Also preserve other important fields from the stored rule
                    if 'fix' in first_rule:
                        scan_rule['fix'] = first_rule['fix']
                    if 'languages' in first_rule and not scan_rule.get('languages'):
                        scan_rule['languages'] = first_rule['languages']
                # Otherwise check for pattern fields at top level
                elif 'patterns' in pattern_data:
                    scan_rule['patterns'] = pattern_data['patterns']
                elif 'pattern' in pattern_data:
                    scan_rule['pattern'] = pattern_data['pattern']
                elif 'pattern-either' in pattern_data:
                    scan_rule['pattern-either'] = pattern_data['pattern-either']
                elif 'pattern-regex' in pattern_data:
                    scan_rule['pattern-regex'] = pattern_data['pattern-regex']
                else:
                    # If pattern_data is the pattern itself
                    scan_rule.update(pattern_data)
            
            # Cache the successful validation
            self.pattern_cache.cache_validated_rule(
                rule_data_for_cache, scan_rule, True, [], rule.tool
            )
            
            # Update cache stats for time saved
            validation_time = time.time() - start_time
            self.pattern_cache.stats['validation_time_saved'] += validation_time
            
            return scan_rule
            
        except ValueError as e:
            # Cache validation failure to avoid reprocessing
            rule_data_for_cache = {
                'pattern': rule.pattern,
                'rule_name': rule.rule_name,
                'tool': rule.tool,
                'language': rule.language
            }
            self.pattern_cache.cache_validated_rule(
                rule_data_for_cache, {}, False, [str(e)], rule.tool
            )
            
            # Specific validation errors - don't include rule in scan
            logger.warning(f"Rule {rule.id} validation failed: {str(e)}")
            raise  # Re-raise to filter out invalid rules
            
        except yaml.YAMLError as e:
            # Cache YAML parsing failure
            rule_data_for_cache = {
                'pattern': rule.pattern,
                'rule_name': rule.rule_name,
                'tool': rule.tool,
                'language': rule.language
            }
            errors = [f"Invalid YAML in rule pattern: {str(e)}"]
            self.pattern_cache.cache_validated_rule(
                rule_data_for_cache, {}, False, errors, rule.tool
            )
            
            # YAML parsing errors - critical for rule functionality
            logger.error(f"YAML parsing error for rule {rule.id}: {str(e)}")
            raise ValueError(f"Invalid YAML in rule pattern: {str(e)}")
            
        except Exception as e:
            # Cache unexpected validation failure
            rule_data_for_cache = {
                'pattern': rule.pattern,
                'rule_name': rule.rule_name,
                'tool': rule.tool,
                'language': rule.language
            }
            errors = [f"Rule conversion failed: {str(e)}"]
            self.pattern_cache.cache_validated_rule(
                rule_data_for_cache, {}, False, errors, rule.tool
            )
            
            # Unexpected errors - log and skip rule
            logger.error(f"Unexpected error converting rule {rule.id}: {str(e)}", exc_info=True)
            # Don't return dummy rule - raise to skip invalid rules entirely
            raise ValueError(f"Rule conversion failed: {str(e)}")
    
    async def _create_rule_file(
        self, 
        rules: List[Dict[str, Any]], 
        file_path: str, 
        description: str
    ) -> str:
        """Create a rule file from list of rules with validation"""
        
        if not rules:
            raise ValueError("No rules to write to file")
        
        # Final validation of rules before writing
        validated_rules = []
        for rule in rules:
            if self._validate_rule_structure(rule):
                validated_rules.append(rule)
            else:
                logger.warning(f"Skipping invalid rule {rule.get('id', 'unknown')} during file creation")
        
        if not validated_rules:
            raise ValueError("No valid rules remaining after validation")
        
        rule_data = {
            'rules': validated_rules
        }
        
        # Add metadata
        rule_data['metadata'] = {
            'description': description,
            'total_rules': len(validated_rules),
            'created_by': 'devsecurex-custom-rules',
            'version': '1.0',
            'generated_at': uuid.uuid4().hex[:8]  # Add unique identifier
        }
        
        # Write YAML file with enhanced error handling and validation
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                # Use safe YAML dumping with proper formatting
                yaml.dump(
                    rule_data, 
                    f, 
                    default_flow_style=False, 
                    sort_keys=False,
                    allow_unicode=True,
                    width=120,
                    indent=2
                )
            
            # Verify file was written correctly
            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                raise IOError(f"Failed to write rule file: {file_path}")
            
            # Validate the written YAML can be parsed back
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    test_load = yaml.safe_load(f)
                    if not isinstance(test_load, dict) or 'rules' not in test_load:
                        raise ValueError("Generated YAML does not have expected structure")
            except yaml.YAMLError as e:
                raise ValueError(f"Generated YAML is not valid: {e}")
            
            logger.info(f"Created rule file: {file_path} with {len(validated_rules)} rules")
            return file_path
            
        except Exception as e:
            logger.error(f"Error writing rule file {file_path}: {e}")
            # Clean up failed file
            if os.path.exists(file_path):
                try:
                    os.unlink(file_path)
                except:
                    pass
            raise
    
    def _validate_rule_structure(self, rule: Dict[str, Any]) -> bool:
        """Validate rule structure for Semgrep compatibility"""
        
        if not isinstance(rule, dict):
            logger.warning("Rule is not a dictionary")
            return False
        
        # Required fields
        required_fields = ['id', 'message']
        for field in required_fields:
            if field not in rule or not rule[field] or not isinstance(rule[field], str):
                logger.warning(f"Rule missing or invalid required field '{field}': {rule.get('id', 'unknown')}")
                return False
        
        # Validate ID format (should be a valid identifier)
        rule_id = rule['id']
        if not rule_id.replace('-', '').replace('_', '').replace('.', '').isalnum():
            logger.warning(f"Invalid rule ID format: {rule_id}")
            return False
        
        # Must have at least one pattern field
        pattern_fields = ['pattern', 'patterns', 'pattern-either', 'pattern-regex', 'pattern-not', 'pattern-inside']
        if not any(field in rule for field in pattern_fields):
            logger.warning(f"Rule {rule_id} missing pattern field - available fields: {list(rule.keys())}")
            return False
        
        # Validate pattern content is not empty
        for field in pattern_fields:
            if field in rule:
                if field == 'patterns' and isinstance(rule[field], list):
                    if len(rule[field]) == 0:
                        logger.warning(f"Rule {rule_id} has empty patterns list")
                        return False
                elif not rule[field] or (isinstance(rule[field], str) and not rule[field].strip()):
                    logger.warning(f"Rule {rule_id} has empty {field}")
                    return False
        
        # Validate severity if present
        if 'severity' in rule:
            valid_severities = ['ERROR', 'WARNING', 'INFO']
            severity = str(rule['severity']).upper()
            if severity not in valid_severities:
                logger.warning(f"Rule {rule_id} has invalid severity: {rule['severity']}")
                return False
            # Normalize severity
            rule['severity'] = severity
        else:
            # Set default severity
            rule['severity'] = 'WARNING'
        
        # Validate languages if present
        if 'languages' in rule:
            if not isinstance(rule['languages'], list) or not rule['languages']:
                logger.warning(f"Rule {rule_id} has invalid languages field")
                return False
            # Validate each language is a string
            for lang in rule['languages']:
                if not isinstance(lang, str) or not lang.strip():
                    logger.warning(f"Rule {rule_id} has invalid language: {lang}")
                    return False
        
        # Validate message is descriptive
        if len(rule['message'].strip()) < 10:
            logger.warning(f"Rule {rule_id} has too short message")
            return False
        
        return True

# Integration with existing scanner engine
async def enhance_scanner_with_custom_rules(
    scanner_engine,
    user_id: int,
    db: AsyncSession,
    niche: str,
    temp_dir: str,
    include_community: bool = False,
    selected_custom_rule_ids: Optional[List[str]] = None,
    selected_community_rule_ids: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Enhance the existing scanner engine with custom rules
    
    This function integrates with the existing ScannerEngine to add custom rules
    """
    
    integration_service = CustomRulesIntegration(db)
    
    try:
        # Prepare custom rules
        custom_rules_info = await integration_service.prepare_custom_rules_for_scan(
            user_id=user_id,
            niche=niche,
            tool='semgrep',
            include_community=include_community,
            temp_dir=temp_dir,
            selected_custom_rule_ids=selected_custom_rule_ids,
            selected_community_rule_ids=selected_community_rule_ids
        )
        
        # Update usage statistics (fire and forget)
        try:
            await integration_service.update_rule_usage_stats(user_id, 'semgrep')
        except Exception as e:
            logger.warning(f"Failed to update usage stats: {str(e)}")
        
        return custom_rules_info
        
    except Exception as e:
        logger.error(f"Error enhancing scanner with custom rules: {str(e)}")
        # Return empty result to not break the scan
        return {
            'temp_dir': temp_dir,
            'rule_files': [],
            'user_rules_count': 0,
            'community_rules_count': 0,
            'total_rules': 0,
            'rule_categories': [],
            'error': str(e)
        }