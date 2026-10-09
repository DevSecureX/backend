"""
Rule Import/Export Service
Handles importing and exporting custom security rules in various formats
"""

import uuid
import json
import yaml
import zipfile
import tempfile
import os
from typing import Dict, List, Any, Optional, BinaryIO
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status, UploadFile
from io import BytesIO, StringIO

from ..models import CommunityRules
from scans.models import RuleCollections, RuleCollectionItems
from .rules_service import CustomRulesService

import logging
logger = logging.getLogger(__name__)


class RuleImportExportService:
    """Service for importing and exporting rules in various formats"""
    
    SUPPORTED_FORMATS = ['json', 'yaml', 'yml', 'zip']
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    MAX_RULES_PER_IMPORT = 100
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.base_service = CustomRulesService(db)
    
    async def export_user_rules(
        self,
        user_id: int,
        export_format: str = 'yaml',
        rule_ids: Optional[List[str]] = None,
        include_metadata: bool = True
    ) -> Dict[str, Any]:
        """Export user's rules in specified format"""
        
        if export_format.lower() not in self.SUPPORTED_FORMATS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported format. Supported: {self.SUPPORTED_FORMATS}"
            )
        
        # Get user's rules
        if rule_ids:
            # Export specific rules
            rules = []
            for rule_id in rule_ids:
                try:
                    rule = await self.base_service.get_rule_by_id(rule_id, user_id)
                    if rule['author_id'] == user_id:  # Only export own rules
                        rules.append(rule)
                except HTTPException:
                    continue  # Skip inaccessible rules
        else:
            # Export all user's rules
            user_rules = await self.base_service.get_user_rules(user_id, limit=1000)
            rules = user_rules['rules']
        
        if not rules:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No rules found to export"
            )
        
        # Format rules for export
        export_data = {
            'metadata': {
                'export_date': datetime.now(timezone.utc).isoformat(),
                'exported_by': user_id,
                'total_rules': len(rules),
                'format_version': '1.0',
                'devsecurex_version': '1.0.0'
            } if include_metadata else {},
            'rules': []
        }
        
        for rule in rules:
            rule_export = self._format_rule_for_export(rule, include_metadata)
            export_data['rules'].append(rule_export)
        
        # Convert to requested format
        if export_format.lower() in ['yaml', 'yml']:
            export_content = yaml.dump(export_data, default_flow_style=False, sort_keys=False)
            content_type = 'application/x-yaml'
            filename = f'devsecurex_rules_{user_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.yaml'
        else:  # json
            export_content = json.dumps(export_data, indent=2)
            content_type = 'application/json'
            filename = f'devsecurex_rules_{user_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        logger.info(f"Exported {len(rules)} rules for user {user_id} in {export_format} format")
        
        return {
            'content': export_content,
            'content_type': content_type,
            'filename': filename,
            'stats': {
                'total_rules': len(rules),
                'tools': list(set(rule['tool'] for rule in rules)),
                'languages': list(set(rule['language'] for rule in rules if rule['language'])),
                'export_size_bytes': len(export_content.encode('utf-8'))
            }
        }
    
    async def export_rule_collection(
        self,
        collection_id: str,
        user_id: int,
        export_format: str = 'yaml',
        include_metadata: bool = True
    ) -> Dict[str, Any]:
        """Export a rule collection"""
        
        # Get collection and verify access
        collection_query = select(RuleCollections).where(RuleCollections.id == collection_id)
        collection_result = await self.db.execute(collection_query)
        collection = collection_result.scalar_one_or_none()
        
        if not collection:
            raise HTTPException(status_code=404, detail="Collection not found")
        
        if not collection.is_public and collection.author_id != user_id:
            raise HTTPException(status_code=403, detail="Access denied to private collection")
        
        # Get collection items
        items_query = (
            select(RuleCollectionItems, CommunityRules)
            .join(CommunityRules, RuleCollectionItems.rule_id == CommunityRules.id)
            .where(RuleCollectionItems.collection_id == collection_id)
            .order_by(RuleCollectionItems.order_index)
        )
        
        items_result = await self.db.execute(items_query)
        items_data = items_result.all()
        
        # Format collection data
        export_data = {
            'collection_metadata': {
                'id': collection.id,
                'name': collection.name,
                'description': collection.description,
                'category': collection.category,
                'tags': collection.tags,
                'author_id': collection.author_id,
                'created_at': collection.created_at.isoformat(),
                'total_rules': len(items_data)
            } if include_metadata else {'name': collection.name},
            'rules': []
        }
        
        for item, rule in items_data:
            rule_dict = await self.base_service._rule_to_dict(rule)
            rule_export = self._format_rule_for_export(rule_dict, include_metadata)
            rule_export['collection_order'] = item.order_index
            export_data['rules'].append(rule_export)
        
        # Convert to format
        if export_format.lower() in ['yaml', 'yml']:
            export_content = yaml.dump(export_data, default_flow_style=False)
            content_type = 'application/x-yaml'
            filename = f'collection_{collection.name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.yaml'
        else:
            export_content = json.dumps(export_data, indent=2)
            content_type = 'application/json'
            filename = f'collection_{collection.name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        
        logger.info(f"Exported collection {collection_id} with {len(items_data)} rules")
        
        return {
            'content': export_content,
            'content_type': content_type,
            'filename': filename,
            'collection_info': {
                'name': collection.name,
                'total_rules': len(items_data),
                'export_size_bytes': len(export_content.encode('utf-8'))
            }
        }
    
    async def import_rules(
        self,
        user_id: int,
        file: UploadFile,
        import_options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Import rules from uploaded file"""
        
        options = import_options or {}
        
        # Validate file
        if file.size > self.MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size: {self.MAX_FILE_SIZE // (1024*1024)}MB"
            )
        
        file_extension = file.filename.split('.')[-1].lower()
        if file_extension not in self.SUPPORTED_FORMATS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file format. Supported: {self.SUPPORTED_FORMATS}"
            )
        
        # Read file content
        content = await file.read()
        
        try:
            if file_extension == 'zip':
                import_results = await self._import_from_zip(user_id, content, options)
            else:
                import_results = await self._import_from_text_file(user_id, content, file_extension, options)
        except Exception as e:
            logger.error(f"Import failed for user {user_id}: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Import failed: {str(e)}"
            )
        
        logger.info(f"Import completed for user {user_id}: {import_results['summary']}")
        
        return import_results
    
    async def import_rules_from_template(
        self,
        user_id: int,
        template_name: str,
        customizations: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Import rules from predefined templates"""
        
        templates = await self._get_rule_templates()
        
        if template_name not in templates:
            available_templates = list(templates.keys())
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Template not found. Available templates: {available_templates}"
            )
        
        template_data = templates[template_name]
        customizations = customizations or {}
        
        imported_rules = []
        failed_imports = []
        
        for rule_template in template_data['rules']:
            try:
                # Apply customizations
                rule_data = {**rule_template}
                
                if 'name_prefix' in customizations:
                    rule_data['rule_name'] = f"{customizations['name_prefix']}{rule_data['rule_name']}"
                
                if 'severity_override' in customizations:
                    rule_data['severity'] = customizations['severity_override']
                
                if 'make_public' in customizations:
                    rule_data['is_public'] = customizations['make_public']
                
                # Create rule
                created_rule = await self.base_service.create_rule(user_id, rule_data)
                imported_rules.append(created_rule)
                
            except Exception as e:
                failed_imports.append({
                    'rule_name': rule_template.get('rule_name', 'Unknown'),
                    'error': str(e)
                })
        
        return {
            'template_name': template_name,
            'total_attempted': len(template_data['rules']),
            'successful_imports': len(imported_rules),
            'failed_imports': len(failed_imports),
            'imported_rules': [rule['id'] for rule in imported_rules],
            'failures': failed_imports
        }
    
    async def validate_import_file(
        self,
        file: UploadFile
    ) -> Dict[str, Any]:
        """Validate import file without actually importing"""
        
        if file.size > self.MAX_FILE_SIZE:
            return {
                'valid': False,
                'errors': [f"File too large. Maximum size: {self.MAX_FILE_SIZE // (1024*1024)}MB"]
            }
        
        file_extension = file.filename.split('.')[-1].lower()
        if file_extension not in self.SUPPORTED_FORMATS:
            return {
                'valid': False,
                'errors': [f"Unsupported file format. Supported: {self.SUPPORTED_FORMATS}"]
            }
        
        content = await file.read()
        
        try:
            if file_extension == 'zip':
                validation_result = await self._validate_zip_file(content)
            else:
                validation_result = await self._validate_text_file(content, file_extension)
            
            return validation_result
            
        except Exception as e:
            return {
                'valid': False,
                'errors': [f"Validation failed: {str(e)}"]
            }
    
    # Private helper methods
    
    def _format_rule_for_export(self, rule: Dict[str, Any], include_metadata: bool) -> Dict[str, Any]:
        """Format a rule for export"""
        
        export_rule = {
            'rule_name': rule['rule_name'],
            'tool': rule['tool'],
            'language': rule['language'],
            'pattern': rule['pattern'],
            'description': rule['description'],
            'severity': rule['severity']
        }
        
        if include_metadata:
            export_rule.update({
                'id': rule['id'],
                'author_id': rule['author_id'],
                'is_public': rule['is_public'],
                'upvotes': rule['upvotes'],
                'usage_count': rule['usage_count'],
                'created_at': rule['created_at'],
                'updated_at': rule['updated_at']
            })
        
        return export_rule
    
    async def _import_from_text_file(
        self,
        user_id: int,
        content: bytes,
        file_extension: str,
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Import rules from JSON/YAML file"""
        
        content_str = content.decode('utf-8')
        
        if file_extension in ['yaml', 'yml']:
            data = yaml.safe_load(content_str)
        else:  # json
            data = json.loads(content_str)
        
        if not isinstance(data, dict) or 'rules' not in data:
            raise ValueError("File must contain a 'rules' array")
        
        rules_data = data['rules']
        if len(rules_data) > self.MAX_RULES_PER_IMPORT:
            raise ValueError(f"Too many rules. Maximum: {self.MAX_RULES_PER_IMPORT}")
        
        imported_rules = []
        failed_imports = []
        
        for rule_data in rules_data:
            try:
                # Apply import options
                if options.get('override_public', False):
                    rule_data['is_public'] = options['override_public']
                
                if options.get('name_prefix'):
                    rule_data['rule_name'] = f"{options['name_prefix']}{rule_data['rule_name']}"
                
                # Remove metadata fields that shouldn't be imported
                import_rule_data = {
                    k: v for k, v in rule_data.items()
                    if k not in ['id', 'author_id', 'upvotes', 'usage_count', 'created_at', 'updated_at']
                }
                
                # Create rule
                created_rule = await self.base_service.create_rule(user_id, import_rule_data)
                imported_rules.append(created_rule)
                
            except Exception as e:
                failed_imports.append({
                    'rule_name': rule_data.get('rule_name', 'Unknown'),
                    'error': str(e)
                })
        
        return {
            'format': file_extension,
            'total_attempted': len(rules_data),
            'successful_imports': len(imported_rules),
            'failed_imports': len(failed_imports),
            'imported_rules': [rule['id'] for rule in imported_rules],
            'failures': failed_imports,
            'summary': f"Imported {len(imported_rules)}/{len(rules_data)} rules successfully"
        }
    
    async def _import_from_zip(
        self,
        user_id: int,
        content: bytes,
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Import rules from ZIP archive"""
        
        with zipfile.ZipFile(BytesIO(content), 'r') as zip_file:
            all_imported = []
            all_failed = []
            
            for file_info in zip_file.filelist:
                if file_info.filename.endswith(('.json', '.yaml', '.yml')):
                    try:
                        file_content = zip_file.read(file_info)
                        file_ext = file_info.filename.split('.')[-1].lower()
                        
                        result = await self._import_from_text_file(user_id, file_content, file_ext, options)
                        all_imported.extend(result['imported_rules'])
                        all_failed.extend(result['failures'])
                        
                    except Exception as e:
                        all_failed.append({
                            'file': file_info.filename,
                            'error': str(e)
                        })
            
            return {
                'format': 'zip',
                'total_attempted': len(all_imported) + len(all_failed),
                'successful_imports': len(all_imported),
                'failed_imports': len(all_failed),
                'imported_rules': all_imported,
                'failures': all_failed,
                'summary': f"Imported {len(all_imported)} rules from ZIP archive"
            }
    
    async def _validate_text_file(self, content: bytes, file_extension: str) -> Dict[str, Any]:
        """Validate JSON/YAML file structure"""
        
        errors = []
        warnings = []
        
        try:
            content_str = content.decode('utf-8')
            
            if file_extension in ['yaml', 'yml']:
                data = yaml.safe_load(content_str)
            else:
                data = json.loads(content_str)
            
            if not isinstance(data, dict):
                errors.append("File must contain a JSON/YAML object")
                return {'valid': False, 'errors': errors}
            
            if 'rules' not in data:
                errors.append("File must contain a 'rules' array")
                return {'valid': False, 'errors': errors}
            
            rules_data = data['rules']
            if not isinstance(rules_data, list):
                errors.append("'rules' must be an array")
                return {'valid': False, 'errors': errors}
            
            if len(rules_data) > self.MAX_RULES_PER_IMPORT:
                errors.append(f"Too many rules. Maximum: {self.MAX_RULES_PER_IMPORT}")
            
            # Validate individual rules
            required_fields = ['rule_name', 'tool', 'pattern', 'severity']
            for i, rule in enumerate(rules_data[:10]):  # Check first 10 rules
                missing_fields = [f for f in required_fields if f not in rule or not rule[f]]
                if missing_fields:
                    warnings.append(f"Rule {i+1}: Missing required fields: {missing_fields}")
            
            return {
                'valid': len(errors) == 0,
                'errors': errors,
                'warnings': warnings,
                'stats': {
                    'total_rules': len(rules_data),
                    'file_size_bytes': len(content),
                    'tools': list(set(rule.get('tool', 'unknown') for rule in rules_data)),
                    'languages': list(set(rule.get('language', '') for rule in rules_data if rule.get('language')))
                }
            }
            
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            errors.append(f"Invalid {file_extension.upper()} format: {str(e)}")
            return {'valid': False, 'errors': errors}
    
    async def _validate_zip_file(self, content: bytes) -> Dict[str, Any]:
        """Validate ZIP file structure"""
        
        errors = []
        warnings = []
        stats = {'files': 0, 'total_rules': 0, 'tools': set(), 'languages': set()}
        
        try:
            with zipfile.ZipFile(BytesIO(content), 'r') as zip_file:
                for file_info in zip_file.filelist:
                    if file_info.filename.endswith(('.json', '.yaml', '.yml')):
                        stats['files'] += 1
                        
                        try:
                            file_content = zip_file.read(file_info)
                            file_ext = file_info.filename.split('.')[-1].lower()
                            
                            validation = await self._validate_text_file(file_content, file_ext)
                            
                            if not validation['valid']:
                                errors.extend([f"{file_info.filename}: {err}" for err in validation['errors']])
                            else:
                                file_stats = validation['stats']
                                stats['total_rules'] += file_stats['total_rules']
                                stats['tools'].update(file_stats['tools'])
                                stats['languages'].update(file_stats['languages'])
                                
                        except Exception as e:
                            errors.append(f"{file_info.filename}: Validation failed - {str(e)}")
                
                if stats['files'] == 0:
                    warnings.append("No rule files found in ZIP archive")
                
                stats['tools'] = list(stats['tools'])
                stats['languages'] = list(stats['languages'])
                
                return {
                    'valid': len(errors) == 0,
                    'errors': errors,
                    'warnings': warnings,
                    'stats': stats
                }
                
        except zipfile.BadZipFile:
            return {'valid': False, 'errors': ['Invalid ZIP file']}
    
    async def _get_rule_templates(self) -> Dict[str, Any]:
        """Get predefined rule templates"""
        
        return {
            'basic_security': {
                'name': 'Basic Security Rules',
                'description': 'Essential security rules for common vulnerabilities',
                'rules': [
                    {
                        'rule_name': 'SQL Injection Detection',
                        'tool': 'semgrep',
                        'language': 'python',
                        'pattern': 'patterns:\n  - pattern: execute($SQL)\n  - pattern: cursor.execute($SQL)',
                        'description': 'Detects potential SQL injection vulnerabilities',
                        'severity': 'ERROR',
                        'is_public': False
                    },
                    {
                        'rule_name': 'Hardcoded Password',
                        'tool': 'semgrep',
                        'language': 'python',
                        'pattern': 'patterns:\n  - pattern: password = "..."\n  - pattern: pwd = "..."',
                        'description': 'Detects hardcoded passwords in code',
                        'severity': 'WARNING',
                        'is_public': False
                    }
                ]
            },
            'web_security': {
                'name': 'Web Security Rules',
                'description': 'Security rules for web applications',
                'rules': [
                    {
                        'rule_name': 'XSS Prevention',
                        'tool': 'eslint-security',
                        'language': 'javascript',
                        'pattern': '{"meta": {"type": "problem"}, "create": "function(context) { return { CallExpression: function(node) { if (node.callee.property && node.callee.property.name === \\"innerHTML\\") { context.report(node, \\"Potential XSS vulnerability\\"); } } }; }"}',
                        'description': 'Detects potential XSS vulnerabilities via innerHTML',
                        'severity': 'ERROR',
                        'is_public': False
                    }
                ]
            }
        }