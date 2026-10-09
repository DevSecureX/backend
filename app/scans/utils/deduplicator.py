import hashlib
import json
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class IssueDuplicator:
    def __init__(self):
        self.similarity_threshold = 0.8
        
    def deduplicate(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate issues using multiple strategies"""
        
        if not issues:
            return issues
        
        logger.info(f"Starting deduplication of {len(issues)} issues")
        
        # Step 1: Exact duplicate removal
        exact_dedupe = self._remove_exact_duplicates(issues)
        logger.info(f"After exact deduplication: {len(exact_dedupe)} issues")
        
        # Step 2: Same location deduplication (same file + line)
        location_dedupe = self._remove_location_duplicates(exact_dedupe)
        logger.info(f"After location deduplication: {len(location_dedupe)} issues")
        
        # Step 3: Rule-based deduplication (same rule in same file)
        rule_dedupe = self._remove_rule_duplicates(location_dedupe)
        logger.info(f"After rule deduplication: {len(rule_dedupe)} issues")
        
        # Step 4: Add confidence scoring based on multiple tool agreement
        scored_issues = self._add_confidence_scoring(rule_dedupe, issues)
        
        logger.info(f"Final deduplicated count: {len(scored_issues)} issues")
        return scored_issues
    
    def _remove_exact_duplicates(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove exact duplicates based on content hash"""
        seen_hashes = set()
        unique_issues = []
        
        for issue in issues:
            content_hash = self._calculate_content_hash(issue)
            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                unique_issues.append(issue)
        
        return unique_issues
    
    def _remove_location_duplicates(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicates at the same file location, keeping highest severity"""
        location_groups = {}
        
        for issue in issues:
            location_key = self._get_location_key(issue)
            if location_key not in location_groups:
                location_groups[location_key] = []
            location_groups[location_key].append(issue)
        
        deduplicated = []
        for location, group in location_groups.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                # Keep the highest severity issue
                best_issue = self._select_best_issue(group)
                # Merge information from other issues
                merged_issue = self._merge_issue_info(best_issue, group)
                deduplicated.append(merged_issue)
        
        return deduplicated
    
    def _remove_rule_duplicates(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicates of the same rule in the same file - ENHANCED for Gosec compatibility"""
        rule_groups = {}
        
        for issue in issues:
            # CRITICAL FIX: Include line number in rule key to prevent over-deduplication
            # This ensures that multiple instances of the same Gosec rule at different lines are preserved
            rule_key = f"{issue.get('file_path', 'unknown')}:{issue.get('rule_id', 'unknown')}:{issue.get('line_start', 0)}"
            if rule_key not in rule_groups:
                rule_groups[rule_key] = []
            rule_groups[rule_key].append(issue)
        
        deduplicated = []
        for rule_key, group in rule_groups.items():
            # Keep ALL instances of the same rule at different locations (removed limit entirely)
            # This is critical for Gosec which often finds the same vulnerability pattern in multiple locations
            deduplicated.extend(group)
            
            # DEBUG: Log when multiple instances of same rule are found
            if len(group) > 1:
                tool = group[0].get('tool', 'unknown')
                rule_id = group[0].get('rule_id', 'unknown')
                logger.info(f"Preserving {len(group)} instances of {tool} rule {rule_id} at different locations")
        
        return deduplicated
    
    def _add_confidence_scoring(self, issues: List[Dict[str, Any]], original_issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add confidence scoring based on multiple tool agreement"""
        
        # Count how many tools found similar issues
        tool_agreement = {}
        
        for issue in original_issues:
            signature = self._get_issue_signature(issue)
            if signature not in tool_agreement:
                tool_agreement[signature] = set()
            tool_agreement[signature].add(issue.get('tool', 'unknown'))
        
        # Update confidence based on tool agreement and add multi-tool detection info
        for issue in issues:
            signature = self._get_issue_signature(issue)
            tool_count = len(tool_agreement.get(signature, {issue.get('tool', 'unknown')}))
            confirming_tools_list = list(tool_agreement.get(signature, set()))
            
            # Always add tool agreement information for API transparency
            issue['tool_agreement'] = tool_count
            issue['confirming_tools'] = confirming_tools_list
            
            # Add user-friendly multi-tool detection information
            if tool_count > 1:
                # Boost confidence if multiple tools agree
                original_confidence = issue.get('confidence', 'medium')
                if tool_count >= 3:
                    issue['confidence'] = 'very_high'
                elif tool_count == 2:
                    issue['confidence'] = 'high'
                
                # Add prominent multi-tool detection fields for API response
                issue['found_by_multiple_tools'] = True
                issue['detection_summary'] = f"Found by {tool_count} tools: {', '.join(sorted(confirming_tools_list))}"
                
                # Add severity boost indicator for critical multi-tool findings
                if tool_count >= 3 and issue.get('severity') in ['high', 'medium']:
                    issue['multi_tool_severity_boost'] = True
                    issue['original_severity'] = issue.get('severity')
                    # Keep original severity but mark the boost for API consumers
            else:
                # Single tool detection
                issue['found_by_multiple_tools'] = False
                issue['detection_summary'] = f"Found by {issue.get('tool', 'unknown')}"
        
        return issues
    
    def _calculate_content_hash(self, issue: Dict[str, Any]) -> str:
        """Calculate hash for exact duplicate detection"""
        content = {
            'tool': issue.get('tool'),
            'rule_id': issue.get('rule_id'),
            'file_path': issue.get('file_path'),
            'line_start': issue.get('line_start'),
            'message': issue.get('message'),
            'severity': issue.get('severity')
        }
        content_str = json.dumps(content, sort_keys=True)
        return hashlib.md5(content_str.encode()).hexdigest()
    
    def _get_location_key(self, issue: Dict[str, Any]) -> str:
        """Get location key for grouping issues at same location"""
        file_path = issue.get('file_path', 'unknown')
        line = issue.get('line_start', 0)
        return f"{file_path}:{line}"
    
    def _get_issue_signature(self, issue: Dict[str, Any]) -> str:
        """Get issue signature for tool agreement detection"""
        return f"{issue.get('file_path', 'unknown')}:{issue.get('category', 'unknown')}:{issue.get('severity', 'medium')}"
    
    def _select_best_issue(self, issues: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Select the best issue from a group"""
        # Sort by severity (highest first), then by confidence
        sorted_issues = sorted(
            issues,
            key=lambda x: (
                self._severity_weight(x.get('severity', 'medium')),
                self._confidence_weight(x.get('confidence', 'medium'))
            ),
            reverse=True
        )
        return sorted_issues[0]
    
    def _merge_issue_info(self, best_issue: Dict[str, Any], all_issues: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge information from multiple issues into one with enhanced multi-tool detection"""
        merged = best_issue.copy()
        
        # Collect all tools that found this issue
        tools = set()
        rule_ids = set()
        messages = set()
        
        for issue in all_issues:
            if issue.get('tool'):
                tools.add(issue['tool'])
            if issue.get('rule_id'):
                rule_ids.add(issue['rule_id'])
            if issue.get('message'):
                messages.add(issue['message'])
        
        tool_count = len(tools)
        
        # Enhanced multi-tool detection information
        if tool_count > 1:
            merged['multiple_tools'] = sorted(list(tools))
            merged['confidence'] = 'high'  # Higher confidence when multiple tools agree
            merged['found_by_multiple_tools'] = True
            merged['tool_agreement'] = tool_count
            merged['detection_summary'] = f"Found by {tool_count} tools: {', '.join(sorted(tools))}"
            
            # If tools found different messages, combine them
            if len(messages) > 1:
                merged['combined_messages'] = list(messages)
                merged['message'] = f"{merged.get('message', '')} [Multiple tool detection: {'; '.join(messages)}]"
        else:
            merged['found_by_multiple_tools'] = False
            merged['tool_agreement'] = 1
            merged['detection_summary'] = f"Found by {list(tools)[0] if tools else 'unknown'}"
        
        if len(rule_ids) > 1:
            merged['multiple_rules'] = sorted(list(rule_ids))
            merged['rule_variation_count'] = len(rule_ids)
        
        return merged
    
    def _severity_weight(self, severity: str) -> int:
        """Get numeric weight for severity"""
        weights = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        return weights.get(severity.lower(), 2)
    
    def _confidence_weight(self, confidence: str) -> int:
        """Get numeric weight for confidence"""
        weights = {
            'very_high': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'very_low': 1
        }
        return weights.get(confidence.lower(), 3)
    
    def deduplicate_smart(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Smart deduplication with advanced heuristics"""
        
        if not issues:
            return issues
            
        logger.info(f"Starting smart deduplication of {len(issues)} issues")
        
        # Use regular deduplication as base
        deduplicated = self.deduplicate(issues)
        
        # Additional smart filtering
        # Group by file and aggregate similar issues
        file_groups = {}
        for issue in deduplicated:
            file_path = issue.get('file_path', 'unknown')
            if file_path not in file_groups:
                file_groups[file_path] = []
            file_groups[file_path].append(issue)
        
        smart_filtered = []
        for file_path, file_issues in file_groups.items():
            # REMOVED AGGRESSIVE FILTERING to maximize vulnerability detection
            if len(file_issues) > 100:  # Significantly increased threshold from 50 to 100
                # Keep only the most severe unique issues but with much higher limits
                seen_patterns = set()
                filtered_file_issues = []
                
                for issue in sorted(file_issues, key=lambda x: self._severity_weight(x.get('severity', 'medium')), reverse=True):
                    # CRITICAL FIX: Create even more specific pattern to prevent issue loss
                    # Include tool name and line number to ensure different tools' findings are preserved
                    pattern = f"{issue.get('tool')}:{issue.get('category')}:{issue.get('rule_id')}:{issue.get('line_start', 0)}"
                    if pattern not in seen_patterns:
                        seen_patterns.add(pattern)
                        filtered_file_issues.append(issue)
                        # MAXIMIZED limit to preserve ALL security findings
                        if len(filtered_file_issues) >= 80:  # Doubled max from 40 to 80 per file
                            break
                
                smart_filtered.extend(filtered_file_issues)
            else:
                smart_filtered.extend(file_issues)
        
        logger.info(f"Smart deduplication complete: {len(smart_filtered)} issues")
        return smart_filtered
    
    def get_multi_tool_detection_stats(self, issues: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistics about multi-tool detections for scan summary"""
        stats = {
            'total_issues': len(issues),
            'single_tool_detections': 0,
            'multi_tool_detections': 0,
            'highly_confident_detections': 0,  # 3+ tools
            'tool_agreement_distribution': {},
            'most_agreed_upon_issues': []
        }
        
        tool_agreement_counts = {}
        highly_agreed_issues = []
        
        for issue in issues:
            tool_count = issue.get('tool_agreement', 1)
            
            # Count by agreement level
            if tool_count == 1:
                stats['single_tool_detections'] += 1
            else:
                stats['multi_tool_detections'] += 1
                
            if tool_count >= 3:
                stats['highly_confident_detections'] += 1
                highly_agreed_issues.append({
                    'file_path': issue.get('file_path'),
                    'message': issue.get('message'),
                    'tool_count': tool_count,
                    'tools': issue.get('confirming_tools', []),
                    'severity': issue.get('severity')
                })
            
            # Track agreement distribution
            tool_agreement_counts[tool_count] = tool_agreement_counts.get(tool_count, 0) + 1
        
        stats['tool_agreement_distribution'] = tool_agreement_counts
        
        # Sort highly agreed issues by tool count (most agreed first)
        stats['most_agreed_upon_issues'] = sorted(
            highly_agreed_issues, 
            key=lambda x: x['tool_count'], 
            reverse=True
        )[:5]  # Top 5 most agreed upon issues
        
        # Add percentages for better understanding
        if stats['total_issues'] > 0:
            stats['multi_tool_percentage'] = round(
                (stats['multi_tool_detections'] / stats['total_issues']) * 100, 1
            )
            stats['high_confidence_percentage'] = round(
                (stats['highly_confident_detections'] / stats['total_issues']) * 100, 1
            )
        else:
            stats['multi_tool_percentage'] = 0
            stats['high_confidence_percentage'] = 0
        
        return stats