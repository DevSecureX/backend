"""
Code Context Extractor
Extracts vulnerable code snippets with surrounding context for better user understanding
Similar to how major code review platforms like Snyk and CodeRabbit work
"""

import os
import logging
from typing import Optional, Dict, List
from pathlib import Path

logger = logging.getLogger(__name__)

class CodeContextExtractor:
    """Extracts code context from files for security issues"""
    
    def __init__(self, context_lines: int = 3):
        """
        Initialize the code context extractor
        
        Args:
            context_lines: Number of lines to show before and after the vulnerable line
        """
        self.context_lines = context_lines
        
    def extract_context(self, file_path: str, line_start: int, line_end: Optional[int] = None, temp_dir: str = None) -> Optional[Dict]:
        """
        Extract code context for a vulnerable line or range
        
        Args:
            file_path: Path to the file (relative to temp_dir if provided)
            line_start: Starting line number (1-indexed)
            line_end: Ending line number (1-indexed), if None defaults to line_start
            temp_dir: Base directory for file resolution
            
        Returns:
            Dict with code context information or None if extraction fails
        """
        try:
            # Resolve the actual file path
            if temp_dir:
                full_path = os.path.join(temp_dir, file_path)
            else:
                full_path = file_path
                
            if not os.path.exists(full_path):
                logger.warning(f"File not found for context extraction: {full_path}")
                return None
                
            # Default line_end to line_start if not provided
            if line_end is None:
                line_end = line_start
                
            # Validate line numbers
            if line_start < 1:
                line_start = 1
            if line_end < line_start:
                line_end = line_start
                
            # Read the file content
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            total_lines = len(lines)
            
            # Calculate context boundaries
            context_start = max(1, line_start - self.context_lines)
            context_end = min(total_lines, line_end + self.context_lines)
            
            # Extract lines (convert to 0-indexed for array access)
            context_lines_data = []
            
            for i in range(context_start - 1, context_end):
                if i < len(lines):
                    line_number = i + 1
                    line_content = lines[i].rstrip('\n\r')
                    is_vulnerable = line_start <= line_number <= line_end
                    
                    context_lines_data.append({
                        "line_number": line_number,
                        "content": line_content,
                        "is_vulnerable": is_vulnerable
                    })
            
            # Extract just the vulnerable lines for compact display
            vulnerable_lines = []
            for i in range(line_start - 1, min(line_end, total_lines)):
                if i < len(lines):
                    vulnerable_lines.append(lines[i].rstrip('\n\r'))
            
            return {
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "context_start": context_start,
                "context_end": context_end,
                "context_lines": context_lines_data,
                "vulnerable_code": '\n'.join(vulnerable_lines),
                "total_file_lines": total_lines,
                "language": self.get_file_language(file_path)
            }
            
        except Exception as e:
            logger.error(f"Error extracting code context for {file_path}:{line_start}: {e}")
            return None
    
    def format_context_for_display(self, context: Dict) -> str:
        """
        Format code context for display in PR comments or API responses
        
        Args:
            context: Context data from extract_context()
            
        Returns:
            Formatted string for display
        """
        if not context or not context.get("context_lines"):
            return "Code context not available"
            
        lines = []
        for line_data in context["context_lines"]:
            line_num = line_data["line_number"]
            content = line_data["content"]
            is_vulnerable = line_data["is_vulnerable"]
            
            # Add indicator for vulnerable lines
            indicator = ">>> " if is_vulnerable else "    "
            lines.append(f"{indicator}{line_num:4d} | {content}")
        
        return '\n'.join(lines)
    
    def get_file_language(self, file_path: str) -> str:
        """
        Determine the programming language based on file extension
        
        Args:
            file_path: Path to the file
            
        Returns:
            Language identifier for syntax highlighting
        """
        file_ext = Path(file_path).suffix.lower()
        
        language_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'jsx',
            '.tsx': 'tsx',
            '.java': 'java',
            '.go': 'go',
            '.rs': 'rust',
            '.cpp': 'cpp',
            '.c': 'c',
            '.cs': 'csharp',
            '.php': 'php',
            '.rb': 'ruby',
            '.scala': 'scala',
            '.kt': 'kotlin',
            '.swift': 'swift',
            '.sh': 'shell',
            '.bash': 'shell',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.json': 'json',
            '.xml': 'xml',
            '.html': 'html',
            '.css': 'css',
            '.sql': 'sql',
            '.dockerfile': 'dockerfile'
        }
        
        return language_map.get(file_ext, 'text')
    
    def extract_batch_context(self, issues: List[Dict], temp_dir: str) -> List[Dict]:
        """
        Extract code context for a batch of issues efficiently
        
        Args:
            issues: List of security issues with file_path and line information
            temp_dir: Base directory for file resolution
            
        Returns:
            Updated issues list with code_context added
        """
        file_cache = {}  # Cache file contents to avoid repeated reads
        updated_issues = []
        
        for issue in issues:
            try:
                file_path = issue.get("file_path")
                line_start = issue.get("line_start")
                line_end = issue.get("line_end")
                
                if not file_path or not line_start:
                    updated_issues.append(issue)
                    continue
                
                # Use cached file content if available
                if file_path not in file_cache:
                    full_path = os.path.join(temp_dir, file_path)
                    if os.path.exists(full_path):
                        try:
                            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                                file_cache[file_path] = f.readlines()
                        except Exception as e:
                            logger.warning(f"Could not read file {file_path}: {e}")
                            file_cache[file_path] = None
                    else:
                        file_cache[file_path] = None
                
                # Extract context using cached content
                if file_cache[file_path]:
                    context_info = self._extract_from_cached_lines(
                        file_cache[file_path], 
                        file_path, 
                        line_start, 
                        line_end
                    )
                    issue["code_context"] = context_info
                
                updated_issues.append(issue)
                
            except Exception as e:
                logger.error(f"Error processing issue for context extraction: {e}")
                updated_issues.append(issue)
        
        return updated_issues
    
    def _extract_from_cached_lines(self, lines: List[str], file_path: str, line_start: int, line_end: Optional[int] = None) -> Optional[Dict]:
        """Extract context from pre-loaded file lines"""
        try:
            if line_end is None:
                line_end = line_start
                
            total_lines = len(lines)
            
            # Calculate context boundaries
            context_start = max(1, line_start - self.context_lines)
            context_end = min(total_lines, line_end + self.context_lines)
            
            # Extract context lines
            context_lines_data = []
            for i in range(context_start - 1, context_end):
                if i < len(lines):
                    line_number = i + 1
                    line_content = lines[i].rstrip('\n\r')
                    is_vulnerable = line_start <= line_number <= line_end
                    
                    context_lines_data.append({
                        "line_number": line_number,
                        "content": line_content,
                        "is_vulnerable": is_vulnerable
                    })
            
            # Extract vulnerable code
            vulnerable_lines = []
            for i in range(line_start - 1, min(line_end, total_lines)):
                if i < len(lines):
                    vulnerable_lines.append(lines[i].rstrip('\n\r'))
            
            return {
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "context_start": context_start,
                "context_end": context_end,
                "context_lines": context_lines_data,
                "vulnerable_code": '\n'.join(vulnerable_lines),
                "total_file_lines": total_lines,
                "language": self.get_file_language(file_path)
            }
            
        except Exception as e:
            logger.error(f"Error extracting context from cached lines: {e}")
            return None