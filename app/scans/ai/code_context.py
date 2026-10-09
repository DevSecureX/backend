import os
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)

class CodeContextExtractor:
    def __init__(self):
        self.context_lines = 7  # Lines before and after
        self.max_line_length = 120  # Truncate long lines
        
    async def extract_context(
        self,
        file_path: str,
        line_start: int,
        temp_dir: str,
        commit_sha: Optional[str] = None,
        gh_token: Optional[str] = None
    ) -> Dict[str, any]:
        """Extract code context around a vulnerability"""
        
        full_path = os.path.join(temp_dir, file_path) if temp_dir else file_path
        
        if not os.path.exists(full_path):
            logger.warning(f"File not found: {full_path}")
            return {
                "code_snippet": "",
                "highlighted_line": "",
                "start_line": line_start,
                "end_line": line_start
            }
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Calculate context bounds
            total_lines = len(lines)
            start_line = max(1, line_start - self.context_lines)
            end_line = min(total_lines, line_start + self.context_lines)
            
            # Extract context lines
            context_lines = []
            highlighted_line = ""
            
            for i in range(start_line - 1, end_line):
                if i < len(lines):
                    line = lines[i].rstrip()
                    # Truncate long lines
                    if len(line) > self.max_line_length:
                        line = line[:self.max_line_length] + "..."
                    
                    line_num = i + 1
                    
                    # Format line with line number
                    if line_num == line_start:
                        # Highlight the vulnerable line
                        formatted_line = f">> {line_num:4d} | {line}"
                        highlighted_line = line
                    else:
                        formatted_line = f"   {line_num:4d} | {line}"
                    
                    context_lines.append(formatted_line)
            
            # Create code snippet
            code_snippet = "\n".join(context_lines)
            
            # Get file extension for syntax highlighting
            file_extension = os.path.splitext(file_path)[1].lstrip('.')
            
            return {
                "code_snippet": code_snippet,
                "highlighted_line": highlighted_line,
                "start_line": start_line,
                "end_line": end_line,
                "file_extension": file_extension,
                "file_path": file_path,
                "commit_sha": commit_sha
            }
            
        except Exception as e:
            logger.error(f"Error extracting code context: {e}")
            return {
                "code_snippet": "",
                "highlighted_line": "",
                "start_line": line_start,
                "end_line": line_start
            }
    
    def extract_function_context(self, file_path: str, line_start: int, temp_dir: str) -> Dict[str, any]:
        """Extract the entire function/method containing the vulnerability"""
        
        full_path = os.path.join(temp_dir, file_path) if temp_dir else file_path
        
        if not os.path.exists(full_path):
            return {"function_name": "", "function_code": ""}
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Simple heuristic to find function boundaries
            # This works for languages with consistent indentation
            function_start = line_start - 1
            function_end = line_start - 1
            
            # Find function start (look for def, function, func, etc.)
            for i in range(line_start - 1, -1, -1):
                line = lines[i].strip()
                if any(keyword in line for keyword in ['def ', 'function ', 'func ', 'fn ', 'sub ', 'method ']):
                    function_start = i
                    break
                elif i < line_start - 50:  # Don't look too far back
                    break
            
            # Find function end (look for dedent or next function)
            if function_start < line_start - 1:
                base_indent = len(lines[function_start]) - len(lines[function_start].lstrip())
                for i in range(line_start, len(lines)):
                    line = lines[i]
                    if line.strip():  # Non-empty line
                        current_indent = len(line) - len(line.lstrip())
                        if current_indent <= base_indent:
                            function_end = i - 1
                            break
                    if i > line_start + 100:  # Don't include too much
                        function_end = i
                        break
                else:
                    function_end = min(len(lines) - 1, line_start + 20)
            
            # Extract function code
            function_lines = lines[function_start:function_end + 1]
            function_code = ''.join(function_lines)
            
            # Extract function name
            function_name = ""
            first_line = lines[function_start].strip()
            for keyword in ['def ', 'function ', 'func ', 'fn ']:
                if keyword in first_line:
                    # Extract name after keyword
                    parts = first_line.split(keyword)
                    if len(parts) > 1:
                        name_part = parts[1].split('(')[0].strip()
                        function_name = name_part
                        break
            
            return {
                "function_name": function_name,
                "function_code": function_code,
                "function_start_line": function_start + 1,
                "function_end_line": function_end + 1
            }
            
        except Exception as e:
            logger.error(f"Error extracting function context: {e}")
            return {"function_name": "", "function_code": ""}
    
    def create_github_permalink(
        self,
        repo_full_name: str,
        file_path: str,
        line_start: int,
        commit_sha: str
    ) -> str:
        """Create GitHub permalink to the specific line"""
        return f"https://github.com/{repo_full_name}/blob/{commit_sha}/{file_path}#L{line_start}"
    
    def format_for_markdown(self, context: Dict[str, any]) -> str:
        """Format code context for markdown display"""
        file_ext = context.get('file_extension', '')
        code_snippet = context.get('code_snippet', '')
        
        # Language mapping for syntax highlighting
        lang_map = {
            'py': 'python',
            'js': 'javascript',
            'ts': 'typescript',
            'java': 'java',
            'go': 'go',
            'rb': 'ruby',
            'php': 'php',
            'cs': 'csharp',
            'cpp': 'cpp',
            'c': 'c',
            'rs': 'rust',
            'kt': 'kotlin',
            'swift': 'swift',
            'scala': 'scala',
            'r': 'r',
            'sh': 'bash',
            'yml': 'yaml',
            'yaml': 'yaml',
            'json': 'json',
            'xml': 'xml',
            'sql': 'sql'
        }
        
        language = lang_map.get(file_ext, file_ext)
        
        return f"```{language}\n{code_snippet}\n```"