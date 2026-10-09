import json
import os
from typing import Dict, List, Any
from ..base_runner import BaseToolRunner
import logging

logger = logging.getLogger(__name__)

class BrakemanRunner(BaseToolRunner):
    def __init__(self):
        super().__init__("brakeman")
        self.timeout = 600  # 10 minutes for Ruby analysis

    async def run(self, temp_dir: str, file_list: List[str] = None, **kwargs) -> Dict[str, Any]:
        """Brakeman Ruby/Rails security analysis with full CLI-main scan parity"""
        
        # Extract CLI parameters (for optimization, not different behavior)
        is_cli_scan = kwargs.get('is_cli_scan', False)
        scan_mode = kwargs.get('scan_mode', 'fast')
        timeout = kwargs.get('timeout_per_tool', self.timeout)
        
        # Adjust ONLY performance parameters for CLI
        if is_cli_scan:
            # CLI optimization: shorter timeout but same analysis depth
            self.timeout = min(timeout, 180)  # Max 3 minutes for CLI
            logger.info(f"Running Brakeman in CLI mode with {self.timeout}s timeout")
        
        # Check if this is a Rails application - be more lenient for testing
        has_ruby_files = self._has_ruby_files(temp_dir)
        if not has_ruby_files:
            return {
                "issues": [], 
                "tool": "brakeman", 
                "duration": 0, 
                "metadata": {"message": "No Ruby files found, skipping Brakeman scan"}
            }
        
        # Create minimal Rails structure if not present but Ruby files exist
        if not self._is_rails_app(temp_dir) and has_ruby_files:
            logger.info("Creating minimal Rails structure for Brakeman analysis")
            self._create_minimal_rails_structure(temp_dir)
        
        # Filter for Ruby files if file_list provided
        if file_list:
            rb_files = [f for f in file_list if f.endswith('.rb')]
            if not rb_files:
                return {"issues": [], "tool": "brakeman", "duration": 0, "metadata": {"message": "No Ruby files to scan"}}
        
        cmd = [
            'brakeman',
            '-o', '/tmp/brakeman-report.json',
            '--quiet',
            '--no-exit-on-warn',
            '--force',  # Run even if not a perfect Rails app
            temp_dir
        ]

        logger.info(f"Executing Brakeman command: {' '.join(cmd)}")
        result = await self.execute_command(cmd, cwd=temp_dir)

        if "error" in result:
            logger.error(f"Brakeman command failed: {result['error']}")
            return {"issues": [], "error": result["error"], "tool": "brakeman"}

        try:
            with open('/tmp/brakeman-report.json', 'r') as f:
                output = json.load(f)

            issues = []
            for warning in output.get("warnings", []):
                issue = {
                    "tool": "brakeman",
                    "category": "code",
                    "rule_id": warning.get("warning_type"),
                    "message": warning.get("message", "Ruby/Rails security issue"),
                    "severity": self.normalize_severity(warning.get("confidence", "Medium")),
                    "file_path": self.clean_file_path(warning.get("file", ""), temp_dir),
                    "line_start": warning.get("line", 0),
                    "line_end": warning.get("line", 0),
                    "confidence": self.normalize_severity(warning.get("confidence", "Medium")),
                    "owasp_category": self._map_to_owasp(warning.get("warning_type", "")),
                    "cwe_id": warning.get("cwe_id", "CWE-200")
                }
                issues.append(issue)

            # Clean up report file
            if os.path.exists('/tmp/brakeman-report.json'):
                os.remove('/tmp/brakeman-report.json')

            return {
                "issues": issues,
                "tool": "brakeman",
                "duration": result["duration"],
                "files_scanned": len(set(issue.get("file_path") for issue in issues))
            }

        except (json.JSONDecodeError, FileNotFoundError) as e:
            logger.error(f"Failed to parse Brakeman output: {e}")
            return {"issues": [], "error": f"Failed to parse output: {str(e)}", "tool": "brakeman"}

    def _map_to_owasp(self, warning_type: str) -> str:
        """Map Brakeman warning type to OWASP category"""
        owasp_mappings = {
            "SQL Injection": "A03:2021 – Injection",
            "Cross-Site Scripting": "A03:2021 – Injection",
            "Authentication": "A07:2021 – Identification and Authentication Failures",
            "File Access": "A01:2021 – Broken Access Control",
            "Mass Assignment": "A01:2021 – Broken Access Control"
        }
        warning_lower = warning_type.lower()
        for key, category in owasp_mappings.items():
            if key.lower() in warning_lower:
                return category
        return "A06:2021 – Vulnerable and Outdated Components"
    
    def _is_rails_app(self, temp_dir: str) -> bool:
        """Check if directory contains a Rails application"""
        rails_indicators = [
            'Gemfile',
            'config/application.rb',
            'config/environment.rb',
            'app/controllers',
            'app/models',
            'app/views'
        ]
        
        for indicator in rails_indicators:
            if os.path.exists(os.path.join(temp_dir, indicator)):
                return True
        
        # Check for Ruby files with Rails patterns
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith('.rb'):
                    return True  # At least has Ruby files
        
        return False
    
    def _has_ruby_files(self, temp_dir: str) -> bool:
        """Check if directory contains any Ruby files"""
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith('.rb'):
                    return True
        return False
    
    def _create_minimal_rails_structure(self, temp_dir: str) -> None:
        """Create minimal Rails directory structure for Brakeman analysis"""
        try:
            # Create Rails directories
            rails_dirs = [
                'app/controllers',
                'app/models', 
                'app/views',
                'config'
            ]
            
            for rail_dir in rails_dirs:
                os.makedirs(os.path.join(temp_dir, rail_dir), exist_ok=True)
            
            # Create Gemfile
            gemfile_path = os.path.join(temp_dir, 'Gemfile')
            if not os.path.exists(gemfile_path):
                with open(gemfile_path, 'w') as f:
                    f.write("""source 'https://rubygems.org'
gem 'rails', '~> 7.0'
gem 'sinatra'
""")
            
            # Create basic config/application.rb
            app_config_path = os.path.join(temp_dir, 'config', 'application.rb')
            if not os.path.exists(app_config_path):
                with open(app_config_path, 'w') as f:
                    f.write("""require_relative "boot"
require "rails/all"
module TempSecurityScan
  class Application < Rails::Application
    config.load_defaults 7.0
  end
end
""")
            
            # Move Ruby files to appropriate Rails locations
            self._organize_ruby_files_for_rails(temp_dir)
            
            logger.info("Created minimal Rails structure for Brakeman analysis")
            
        except Exception as e:
            logger.warning(f"Failed to create Rails structure: {e}")
    
    def _organize_ruby_files_for_rails(self, temp_dir: str) -> None:
        """Organize standalone Ruby files into Rails app structure"""
        try:
            # Find all Ruby files in root directory
            ruby_files = []
            for file in os.listdir(temp_dir):
                if file.endswith('.rb') and os.path.isfile(os.path.join(temp_dir, file)):
                    ruby_files.append(file)
            
            # Move Ruby files to controllers directory (Brakeman analyzes controllers heavily)
            controllers_dir = os.path.join(temp_dir, 'app', 'controllers')
            for i, ruby_file in enumerate(ruby_files):
                source_path = os.path.join(temp_dir, ruby_file)
                # Create controller-like filename
                controller_name = f"temp_controller_{i}.rb"
                dest_path = os.path.join(controllers_dir, controller_name)
                
                # Move file
                if os.path.exists(source_path):
                    os.rename(source_path, dest_path)
                    logger.debug(f"Moved {ruby_file} to {controller_name}")
                    
        except Exception as e:
            logger.warning(f"Failed to organize Ruby files: {e}")