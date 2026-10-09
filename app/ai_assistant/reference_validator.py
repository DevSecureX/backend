"""
Reference validation system for AI assistant
Ensures only current, valid security resources are referenced
"""

from typing import Dict, List, Set
from datetime import datetime
import re

class SecurityReferenceValidator:
    """Validates and standardizes security references"""
    
    def __init__(self):
        # Current valid security frameworks and standards (by category only)
        self.valid_frameworks = {
            "OWASP": [
                "OWASP Top 10",
                "OWASP API Security Top 10", 
                "OWASP Mobile Top 10",
                "OWASP Proactive Controls",
                "OWASP ASVS (Application Security Verification Standard)",
                "OWASP SAMM (Software Assurance Maturity Model)",
                "OWASP Testing Guide",
                "OWASP Code Review Guide"
            ],
            "NIST": [
                "NIST Cybersecurity Framework",
                "NIST SP 800-53 (Security Controls)",
                "NIST SP 800-63 (Digital Identity Guidelines)",
                "NIST Privacy Framework"
            ],
            "CIS": [
                "CIS Controls",
                "CIS Benchmarks"
            ],
            "SANS": [
                "SANS Top 25 Most Dangerous Software Errors",
                "SANS Security Policies"
            ],
            "ISO": [
                "ISO 27001",
                "ISO 27002"
            ],
            "PCI": [
                "PCI DSS (Data Security Standard)"
            ]
        }
        
        # Current technology documentation sites (domain only)
        self.valid_tech_domains = {
            "docs.microsoft.com",
            "developer.mozilla.org", 
            "docs.aws.amazon.com",
            "cloud.google.com/docs",
            "docs.docker.com",
            "kubernetes.io/docs",
            "nodejs.org/docs",
            "docs.python.org",
            "golang.org/doc",
            "docs.oracle.com",
            "docs.github.com"
        }
        
        # Deprecated or commonly broken reference patterns
        self.deprecated_patterns = [
            r"owasp\.org/.*cheat.*sheet",  # OWASP cheat sheets often moved/deleted
            r"cwe\.mitre\.org/data/definitions/\d+\.html",  # Specific CWE URLs change
            r"nvd\.nist\.gov/vuln/detail/CVE-\d{4}-\d{4,7}",  # Specific CVE URLs
            r"capec\.mitre\.org/data/definitions/\d+\.html",  # CAPEC specific URLs
        ]
    
    def validate_reference_text(self, text: str) -> str:
        """
        Validate and clean reference text to remove potentially broken links
        """
        # Remove URLs that match deprecated patterns
        cleaned_text = text
        for pattern in self.deprecated_patterns:
            cleaned_text = re.sub(pattern, "[Link removed - refer to official documentation]", cleaned_text)
        
        # Remove any remaining URLs that aren't from verified domains
        url_pattern = r'https?://([^/\s]+)'
        
        def url_replacer(match):
            domain = match.group(1)
            if any(valid_domain in domain for valid_domain in self.valid_tech_domains):
                return match.group(0)  # Keep valid domain URLs
            else:
                return "[Official documentation available online]"
        
        cleaned_text = re.sub(url_pattern, url_replacer, cleaned_text)
        
        return cleaned_text
    
    def get_valid_framework_references(self, category: str = None) -> Dict[str, List[str]]:
        """Get current valid framework references"""
        if category and category.upper() in self.valid_frameworks:
            return {category.upper(): self.valid_frameworks[category.upper()]}
        return self.valid_frameworks
    
    def suggest_current_reference(self, deprecated_ref: str) -> str:
        """Suggest current alternative for deprecated reference"""
        
        # Common deprecated reference mappings
        suggestions = {
            "OWASP XSS Prevention Cheat Sheet": "OWASP Top 10 - A03:2021 Injection and A07:2021 Cross-Site Scripting",
            "OWASP Input Validation Cheat Sheet": "OWASP Top 10 - A03:2021 Injection and OWASP Proactive Controls",
            "OWASP Authentication Cheat Sheet": "OWASP Top 10 - A07:2021 Identification and Authentication Failures",
            "OWASP Session Management Cheat Sheet": "OWASP Top 10 - A07:2021 Identification and Authentication Failures",
            "OWASP SQL Injection Prevention Cheat Sheet": "OWASP Top 10 - A03:2021 Injection",
            "OWASP Cross-Site Request Forgery Prevention Cheat Sheet": "OWASP Top 10 and OWASP Proactive Controls"
        }
        
        # Check for exact matches
        for deprecated, current in suggestions.items():
            if deprecated.lower() in deprecated_ref.lower():
                return current
        
        # General fallback suggestions
        if "xss" in deprecated_ref.lower() or "cross-site scripting" in deprecated_ref.lower():
            return "OWASP Top 10 - A03:2021 Injection"
        elif "sql injection" in deprecated_ref.lower():
            return "OWASP Top 10 - A03:2021 Injection"
        elif "authentication" in deprecated_ref.lower():
            return "OWASP Top 10 - A07:2021 Identification and Authentication Failures"
        elif "session" in deprecated_ref.lower():
            return "OWASP Top 10 - A07:2021 Identification and Authentication Failures"
        elif "csrf" in deprecated_ref.lower():
            return "OWASP Top 10 and OWASP Proactive Controls"
        
        # Default to OWASP Top 10
        return "OWASP Top 10 (current version)"
    
    def format_safe_reference(self, framework: str, specific_item: str = None) -> str:
        """Format a safe, URL-free reference"""
        
        if framework.upper() == "OWASP" and specific_item:
            if specific_item in self.valid_frameworks["OWASP"]:
                return f"**{specific_item}** (available on the official OWASP website)"
            else:
                # Try to map to current equivalent
                current_ref = self.suggest_current_reference(specific_item)
                return f"**{current_ref}** (available on the official OWASP website)"
        
        elif framework.upper() in self.valid_frameworks:
            framework_list = self.valid_frameworks[framework.upper()]
            if len(framework_list) == 1:
                return f"**{framework_list[0]}** (available on the official {framework.upper()} website)"
            else:
                items = ", ".join(framework_list[:3])  # Show first 3 items
                return f"**{framework.upper()} resources** including {items} (available on the official {framework.upper()} website)"
        
        return f"**{framework}** (refer to official documentation)"
    
    def create_reference_guidelines(self) -> str:
        """Create guidelines for current security references"""
        
        guidelines = """
**Current Security Reference Guidelines:**

**OWASP Resources:**
- OWASP Top 10 (latest version)
- OWASP API Security Top 10
- OWASP Proactive Controls
- OWASP ASVS (Application Security Verification Standard)

**Standards & Frameworks:**
- NIST Cybersecurity Framework
- CIS Controls
- ISO 27001/27002
- PCI DSS

**Note:** Always refer to the official websites for these organizations for the most current documentation. Specific cheat sheets and detailed guides may be reorganized or updated frequently.
"""
        return guidelines

# Global validator instance
reference_validator = SecurityReferenceValidator()