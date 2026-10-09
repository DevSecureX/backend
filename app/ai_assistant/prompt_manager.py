"""
Prompt management for AI security assistant
Handles system prompts, analysis prompts, and recommendation prompts
"""

from typing import Dict, List, Any, Optional
import json

class PromptManager:
    """Manages AI prompts for security analysis and assistance"""
    
    def __init__(self):
        self.system_prompts = {
            "security_assistant": """You are DevSecureX AI Assistant, a world-class security expert specializing in modern application security, helping developers build secure software in today's evolving threat landscape.

Your comprehensive expertise includes:

**Core Security Testing:**
- Static Application Security Testing (SAST)
- Dynamic Application Security Testing (DAST)
- Interactive Application Security Testing (IAST)
- Software Composition Analysis (SCA)
- Container and Infrastructure security scanning

**Modern Security Domains:**
- Cloud Security (AWS, Azure, GCP) & Cloud-native security
- API Security (REST, GraphQL, microservices, rate limiting)
- DevSecOps & CI/CD pipeline security (shift-left practices)
- Supply Chain Security (SBOM, dependency attacks, software integrity)
- AI/ML Security (prompt injection, model poisoning, data privacy)
- Container Security (Docker, Kubernetes, serverless security)
- Zero Trust Architecture & Identity-based security

**Vulnerability Categories:**
- OWASP Top 10 2021 (including Insecure Design, Software Integrity Failures)
- Injection attacks (SQL, NoSQL, LDAP, OS command, XXE)
- Authentication/Authorization flaws & broken access control
- Cryptographic failures & insecure communications
- Security misconfiguration & exposed sensitive data
- Cross-Site Scripting (XSS) & Cross-Site Request Forgery (CSRF)
- Server-Side Request Forgery (SSRF) & business logic flaws

**Modern Development Security:**
- Infrastructure as Code (IaC) security (Terraform, CloudFormation)
- Secure coding for modern frameworks (React, Vue, Node.js, Python, Go, Rust)
- Microservices security patterns & service mesh security
- Mobile application security (iOS, Android, React Native)
- Web3/Blockchain security (smart contracts, DeFi protocols)

**Security Architecture & Processes:**
- Threat modeling (STRIDE, PASTA, OCTAVE)
- Privacy engineering (GDPR, CCPA compliance, data protection)
- Security monitoring, logging, and incident response
- Secure SDLC integration and security requirements

Guidelines for responses:
- Provide immediately actionable, specific security advice
- Always explain the business impact and attack scenarios
- Include concrete code fixes with before/after examples
- Reference ONLY current, valid security standards and documentation
- Consider modern deployment contexts (cloud, containers, serverless)
- Address both preventive controls and detective measures
- Ask clarifying questions about architecture, tech stack, and threat model when needed
- Prioritize fixes by risk level and implementation complexity
- Stay current with emerging threats and attack techniques

**CRITICAL: When providing references, only use currently available resources:**
- For OWASP: Use only main categories (e.g., "OWASP Top 10", "OWASP API Security Top 10") without specific cheat sheet URLs
- For standards: Reference general frameworks (NIST Cybersecurity Framework, CIS Controls) without specific document links
- For tools/libraries: Reference current official documentation sites only
- When unsure about link validity, provide general guidance without specific URLs
- Focus on teaching principles rather than linking to potentially outdated resources""",

            "issue_analyzer": """You are a security code analyzer. Your task is to analyze code snippets for security vulnerabilities and provide detailed explanations.

When analyzing code:
1. Identify specific security issues
2. Explain the vulnerability type and impact
3. Assess the severity level (Critical, High, Medium, Low)
4. Provide concrete remediation steps
5. Reference relevant security standards

Focus on:
- Input validation issues
- Authentication/authorization flaws
- Data exposure risks
- Injection vulnerabilities
- Cryptographic weaknesses
- Business logic flaws""",

            "security_advisor": """You are a security advisor providing recommendations for secure development practices.

Your recommendations should:
- Be specific and actionable
- Include implementation examples
- Consider the development context
- Follow industry best practices
- Be prioritized by security impact

Topics you cover:
- Secure architecture patterns
- Security testing strategies
- Dependency management
- Deployment security
- Monitoring and logging
- Incident response"""
        }
    
    def get_system_prompt(self, prompt_type: str) -> str:
        """Get system prompt by type"""
        return self.system_prompts.get(prompt_type, self.system_prompts["security_assistant"])
    
    def get_analysis_prompt(
        self,
        code_snippet: str,
        language: str,
        context: Optional[str] = None,
        scan_results: Optional[List[Dict]] = None
    ) -> str:
        """Generate analysis prompt for code security review"""
        
        prompt = f"""Analyze this {language} code for security vulnerabilities:

```{language}
{code_snippet}
```

"""
        
        if context:
            prompt += f"Additional context: {context}\n\n"
        
        if scan_results:
            prompt += "Related scan findings:\n"
            for result in scan_results[:3]:  # Limit to first 3 results
                prompt += f"- {result.get('rule_id', 'Unknown')}: {result.get('message', 'No message')}\n"
            prompt += "\n"
        
        prompt += """Please provide:
1. **Security Issues Found**: List specific vulnerabilities with line references
2. **Severity Assessment**: Rate each issue (Critical/High/Medium/Low)
3. **Impact Analysis**: Explain potential security consequences
4. **Remediation Steps**: Provide concrete fixes with code examples
5. **Best Practices**: Suggest additional security improvements
6. **Standards Alignment**: Reference relevant security frameworks (OWASP Top 10, NIST, etc.) by category only

Format your response clearly with sections and code examples. Only reference current, validated security resources without specific URLs."""
        
        return prompt
    
    def get_recommendation_prompt(
        self,
        topic: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate recommendation prompt for security topics"""
        
        prompt = f"Provide security recommendations for: {topic}\n\n"
        
        if context:
            prompt += "Context:\n"
            for key, value in context.items():
                prompt += f"- {key}: {value}\n"
            prompt += "\n"
        
        prompt += """Please provide:
1. **Key Security Considerations**: Main points to address
2. **Implementation Guidelines**: Step-by-step recommendations
3. **Code Examples**: Practical implementation samples
4. **Common Pitfalls**: What to avoid
5. **Testing Strategies**: How to verify security
6. **Standards Reference**: Relevant security frameworks by name only (e.g., OWASP Top 10, NIST)

Focus on practical, actionable advice that developers can implement immediately. Reference security standards by category without specific URLs or cheat sheet links."""
        
        return prompt
    
    def get_chat_context_prompt(
        self,
        user_message: str,
        conversation_history: List[Dict[str, str]],
        user_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate contextual prompt for chat conversations"""
        
        prompt = ""
        
        # Add user context if available
        if user_context:
            prompt += "User Context:\n"
            if user_context.get("current_project"):
                prompt += f"- Current Project: {user_context['current_project']}\n"
            if user_context.get("tech_stack"):
                prompt += f"- Tech Stack: {', '.join(user_context['tech_stack'])}\n"
            if user_context.get("security_focus"):
                prompt += f"- Security Focus: {user_context['security_focus']}\n"
            prompt += "\n"
        
        # Add recent conversation history for context
        if conversation_history:
            prompt += "Recent Conversation:\n"
            for msg in conversation_history[-3:]:  # Last 3 messages for context
                role = msg.get("role", "user")
                content = msg.get("content", "")[:200]  # Truncate long messages
                prompt += f"{role.title()}: {content}\n"
            prompt += "\n"
        
        prompt += f"Current Question: {user_message}\n\n"
        prompt += "Please provide a helpful, security-focused response that builds on our conversation."
        
        return prompt
    
    def get_code_explanation_prompt(
        self,
        code_snippet: str,
        language: str,
        focus_area: Optional[str] = None
    ) -> str:
        """Generate prompt for explaining code functionality"""
        
        prompt = f"""Explain this {language} code with a focus on security implications:

```{language}
{code_snippet}
```

"""
        
        if focus_area:
            prompt += f"Pay special attention to: {focus_area}\n\n"
        
        prompt += """Please explain:
1. **What the code does**: High-level functionality
2. **Security relevance**: How it relates to application security
3. **Potential risks**: Security concerns or vulnerabilities
4. **Best practices**: How it could be improved from a security perspective

Keep the explanation clear and educational, suitable for developers learning about secure coding."""
        
        return prompt
    
    def customize_prompt(
        self,
        base_prompt: str,
        customizations: Dict[str, str]
    ) -> str:
        """Apply customizations to a base prompt"""
        
        customized = base_prompt
        
        for placeholder, value in customizations.items():
            customized = customized.replace(f"{{{placeholder}}}", str(value))
        
        return customized