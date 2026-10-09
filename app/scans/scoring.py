from typing import List, Dict, Any
import logging
import math

logger = logging.getLogger(__name__)

class AdvancedScoring:
    def __init__(self):
        self.severity_weights = {
            'critical': 10,      # Reduced from 25
            'high': 5,           # Reduced from 15
            'medium': 2,         # Reduced from 8
            'low': 1             # Reduced from 3
        }
        
        self.category_weights = {
            'secrets': 1.2,      # Secrets are more critical (reduced from 1.5)
            'code': 1.0,         # Code issues baseline (reduced from 1.2)
            'deps': 0.9,         # Dependencies (reduced from 1.0)
            'configs': 0.7,      # Config issues less critical (reduced from 0.8)
        }
        
    def calculate_comprehensive_scores(
        self, 
        issues: List[Dict[str, Any]], 
        scope: str, 
        niche: str
    ) -> Dict[str, Any]:
        """Calculate comprehensive scoring with business context"""
        
        if not issues:
            return self._perfect_scores()
        
        # Group issues by category
        categorized_issues = self._categorize_issues(issues)
        
        # Calculate category-specific scores
        category_scores = {}
        for category, category_issues in categorized_issues.items():
            score = self._calculate_category_score(
                category_issues, category, niche
            )
            category_scores[f"{category}_score"] = score
            logger.info(f"Category {category}: {len(category_issues)} issues, score={score}")
        
        # Calculate overall score
        total_score = self._calculate_weighted_total_score(categorized_issues, scope, niche)
        
        # Add business impact assessment
        business_impact = self._assess_business_impact(issues, niche)
        
        # Calculate trend score (improvement over time)
        trend_score = self._calculate_trend_score(total_score)
        
        result = {
            'total_score': total_score,
            **category_scores,
            'business_impact': business_impact,
            'trend_score': trend_score,
            'score_breakdown': self._generate_score_breakdown(categorized_issues),
            'recommendations': self._generate_recommendations(categorized_issues, total_score)
        }
        
        # Debug logging
        logger.info(f"Scoring result: total_score={total_score}, category_scores={category_scores}")
        
        return result
    
    def _categorize_issues(self, issues: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group issues by category"""
        categories = {
            'code': [],
            'deps': [],
            'secrets': [],
            'configs': []
        }
        
        for issue in issues:
            category = issue.get('category', 'code')
            if category in categories:
                categories[category].append(issue)
            else:
                categories['code'].append(issue)  # Default to code
        
        return categories
    
    def _calculate_category_score(
        self, 
        issues: List[Dict[str, Any]], 
        category: str, 
        niche: str
    ) -> float:
        """Calculate score for a specific category using logarithmic scaling"""
        
        if not issues:
            return 100.0
        
        # Calculate weighted impact using logarithmic scaling
        total_impact = 0
        for issue in issues:
            severity = issue.get('severity', 'medium')
            base_weight = self.severity_weights.get(severity, 2)
            
            # Apply category weight
            category_weight = self.category_weights.get(category, 1.0)
            
            # Apply niche-specific adjustments
            niche_weight = self._get_niche_weight(category, niche)
            
            # Apply confidence multiplier
            confidence_multiplier = self._get_confidence_multiplier(issue.get('confidence', 'medium'))
            
            impact = base_weight * category_weight * niche_weight * confidence_multiplier
            total_impact += impact
        
        # Use logarithmic scaling for proper score calculation
        # This ensures scores are meaningful even with high issue counts
        if total_impact <= 0:
            return 100.0
        
        # Improved logarithmic scaling with adaptive scaling factor
        # Formula: score = 100 - (log(impact + 1) * adaptive_scaling)
        
        # Calculate adaptive scaling factor based on issue count and impact
        base_scaling = 20  # Base scaling factor (reduced from 25)
        
        # Adjust scaling to ensure meaningful scores for any issue count
        if len(issues) > 100:
            # For very high issue counts, use more gentle scaling
            adaptive_scaling = base_scaling - (math.log10(len(issues)) * 3)
            adaptive_scaling = max(adaptive_scaling, 12)  # Minimum scaling of 12
        elif len(issues) > 50:
            adaptive_scaling = base_scaling - 2  # Slightly reduced scaling
        elif len(issues) > 20:
            adaptive_scaling = base_scaling  # Base scaling
        else:
            adaptive_scaling = base_scaling + 2  # More sensitive for few issues
        
        log_score = 100 - (math.log10(total_impact + 1) * adaptive_scaling)
        
        # Ensure minimum meaningful scores (never below 5 for high issue counts)
        if len(issues) > 50 and log_score < 5:
            # Use a floor function: minimum 5 + extra points for very high counts
            floor_score = 5 + min(15, math.log10(len(issues)) * 5)
            log_score = max(log_score, floor_score)
        
        # Ensure score is within bounds [0, 100]
        final_score = max(0.0, min(100.0, log_score))
        
        return round(final_score, 1)
    
    def _calculate_weighted_total_score(
        self, 
        categorized_issues: Dict[str, List[Dict[str, Any]]], 
        scope: str, 
        niche: str
    ) -> int:
        """Calculate weighted total score based on scope and context"""
        
        if not any(categorized_issues.values()):
            return 100
        
        # Calculate weighted average based on scope
        scope_weights = self._get_scope_weights(scope)
        
        weighted_sum = 0
        total_weight = 0
        
        for category, weight in scope_weights.items():
            if category in categorized_issues:
                category_score = self._calculate_category_score(
                    categorized_issues[category], 
                    category, 
                    niche
                )
                weighted_sum += category_score * weight
                total_weight += weight
        
        if total_weight == 0:
            return 100
        
        base_score = weighted_sum / total_weight
        
        # Apply penalties for critical issues
        critical_penalty = self._calculate_critical_penalty(categorized_issues)
        
        final_score = max(base_score - critical_penalty, 0)
        return int(round(final_score))
    
    def _get_scope_weights(self, scope: str) -> Dict[str, float]:
        """Get category weights based on scan scope"""
        
        if scope == "code-only":
            return {
                'code': 0.9,
                'secrets': 0.1,
                'configs': 0.0,
                'deps': 0.0
            }
        elif scope == "code+deps":
            return {
                'code': 0.55,
                'deps': 0.3,
                'secrets': 0.15,
                'configs': 0.0
            }
        else:  # full
            return {
                'code': 0.35,
                'deps': 0.25,
                'secrets': 0.2,
                'configs': 0.2
            }
    
    def _get_niche_weight(self, category: str, niche: str) -> float:
        """Get niche-specific weight adjustments"""
        
        niche_adjustments = {
            'ai': {
                'code': 1.3,      # AI code is critical
                'deps': 1.2,      # AI dependencies important
                'secrets': 1.5,   # API keys very critical
                'configs': 1.0
            },
            'blockchain': {
                'code': 1.5,      # Smart contract bugs critical
                'deps': 1.1,
                'secrets': 1.8,   # Private keys extremely critical
                'configs': 1.2
            },
            'iot': {
                'code': 1.2,
                'deps': 1.3,      # IoT deps often vulnerable
                'secrets': 1.6,   # Device credentials critical
                'configs': 1.4    # Config important for IoT
            },
            'web3': {
                'code': 1.4,      # Frontend security critical
                'deps': 1.3,      # NPM supply chain risks
                'secrets': 2.0,   # Private keys in frontend = disaster
                'configs': 1.1
            },
            'cloud': {
                'code': 1.2,
                'deps': 1.1,
                'secrets': 1.7,   # Cloud credentials critical
                'configs': 1.5    # Misconfigurations common
            },
            'api': {
                'code': 1.4,      # API security critical
                'deps': 1.0,
                'secrets': 1.6,   # API keys exposure
                'configs': 1.3    # CORS, rate limits
            }
        }
        
        return niche_adjustments.get(niche, {}).get(category, 1.0)
    
    def _get_confidence_multiplier(self, confidence: str) -> float:
        """Get confidence-based multiplier"""
        multipliers = {
            'very_high': 1.2,
            'high': 1.1,
            'medium': 1.0,
            'low': 0.8,
            'very_low': 0.6
        }
        return multipliers.get(confidence, 1.0)
    
    def _calculate_critical_penalty(self, categorized_issues: Dict[str, List[Dict[str, Any]]]) -> float:
        """Calculate logarithmic penalty for critical issues"""
        
        critical_count = 0
        high_count = 0
        
        for issues in categorized_issues.values():
            for issue in issues:
                severity = issue.get('severity', 'medium')
                if severity == 'critical':
                    critical_count += 1
                elif severity == 'high':
                    high_count += 1
        
        if critical_count == 0 and high_count == 0:
            return 0
        
        # Use logarithmic penalty to avoid extreme deductions
        # Base penalty using log scaling with improved distribution
        total_severe_issues = critical_count * 3 + high_count  # Weight critical more
        
        # Improved logarithmic penalty with adaptive scaling
        if total_severe_issues == 0:
            return 0
        
        # Adaptive penalty scaling - more lenient for very high counts
        penalty_scaling = 12  # Base scaling (reduced from 15)
        
        # Reduce penalty scaling for extremely high issue counts
        if total_severe_issues > 100:
            penalty_scaling = max(8, penalty_scaling - math.log10(total_severe_issues) * 2)
        
        penalty = math.log10(total_severe_issues + 1) * penalty_scaling
        
        # Cap penalty at 15 points maximum (reduced from 20)
        return min(penalty, 15)
    
    def _assess_business_impact(self, issues: List[Dict[str, Any]], niche: str) -> Dict[str, Any]:
        """Assess business impact of security issues"""
        
        impact_factors = {
            'data_breach_risk': 'low',
            'compliance_risk': 'low',
            'reputation_risk': 'low',
            'financial_risk': 'low',
            'operational_risk': 'low'
        }
        
        critical_count = len([i for i in issues if i.get('severity') == 'critical'])
        secrets_count = len([i for i in issues if i.get('category') == 'secrets'])
        
        # Assess data breach risk
        if secrets_count > 0 or critical_count > 0:
            impact_factors['data_breach_risk'] = 'high' if secrets_count > 2 else 'medium'
        
        # Assess compliance risk based on niche
        if niche in ['ai', 'blockchain'] and critical_count > 0:
            impact_factors['compliance_risk'] = 'high'
        
        # Assess reputation risk
        if critical_count > 2:
            impact_factors['reputation_risk'] = 'high'
        elif critical_count > 0:
            impact_factors['reputation_risk'] = 'medium'
        
        return impact_factors
    
    def _calculate_trend_score(self, current_score: int) -> str:
        """Calculate trend score (placeholder - would need historical data)"""
        # This would typically compare with previous scans
        # For now, return neutral
        return 'stable'
    
    def _generate_score_breakdown(self, categorized_issues: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Dict[str, int]]:
        """Generate detailed score breakdown"""
        
        breakdown = {}
        
        for category, issues in categorized_issues.items():
            if not issues:
                continue
                
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            for issue in issues:
                severity = issue.get('severity', 'medium')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            breakdown[category] = severity_counts
        
        return breakdown
    
    def _generate_recommendations(
        self, 
        categorized_issues: Dict[str, List[Dict[str, Any]]], 
        total_score: int
    ) -> List[str]:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        # Critical issues first
        critical_issues = []
        for issues in categorized_issues.values():
            critical_issues.extend([i for i in issues if i.get('severity') == 'critical'])
        
        if critical_issues:
            recommendations.append(f"🚨 Address {len(critical_issues)} critical security issues immediately")
        
        # Category-specific recommendations
        if categorized_issues.get('secrets'):
            recommendations.append("🔐 Review and rotate any exposed secrets or credentials")
        
        if categorized_issues.get('deps') and len(categorized_issues['deps']) > 5:
            recommendations.append("📦 Update vulnerable dependencies and implement dependency scanning")
        
        if categorized_issues.get('code') and len(categorized_issues['code']) > 10:
            recommendations.append("💻 Implement secure coding practices and code review process")
        
        # Score-based recommendations
        if total_score < 50:
            recommendations.append("⚠️ Security posture needs immediate attention - consider security audit")
        elif total_score < 70:
            recommendations.append("📈 Good progress, focus on reducing medium and high severity issues")
        elif total_score >= 90:
            recommendations.append("✅ Excellent security posture - maintain current practices")
        
        return recommendations[:10]  # Show up to 10 recommendations (increased from 5)
    
    def _perfect_scores(self) -> Dict[str, Any]:
        """Return perfect scores when no issues found"""
        return {
            'total_score': 100,
            'code_score': 100.0,
            'deps_score': 100.0,
            'secrets_score': 100.0,
            'configs_score': 100.0,
            'business_impact': {
                'data_breach_risk': 'low',
                'compliance_risk': 'low',
                'reputation_risk': 'low',
                'financial_risk': 'low',
                'operational_risk': 'low'
            },
            'trend_score': 'stable',
            'score_breakdown': {},
            'recommendations': ["✅ No security issues found - excellent work!"]
        }