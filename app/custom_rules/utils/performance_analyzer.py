"""
Performance Analyzer for Custom Rules Queries

This utility measures query performance before and after index optimization
to demonstrate the performance improvements.
"""

import asyncio
import time
import logging
from typing import Dict, List, Any
from sqlalchemy import select, and_, or_, func, text
from sqlalchemy.ext.asyncio import AsyncSession
from custom_rules.models import CommunityRules, CommunityRuleVotes
from core.database import get_db

logger = logging.getLogger(__name__)

class CustomRulesPerformanceAnalyzer:
    """Analyze query performance for custom rules operations"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.results = {}
        
    async def measure_query_time(self, query_name: str, query_func) -> Dict[str, Any]:
        """Measure execution time for a query"""
        start_time = time.perf_counter()
        
        try:
            result = await query_func()
            execution_time = time.perf_counter() - start_time
            
            return {
                "query_name": query_name,
                "execution_time_ms": round(execution_time * 1000, 2),
                "status": "success",
                "row_count": len(result) if isinstance(result, list) else 1
            }
        except Exception as e:
            execution_time = time.perf_counter() - start_time
            return {
                "query_name": query_name,
                "execution_time_ms": round(execution_time * 1000, 2),
                "status": "error",
                "error": str(e)
            }
    
    async def test_user_rules_by_niche(self, user_id: int = 2) -> List:
        """Test fetching user's custom rules filtered by niche"""
        query = select(CommunityRules).where(
            and_(
                CommunityRules.author_id == user_id,
                CommunityRules.tool == 'semgrep',
                or_(
                    CommunityRules.language.in_(['python', 'javascript', 'typescript']),
                    CommunityRules.language.is_(None)
                )
            )
        )
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def test_popular_community_rules(self) -> List:
        """Test fetching popular community rules"""
        query = select(CommunityRules).where(
            and_(
                CommunityRules.is_public == True,
                CommunityRules.upvotes >= 0
            )
        ).order_by(
            (CommunityRules.upvotes + CommunityRules.usage_count * 0.1).desc()
        ).limit(20)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def test_rule_search(self, search_term: str = "SQL") -> List:
        """Test searching rules by name or description"""
        query = select(CommunityRules).where(
            or_(
                CommunityRules.rule_name.ilike(f"%{search_term}%"),
                CommunityRules.description.ilike(f"%{search_term}%")
            )
        ).limit(50)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def test_rules_by_ids(self, rule_ids: List[str]) -> List:
        """Test fetching specific rules by IDs"""
        if not rule_ids:
            # Generate sample IDs for testing
            rule_ids = [
                "c3d4e5f6-a7b8-9012-cdef-345678901234",
                "d1513d12-60af-4700-8b39-5ea9797c60e7",
                "990db2e2-efe3-4d77-a934-ca7db7b6bd62"
            ]
        
        query = select(CommunityRules).where(
            CommunityRules.id.in_(rule_ids)
        )
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def test_vote_check(self, rule_id: str, user_id: int = 2) -> Any:
        """Test checking if user has voted on a rule"""
        query = select(CommunityRuleVotes).where(
            and_(
                CommunityRuleVotes.rule_id == rule_id,
                CommunityRuleVotes.user_id == user_id
            )
        )
        
        result = await self.db.execute(query)
        return result.scalar_one_or_none()
    
    async def test_trending_rules(self) -> List:
        """Test fetching trending rules (recent + popular)"""
        # For SQLite, we can't use interval arithmetic directly
        query = select(CommunityRules).where(
            CommunityRules.is_public == True
        ).order_by(
            CommunityRules.created_at.desc(),
            CommunityRules.upvotes.desc()
        ).limit(10)
        
        result = await self.db.execute(query)
        return result.scalars().all()
    
    async def test_analytics_aggregation(self) -> Dict:
        """Test analytics aggregation query"""
        query = select(
            CommunityRules.tool,
            CommunityRules.severity,
            func.count(CommunityRules.id).label('count'),
            func.avg(CommunityRules.upvotes).label('avg_upvotes')
        ).where(
            CommunityRules.is_public == True
        ).group_by(
            CommunityRules.tool,
            CommunityRules.severity
        )
        
        result = await self.db.execute(query)
        return result.all()
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """Run all performance tests"""
        logger.info("Starting performance analysis...")
        
        tests = [
            ("User Rules by Niche", self.test_user_rules_by_niche),
            ("Popular Community Rules", self.test_popular_community_rules),
            ("Rule Text Search", self.test_rule_search),
            ("Rules by IDs", self.test_rules_by_ids),
            ("Vote Check", lambda: self.test_vote_check("c3d4e5f6-a7b8-9012-cdef-345678901234")),
            ("Trending Rules", self.test_trending_rules),
            ("Analytics Aggregation", self.test_analytics_aggregation)
        ]
        
        results = []
        total_time = 0
        
        for test_name, test_func in tests:
            result = await self.measure_query_time(test_name, test_func)
            results.append(result)
            total_time += result["execution_time_ms"]
            
            # Log individual result
            status_emoji = "✅" if result["status"] == "success" else "❌"
            logger.info(
                f"{status_emoji} {test_name}: {result['execution_time_ms']}ms "
                f"({result.get('row_count', 0)} rows)"
            )
        
        # Calculate statistics
        successful_tests = [r for r in results if r["status"] == "success"]
        avg_time = total_time / len(results) if results else 0
        
        summary = {
            "total_tests": len(results),
            "successful_tests": len(successful_tests),
            "failed_tests": len(results) - len(successful_tests),
            "total_time_ms": round(total_time, 2),
            "average_time_ms": round(avg_time, 2),
            "results": results
        }
        
        # Performance recommendations
        recommendations = []
        
        for result in results:
            if result["execution_time_ms"] > 100:
                recommendations.append(
                    f"⚠️ {result['query_name']} is slow ({result['execution_time_ms']}ms). "
                    "Consider adding indexes."
                )
            elif result["execution_time_ms"] > 50:
                recommendations.append(
                    f"🟡 {result['query_name']} could be optimized ({result['execution_time_ms']}ms)."
                )
        
        if not recommendations:
            recommendations.append("✅ All queries are performing well!")
        
        summary["recommendations"] = recommendations
        
        return summary
    
    async def compare_performance(self, before_indexes: Dict, after_indexes: Dict) -> Dict:
        """Compare performance before and after adding indexes"""
        
        comparison = {
            "improvements": [],
            "regressions": [],
            "unchanged": [],
            "summary": {}
        }
        
        # Map results by query name for comparison
        before_map = {r["query_name"]: r for r in before_indexes.get("results", [])}
        after_map = {r["query_name"]: r for r in after_indexes.get("results", [])}
        
        total_improvement = 0
        improvement_count = 0
        
        for query_name, before in before_map.items():
            after = after_map.get(query_name)
            
            if not after or before["status"] != "success" or after["status"] != "success":
                continue
            
            before_time = before["execution_time_ms"]
            after_time = after["execution_time_ms"]
            improvement = before_time - after_time
            improvement_percent = (improvement / before_time * 100) if before_time > 0 else 0
            
            result = {
                "query": query_name,
                "before_ms": before_time,
                "after_ms": after_time,
                "improvement_ms": round(improvement, 2),
                "improvement_percent": round(improvement_percent, 1)
            }
            
            if improvement > 0:
                comparison["improvements"].append(result)
                total_improvement += improvement
                improvement_count += 1
            elif improvement < 0:
                comparison["regressions"].append(result)
            else:
                comparison["unchanged"].append(result)
        
        # Calculate summary statistics
        comparison["summary"] = {
            "total_queries": len(before_map),
            "improved_queries": len(comparison["improvements"]),
            "regressed_queries": len(comparison["regressions"]),
            "unchanged_queries": len(comparison["unchanged"]),
            "total_improvement_ms": round(total_improvement, 2),
            "average_improvement_ms": round(total_improvement / improvement_count, 2) if improvement_count > 0 else 0,
            "before_total_ms": before_indexes.get("total_time_ms", 0),
            "after_total_ms": after_indexes.get("total_time_ms", 0),
            "overall_improvement_percent": round(
                (before_indexes.get("total_time_ms", 0) - after_indexes.get("total_time_ms", 0)) / 
                before_indexes.get("total_time_ms", 1) * 100, 1
            )
        }
        
        return comparison


async def analyze_performance():
    """Main function to analyze performance"""
    async for db in get_db():
        analyzer = CustomRulesPerformanceAnalyzer(db)
        
        logger.info("=" * 60)
        logger.info("CUSTOM RULES QUERY PERFORMANCE ANALYSIS")
        logger.info("=" * 60)
        
        # Run performance tests
        results = await analyzer.run_all_tests()
        
        # Print summary
        logger.info("\n" + "=" * 60)
        logger.info("PERFORMANCE SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total Tests: {results['total_tests']}")
        logger.info(f"Successful: {results['successful_tests']}")
        logger.info(f"Failed: {results['failed_tests']}")
        logger.info(f"Total Time: {results['total_time_ms']}ms")
        logger.info(f"Average Time: {results['average_time_ms']}ms")
        
        logger.info("\n" + "=" * 60)
        logger.info("RECOMMENDATIONS")
        logger.info("=" * 60)
        for rec in results['recommendations']:
            logger.info(rec)
        
        return results


if __name__ == "__main__":
    asyncio.run(analyze_performance())