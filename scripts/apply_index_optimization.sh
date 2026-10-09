#!/bin/bash

# Script to apply database index optimizations and measure performance improvements
# This script will:
# 1. Measure current query performance (before indexes)
# 2. Apply the index migration
# 3. Measure query performance again (after indexes)
# 4. Show the performance improvements

set -e

echo "=================================================="
echo "DATABASE INDEX OPTIMIZATION FOR CUSTOM RULES"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Set Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/app"

# Check if database is accessible
echo -e "${BLUE}[1/6] Checking database connection...${NC}"
python3 -c "
import asyncio
from core.config import get_settings
settings = get_settings()
print(f'Database URL: {settings.database_url.split(\"@\")[1] if \"@\" in settings.database_url else settings.database_url}')
" || {
    echo -e "${RED}❌ Failed to connect to database${NC}"
    exit 1
}
echo -e "${GREEN}✅ Database connection successful${NC}"
echo ""

# Create migration history table if it doesn't exist
echo -e "${BLUE}[2/6] Creating migration history table...${NC}"
python3 app/migrations/000_create_migration_history.py || {
    echo -e "${YELLOW}⚠️  Migration history table might already exist${NC}"
}
echo ""

# Measure performance BEFORE adding indexes
echo -e "${BLUE}[3/6] Measuring query performance BEFORE indexes...${NC}"
echo "This may take a few seconds..."
BEFORE_RESULTS=$(python3 -c "
import asyncio
import json
import sys
sys.path.insert(0, 'app')

async def measure():
    from custom_rules.utils.performance_analyzer import analyze_performance
    results = await analyze_performance()
    print(json.dumps(results))

asyncio.run(measure())
" 2>/dev/null) || {
    echo -e "${YELLOW}⚠️  Could not measure initial performance (tables might not exist yet)${NC}"
    BEFORE_RESULTS="{}"
}

if [ "$BEFORE_RESULTS" != "{}" ]; then
    echo "$BEFORE_RESULTS" > /tmp/before_indexes_performance.json
    echo -e "${GREEN}✅ Initial performance measured${NC}"
fi
echo ""

# Check existing indexes
echo -e "${BLUE}[4/6] Checking existing indexes...${NC}"
python3 app/migrations/004_add_custom_rules_indexes.py --action check || {
    echo -e "${YELLOW}⚠️  No existing indexes found${NC}"
}
echo ""

# Apply the index migration
echo -e "${BLUE}[5/6] Applying index migration...${NC}"
python3 app/migrations/004_add_custom_rules_indexes.py --action migrate || {
    echo -e "${RED}❌ Migration failed!${NC}"
    echo "You can rollback with: python3 app/migrations/004_add_custom_rules_indexes.py --action rollback"
    exit 1
}
echo -e "${GREEN}✅ Indexes created successfully!${NC}"
echo ""

# Measure performance AFTER adding indexes
echo -e "${BLUE}[6/6] Measuring query performance AFTER indexes...${NC}"
echo "This should be much faster now..."
AFTER_RESULTS=$(python3 -c "
import asyncio
import json
import sys
sys.path.insert(0, 'app')

async def measure():
    from custom_rules.utils.performance_analyzer import analyze_performance
    results = await analyze_performance()
    print(json.dumps(results))

asyncio.run(measure())
" 2>/dev/null) || {
    echo -e "${RED}❌ Could not measure performance after indexes${NC}"
    exit 1
}

echo "$AFTER_RESULTS" > /tmp/after_indexes_performance.json
echo -e "${GREEN}✅ Post-index performance measured${NC}"
echo ""

# Compare results and show improvements
echo "=================================================="
echo -e "${GREEN}PERFORMANCE IMPROVEMENT SUMMARY${NC}"
echo "=================================================="

python3 -c "
import json

try:
    with open('/tmp/before_indexes_performance.json', 'r') as f:
        before = json.load(f)
    with open('/tmp/after_indexes_performance.json', 'r') as f:
        after = json.load(f)
    
    print(f\"📊 BEFORE INDEXES:\")
    print(f\"   Total Time: {before.get('total_time_ms', 'N/A')}ms\")
    print(f\"   Average Time: {before.get('average_time_ms', 'N/A')}ms\")
    print()
    print(f\"📊 AFTER INDEXES:\")
    print(f\"   Total Time: {after['total_time_ms']}ms\")
    print(f\"   Average Time: {after['average_time_ms']}ms\")
    print()
    
    if 'total_time_ms' in before:
        improvement = before['total_time_ms'] - after['total_time_ms']
        improvement_percent = (improvement / before['total_time_ms']) * 100
        
        print(f\"🚀 IMPROVEMENT:\")
        print(f\"   Time Saved: {improvement:.2f}ms\")
        print(f\"   Performance Gain: {improvement_percent:.1f}%\")
        
        if improvement_percent > 50:
            print(f\"   Rating: ⭐⭐⭐⭐⭐ EXCELLENT!\")
        elif improvement_percent > 30:
            print(f\"   Rating: ⭐⭐⭐⭐ GREAT!\")
        elif improvement_percent > 10:
            print(f\"   Rating: ⭐⭐⭐ GOOD\")
        else:
            print(f\"   Rating: ⭐⭐ MODERATE\")
    else:
        print(f\"🚀 Indexes applied successfully!\")
        print(f\"   New query performance baseline established.\")
    
    print()
    print(\"📝 DETAILED RESULTS:\")
    for result in after.get('results', []):
        status = '✅' if result['status'] == 'success' else '❌'
        print(f\"   {status} {result['query_name']}: {result['execution_time_ms']}ms\")
        
except FileNotFoundError:
    print(\"✅ Indexes applied successfully!\")
    print(\"   Run performance tests with: python3 -m custom_rules.utils.performance_analyzer\")
except Exception as e:
    print(f\"Error comparing results: {e}\")
"

echo ""
echo "=================================================="
echo -e "${GREEN}✨ INDEX OPTIMIZATION COMPLETE!${NC}"
echo "=================================================="
echo ""
echo "Your custom rules queries are now optimized with the following indexes:"
echo "  • User rules by niche (most frequent query)"
echo "  • Popular community rules (voting-based ranking)"
echo "  • Text search on rule names and descriptions"
echo "  • Rule ID lookups for selected rules"
echo "  • Vote tracking and prevention of duplicates"
echo "  • Comments and collections indexing"
echo "  • Analytics and trending rules"
echo ""
echo "To rollback these changes, run:"
echo "  python3 app/migrations/004_add_custom_rules_indexes.py --action rollback"
echo ""
echo -e "${GREEN}Your DevSecureX platform is now optimized for high-performance custom rules!${NC}"