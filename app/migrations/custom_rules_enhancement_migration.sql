-- Custom Rules Enhancement Migration
-- This migration enhances the community rules system with better security, validation, and cross-user functionality

-- 1. Add new columns to community_rules table
ALTER TABLE community_rules 
ADD COLUMN IF NOT EXISTS downvotes INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS verification_notes TEXT,
ADD COLUMN IF NOT EXISTS pattern_hash VARCHAR(64);

-- 2. Update author_id to be INTEGER instead of STRING (for foreign key compatibility)
-- First, create a backup column
ALTER TABLE community_rules ADD COLUMN IF NOT EXISTS author_id_backup VARCHAR(36);
UPDATE community_rules SET author_id_backup = author_id;

-- Convert string author_ids to integers (assuming they represent user IDs)
ALTER TABLE community_rules ALTER COLUMN author_id TYPE INTEGER USING CAST(author_id AS INTEGER);

-- 3. Add foreign key constraint to users table
ALTER TABLE community_rules 
ADD CONSTRAINT IF NOT EXISTS fk_community_rules_author 
FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE;

-- 4. Create community_rule_votes table for tracking individual votes
CREATE TABLE IF NOT EXISTS community_rule_votes (
    id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    rule_id VARCHAR(36) NOT NULL REFERENCES community_rules(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vote_type VARCHAR(10) NOT NULL CHECK (vote_type IN ('up', 'down')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(rule_id, user_id)  -- One vote per user per rule
);

-- 5. Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_community_rules_downvotes ON community_rules(downvotes);
CREATE INDEX IF NOT EXISTS idx_community_rules_is_verified ON community_rules(is_verified);
CREATE INDEX IF NOT EXISTS idx_community_rules_pattern_hash ON community_rules(pattern_hash);
CREATE INDEX IF NOT EXISTS idx_community_rules_author_public ON community_rules(author_id, is_public);
CREATE INDEX IF NOT EXISTS idx_community_rules_verified_public ON community_rules(is_verified, is_public);

CREATE INDEX IF NOT EXISTS idx_community_rule_votes_rule ON community_rule_votes(rule_id);
CREATE INDEX IF NOT EXISTS idx_community_rule_votes_user ON community_rule_votes(user_id);
CREATE INDEX IF NOT EXISTS idx_community_rule_votes_type ON community_rule_votes(vote_type);

-- 6. Update existing records to generate pattern hashes
-- Note: This would need to be done by the application code since we need to process YAML patterns

-- 7. Create a function to automatically update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- 8. Create triggers for automatic timestamp updates
DROP TRIGGER IF EXISTS update_community_rule_votes_updated_at ON community_rule_votes;
CREATE TRIGGER update_community_rule_votes_updated_at 
    BEFORE UPDATE ON community_rule_votes 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 9. Add check constraints for data integrity
ALTER TABLE community_rules 
ADD CONSTRAINT IF NOT EXISTS chk_upvotes_non_negative CHECK (upvotes >= 0),
ADD CONSTRAINT IF NOT EXISTS chk_downvotes_non_negative CHECK (downvotes >= 0),
ADD CONSTRAINT IF NOT EXISTS chk_usage_count_non_negative CHECK (usage_count >= 0);

-- 10. Create a view for popular community rules
CREATE OR REPLACE VIEW popular_community_rules AS
SELECT 
    cr.*,
    (cr.upvotes - cr.downvotes) as net_votes,
    CASE 
        WHEN cr.usage_count > 0 AND cr.upvotes > 0 THEN 
            (cr.upvotes - cr.downvotes) * LOG(cr.usage_count + 1) 
        ELSE (cr.upvotes - cr.downvotes) 
    END as popularity_score
FROM community_rules cr
WHERE cr.is_public = TRUE
ORDER BY popularity_score DESC;

-- 11. Create indexes for the view
CREATE INDEX IF NOT EXISTS idx_community_rules_popularity 
ON community_rules((upvotes - downvotes) * LOG(usage_count + 1)) 
WHERE is_public = TRUE;

-- 12. Add sample community rules data (for testing)
-- This would be done by the application, not in migration

-- 13. Security: Create a function to validate rule patterns (placeholder)
CREATE OR REPLACE FUNCTION validate_rule_pattern(pattern TEXT) 
RETURNS BOOLEAN AS $$
BEGIN
    -- Basic validation (expand as needed)
    IF LENGTH(pattern) > 10000 THEN
        RETURN FALSE;
    END IF;
    
    -- Check for dangerous patterns
    IF pattern ILIKE '%subprocess%' OR 
       pattern ILIKE '%os.system%' OR 
       pattern ILIKE '%eval(%' OR 
       pattern ILIKE '%exec(%' THEN
        -- Log warning but don't block (application handles this)
        RAISE NOTICE 'Potentially dangerous pattern detected in rule';
    END IF;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- 14. Add constraint to validate patterns
ALTER TABLE community_rules 
ADD CONSTRAINT IF NOT EXISTS chk_pattern_valid 
CHECK (validate_rule_pattern(pattern));

-- 15. Create materialized view for analytics (refreshed periodically)
CREATE MATERIALIZED VIEW IF NOT EXISTS community_rules_analytics AS
SELECT 
    COUNT(*) as total_rules,
    COUNT(CASE WHEN is_public = TRUE THEN 1 END) as public_rules,
    COUNT(CASE WHEN is_verified = TRUE THEN 1 END) as verified_rules,
    COUNT(DISTINCT author_id) as unique_authors,
    AVG(upvotes - downvotes) as avg_net_votes,
    SUM(usage_count) as total_usage,
    tool,
    COUNT(*) as rules_per_tool
FROM community_rules 
GROUP BY ROLLUP(tool);

-- Create unique index for materialized view
CREATE UNIQUE INDEX IF NOT EXISTS idx_community_rules_analytics_tool 
ON community_rules_analytics(COALESCE(tool, 'ALL'));

-- 16. Create a function to refresh analytics
CREATE OR REPLACE FUNCTION refresh_community_analytics()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW community_rules_analytics;
END;
$$ LANGUAGE plpgsql;

-- 17. Grant necessary permissions (adjust as needed for your user roles)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON community_rules TO app_user;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON community_rule_votes TO app_user;
-- GRANT SELECT ON popular_community_rules TO app_user;
-- GRANT SELECT ON community_rules_analytics TO app_user;

-- 18. Add comments for documentation
COMMENT ON TABLE community_rules IS 'User-created custom security rules that can be shared with the community';
COMMENT ON TABLE community_rule_votes IS 'Individual user votes on community rules to prevent duplicate voting';
COMMENT ON VIEW popular_community_rules IS 'Pre-calculated view of popular community rules based on votes and usage';
COMMENT ON MATERIALIZED VIEW community_rules_analytics IS 'Aggregated analytics for community rules performance and engagement';

COMMENT ON COLUMN community_rules.pattern_hash IS 'SHA-256 hash of normalized pattern for duplicate detection';
COMMENT ON COLUMN community_rules.is_verified IS 'Whether rule has been verified by administrators';
COMMENT ON COLUMN community_rules.downvotes IS 'Number of negative votes from community';

-- 19. Migration completion log
INSERT INTO migration_log (migration_name, applied_at) 
VALUES ('custom_rules_enhancement_migration', NOW())
ON CONFLICT (migration_name) DO UPDATE SET applied_at = NOW();