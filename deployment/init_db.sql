-- SecureOps Database Initialization Script
-- Author: Chukwuebuka Tobiloba Nwaizugbe
-- Description: Initial database setup for SecureOps DevSecOps platform

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create custom types
DO $$ BEGIN
    CREATE TYPE vulnerability_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE vulnerability_status AS ENUM ('open', 'acknowledged', 'resolved', 'false_positive', 'wont_fix');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE scanner_type AS ENUM ('dependency', 'secret', 'container', 'sast', 'dast', 'policy');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE alert_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE alert_status AS ENUM ('open', 'acknowledged', 'resolved', 'closed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE pipeline_status AS ENUM ('active', 'inactive', 'error', 'scanning', 'maintenance');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE scan_job_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create indexes for better performance
-- These will be created automatically by SQLAlchemy, but we can pre-create some critical ones

-- Function to create indexes if they don't exist
CREATE OR REPLACE FUNCTION create_index_if_not_exists(index_name text, table_name text, columns text) 
RETURNS void AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = index_name) THEN
        EXECUTE format('CREATE INDEX %I ON %I (%s)', index_name, table_name, columns);
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Performance optimization settings
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET track_activity_query_size = 2048;
ALTER SYSTEM SET log_min_duration_statement = 1000;
ALTER SYSTEM SET log_checkpoints = on;
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;
ALTER SYSTEM SET log_lock_waits = on;

-- Create application-specific schemas
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS monitoring;
CREATE SCHEMA IF NOT EXISTS compliance;

-- Grant permissions to application user
GRANT USAGE ON SCHEMA public TO secureops;
GRANT USAGE ON SCHEMA security TO secureops;
GRANT USAGE ON SCHEMA monitoring TO secureops;
GRANT USAGE ON SCHEMA compliance TO secureops;

GRANT CREATE ON SCHEMA public TO secureops;
GRANT CREATE ON SCHEMA security TO secureops;
GRANT CREATE ON SCHEMA monitoring TO secureops;
GRANT CREATE ON SCHEMA compliance TO secureops;

-- Create audit trigger function
CREATE OR REPLACE FUNCTION audit_trigger()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.created_at = COALESCE(NEW.created_at, NOW());
        NEW.updated_at = NOW();
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        NEW.updated_at = NOW();
        NEW.created_at = OLD.created_at; -- Preserve original created_at
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create function for vulnerability fingerprinting
CREATE OR REPLACE FUNCTION generate_vulnerability_fingerprint(
    title text,
    file_path text DEFAULT NULL,
    line_number integer DEFAULT NULL,
    cve_id text DEFAULT NULL,
    vulnerability_id text DEFAULT NULL
)
RETURNS text AS $$
BEGIN
    RETURN encode(
        digest(
            COALESCE(lower(trim(title)), '') || '|' ||
            COALESCE(file_path, '') || '|' ||
            COALESCE(line_number::text, '0') || '|' ||
            COALESCE(cve_id, '') || '|' ||
            COALESCE(vulnerability_id, ''),
            'sha256'
        ),
        'hex'
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Create function for calculating security score
CREATE OR REPLACE FUNCTION calculate_security_score(
    critical_count integer DEFAULT 0,
    high_count integer DEFAULT 0,
    medium_count integer DEFAULT 0,
    low_count integer DEFAULT 0
)
RETURNS numeric AS $$
DECLARE
    total_vulns integer;
    score numeric;
BEGIN
    total_vulns := critical_count + high_count + medium_count + low_count;
    
    -- Base score of 100
    score := 100.0;
    
    IF total_vulns > 0 THEN
        -- Deduct points based on severity
        score := score - (critical_count * 20.0) - (high_count * 10.0) - (medium_count * 5.0) - (low_count * 1.0);
        
        -- Additional penalty for high volume
        IF total_vulns > 50 THEN
            score := score - (total_vulns - 50) * 0.5;
        END IF;
    END IF;
    
    -- Ensure score is between 0 and 100
    RETURN GREATEST(0.0, LEAST(100.0, score));
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Create materialized view for dashboard statistics (will be refreshed periodically)
-- This is a placeholder - the actual view will be created after tables exist

-- Create function to refresh materialized views
CREATE OR REPLACE FUNCTION refresh_dashboard_stats()
RETURNS void AS $$
BEGIN
    -- This function will refresh materialized views for dashboard
    -- Implementation will be added after table creation
    PERFORM 1;
END;
$$ LANGUAGE plpgsql;

-- Create function for compliance score calculation
CREATE OR REPLACE FUNCTION calculate_compliance_score(
    framework text,
    total_requirements integer,
    passed_requirements integer
)
RETURNS numeric AS $$
DECLARE
    base_score numeric;
    framework_threshold numeric;
BEGIN
    IF total_requirements = 0 THEN
        RETURN 0;
    END IF;
    
    base_score := (passed_requirements::numeric / total_requirements::numeric) * 100;
    
    -- Apply framework-specific thresholds
    framework_threshold := CASE
        WHEN framework = 'owasp_top_10' THEN 80
        WHEN framework = 'nist_csf' THEN 70
        WHEN framework = 'soc2' THEN 85
        WHEN framework = 'gdpr' THEN 90
        WHEN framework = 'pci_dss' THEN 85
        ELSE 75
    END;
    
    RETURN base_score;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Set up row level security policies (basic setup)
-- Actual policies will be created with table definitions

-- Create notification function for real-time updates
CREATE OR REPLACE FUNCTION notify_vulnerability_change()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM pg_notify('vulnerability_inserted', json_build_object(
            'id', NEW.id,
            'severity', NEW.severity,
            'pipeline_id', NEW.pipeline_id
        )::text);
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        PERFORM pg_notify('vulnerability_updated', json_build_object(
            'id', NEW.id,
            'old_status', OLD.status,
            'new_status', NEW.status
        )::text);
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create function for alert escalation
CREATE OR REPLACE FUNCTION escalate_alerts()
RETURNS void AS $$
DECLARE
    alert_record RECORD;
BEGIN
    -- Find alerts that need escalation (open for more than threshold)
    FOR alert_record IN
        SELECT id, severity, created_at, escalation_level
        FROM alerts
        WHERE status = 'open'
        AND (
            (severity = 'critical' AND created_at < NOW() - INTERVAL '15 minutes') OR
            (severity = 'high' AND created_at < NOW() - INTERVAL '1 hour') OR
            (severity = 'medium' AND created_at < NOW() - INTERVAL '4 hours')
        )
        AND escalation_level < 3
    LOOP
        UPDATE alerts 
        SET escalation_level = alert_record.escalation_level + 1,
            updated_at = NOW()
        WHERE id = alert_record.id;
        
        -- Notify about escalation
        PERFORM pg_notify('alert_escalated', json_build_object(
            'id', alert_record.id,
            'escalation_level', alert_record.escalation_level + 1
        )::text);
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- Create cleanup function for old data
CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS void AS $$
BEGIN
    -- Clean up old scan results (older than 90 days)
    DELETE FROM scan_jobs 
    WHERE created_at < NOW() - INTERVAL '90 days'
    AND status IN ('completed', 'failed');
    
    -- Clean up resolved vulnerabilities (older than 180 days)
    DELETE FROM vulnerabilities 
    WHERE status = 'resolved' 
    AND resolved_at < NOW() - INTERVAL '180 days';
    
    -- Clean up old alerts (older than 365 days)
    DELETE FROM alerts 
    WHERE status = 'resolved'
    AND resolved_at < NOW() - INTERVAL '365 days';
    
    -- Log cleanup
    RAISE NOTICE 'Database cleanup completed at %', NOW();
END;
$$ LANGUAGE plpgsql;

-- Initial data setup
INSERT INTO pg_stat_statements_info (dealloc) VALUES (0) ON CONFLICT DO NOTHING;

-- Create admin role with appropriate permissions
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'secureops_admin') THEN
        CREATE ROLE secureops_admin;
        GRANT ALL PRIVILEGES ON DATABASE secureops TO secureops_admin;
        GRANT secureops_admin TO secureops;
    END IF;
END
$$;

-- Performance monitoring setup
CREATE OR REPLACE FUNCTION monitor_slow_queries()
RETURNS TABLE(query text, mean_time numeric, calls bigint) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        pss.query,
        pss.mean_exec_time,
        pss.calls
    FROM pg_stat_statements pss
    WHERE pss.mean_exec_time > 1000  -- Queries taking more than 1 second
    ORDER BY pss.mean_exec_time DESC
    LIMIT 10;
END;
$$ LANGUAGE plpgsql;

-- Success message
DO $$
BEGIN
    RAISE NOTICE 'SecureOps database initialization completed successfully!';
    RAISE NOTICE 'Database: secureops';
    RAISE NOTICE 'User: secureops';
    RAISE NOTICE 'Extensions: uuid-ossp, pg_trgm, btree_gin';
    RAISE NOTICE 'Custom functions and types created';
END
$$;
