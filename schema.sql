CREATE TABLE IF NOT EXISTS log_events (
    id SERIAL PRIMARY KEY,
    source_file TEXT NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    log_type TEXT NOT NULL,          -- 'ssh' or 'windows'
    event_type TEXT NOT NULL,        -- 'failed_login', 'successful_login', 'connection', etc.
    source_ip TEXT,
    username TEXT,
    port INTEGER,
    raw_line TEXT,
    ingested_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    incident_type TEXT NOT NULL,     -- 'brute_force' or 'port_scan'
    source_ip TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    event_count INTEGER NOT NULL,
    details JSONB,
    detected_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_log_events_source_ip ON log_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_log_events_event_time ON log_events(event_time);
CREATE INDEX IF NOT EXISTS idx_incidents_source_ip ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_type ON incidents(incident_type);
