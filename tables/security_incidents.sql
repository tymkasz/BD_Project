CREATE TABLE security_incidents (
    incident_id SERIAL PRIMARY KEY,
    title VARCHAR(200),
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(20) DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE')),
    primary_malware_log_id BIGINT REFERENCES malware_logs(log_id),
    assigned_user_id INT REFERENCES system_users(user_id),
    investigation_notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
