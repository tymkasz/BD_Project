CREATE TABLE threat_intelligence_feed (
    threat_id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    risk_score INT,
    threat_category VARCHAR(50),
    provider_name VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);
