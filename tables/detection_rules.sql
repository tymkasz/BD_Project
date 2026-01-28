CREATE TABLE detection_rules (
    rule_id SERIAL PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    description TEXT,
    related_cve_id VARCHAR(20) REFERENCES vulnerability_database(cve_id),
    threat_type VARCHAR(20),
    severity_level INT CHECK (severity_level BETWEEN 1 AND 5)
);
