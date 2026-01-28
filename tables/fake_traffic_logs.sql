CREATE TABLE fake_traffic_logs (
    log_id BIGSERIAL PRIMARY KEY,
    source_ip INET,
    detected_rule_id INT REFERENCES detection_rules(rule_id),
    request_frequency INT,
    action_taken VARCHAR(50),
    detection_time TIMESTAMP DEFAULT NOW()
);
