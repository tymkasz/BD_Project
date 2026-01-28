CREATE TABLE incident_audit_log (
    audit_id BIGSERIAL PRIMARY KEY,
    incident_id INT REFERENCES security_incidents(incident_id),
    changed_by_user_id INT REFERENCES system_users(user_id),
    old_status VARCHAR(20),
    new_status VARCHAR(20),
    change_timestamp TIMESTAMP DEFAULT NOW()
);
