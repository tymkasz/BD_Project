CREATE OR REPLACE FUNCTION audit_incident_changes() RETURNS TRIGGER AS $$
BEGIN
    -- Sprawdź, czy status uległ zmianie
    IF OLD.status <> NEW.status THEN
        INSERT INTO incident_audit_log (incident_id, changed_by_user_id, old_status, new_status)
        VALUES (NEW.incident_id, NEW.assigned_user_id, OLD.status, NEW.status);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_incident AFTER UPDATE ON security_incidents
FOR EACH ROW EXECUTE FUNCTION audit_incident_changes();
