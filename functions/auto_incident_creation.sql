CREATE OR REPLACE FUNCTION auto_incident_creation() RETURNS TRIGGER AS $$
DECLARE
    v_severity INT;
    v_rule_name VARCHAR;
BEGIN
    -- Pobierz poziom zagrożenia i nazwę reguły dla wykrytego ataku
    SELECT severity_level, rule_name INTO v_severity, v_rule_name 
    FROM detection_rules WHERE rule_id = NEW.detected_rule_id;

    -- Jeśli zagrożenie jest poważne (>= 4), utwórz ticket dla człowieka
    IF v_severity >= 4 THEN
        INSERT INTO security_incidents (title, severity, primary_malware_log_id, status)
        VALUES ('Automated Alert: ' || v_rule_name, 'CRITICAL', NEW.log_id, 'OPEN');
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_auto_incident AFTER INSERT ON malware_logs
FOR EACH ROW EXECUTE FUNCTION auto_incident_creation();
