CREATE OR REPLACE FUNCTION detect_scan_burst() RETURNS TRIGGER AS $$
DECLARE
    v_count INT;
BEGIN
    -- Policz, ile razy to IP zostało zablokowane w ciągu ostatniej minuty
    SELECT count(*) INTO v_count FROM fake_traffic_logs 
    WHERE source_ip = NEW.source_ip AND detection_time > NOW() - INTERVAL '1 minute';

    -- Jeśli 5 lub więcej razy -> dodaj do czarnej listy
    IF v_count >= 5 THEN
        INSERT INTO threat_intelligence_feed (ip_address, risk_score, threat_category, provider_name)
        VALUES (NEW.source_ip, 100, 'AUTO_BAN_SCANNER', 'Internal IDS')
        ON CONFLICT (ip_address) DO NOTHING; -- Ignoruj, jeśli już tam jest
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_detect_scan AFTER INSERT ON fake_traffic_logs
FOR EACH ROW EXECUTE FUNCTION detect_scan_burst();
