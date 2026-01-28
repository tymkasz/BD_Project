CREATE OR REPLACE FUNCTION update_device_presence() RETURNS TRIGGER AS $$
BEGIN
    -- Zaktualizuj pole 'last_seen' dla urządzenia o danym IP
    UPDATE connected_devices 
    SET last_seen = NOW() 
    WHERE ip_address = NEW.source_ip;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_device AFTER INSERT ON raw_input_traffic
FOR EACH ROW EXECUTE FUNCTION update_device_presence();
