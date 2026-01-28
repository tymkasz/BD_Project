CREATE OR REPLACE FUNCTION analyze_packet_traffic() RETURNS TRIGGER AS $$
DECLARE
    v_rule_id INT;
    v_is_threat BOOLEAN;
BEGIN
    -- 1. Threat Intel Check (Najszybsze odrzucenie)
    SELECT EXISTS(SELECT 1 FROM threat_intelligence_feed WHERE ip_address = NEW.source_ip) INTO v_is_threat;
    IF v_is_threat THEN
        INSERT INTO fake_traffic_logs (source_ip, action_taken) 
        VALUES (NEW.source_ip, 'BLOCKED_THREAT_INTEL');
        RETURN NEW; -- Koniec. Nie analizujemy treści pakietu.
    END IF;

    -- 2. Heurystyka (Rozmiar i Pusty Payload)
    IF NEW.packet_size < 20 OR NEW.raw_packet_payload::text = '{}' THEN
        SELECT rule_id INTO v_rule_id FROM detection_rules WHERE rule_name = 'Suspiciously Small Packet' LIMIT 1;
        
        INSERT INTO fake_traffic_logs (source_ip, detected_rule_id, request_frequency, action_taken)
        VALUES (NEW.source_ip, v_rule_id, 1, 'DROPPED_HEURISTIC');
        RETURN NEW;
    END IF;

    -- 3. Analiza Treści (Malware - SQL Injection)
    IF NEW.raw_packet_payload::text ILIKE '%UNION SELECT%' OR NEW.raw_packet_payload::text ILIKE '%DROP TABLE%' THEN
        SELECT rule_id INTO v_rule_id FROM detection_rules WHERE rule_name LIKE '%SQLi%' LIMIT 1;
        
        INSERT INTO malware_logs (raw_packet_id, source_ip, dest_ip, detected_rule_id, quarantined_payload)
        VALUES (NEW.packet_id, NEW.source_ip, NEW.dest_ip, v_rule_id, NEW.raw_packet_payload);
        RETURN NEW;
    END IF;
    
    -- 4. Analiza Treści (Malware - XSS)
    IF NEW.raw_packet_payload::text ILIKE '%<script>%' THEN
        SELECT rule_id INTO v_rule_id FROM detection_rules WHERE rule_name LIKE '%XSS%' LIMIT 1;
        
        INSERT INTO malware_logs (raw_packet_id, source_ip, dest_ip, detected_rule_id, quarantined_payload)
        VALUES (NEW.packet_id, NEW.source_ip, NEW.dest_ip, v_rule_id, NEW.raw_packet_payload);
        RETURN NEW;
    END IF;

    -- 5. Ruch Czysty (Domyślny)
    INSERT INTO clean_network_logs (original_packet_id, source_ip, dest_ip, packet_size)
    VALUES (NEW.packet_id, NEW.source_ip, NEW.dest_ip, NEW.packet_size);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Podpięcie triggera
CREATE TRIGGER trg_packet_filter AFTER INSERT ON raw_input_traffic
FOR EACH ROW EXECUTE FUNCTION analyze_packet_traffic();
