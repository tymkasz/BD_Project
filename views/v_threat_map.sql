CREATE VIEW v_threat_map AS
SELECT 
    source_ip,
    COUNT(*) as attack_count,           -- Liczymy ile razy ten IP nas zaatakował
    MAX(detection_time) as last_attack  -- Kiedy był ostatni atak
FROM malware_logs
GROUP BY source_ip                      -- Grupujemy po adresie IP
ORDER BY attack_count DESC;             -- Sortujemy od najgroźniejszych
