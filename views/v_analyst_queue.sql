CREATE VIEW v_analyst_queue AS
SELECT 
    i.incident_id,
    i.title,
    i.severity,
    i.status,
    u.username AS assigned_to,      -- Zamiast ID użytkownika, widzimy Login
    dr.rule_name,                   -- Zamiast ID reguły, widzimy nazwę ataku
    dr.threat_type,
    m.source_ip AS attacker_ip      -- Wyciągamy IP atakującego z powiązanego logu
FROM security_incidents i
LEFT JOIN system_users u ON i.assigned_user_id = u.user_id
LEFT JOIN malware_logs m ON i.primary_malware_log_id = m.log_id
LEFT JOIN detection_rules dr ON m.detected_rule_id = dr.rule_id
WHERE i.status != 'RESOLVED';       -- Filtr: Ukrywamy zamknięte sprawy
