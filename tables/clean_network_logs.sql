CREATE TABLE clean_network_logs (
    clean_id BIGSERIAL PRIMARY KEY,
    original_packet_id BIGINT REFERENCES raw_input_traffic(packet_id) ON DELETE SET NULL,
    source_ip INET,
    dest_ip INET,
    packet_size INT,
    processed_at TIMESTAMP DEFAULT NOW()
);
