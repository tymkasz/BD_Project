CREATE TABLE raw_input_traffic (
    packet_id BIGSERIAL PRIMARY KEY,
    source_ip INET NOT NULL,
    dest_ip INET NOT NULL,
    raw_packet_payload JSONB,
    packet_size INT,
    arrival_time TIMESTAMP DEFAULT NOW()
);
