CREATE TABLE connected_devices (
    device_id SERIAL PRIMARY KEY,
    mac_address MACADDR NOT NULL UNIQUE,
    ip_address INET,
    hostname VARCHAR(100),
    segment_id INT REFERENCES network_segments(segment_id),
    trust_level INT CHECK (trust_level BETWEEN 0 AND 100),
    last_seen TIMESTAMP DEFAULT NOW()
);
