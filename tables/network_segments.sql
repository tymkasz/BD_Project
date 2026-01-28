CREATE TABLE network_segments (
    segment_id SERIAL PRIMARY KEY,
    segment_name VARCHAR(50) NOT NULL,
    cidr_block CIDR NOT NULL,
    security_level INT CHECK (security_level BETWEEN 1 AND 10)
);
