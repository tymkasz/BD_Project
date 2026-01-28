CREATE TABLE system_users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    role VARCHAR(20) CHECK (role IN ('ADMIN', 'ANALYST_L1', 'ANALYST_L2', 'AUDITOR')),
    email VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE
);
