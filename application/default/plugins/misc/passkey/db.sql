CREATE TABLE IF NOT EXISTS am_passkey_credentials (
    user_id INT NOT NULL,
    credential_id VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INT NOT NULL,
    transports VARCHAR(255),
    PRIMARY KEY (user_id, credential_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
