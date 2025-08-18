<?php
// Migration for passkey table
// Table: ?_passkey
// Columns: passkey_id, user_id, credential_id, public_key, sign_count, transports, created_at

$this->db->query(<<<CUT
CREATE TABLE IF NOT EXISTS ?_passkey (
    passkey_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    credential_id VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INT NOT NULL DEFAULT 0,
    transports VARCHAR(255),
    created_at DATETIME NOT NULL,
    UNIQUE KEY (credential_id),
    KEY (user_id)
) ENGINE=InnoDB;
CUT
);
