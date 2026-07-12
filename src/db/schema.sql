CREATE TABLE IF NOT EXISTS events (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    ingested_at     DATETIME NOT NULL,
    event_timestamp DATETIME,
    source          VARCHAR(50) NOT NULL,
    event_type      VARCHAR(50),
    severity        INT,
    src_ip          VARCHAR(45),
    src_port        INT,
    dest_ip         VARCHAR(45),
    dest_port       INT,
    protocol        VARCHAR(10),
    signature       VARCHAR(255),
    raw_message     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_reputation (
    ip           VARCHAR(45) PRIMARY KEY,
    abuse_score  INT,
    is_known_bad BOOLEAN,
    checked_at   DATETIME NOT NULL,
    raw_response TEXT
);

CREATE INDEX idx_events_src_ip    ON events (src_ip);
CREATE INDEX idx_events_dest_ip   ON events (dest_ip);
CREATE INDEX idx_events_timestamp ON events (event_timestamp);
CREATE INDEX idx_events_source    ON events (source);
CREATE INDEX idx_events_type      ON events (event_type);