-- Crusade SQLite schema. Applied idempotently at open; see migrations.rs.
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- One row per IP ever observed. The full enriched Host is kept as JSON in
-- `doc` for cheap round-tripping; the columns are projections used for
-- filtering and faceting.
CREATE TABLE IF NOT EXISTS hosts (
    ip          TEXT PRIMARY KEY,
    asn         INTEGER,
    org         TEXT,
    country     TEXT,
    city        TEXT,
    latitude    REAL,
    longitude   REAL,
    hostnames   TEXT,           -- space-joined, for LIKE/FTS
    ip_sort     BLOB,           -- 16-byte big-endian IP, for net:/range queries
    last_seen   INTEGER NOT NULL, -- unix seconds
    doc         TEXT NOT NULL,  -- full Host JSON
    honeypot    REAL            -- honeypot score 0..1, NULL = unscored
);
CREATE INDEX IF NOT EXISTS idx_hosts_asn     ON hosts(asn);
CREATE INDEX IF NOT EXISTS idx_hosts_country ON hosts(country);
CREATE INDEX IF NOT EXISTS idx_hosts_seen    ON hosts(last_seen);
CREATE INDEX IF NOT EXISTS idx_hosts_city    ON hosts(city);
CREATE INDEX IF NOT EXISTS idx_hosts_ipsort  ON hosts(ip_sort);

-- One row per (ip, port, transport). Current state only; history below.
CREATE TABLE IF NOT EXISTS services (
    ip          TEXT NOT NULL,
    port        INTEGER NOT NULL,
    transport   TEXT NOT NULL,
    service     TEXT,
    product     TEXT,
    version     TEXT,
    cpe         TEXT,
    ssl_cn      TEXT,
    jarm        TEXT,
    favicon_hash INTEGER,
    ssh_hostkey TEXT,
    hassh       TEXT,
    tls_version TEXT,
    ics_protocol TEXT,
    auth_state  TEXT,
    screenshot  TEXT,
    has_screenshot INTEGER NOT NULL DEFAULT 0,
    observed_at INTEGER NOT NULL,
    banner      TEXT,
    PRIMARY KEY (ip, port, transport),
    FOREIGN KEY (ip) REFERENCES hosts(ip) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_services_port    ON services(port);
CREATE INDEX IF NOT EXISTS idx_services_product ON services(product);
CREATE INDEX IF NOT EXISTS idx_services_ip      ON services(ip);
CREATE INDEX IF NOT EXISTS idx_services_jarm    ON services(jarm);
CREATE INDEX IF NOT EXISTS idx_services_favicon ON services(favicon_hash);
CREATE INDEX IF NOT EXISTS idx_services_hassh   ON services(hassh);
CREATE INDEX IF NOT EXISTS idx_services_transport ON services(transport);
CREATE INDEX IF NOT EXISTS idx_services_ics     ON services(ics_protocol);
CREATE INDEX IF NOT EXISTS idx_services_auth    ON services(auth_state);

-- Tags attached to a host (vuln tags carry a cve id).
CREATE TABLE IF NOT EXISTS tags (
    ip     TEXT NOT NULL,
    name   TEXT NOT NULL,
    cve    TEXT,
    detail TEXT,
    PRIMARY KEY (ip, name, cve),
    FOREIGN KEY (ip) REFERENCES hosts(ip) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name);
CREATE INDEX IF NOT EXISTS idx_tags_cve  ON tags(cve);

-- Append-only history of every scan of a service, for the host detail page.
CREATE TABLE IF NOT EXISTS service_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    port        INTEGER NOT NULL,
    transport   TEXT NOT NULL,
    observed_at INTEGER NOT NULL,
    doc         TEXT NOT NULL   -- full Service JSON snapshot
);
CREATE INDEX IF NOT EXISTS idx_hist_ip ON service_history(ip, observed_at);

-- Full-text index over banners / titles / certs for free-text search.
-- Content-less FTS5: we populate it explicitly on upsert.
CREATE VIRTUAL TABLE IF NOT EXISTS banner_fts USING fts5(
    ip UNINDEXED,
    body,
    tokenize = "unicode61"
);

-- Alerts raised by `crusade monitor` (new port / new vuln / exposure), with a
-- delivery flag so transports (webhook/email) send each one at most once.
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,     -- unix seconds
    ip         TEXT NOT NULL,
    kind       TEXT NOT NULL,        -- new-port | new-vuln | new-exposure | test
    detail     TEXT NOT NULL,
    delivered  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts        ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_delivered ON alerts(delivered);

-- Distributed scan job queue. Multiple `crusade worker` processes on the same
-- host (WAL) claim pending jobs atomically and record completion. (Cross-host
-- scale-out needs a shared/networked DB — see ROADMAP.)
CREATE TABLE IF NOT EXISTS jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,       -- IP or CIDR
    ports       TEXT,                -- CSV of TCP ports, or NULL for defaults
    udp         INTEGER NOT NULL DEFAULT 0,
    ics         INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'pending', -- pending|running|done|failed
    worker      TEXT,
    note        TEXT,                -- result summary or error
    created_at  INTEGER NOT NULL,
    claimed_at  INTEGER,
    finished_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, id);
