CREATE TABLE IF NOT EXISTS notification_health_scan_leases (
    lease_name text PRIMARY KEY,
    claimed_by text NOT NULL,
    claimed_until timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS notification_health_scan_leases_until_idx
    ON notification_health_scan_leases(claimed_until);
