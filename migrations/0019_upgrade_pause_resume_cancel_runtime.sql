ALTER TYPE upgrade_campaign_state ADD VALUE IF NOT EXISTS 'PAUSE_REQUESTED';
ALTER TYPE upgrade_campaign_state ADD VALUE IF NOT EXISTS 'PAUSED';
ALTER TYPE upgrade_campaign_state ADD VALUE IF NOT EXISTS 'CANCEL_REQUESTED';
ALTER TYPE upgrade_campaign_state ADD VALUE IF NOT EXISTS 'CANCELLED';

ALTER TABLE upgrade_campaigns
  ADD COLUMN paused_by text NOT NULL DEFAULT '',
  ADD COLUMN paused_at timestamptz,
  ADD COLUMN pause_count integer NOT NULL DEFAULT 0 CHECK(pause_count >= 0),
  ADD COLUMN cancel_requested_by text NOT NULL DEFAULT '',
  ADD COLUMN cancel_requested_at timestamptz,
  ADD COLUMN cancelled_by text NOT NULL DEFAULT '',
  ADD COLUMN cancelled_at timestamptz,
  ADD COLUMN control_reason text NOT NULL DEFAULT '';

CREATE INDEX upgrade_campaigns_control_state_idx
  ON upgrade_campaigns(state,updated_at);
