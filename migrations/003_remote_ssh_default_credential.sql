BEGIN;

ALTER TABLE remote.credentials
    ADD COLUMN IF NOT EXISTS is_default boolean NOT NULL DEFAULT false;

-- A disabled key must never remain the implicit execution credential.
UPDATE remote.credentials SET is_default = FALSE
WHERE is_default = TRUE AND is_enabled = FALSE;

-- Preserve an existing enabled default. Legacy targets without one receive
-- their oldest enabled credential as a deterministic initial default.
WITH first_enabled AS (
    SELECT DISTINCT ON (target_id) target_id, id
    FROM remote.credentials
    WHERE is_enabled = TRUE
    ORDER BY target_id, created_at, id
)
UPDATE remote.credentials AS credential
SET is_default = TRUE
FROM first_enabled
WHERE credential.id = first_enabled.id
  AND NOT EXISTS (
      SELECT 1 FROM remote.credentials AS existing
      WHERE existing.target_id = first_enabled.target_id
        AND existing.is_enabled = TRUE AND existing.is_default = TRUE
  );

CREATE UNIQUE INDEX IF NOT EXISTS remote_credentials_single_default_idx
    ON remote.credentials(target_id) WHERE is_default = TRUE;

COMMIT;
