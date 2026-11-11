-- 0002: no seed users on purpose.
-- Users (and their tokens) are created by scripts/setup-admin.mjs after deploy,
-- so no credential ever lives in git history.
-- Nothing to migrate here; this file only documents that decision.
SELECT 1;
