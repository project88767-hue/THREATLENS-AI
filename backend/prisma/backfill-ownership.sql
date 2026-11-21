-- Idempotent one-off backfill for per-user data isolation.
-- Safe to re-run: only touches rows whose owner column is still NULL.

-- Incidents: creator defaults to the assignee (the creator was auto-assigned on creation).
UPDATE "Incident" SET "createdById" = "assignedToId"
WHERE "createdById" IS NULL AND "assignedToId" IS NOT NULL;

-- Threat relations: inherit owner from the linked investigation, else from the
-- earliest scan whose target matches either endpoint of the relation.
UPDATE "ThreatRelation" r SET "createdById" = i."ownerId"
FROM "Investigation" i
WHERE r."createdById" IS NULL AND r."investigationId" = i.id;

UPDATE "ThreatRelation" r SET "createdById" = (
  SELECT s."userId" FROM "ScanResult" s
  WHERE s."targetValue" IN (r."sourceValue", r."targetValue")
     OR s."normalizedValue" IN (lower(r."sourceValue"), lower(r."targetValue"))
  ORDER BY s."createdAt" ASC LIMIT 1
)
WHERE r."createdById" IS NULL;

-- Orphans nobody can be shown to are removed.
DELETE FROM "ThreatRelation" WHERE "createdById" IS NULL;
