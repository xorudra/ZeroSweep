-- Rename stored platform-origin values from the pre-rename product name.
-- Safe no-op when no rows carry the old values; runs with the normal migrate step.
UPDATE "MobileTestDevice" SET ownership = 'ZEROSWEEP_MANAGED' WHERE ownership = 'DSRCLONE_MANAGED';
UPDATE "ExternalFindingReference" SET origin = 'ZEROSWEEP' WHERE origin = 'DSRCLONE';
