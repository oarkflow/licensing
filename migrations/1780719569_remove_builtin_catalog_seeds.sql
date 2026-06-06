-- migration-up
-- Built-in catalog seed code was removed from runtime.
-- Existing product, plan, feature, scope, license, and email-provider rows are
-- intentionally preserved; catalog data is now managed through Admin UI/API.
SELECT 1;

-- migration-down
SELECT 1;
