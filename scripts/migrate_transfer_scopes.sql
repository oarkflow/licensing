-- Migration Script: Add Transfer Feature Scopes
-- This script adds the transfer feature scopes to the Secretr API feature if they don't already exist.
-- Transfer features require Business+ plan.
-- Run this after ensuring the Secretr product and features have been bootstrapped.

-- Get the API feature ID (feat_api_001) for Secretr product
-- The feature_id for API feature should be 'feat_api_001' based on the secretr_product.go definitions

-- Insert transfer scopes if they don't exist
-- Using INSERT OR IGNORE to skip if the scope already exists (based on unique id)

INSERT OR
IGNORE INTO feature_scopes (id, feature_id, name, slug, permission, scope_limit, metadata, created_at, updated_at)
VALUES
    ('api_s070', 'feat_api_001', 'Transfer Devices List', 'transfer_devices_list', 'allow', 0, '{"description":"List trusted devices"}', datetime('now'), datetime('now')),
    ('api_s071', 'feat_api_001', 'Transfer Devices Trust', 'transfer_devices_trust', 'allow', 0, '{"description":"Trust a device"}', datetime('now'), datetime('now')),
    ('api_s072', 'feat_api_001', 'Transfer Devices Revoke', 'transfer_devices_revoke', 'allow', 0, '{"description":"Revoke device trust"}', datetime('now'), datetime('now')),
    ('api_s073', 'feat_api_001', 'Transfer Device Initiate', 'transfer_device_initiate', 'allow', 0, '{"description":"Initiate device transfer"}', datetime('now'), datetime('now')),
    ('api_s074', 'feat_api_001', 'Transfer Device Status', 'transfer_device_status', 'allow', 0, '{"description":"Get device transfer status"}', datetime('now'), datetime('now')),
    ('api_s075', 'feat_api_001', 'Transfer Cloud Config', 'transfer_cloud_config', 'allow', 0, '{"description":"Cloud transfer configuration"}', datetime('now'), datetime('now')),
    ('api_s076', 'feat_api_001', 'Transfer Cloud Upload', 'transfer_cloud_upload', 'allow', 0, '{"description":"Upload to cloud storage"}', datetime('now'), datetime('now')),
    ('api_s077', 'feat_api_001', 'Transfer Cloud Download', 'transfer_cloud_download', 'allow', 0, '{"description":"Download from cloud storage"}', datetime('now'), datetime('now')),
    ('api_s078', 'feat_api_001', 'Transfer History List', 'transfer_history_list', 'allow', 0, '{"description":"List transfer history"}', datetime('now'), datetime('now')),
    ('api_s079', 'feat_api_001', 'Transfer History Detail', 'transfer_history_detail', 'allow', 0, '{"description":"Get transfer details"}', datetime('now'), datetime('now')),
    ('api_s080', 'feat_api_001', 'Transfer Schedules List', 'transfer_schedules_list', 'allow', 0, '{"description":"List transfer schedules"}', datetime('now'), datetime('now')),
    ('api_s081', 'feat_api_001', 'Transfer Schedules Create', 'transfer_schedules_create', 'allow', 0, '{"description":"Create transfer schedule"}', datetime('now'), datetime('now')),
    ('api_s082', 'feat_api_001', 'Transfer Schedules Update', 'transfer_schedules_update', 'allow', 0, '{"description":"Update transfer schedule"}', datetime('now'), datetime('now')),
    ('api_s083', 'feat_api_001', 'Transfer Schedules Delete', 'transfer_schedules_delete', 'allow', 0, '{"description":"Delete transfer schedule"}', datetime('now'), datetime('now'));

-- Verify the insertion (optional query to run separately)
-- SELECT id, name, slug FROM feature_scopes WHERE id LIKE 'api_s07%' OR id LIKE 'api_s08%';
