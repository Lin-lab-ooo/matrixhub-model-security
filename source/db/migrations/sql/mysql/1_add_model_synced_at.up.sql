ALTER TABLE `models`
    ADD COLUMN `synced_at` timestamp NULL DEFAULT NULL COMMENT 'Model sync time'
        AFTER `is_popular`;
