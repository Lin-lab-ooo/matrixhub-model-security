CREATE TABLE security_tasks (
 id BIGINT PRIMARY KEY AUTO_INCREMENT,
 scope VARCHAR(96) NOT NULL, repo VARCHAR(255) NOT NULL, revision VARCHAR(40) NOT NULL,
 generation VARCHAR(96) NOT NULL, state VARCHAR(16) NOT NULL, `trigger` VARCHAR(64) NOT NULL DEFAULT '',
 `force` BOOLEAN NOT NULL DEFAULT FALSE, attempt INT NOT NULL DEFAULT 0,
 retry_count INT NOT NULL DEFAULT 0, token VARCHAR(64) NOT NULL DEFAULT '',
 lease_until DATETIME(3), created_at DATETIME(3) NOT NULL, updated_at DATETIME(3) NOT NULL,
 error TEXT NOT NULL, report_json LONGTEXT NOT NULL,
 UNIQUE KEY uq_security_task(scope,revision,generation),
 KEY idx_security_tasks_queue(state,generation,id), KEY idx_security_tasks_lease(state,lease_until)
);
CREATE TABLE security_reports (
 report_id VARCHAR(96) PRIMARY KEY, scope VARCHAR(96) NOT NULL, repo VARCHAR(255) NOT NULL,
 task_id BIGINT NOT NULL, attempt INT NOT NULL, report_json LONGTEXT NOT NULL,
 created_at DATETIME(3) NOT NULL, KEY idx_security_reports_scope(scope,task_id)
);
CREATE TABLE security_cache (
 id BIGINT PRIMARY KEY AUTO_INCREMENT, scope VARCHAR(96) NOT NULL, digest VARCHAR(64) NOT NULL,
 size BIGINT NOT NULL, type VARCHAR(128) NOT NULL, generation VARCHAR(96) NOT NULL,
 analysis_json LONGTEXT NOT NULL, created_at DATETIME(3) NOT NULL,
 UNIQUE KEY uq_security_cache(scope,digest,size,type,generation)
);
CREATE TABLE security_policies (
 scope VARCHAR(96) PRIMARY KEY, repo VARCHAR(255) NOT NULL, mode VARCHAR(16) NOT NULL,
 block_severity VARCHAR(16) NOT NULL, version BIGINT NOT NULL, updated_at DATETIME(3) NOT NULL
);
CREATE TABLE security_audit (
 id BIGINT PRIMARY KEY AUTO_INCREMENT, scope VARCHAR(96) NOT NULL, repo VARCHAR(255) NOT NULL,
 event_json LONGTEXT NOT NULL, created_at DATETIME(3) NOT NULL, KEY idx_security_audit_scope(scope,id)
);
