CREATE TABLE security_tasks (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 scope TEXT NOT NULL, repo TEXT NOT NULL, revision TEXT NOT NULL,
 generation TEXT NOT NULL, state TEXT NOT NULL, trigger TEXT NOT NULL DEFAULT '',
 force INTEGER NOT NULL DEFAULT 0, attempt INTEGER NOT NULL DEFAULT 0,
 retry_count INTEGER NOT NULL DEFAULT 0, token TEXT NOT NULL DEFAULT '',
 lease_until DATETIME, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL,
 error TEXT NOT NULL DEFAULT '', report_json TEXT NOT NULL DEFAULT '',
 UNIQUE(scope,revision,generation)
);
CREATE INDEX idx_security_tasks_queue ON security_tasks(state,generation,id);
CREATE INDEX idx_security_tasks_lease ON security_tasks(state,lease_until);
CREATE TABLE security_reports (
 report_id TEXT PRIMARY KEY, scope TEXT NOT NULL, repo TEXT NOT NULL,
 task_id INTEGER NOT NULL, attempt INTEGER NOT NULL, report_json TEXT NOT NULL,
 created_at DATETIME NOT NULL
);
CREATE INDEX idx_security_reports_scope ON security_reports(scope,task_id);
CREATE TABLE security_cache (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, digest TEXT NOT NULL,
 size INTEGER NOT NULL, type TEXT NOT NULL, generation TEXT NOT NULL,
 analysis_json TEXT NOT NULL, created_at DATETIME NOT NULL,
 UNIQUE(scope,digest,size,type,generation)
);
CREATE TABLE security_policies (
 scope TEXT PRIMARY KEY, repo TEXT NOT NULL, mode TEXT NOT NULL,
 block_severity TEXT NOT NULL, version INTEGER NOT NULL, updated_at DATETIME NOT NULL
);
CREATE TABLE security_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, repo TEXT NOT NULL,
 event_json TEXT NOT NULL, created_at DATETIME NOT NULL
);
CREATE INDEX idx_security_audit_scope ON security_audit(scope,id);
