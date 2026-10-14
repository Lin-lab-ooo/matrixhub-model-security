CREATE TABLE security_reviews (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 scope TEXT NOT NULL, repo TEXT NOT NULL, report_id TEXT NOT NULL,
 revision TEXT NOT NULL, generation TEXT NOT NULL,
 actor_id INTEGER NOT NULL, actor TEXT NOT NULL,
 verdict TEXT NOT NULL, comment TEXT NOT NULL, created_at DATETIME NOT NULL
);
CREATE INDEX idx_security_reviews_report ON security_reviews(scope,report_id,id);
