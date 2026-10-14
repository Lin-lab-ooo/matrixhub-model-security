CREATE TABLE security_reviews (
 id BIGINT PRIMARY KEY AUTO_INCREMENT,
 scope VARCHAR(96) NOT NULL, repo VARCHAR(255) NOT NULL, report_id VARCHAR(96) NOT NULL,
 revision VARCHAR(40) NOT NULL, generation VARCHAR(96) NOT NULL,
 actor_id BIGINT NOT NULL, actor VARCHAR(512) NOT NULL,
 verdict VARCHAR(32) NOT NULL, comment TEXT NOT NULL, created_at DATETIME(3) NOT NULL,
 KEY idx_security_reviews_report(scope,report_id,id)
);
