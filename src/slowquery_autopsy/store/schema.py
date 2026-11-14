"""SQLite ledger schema DDL."""

SCHEMA_VERSION = 1
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS batches (
  batch_id TEXT PRIMARY KEY, config_hash TEXT NOT NULL, input_hash TEXT NOT NULL,
  created_at TEXT NOT NULL, status TEXT NOT NULL, summary_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS log_files (
  batch_id TEXT NOT NULL, path TEXT NOT NULL, log_format TEXT NOT NULL,
  encoding TEXT NOT NULL, sha256 TEXT NOT NULL, line_count INTEGER NOT NULL,
  parsed_count INTEGER NOT NULL, unparsed_count INTEGER NOT NULL,
  excluded_count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (batch_id, path), FOREIGN KEY (batch_id) REFERENCES batches(batch_id)
);
CREATE TABLE IF NOT EXISTS slow_queries (
  batch_id TEXT NOT NULL, query_id TEXT NOT NULL, source_file TEXT NOT NULL,
  line_no INTEGER NOT NULL, timestamp TEXT NOT NULL, duration_ms REAL NOT NULL,
  lock_time_ms REAL NOT NULL, rows_sent INTEGER NOT NULL, rows_examined INTEGER NOT NULL,
  user_name TEXT NOT NULL, client TEXT NOT NULL, database_name TEXT NOT NULL,
  sql_text TEXT NOT NULL, normalized_sql TEXT NOT NULL, fingerprint TEXT NOT NULL,
  cluster_id TEXT NOT NULL, log_format TEXT NOT NULL, excluded INTEGER NOT NULL,
  exclusion_reason TEXT NOT NULL, cost_json TEXT NOT NULL,
  PRIMARY KEY (batch_id, query_id), FOREIGN KEY (batch_id) REFERENCES batches(batch_id)
);
CREATE TABLE IF NOT EXISTS clusters (
  batch_id TEXT NOT NULL, cluster_id TEXT NOT NULL, sample_sql TEXT NOT NULL,
  normalized_sql TEXT NOT NULL, query_count INTEGER NOT NULL,
  total_duration_ms REAL NOT NULL, avg_duration_ms REAL NOT NULL,
  min_duration_ms REAL NOT NULL, max_duration_ms REAL NOT NULL,
  p50_duration_ms REAL NOT NULL, p95_duration_ms REAL NOT NULL,
  total_rows_examined INTEGER NOT NULL, total_rows_sent INTEGER NOT NULL,
  amplification REAL NOT NULL, lock_ratio REAL NOT NULL, duration_share REAL NOT NULL,
  projected_ms_per_1k_calls REAL NOT NULL, cost_json TEXT NOT NULL,
  PRIMARY KEY (batch_id, cluster_id), FOREIGN KEY (batch_id) REFERENCES batches(batch_id)
);
CREATE TABLE IF NOT EXISTS plans (
  batch_id TEXT NOT NULL, plan_id TEXT NOT NULL, source_file TEXT NOT NULL,
  plan_format TEXT NOT NULL, fingerprint TEXT NOT NULL, linked_cluster_id TEXT NOT NULL,
  node_count INTEGER NOT NULL, error TEXT NOT NULL,
  PRIMARY KEY (batch_id, plan_id), FOREIGN KEY (batch_id) REFERENCES batches(batch_id)
);
CREATE TABLE IF NOT EXISTS plan_nodes (
  batch_id TEXT NOT NULL, plan_id TEXT NOT NULL, path TEXT NOT NULL,
  operation TEXT NOT NULL, depth INTEGER NOT NULL, table_name TEXT NOT NULL,
  access_type TEXT NOT NULL, rows INTEGER NOT NULL, key_name TEXT NOT NULL,
  condition TEXT NOT NULL, node_json TEXT NOT NULL,
  PRIMARY KEY (batch_id, plan_id, path),
  FOREIGN KEY (batch_id, plan_id) REFERENCES plans(batch_id, plan_id)
);
CREATE TABLE IF NOT EXISTS findings (
  batch_id TEXT NOT NULL, finding_id TEXT NOT NULL, category TEXT NOT NULL,
  severity TEXT NOT NULL, cluster_id TEXT NOT NULL, query_id TEXT NOT NULL,
  rule_id TEXT NOT NULL, plan_file TEXT NOT NULL, node_path TEXT NOT NULL,
  title TEXT NOT NULL, description TEXT NOT NULL, evidence_json TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  PRIMARY KEY (batch_id, finding_id), FOREIGN KEY (batch_id) REFERENCES batches(batch_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(batch_id, rule_id);
CREATE TABLE IF NOT EXISTS unparsed_lines (
  batch_id TEXT NOT NULL, file_path TEXT NOT NULL, line_no INTEGER NOT NULL,
  text TEXT NOT NULL, reason TEXT NOT NULL,
  PRIMARY KEY (batch_id, file_path, line_no, reason),
  FOREIGN KEY (batch_id) REFERENCES batches(batch_id)
);
CREATE TABLE IF NOT EXISTS baselines (
  name TEXT PRIMARY KEY, batch_id TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS parse_cache (
  cache_key TEXT PRIMARY KEY, display_path TEXT NOT NULL, sha256 TEXT NOT NULL,
  payload_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS comparisons (
  comparison_id TEXT PRIMARY KEY, base_batch_id TEXT NOT NULL,
  head_batch_id TEXT NOT NULL, created_at TEXT NOT NULL, summary_json TEXT NOT NULL
);
"""
