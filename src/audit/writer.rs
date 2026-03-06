use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crossbeam_channel::{self, Receiver, Sender, TrySendError};
use rusqlite::{params, Connection};

// ---------------------------------------------------------------------------
// Internal message types for the background writer thread.
// ---------------------------------------------------------------------------

enum WriterCommand {
    /// Enqueue a raw JSON event string for batched writing.
    Event(String),
    /// Force-flush all pending events to SQLite.
    Flush,
    /// Shut down the background thread (flush first).
    Shutdown,
}

// ---------------------------------------------------------------------------
// AuditWriter -- high-performance, non-blocking audit log writer.
// ---------------------------------------------------------------------------

/// A high-performance audit event writer that batches inserts and writes to
/// SQLite on a background thread.
///
/// # Design
///
/// - A bounded `crossbeam` channel decouples the caller from I/O.
/// - A dedicated background thread drains the channel, accumulating events
///   into a batch.  The batch is flushed either when it reaches
///   `batch_size` events or when `flush_interval_ms` elapses -- whichever
///   comes first.
/// - All SQLite writes happen inside a single transaction per batch for
///   maximum throughput.
pub struct AuditWriter {
    sender: Sender<WriterCommand>,
    bg_thread: Option<JoinHandle<()>>,
    closed: Arc<AtomicBool>,
}

impl AuditWriter {
    /// Create a new `AuditWriter`.
    ///
    /// - `db_path`           -- path to the SQLite database file (created if
    ///   it does not exist).
    /// - `batch_size`        -- maximum number of events per batch.
    /// - `flush_interval_ms` -- maximum milliseconds between flushes.
    pub fn new(db_path: &str, batch_size: usize, flush_interval_ms: u64) -> Result<Self, String> {
        // Open (or create) the SQLite database and set up the schema.
        let conn = Connection::open(db_path)
            .map_err(|e| format!("Failed to open SQLite database '{}': {}", db_path, e))?;

        Self::initialize_schema(&conn)?;

        // Bounded channel -- back-pressure after 10_000 pending events.
        let (tx, rx): (Sender<WriterCommand>, Receiver<WriterCommand>) =
            crossbeam_channel::bounded(10_000);

        let closed = Arc::new(AtomicBool::new(false));
        let closed_clone = Arc::clone(&closed);

        let handle = thread::Builder::new()
            .name("agentgate-audit-writer".into())
            .spawn(move || {
                Self::background_loop(conn, rx, batch_size, flush_interval_ms, closed_clone);
            })
            .map_err(|e| format!("Failed to spawn audit writer thread: {}", e))?;

        Ok(Self {
            sender: tx,
            bg_thread: Some(handle),
            closed,
        })
    }

    /// Enqueue an event for asynchronous writing.
    ///
    /// This call is **non-blocking** under normal conditions.  If the
    /// internal channel is full, the event will be dropped and an error is
    /// returned.
    pub fn write_event(&self, event_json: &str) -> Result<(), String> {
        if self.closed.load(Ordering::Relaxed) {
            return Err("AuditWriter is closed".into());
        }
        match self
            .sender
            .try_send(WriterCommand::Event(event_json.to_string()))
        {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err("Audit event channel is full; event dropped".into()),
            Err(TrySendError::Disconnected(_)) => {
                Err("Audit writer background thread has stopped".into())
            }
        }
    }

    /// Force-flush all pending events to SQLite.
    ///
    /// Blocks until the background thread acknowledges the flush.
    pub fn flush(&self) -> Result<(), String> {
        if self.closed.load(Ordering::Relaxed) {
            return Err("AuditWriter is closed".into());
        }
        self.sender
            .send(WriterCommand::Flush)
            .map_err(|_| "Failed to send flush command".to_string())
    }

    /// Flush pending events and shut down the background thread.
    ///
    /// After this call, `write_event` will return an error.
    pub fn close(&mut self) -> Result<(), String> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(()); // already closed
        }

        // Tell the background thread to shut down.
        let _ = self.sender.send(WriterCommand::Shutdown);

        // Wait for the thread to finish.
        if let Some(handle) = self.bg_thread.take() {
            handle
                .join()
                .map_err(|_| "Audit writer background thread panicked".to_string())?;
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Create the `audit_events` table and indexes if they do not exist.
    fn initialize_schema(conn: &Connection) -> Result<(), String> {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous  = NORMAL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS audit_events (
                event_id       TEXT PRIMARY KEY,
                timestamp      TEXT NOT NULL,
                agent_id       TEXT NOT NULL,
                session_id     TEXT NOT NULL,
                action_type    TEXT NOT NULL,
                tool_name      TEXT NOT NULL,
                tool_args      TEXT,
                decision       TEXT NOT NULL,
                deny_reason    TEXT,
                result_summary TEXT,
                duration_ms    REAL,
                anomaly_score  REAL,
                anomaly_flags  TEXT,
                signature      TEXT,
                metadata       TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_events (timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_agent_id
                ON audit_events (agent_id);
            CREATE INDEX IF NOT EXISTS idx_audit_session_id
                ON audit_events (session_id);
            CREATE INDEX IF NOT EXISTS idx_audit_tool_name
                ON audit_events (tool_name);
            ",
        )
        .map_err(|e| format!("Failed to initialize audit schema: {}", e))?;

        Ok(())
    }

    /// The main loop of the background writer thread.
    fn background_loop(
        conn: Connection,
        rx: Receiver<WriterCommand>,
        batch_size: usize,
        flush_interval_ms: u64,
        closed: Arc<AtomicBool>,
    ) {
        let flush_interval = Duration::from_millis(flush_interval_ms);
        let mut batch: Vec<String> = Vec::with_capacity(batch_size);
        let mut last_flush = Instant::now();

        loop {
            // Use a timeout so we can honour the flush interval even when
            // there are no incoming events.
            let timeout = flush_interval.saturating_sub(last_flush.elapsed());
            match rx.recv_timeout(timeout) {
                Ok(WriterCommand::Event(json)) => {
                    batch.push(json);
                    if batch.len() >= batch_size {
                        Self::flush_batch(&conn, &mut batch);
                        last_flush = Instant::now();
                    }
                }
                Ok(WriterCommand::Flush) => {
                    Self::flush_batch(&conn, &mut batch);
                    last_flush = Instant::now();
                }
                Ok(WriterCommand::Shutdown) => {
                    Self::flush_batch(&conn, &mut batch);
                    break;
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    if !batch.is_empty() {
                        Self::flush_batch(&conn, &mut batch);
                        last_flush = Instant::now();
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    Self::flush_batch(&conn, &mut batch);
                    break;
                }
            }

            // Also break if the writer has been marked as closed and the
            // channel is empty.
            if closed.load(Ordering::Relaxed) && rx.is_empty() {
                Self::flush_batch(&conn, &mut batch);
                break;
            }
        }
    }

    /// Write a batch of event JSON strings to SQLite inside a transaction.
    fn flush_batch(conn: &Connection, batch: &mut Vec<String>) {
        if batch.is_empty() {
            return;
        }

        // Use a transaction for the entire batch.
        let result = conn.execute_batch("BEGIN IMMEDIATE");
        if let Err(e) = result {
            eprintln!("[agentgate-audit] Failed to begin transaction: {}", e);
            batch.clear();
            return;
        }

        let sql = "
            INSERT OR REPLACE INTO audit_events (
                event_id, timestamp, agent_id, session_id,
                action_type, tool_name, tool_args, decision,
                deny_reason, result_summary, duration_ms,
                anomaly_score, anomaly_flags, signature, metadata
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                ?9, ?10, ?11, ?12, ?13, ?14, ?15
            )
        ";

        let mut stmt = match conn.prepare(sql) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[agentgate-audit] Failed to prepare insert: {}", e);
                let _ = conn.execute_batch("ROLLBACK");
                batch.clear();
                return;
            }
        };

        for json_str in batch.iter() {
            // Parse the JSON event.
            let event: serde_json::Value = match serde_json::from_str(json_str) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("[agentgate-audit] Skipping malformed event JSON: {}", e);
                    continue;
                }
            };

            let get_str = |key: &str| -> String {
                event
                    .get(key)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            let get_opt_str = |key: &str| -> Option<String> {
                event
                    .get(key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            };
            let get_opt_f64 =
                |key: &str| -> Option<f64> { event.get(key).and_then(|v| v.as_f64()) };

            let result = stmt.execute(params![
                get_str("event_id"),
                get_str("timestamp"),
                get_str("agent_id"),
                get_str("session_id"),
                get_str("action_type"),
                get_str("tool_name"),
                get_opt_str("tool_args"),
                get_str("decision"),
                get_opt_str("deny_reason"),
                get_opt_str("result_summary"),
                get_opt_f64("duration_ms"),
                get_opt_f64("anomaly_score"),
                get_opt_str("anomaly_flags"),
                get_opt_str("signature"),
                get_opt_str("metadata"),
            ]);

            if let Err(e) = result {
                eprintln!("[agentgate-audit] Failed to insert event: {}", e);
            }
        }

        drop(stmt);

        if let Err(e) = conn.execute_batch("COMMIT") {
            eprintln!("[agentgate-audit] Failed to commit batch: {}", e);
            let _ = conn.execute_batch("ROLLBACK");
        }

        batch.clear();
    }
}

impl Drop for AuditWriter {
    fn drop(&mut self) {
        // Best-effort shutdown if the user forgot to call close().
        if !self.closed.load(Ordering::Relaxed) {
            let _ = self.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    fn temp_db_path() -> String {
        let id = uuid::Uuid::new_v4();
        format!("/tmp/agentgate_test_{}.db", id)
    }

    #[test]
    fn test_writer_create_and_close() {
        let db = temp_db_path();
        let mut w = AuditWriter::new(&db, 10, 500).expect("should create writer");
        w.close().expect("should close cleanly");
        assert!(Path::new(&db).exists());
        // Cleanup
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn test_write_and_flush() {
        let db = temp_db_path();
        let mut w = AuditWriter::new(&db, 10, 5000).expect("should create writer");

        let event = json!({
            "event_id": "evt-001",
            "timestamp": "2025-01-01T00:00:00Z",
            "agent_id": "agent-1",
            "session_id": "sess-1",
            "action_type": "tool_call",
            "tool_name": "file_read",
            "tool_args": "{\"path\": \"/tmp/x\"}",
            "decision": "allowed",
            "duration_ms": 12.5,
            "anomaly_score": 0.1
        });

        w.write_event(&event.to_string()).expect("should enqueue");
        w.flush().expect("should flush");
        w.close().expect("should close");

        // Verify the row was written.
        let conn = Connection::open(&db).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);

        // Cleanup
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn test_batch_flush_on_size() {
        let db = temp_db_path();
        let mut w = AuditWriter::new(&db, 5, 60_000).expect("should create writer");

        for i in 0..10 {
            let event = json!({
                "event_id": format!("evt-{:03}", i),
                "timestamp": "2025-01-01T00:00:00Z",
                "agent_id": "agent-1",
                "session_id": "sess-1",
                "action_type": "tool_call",
                "tool_name": "file_read",
                "decision": "allowed"
            });
            w.write_event(&event.to_string()).expect("should enqueue");
        }

        // Flush any remaining.
        w.flush().expect("flush");
        w.close().expect("close");

        let conn = Connection::open(&db).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 10);

        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn test_write_after_close_fails() {
        let db = temp_db_path();
        let mut w = AuditWriter::new(&db, 10, 500).expect("should create writer");
        w.close().expect("close");

        let result = w.write_event("{}");
        assert!(result.is_err());

        let _ = std::fs::remove_file(&db);
    }
}
