use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, params};

use crate::{alert::AlertEvent, routing::Delivery};

#[derive(Debug, Clone)]
pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

impl Storage {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        if path != ":memory:"
            && let Some(parent) = Path::new(path).parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let storage = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        storage.migrate()?;
        Ok(storage)
    }

    fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS alert_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                integration TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                raw_payload TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS delivery_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_event_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                next_retry_at INTEGER,
                last_error TEXT,
                request_summary TEXT NOT NULL,
                response_summary TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(alert_event_id) REFERENCES alert_events(id)
            );
            "#,
        )?;
        Ok(())
    }

    pub fn store_event(&self, event: &AlertEvent) -> anyhow::Result<i64> {
        let raw_payload = serde_json::to_string(&event.raw_payload)?;
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            INSERT INTO alert_events (
                event_id, integration, source, status, severity, title,
                fingerprint, raw_payload, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            params![
                event.event_id,
                event.integration,
                event.source,
                event.status,
                event.severity,
                event.title,
                event.fingerprint,
                raw_payload,
                now,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn queue_delivery(&self, alert_event_id: i64, delivery: &Delivery) -> anyhow::Result<i64> {
        let now = now_epoch_millis();
        let request_summary = serde_json::json!({
            "route": delivery.route_name,
            "receiver": delivery.receiver,
        })
        .to_string();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            INSERT INTO delivery_records (
                alert_event_id, target, status, attempt_count, next_retry_at,
                last_error, request_summary, response_summary, created_at, updated_at
            )
            VALUES (?1, ?2, 'queued', 0, ?3, NULL, ?4, NULL, ?3, ?3)
            "#,
            params![alert_event_id, delivery.receiver, now, request_summary],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn mark_attempt(&self, delivery_id: i64, attempt: u32) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            UPDATE delivery_records
            SET status = 'delivering',
                attempt_count = ?2,
                next_retry_at = NULL,
                updated_at = ?3
            WHERE id = ?1
            "#,
            params![delivery_id, attempt, now],
        )?;
        Ok(())
    }

    pub fn mark_succeeded(&self, delivery_id: i64, response_summary: &str) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            UPDATE delivery_records
            SET status = 'succeeded',
                next_retry_at = NULL,
                last_error = NULL,
                response_summary = ?2,
                updated_at = ?3
            WHERE id = ?1
            "#,
            params![delivery_id, response_summary, now],
        )?;
        Ok(())
    }

    pub fn mark_retrying(
        &self,
        delivery_id: i64,
        next_retry_at: i64,
        error: &str,
    ) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            UPDATE delivery_records
            SET status = 'retrying',
                next_retry_at = ?2,
                last_error = ?3,
                updated_at = ?4
            WHERE id = ?1
            "#,
            params![delivery_id, next_retry_at, error, now],
        )?;
        Ok(())
    }

    pub fn mark_dead_letter(&self, delivery_id: i64, error: &str) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            UPDATE delivery_records
            SET status = 'dead_letter',
                next_retry_at = NULL,
                last_error = ?2,
                updated_at = ?3
            WHERE id = ?1
            "#,
            params![delivery_id, error, now],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn delivery_statuses(&self) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT status FROM delivery_records ORDER BY id")?;
        let statuses = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(statuses)
    }

    #[cfg(test)]
    pub fn delivery_attempts(&self) -> anyhow::Result<Vec<u32>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT attempt_count FROM delivery_records ORDER BY id")?;
        let attempts = stmt
            .query_map([], |row| row.get::<_, u32>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(attempts)
    }

    #[cfg(test)]
    pub fn event_count(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count = conn.query_row("SELECT COUNT(*) FROM alert_events", [], |row| {
            row.get::<_, usize>(0)
        })?;
        Ok(count)
    }
}

pub fn now_epoch_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
