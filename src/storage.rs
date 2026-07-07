use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{Connection, params};
use serde::Serialize;

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
                alert_group_id INTEGER,
                event_id TEXT NOT NULL,
                integration TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                raw_payload TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(alert_group_id) REFERENCES alert_groups(id)
            );

            CREATE TABLE IF NOT EXISTS alert_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                integration TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                acknowledged_at INTEGER,
                silenced_until INTEGER,
                first_event_at INTEGER NOT NULL,
                last_event_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
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

            CREATE TABLE IF NOT EXISTS audit_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_group_id INTEGER,
                delivery_record_id INTEGER,
                action TEXT NOT NULL,
                detail TEXT,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(alert_group_id) REFERENCES alert_groups(id),
                FOREIGN KEY(delivery_record_id) REFERENCES delivery_records(id)
            );
            "#,
        )?;
        add_column_if_missing(&conn, "alert_events", "alert_group_id INTEGER")?;
        Ok(())
    }

    pub fn store_event(&self, event: &AlertEvent) -> anyhow::Result<i64> {
        let raw_payload = serde_json::to_string(&event.raw_payload)?;
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        let alert_group_id = upsert_alert_group(&conn, event, now)?;
        conn.execute(
            r#"
            INSERT INTO alert_events (
                alert_group_id, event_id, integration, source, status, severity, title,
                fingerprint, raw_payload, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                alert_group_id,
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

    pub fn list_alert_groups(&self) -> anyhow::Result<Vec<AlertGroupRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT id, fingerprint, integration, source, status, severity, title,
                   event_count, acknowledged_at, silenced_until,
                   first_event_at, last_event_at, updated_at
            FROM alert_groups
            ORDER BY last_event_at DESC, id DESC
            "#,
        )?;
        let records = stmt
            .query_map([], alert_group_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    pub fn list_alert_events(&self) -> anyhow::Result<Vec<AlertEventRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT id, alert_group_id, event_id, integration, source, status,
                   severity, title, fingerprint, created_at
            FROM alert_events
            ORDER BY created_at DESC, id DESC
            LIMIT 500
            "#,
        )?;
        let records = stmt
            .query_map([], alert_event_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    pub fn list_deliveries(&self) -> anyhow::Result<Vec<DeliveryRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT id, alert_event_id, target, status, attempt_count, next_retry_at,
                   last_error, request_summary, response_summary, created_at, updated_at
            FROM delivery_records
            ORDER BY updated_at DESC, id DESC
            LIMIT 500
            "#,
        )?;
        let records = stmt
            .query_map([], delivery_record_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    pub fn acknowledge_group(&self, alert_group_id: i64) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        update_group_exists(&conn, alert_group_id)?;
        conn.execute(
            "UPDATE alert_groups SET acknowledged_at = ?2, updated_at = ?2 WHERE id = ?1",
            params![alert_group_id, now],
        )?;
        insert_audit(&conn, Some(alert_group_id), None, "acknowledge", None, now)?;
        Ok(())
    }

    pub fn resolve_group(&self, alert_group_id: i64) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        update_group_exists(&conn, alert_group_id)?;
        conn.execute(
            "UPDATE alert_groups SET status = 'resolved', updated_at = ?2 WHERE id = ?1",
            params![alert_group_id, now],
        )?;
        insert_audit(&conn, Some(alert_group_id), None, "resolve", None, now)?;
        Ok(())
    }

    pub fn silence_group(&self, alert_group_id: i64) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let silenced_until = now + 60 * 60 * 1000;
        let conn = self.conn.lock().unwrap();
        update_group_exists(&conn, alert_group_id)?;
        conn.execute(
            "UPDATE alert_groups SET silenced_until = ?2, updated_at = ?3 WHERE id = ?1",
            params![alert_group_id, silenced_until, now],
        )?;
        insert_audit(
            &conn,
            Some(alert_group_id),
            None,
            "silence",
            Some("duration_millis=3600000"),
            now,
        )?;
        Ok(())
    }

    pub fn replay_delivery(&self, delivery_id: i64) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        update_delivery_exists(&conn, delivery_id)?;
        conn.execute(
            r#"
            UPDATE delivery_records
            SET status = 'queued',
                next_retry_at = ?2,
                last_error = NULL,
                updated_at = ?2
            WHERE id = ?1
            "#,
            params![delivery_id, now],
        )?;
        insert_audit(&conn, None, Some(delivery_id), "replay", None, now)?;
        Ok(())
    }

    #[cfg(test)]
    pub fn audit_actions(&self) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT action FROM audit_entries ORDER BY id")?;
        let actions = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(actions)
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

#[derive(Debug, Clone, Serialize)]
pub struct AlertGroupRecord {
    pub id: i64,
    pub fingerprint: String,
    pub integration: String,
    pub source: String,
    pub status: String,
    pub severity: String,
    pub title: String,
    pub event_count: u32,
    pub acknowledged_at: Option<i64>,
    pub silenced_until: Option<i64>,
    pub first_event_at: i64,
    pub last_event_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertEventRecord {
    pub id: i64,
    pub alert_group_id: Option<i64>,
    pub event_id: String,
    pub integration: String,
    pub source: String,
    pub status: String,
    pub severity: String,
    pub title: String,
    pub fingerprint: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeliveryRecord {
    pub id: i64,
    pub alert_event_id: i64,
    pub target: String,
    pub status: String,
    pub attempt_count: u32,
    pub next_retry_at: Option<i64>,
    pub last_error: Option<String>,
    pub request_summary: String,
    pub response_summary: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

fn upsert_alert_group(conn: &Connection, event: &AlertEvent, now: i64) -> anyhow::Result<i64> {
    let existing = conn
        .query_row(
            "SELECT id FROM alert_groups WHERE fingerprint = ?1",
            params![event.fingerprint],
            |row| row.get::<_, i64>(0),
        )
        .ok();

    let group_status = if event.status.eq_ignore_ascii_case("resolved") {
        "resolved"
    } else {
        "active"
    };

    if let Some(id) = existing {
        conn.execute(
            r#"
            UPDATE alert_groups
            SET status = ?2,
                severity = ?3,
                title = ?4,
                event_count = event_count + 1,
                last_event_at = ?5,
                updated_at = ?5
            WHERE id = ?1
            "#,
            params![id, group_status, event.severity, event.title, now],
        )?;
        return Ok(id);
    }

    conn.execute(
        r#"
        INSERT INTO alert_groups (
            fingerprint, integration, source, status, severity, title,
            event_count, acknowledged_at, silenced_until,
            first_event_at, last_event_at, updated_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, NULL, NULL, ?7, ?7, ?7)
        "#,
        params![
            event.fingerprint,
            event.integration,
            event.source,
            group_status,
            event.severity,
            event.title,
            now,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn alert_group_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertGroupRecord> {
    Ok(AlertGroupRecord {
        id: row.get(0)?,
        fingerprint: row.get(1)?,
        integration: row.get(2)?,
        source: row.get(3)?,
        status: row.get(4)?,
        severity: row.get(5)?,
        title: row.get(6)?,
        event_count: row.get(7)?,
        acknowledged_at: row.get(8)?,
        silenced_until: row.get(9)?,
        first_event_at: row.get(10)?,
        last_event_at: row.get(11)?,
        updated_at: row.get(12)?,
    })
}

fn alert_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertEventRecord> {
    Ok(AlertEventRecord {
        id: row.get(0)?,
        alert_group_id: row.get(1)?,
        event_id: row.get(2)?,
        integration: row.get(3)?,
        source: row.get(4)?,
        status: row.get(5)?,
        severity: row.get(6)?,
        title: row.get(7)?,
        fingerprint: row.get(8)?,
        created_at: row.get(9)?,
    })
}

fn delivery_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeliveryRecord> {
    Ok(DeliveryRecord {
        id: row.get(0)?,
        alert_event_id: row.get(1)?,
        target: row.get(2)?,
        status: row.get(3)?,
        attempt_count: row.get(4)?,
        next_retry_at: row.get(5)?,
        last_error: row.get(6)?,
        request_summary: row.get(7)?,
        response_summary: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn add_column_if_missing(conn: &Connection, table: &str, column_sql: &str) -> anyhow::Result<()> {
    let column_name = column_sql.split_whitespace().next().unwrap_or_default();
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let exists = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .any(|name| name == column_name);

    if !exists {
        conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column_sql}"), [])?;
    }

    Ok(())
}

fn update_group_exists(conn: &Connection, alert_group_id: i64) -> anyhow::Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM alert_groups WHERE id = ?1)",
        params![alert_group_id],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        anyhow::bail!("alert group {alert_group_id} not found")
    }
}

fn update_delivery_exists(conn: &Connection, delivery_id: i64) -> anyhow::Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM delivery_records WHERE id = ?1)",
        params![delivery_id],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        anyhow::bail!("delivery {delivery_id} not found")
    }
}

fn insert_audit(
    conn: &Connection,
    alert_group_id: Option<i64>,
    delivery_record_id: Option<i64>,
    action: &str,
    detail: Option<&str>,
    now: i64,
) -> anyhow::Result<()> {
    conn.execute(
        r#"
        INSERT INTO audit_entries (
            alert_group_id, delivery_record_id, action, detail, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![alert_group_id, delivery_record_id, action, detail, now],
    )?;
    Ok(())
}
