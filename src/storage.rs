use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

use crate::{alert::AlertEvent, routing::Delivery};

#[derive(Debug, Clone)]
pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisableUserOutcome {
    Disabled,
    LastActiveAdmin,
}

impl Storage {
    pub fn open(path: &str) -> anyhow::Result<Self> {
        if path != ":memory:"
            && let Some(parent) = Path::new(path).parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create sqlite database directory {}",
                    parent.display()
                )
            })?;
        }

        let conn = Connection::open(path).with_context(|| {
            format!(
                "failed to open sqlite database at {path}; for containers, set storage.path under the mounted data directory such as /var/lib/simple-alert-proxy/data/simple-alert-proxy.db"
            )
        })?;
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

            CREATE TABLE IF NOT EXISTS escalation_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_group_id INTEGER NOT NULL,
                policy TEXT NOT NULL,
                step_index INTEGER NOT NULL,
                status TEXT NOT NULL,
                due_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(alert_group_id) REFERENCES alert_groups(id)
            );

            CREATE TABLE IF NOT EXISTS advisory_enrichments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_group_id INTEGER,
                provider TEXT NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(alert_group_id) REFERENCES alert_groups(id)
            );

            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                global_role TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_login_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS teams (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS team_memberships (
                user_id INTEGER NOT NULL,
                team_id INTEGER NOT NULL,
                team_role TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(user_id, team_id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(team_id) REFERENCES teams(id)
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            "#,
        )?;
        add_column_if_missing(&conn, "alert_events", "alert_group_id INTEGER")?;
        add_column_if_missing(&conn, "audit_entries", "actor_user_id INTEGER")?;
        add_column_if_missing(&conn, "audit_entries", "actor_display_name TEXT")?;
        add_column_if_missing(&conn, "audit_entries", "actor_team_id INTEGER")?;
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

    pub fn queue_escalation(
        &self,
        alert_event_id: i64,
        policy: &str,
        delay_millis: u64,
    ) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let due_at = now + delay_millis as i64;
        let conn = self.conn.lock().unwrap();
        let (alert_group_id, group_status): (i64, String) = conn.query_row(
            r#"
            SELECT alert_group_id, alert_groups.status
            FROM alert_events
            JOIN alert_groups ON alert_groups.id = alert_events.alert_group_id
            WHERE alert_events.id = ?1
            "#,
            params![alert_event_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        if group_status == "resolved" {
            return Ok(());
        }

        conn.execute(
            r#"
            INSERT INTO escalation_tasks (
                alert_group_id, policy, step_index, status, due_at, created_at, updated_at
            )
            VALUES (?1, ?2, 0, 'scheduled', ?3, ?4, ?4)
            "#,
            params![alert_group_id, policy, due_at, now],
        )?;
        Ok(())
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
                   severity, title, fingerprint, raw_payload, created_at
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

    #[cfg(test)]
    pub fn acknowledge_group(&self, alert_group_id: i64) -> anyhow::Result<()> {
        self.acknowledge_group_as(alert_group_id, AuditActor::default())
    }

    pub fn acknowledge_group_as(
        &self,
        alert_group_id: i64,
        actor: AuditActor,
    ) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        update_group_exists(&conn, alert_group_id)?;
        conn.execute(
            "UPDATE alert_groups SET acknowledged_at = ?2, updated_at = ?2 WHERE id = ?1",
            params![alert_group_id, now],
        )?;
        cancel_escalations(&conn, alert_group_id, now)?;
        insert_audit(
            &conn,
            Some(alert_group_id),
            None,
            &actor,
            "acknowledge",
            None,
            now,
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn resolve_group(&self, alert_group_id: i64) -> anyhow::Result<()> {
        self.resolve_group_as(alert_group_id, AuditActor::default())
    }

    pub fn resolve_group_as(&self, alert_group_id: i64, actor: AuditActor) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        update_group_exists(&conn, alert_group_id)?;
        conn.execute(
            "UPDATE alert_groups SET status = 'resolved', updated_at = ?2 WHERE id = ?1",
            params![alert_group_id, now],
        )?;
        cancel_escalations(&conn, alert_group_id, now)?;
        insert_audit(
            &conn,
            Some(alert_group_id),
            None,
            &actor,
            "resolve",
            None,
            now,
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn silence_group(&self, alert_group_id: i64) -> anyhow::Result<()> {
        self.silence_group_as(alert_group_id, AuditActor::default())
    }

    pub fn silence_group_as(&self, alert_group_id: i64, actor: AuditActor) -> anyhow::Result<()> {
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
            &actor,
            "silence",
            Some("duration_millis=3600000"),
            now,
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn replay_delivery(&self, delivery_id: i64) -> anyhow::Result<()> {
        self.replay_delivery_as(delivery_id, AuditActor::default())
    }

    pub fn replay_delivery_as(&self, delivery_id: i64, actor: AuditActor) -> anyhow::Result<()> {
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
        insert_audit(&conn, None, Some(delivery_id), &actor, "replay", None, now)?;
        Ok(())
    }

    #[cfg(test)]
    pub fn add_advisory(
        &self,
        alert_group_id: Option<i64>,
        provider: &str,
        kind: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            INSERT INTO advisory_enrichments (
                alert_group_id, provider, kind, value, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![alert_group_id, provider, kind, value, now],
        )?;
        Ok(())
    }

    pub fn list_advisories(&self) -> anyhow::Result<Vec<AdvisoryRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT id, alert_group_id, provider, kind, value, created_at
            FROM advisory_enrichments
            ORDER BY created_at DESC, id DESC
            LIMIT 500
            "#,
        )?;
        let records = stmt
            .query_map([], advisory_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    pub fn user_count(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, i64>(0))?;
        usize::try_from(count).context("user count overflowed usize")
    }

    pub fn create_user(
        &self,
        username: &str,
        display_name: &str,
        password_hash: &str,
        global_role: &str,
    ) -> anyhow::Result<UserRecord> {
        let username = username.trim();
        let display_name = display_name.trim();
        if username.is_empty() {
            anyhow::bail!("username must not be empty");
        }
        if display_name.is_empty() {
            anyhow::bail!("display_name must not be empty");
        }
        validate_global_role(global_role)?;

        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            INSERT INTO users (
                username, display_name, password_hash, global_role, status,
                created_at, updated_at, last_login_at
            )
            VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?5, NULL)
            "#,
            params![username, display_name, password_hash, global_role, now],
        )?;
        user_by_id(&conn, conn.last_insert_rowid())
    }

    pub fn list_users(&self) -> anyhow::Result<Vec<UserRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT id, username, display_name, global_role, status,
                   created_at, updated_at, last_login_at
            FROM users
            ORDER BY username
            "#,
        )?;
        let records = stmt
            .query_map([], user_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    pub fn authenticate_user(
        &self,
        username: &str,
    ) -> anyhow::Result<Option<UserCredentialRecord>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            r#"
            SELECT id, username, display_name, password_hash, global_role, status,
                   created_at, updated_at, last_login_at
            FROM users
            WHERE username = ?1
            "#,
            params![username.trim()],
            user_credential_from_row,
        )
        .optional()
        .map_err(Into::into)
    }

    pub fn update_last_login(&self, user_id: i64) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE users SET last_login_at = ?2, updated_at = ?2 WHERE id = ?1",
            params![user_id, now],
        )?;
        Ok(())
    }

    pub fn update_user_password(
        &self,
        user_id: i64,
        password_hash: &str,
        actor: AuditActor,
    ) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        update_user_exists(&conn, user_id)?;
        conn.execute(
            "UPDATE users SET password_hash = ?2, updated_at = ?3 WHERE id = ?1",
            params![user_id, password_hash, now],
        )?;
        conn.execute(
            "DELETE FROM auth_sessions WHERE user_id = ?1",
            params![user_id],
        )?;
        insert_audit(
            &conn,
            None,
            None,
            &actor,
            "change_password",
            Some(&format!("changed_user_id={user_id}")),
            now,
        )?;
        Ok(())
    }

    pub fn disable_user(
        &self,
        user_id: i64,
        actor: AuditActor,
    ) -> anyhow::Result<DisableUserOutcome> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        update_user_exists(&conn, user_id)?;
        if is_active_admin(&conn, user_id)? && active_admin_count(&conn)? <= 1 {
            return Ok(DisableUserOutcome::LastActiveAdmin);
        }
        conn.execute(
            "UPDATE users SET status = 'disabled', updated_at = ?2 WHERE id = ?1",
            params![user_id, now],
        )?;
        conn.execute(
            "DELETE FROM auth_sessions WHERE user_id = ?1",
            params![user_id],
        )?;
        insert_audit(
            &conn,
            None,
            None,
            &actor,
            "disable_user",
            Some(&format!("disabled_user_id={user_id}")),
            now,
        )?;
        Ok(DisableUserOutcome::Disabled)
    }

    pub fn create_session(
        &self,
        token_hash: &str,
        user_id: i64,
        csrf_token: &str,
        expires_at: i64,
    ) -> anyhow::Result<()> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            INSERT INTO auth_sessions (
                token_hash, user_id, csrf_token, expires_at, created_at, last_seen_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?5)
            "#,
            params![token_hash, user_id, csrf_token, expires_at, now],
        )?;
        Ok(())
    }

    pub fn delete_expired_sessions(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let deleted = conn.execute(
            "DELETE FROM auth_sessions WHERE expires_at <= ?1",
            params![now_epoch_millis()],
        )?;
        Ok(deleted)
    }

    pub fn session_user(&self, token_hash: &str) -> anyhow::Result<Option<SessionUserRecord>> {
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        let record = conn
            .query_row(
                r#"
                SELECT users.id, users.username, users.display_name, users.global_role,
                       users.status, auth_sessions.csrf_token, auth_sessions.expires_at
                FROM auth_sessions
                JOIN users ON users.id = auth_sessions.user_id
                WHERE auth_sessions.token_hash = ?1
                "#,
                params![token_hash],
                session_user_from_row,
            )
            .optional()?;

        let Some(record) = record else {
            return Ok(None);
        };

        if record.expires_at <= now || record.status != "active" {
            conn.execute(
                "DELETE FROM auth_sessions WHERE token_hash = ?1",
                params![token_hash],
            )?;
            return Ok(None);
        }

        conn.execute(
            "UPDATE auth_sessions SET last_seen_at = ?2 WHERE token_hash = ?1",
            params![token_hash, now],
        )?;
        Ok(Some(record))
    }

    pub fn delete_session(&self, token_hash: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM auth_sessions WHERE token_hash = ?1",
            params![token_hash],
        )?;
        Ok(())
    }

    pub fn create_team(&self, name: &str, description: &str) -> anyhow::Result<TeamRecord> {
        let name = name.trim();
        if name.is_empty() {
            anyhow::bail!("team name must not be empty");
        }
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"
            INSERT INTO teams (name, description, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?3)
            "#,
            params![name, description.trim(), now],
        )?;
        team_by_id(&conn, conn.last_insert_rowid())
    }

    pub fn list_teams(&self) -> anyhow::Result<Vec<TeamRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT id, name, description, created_at, updated_at
            FROM teams
            ORDER BY name
            "#,
        )?;
        let records = stmt
            .query_map([], team_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    pub fn list_team_memberships(&self) -> anyhow::Result<Vec<TeamMembershipRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"
            SELECT team_memberships.user_id, users.username,
                   team_memberships.team_id, teams.name,
                   team_memberships.team_role, team_memberships.created_at
            FROM team_memberships
            JOIN users ON users.id = team_memberships.user_id
            JOIN teams ON teams.id = team_memberships.team_id
            ORDER BY teams.name, users.username
            "#,
        )?;
        let records = stmt
            .query_map([], team_membership_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    pub fn set_team_membership(
        &self,
        team_id: i64,
        user_id: i64,
        team_role: &str,
    ) -> anyhow::Result<TeamMembershipRecord> {
        validate_team_role(team_role)?;
        let now = now_epoch_millis();
        let conn = self.conn.lock().unwrap();
        update_team_exists(&conn, team_id)?;
        update_user_exists(&conn, user_id)?;
        conn.execute(
            r#"
            INSERT INTO team_memberships (user_id, team_id, team_role, created_at)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(user_id, team_id) DO UPDATE SET team_role = excluded.team_role
            "#,
            params![user_id, team_id, team_role, now],
        )?;
        conn.query_row(
            r#"
            SELECT team_memberships.user_id, users.username,
                   team_memberships.team_id, teams.name,
                   team_memberships.team_role, team_memberships.created_at
            FROM team_memberships
            JOIN users ON users.id = team_memberships.user_id
            JOIN teams ON teams.id = team_memberships.team_id
            WHERE team_memberships.user_id = ?1 AND team_memberships.team_id = ?2
            "#,
            params![user_id, team_id],
            team_membership_from_row,
        )
        .map_err(Into::into)
    }

    pub fn remove_team_membership(&self, team_id: i64, user_id: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM team_memberships WHERE user_id = ?1 AND team_id = ?2",
            params![user_id, team_id],
        )?;
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
    pub fn audit_actor_user_ids(&self) -> anyhow::Result<Vec<Option<i64>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT actor_user_id FROM audit_entries ORDER BY id")?;
        let actors = stmt
            .query_map([], |row| row.get::<_, Option<i64>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(actors)
    }

    #[cfg(test)]
    pub fn session_count(&self) -> anyhow::Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count = conn.query_row("SELECT COUNT(*) FROM auth_sessions", [], |row| {
            row.get::<_, i64>(0)
        })?;
        usize::try_from(count).context("session count overflowed usize")
    }

    #[cfg(test)]
    pub fn escalation_statuses(&self) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT status FROM escalation_tasks ORDER BY id")?;
        let statuses = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(statuses)
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
            row.get::<_, i64>(0)
        })?;
        usize::try_from(count).context("alert event count overflowed usize")
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
    pub raw_payload: serde_json::Value,
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

#[derive(Debug, Clone, Serialize)]
pub struct AdvisoryRecord {
    pub id: i64,
    pub alert_group_id: Option<i64>,
    pub provider: String,
    pub kind: String,
    pub value: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserRecord {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub global_role: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct UserCredentialRecord {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub password_hash: String,
    pub global_role: String,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login_at: Option<i64>,
}

impl UserCredentialRecord {
    pub fn public_record(&self) -> UserRecord {
        UserRecord {
            id: self.id,
            username: self.username.clone(),
            display_name: self.display_name.clone(),
            global_role: self.global_role.clone(),
            status: self.status.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionUserRecord {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub global_role: String,
    pub status: String,
    pub csrf_token: String,
    pub expires_at: i64,
}

impl SessionUserRecord {
    pub fn public_record(&self) -> UserRecord {
        UserRecord {
            id: self.id,
            username: self.username.clone(),
            display_name: self.display_name.clone(),
            global_role: self.global_role.clone(),
            status: self.status.clone(),
            created_at: 0,
            updated_at: 0,
            last_login_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TeamRecord {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TeamMembershipRecord {
    pub user_id: i64,
    pub username: String,
    pub team_id: i64,
    pub team_name: String,
    pub team_role: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct AuditActor {
    pub user_id: Option<i64>,
    pub display_name: Option<String>,
    pub team_id: Option<i64>,
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
        raw_payload: serde_json::from_str(&row.get::<_, String>(9)?)
            .unwrap_or(serde_json::Value::Null),
        created_at: row.get(10)?,
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

fn advisory_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AdvisoryRecord> {
    Ok(AdvisoryRecord {
        id: row.get(0)?,
        alert_group_id: row.get(1)?,
        provider: row.get(2)?,
        kind: row.get(3)?,
        value: row.get(4)?,
        created_at: row.get(5)?,
    })
}

fn user_by_id(conn: &Connection, user_id: i64) -> anyhow::Result<UserRecord> {
    conn.query_row(
        r#"
        SELECT id, username, display_name, global_role, status,
               created_at, updated_at, last_login_at
        FROM users
        WHERE id = ?1
        "#,
        params![user_id],
        user_from_row,
    )
    .map_err(Into::into)
}

fn user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserRecord> {
    Ok(UserRecord {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        global_role: row.get(3)?,
        status: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        last_login_at: row.get(7)?,
    })
}

fn user_credential_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UserCredentialRecord> {
    Ok(UserCredentialRecord {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        password_hash: row.get(3)?,
        global_role: row.get(4)?,
        status: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
        last_login_at: row.get(8)?,
    })
}

fn session_user_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionUserRecord> {
    Ok(SessionUserRecord {
        id: row.get(0)?,
        username: row.get(1)?,
        display_name: row.get(2)?,
        global_role: row.get(3)?,
        status: row.get(4)?,
        csrf_token: row.get(5)?,
        expires_at: row.get(6)?,
    })
}

fn team_by_id(conn: &Connection, team_id: i64) -> anyhow::Result<TeamRecord> {
    conn.query_row(
        r#"
        SELECT id, name, description, created_at, updated_at
        FROM teams
        WHERE id = ?1
        "#,
        params![team_id],
        team_from_row,
    )
    .map_err(Into::into)
}

fn team_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TeamRecord> {
    Ok(TeamRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        created_at: row.get(3)?,
        updated_at: row.get(4)?,
    })
}

fn team_membership_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TeamMembershipRecord> {
    Ok(TeamMembershipRecord {
        user_id: row.get(0)?,
        username: row.get(1)?,
        team_id: row.get(2)?,
        team_name: row.get(3)?,
        team_role: row.get(4)?,
        created_at: row.get(5)?,
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

fn update_user_exists(conn: &Connection, user_id: i64) -> anyhow::Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1)",
        params![user_id],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        anyhow::bail!("user {user_id} not found")
    }
}

fn is_active_admin(conn: &Connection, user_id: i64) -> anyhow::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND status = 'active' AND global_role = 'admin')",
        params![user_id],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

fn active_admin_count(conn: &Connection) -> anyhow::Result<usize> {
    let count = conn.query_row(
        "SELECT COUNT(*) FROM users WHERE status = 'active' AND global_role = 'admin'",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    usize::try_from(count).context("active admin count overflowed usize")
}

fn update_team_exists(conn: &Connection, team_id: i64) -> anyhow::Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM teams WHERE id = ?1)",
        params![team_id],
        |row| row.get(0),
    )?;
    if exists {
        Ok(())
    } else {
        anyhow::bail!("team {team_id} not found")
    }
}

fn validate_global_role(role: &str) -> anyhow::Result<()> {
    match role {
        "admin" | "operator" | "viewer" => Ok(()),
        _ => anyhow::bail!("global_role must be admin, operator, or viewer"),
    }
}

fn validate_team_role(role: &str) -> anyhow::Result<()> {
    match role {
        "owner" | "operator" | "viewer" => Ok(()),
        _ => anyhow::bail!("team_role must be owner, operator, or viewer"),
    }
}

fn insert_audit(
    conn: &Connection,
    alert_group_id: Option<i64>,
    delivery_record_id: Option<i64>,
    actor: &AuditActor,
    action: &str,
    detail: Option<&str>,
    now: i64,
) -> anyhow::Result<()> {
    conn.execute(
        r#"
        INSERT INTO audit_entries (
            alert_group_id, delivery_record_id, actor_user_id, actor_display_name,
            actor_team_id, action, detail, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            alert_group_id,
            delivery_record_id,
            actor.user_id,
            actor.display_name.as_deref(),
            actor.team_id,
            action,
            detail,
            now
        ],
    )?;
    Ok(())
}

fn cancel_escalations(conn: &Connection, alert_group_id: i64, now: i64) -> anyhow::Result<()> {
    conn.execute(
        r#"
        UPDATE escalation_tasks
        SET status = 'canceled',
            updated_at = ?2
        WHERE alert_group_id = ?1
          AND status = 'scheduled'
        "#,
        params![alert_group_id, now],
    )?;
    Ok(())
}
