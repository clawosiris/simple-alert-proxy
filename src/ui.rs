pub const OPERATOR_UI: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Simple Alert Proxy</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --ink: #1d2430;
      --muted: #647084;
      --line: #d9dee7;
      --accent: #0f766e;
      --bad: #b42318;
      --warn: #b54708;
      --ok: #087443;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font: 14px/1.4 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background: var(--bg);
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 14px 20px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
      position: sticky;
      top: 0;
      z-index: 2;
    }
    h1 { margin: 0; font-size: 18px; font-weight: 700; }
    h2 { margin: 0; font-size: 15px; }
    h3 { margin: 0 0 8px; font-size: 14px; }
    button {
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--ink);
      border-radius: 6px;
      padding: 7px 10px;
      min-height: 34px;
      cursor: pointer;
      font-weight: 600;
    }
    button.primary { background: var(--accent); color: white; border-color: var(--accent); }
    input, select {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 7px 10px;
      min-height: 34px;
      min-width: 160px;
    }
    .toolbar, .actions, .row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .toolbar { justify-content: flex-end; }
    main {
      display: grid;
      grid-template-columns: minmax(320px, 1.05fr) minmax(360px, .95fr);
      gap: 16px;
      padding: 16px;
      max-width: 1440px;
      margin: 0 auto;
    }
    section {
      min-width: 0;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }
    .section-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--line);
    }
    .section-body { padding: 14px; display: grid; gap: 12px; }
    .table-wrap { overflow: auto; }
    table { width: 100%; border-collapse: collapse; min-width: 760px; }
    th, td {
      padding: 9px 10px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      white-space: nowrap;
      vertical-align: top;
    }
    th { font-size: 12px; color: var(--muted); font-weight: 700; background: #fbfcfd; }
    tr[data-selected="true"] { background: #e8f3f1; }
    .pill {
      display: inline-flex;
      align-items: center;
      min-width: 58px;
      justify-content: center;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 12px;
      font-weight: 700;
      background: #eef1f5;
    }
    .critical, .high { color: var(--bad); }
    .warning, .medium { color: var(--warn); }
    .resolved { color: var(--ok); }
    .muted { color: var(--muted); }
    .detail, .stack { display: grid; gap: 12px; }
    .kv {
      display: grid;
      grid-template-columns: 110px minmax(0, 1fr);
      gap: 7px 10px;
    }
    .kv div:nth-child(odd) { color: var(--muted); }
    pre {
      margin: 0;
      max-height: 300px;
      overflow: auto;
      padding: 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #0f172a;
      color: #e5e7eb;
      font-size: 12px;
      line-height: 1.45;
    }
    .item {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px;
      overflow-wrap: anywhere;
    }
    .error { color: var(--bad); font-weight: 700; }
    @media (max-width: 900px) {
      main { grid-template-columns: 1fr; padding: 10px; }
      header { padding: 12px; align-items: flex-start; flex-direction: column; }
      table { min-width: 680px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Simple Alert Proxy</h1>
    <div class="toolbar">
      <span id="identity" class="muted"></span>
      <input id="login-user" autocomplete="username" placeholder="Username">
      <input id="login-password" type="password" autocomplete="current-password" placeholder="Password">
      <button id="login" class="primary">Login</button>
      <button id="logout">Logout</button>
      <input id="token" type="password" autocomplete="off" placeholder="Management token">
      <button id="save-token">Save token</button>
      <button id="forget-token">Forget</button>
      <button id="refresh" class="primary">Refresh</button>
    </div>
  </header>
  <main>
    <section>
      <div class="section-head">
        <h2>Alert Groups</h2>
        <span id="count" class="muted"></span>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Severity</th>
              <th>Title</th>
              <th>Source</th>
              <th>Events</th>
              <th>Last Event</th>
              <th>Ack</th>
            </tr>
          </thead>
          <tbody id="groups"></tbody>
        </table>
      </div>
    </section>
    <section>
      <div class="section-head">
        <h2>Detail</h2>
      </div>
      <div id="detail" class="section-body detail"></div>
    </section>
    <section>
      <div class="section-head">
        <h2>Access</h2>
        <span id="access-state" class="muted"></span>
      </div>
      <div id="access" class="section-body"></div>
    </section>
  </main>
  <script>
    const TOKEN_KEY = "simple-alert-proxy.managementToken";
    const CSRF_KEY = "simple-alert-proxy.csrfToken";
    const state = {
      me: null, groups: [], events: [], deliveries: [], advisories: [],
      routes: [], integrations: [], users: [], teams: [], memberships: [],
      selected: null
    };
    const $ = (id) => document.getElementById(id);
    const authHeaders = () => {
      const headers = {};
      const token = sessionStorage.getItem(TOKEN_KEY);
      const csrf = sessionStorage.getItem(CSRF_KEY);
      if (token) headers.Authorization = `Bearer ${token}`;
      if (csrf) headers["X-CSRF-Token"] = csrf;
      return headers;
    };
    const api = (url, options = {}) => fetch(url, {
      ...options,
      credentials: "same-origin",
      headers: { ...authHeaders(), ...(options.headers || {}) },
    }).then(async (r) => {
      if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
      return r.status === 204 ? null : r.json().catch(() => null);
    });
    const jsonApi = (url, body, options = {}) => api(url, {
      ...options,
      method: options.method || "POST",
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      body: JSON.stringify(body),
    });
    const fmtTime = (ms) => ms ? new Date(ms).toLocaleString() : "";
    const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
    })[ch]);
    const canAdmin = () => state.me?.role === "admin";
    const canOperate = () => ["admin", "operator"].includes(state.me?.role);

    async function load() {
      $("token").value = sessionStorage.getItem(TOKEN_KEY) || "";
      state.me = await api("/api/me");
      if (state.me.csrf_token) sessionStorage.setItem(CSRF_KEY, state.me.csrf_token);
      [state.groups, state.events, state.deliveries, state.advisories, state.integrations, state.routes, state.teams, state.memberships] = await Promise.all([
        api("/api/alert-groups"),
        api("/api/alert-events"),
        api("/api/deliveries"),
        api("/api/advisories"),
        api("/api/integrations"),
        api("/api/routes"),
        api("/api/teams"),
        api("/api/team-memberships"),
      ]);
      state.users = canAdmin() ? await api("/api/users") : [];
      if (!state.selected && state.groups[0]) state.selected = state.groups[0].id;
      render();
    }

    function render() {
      $("identity").textContent = state.me.user
        ? `${state.me.user.display_name} (${state.me.role})`
        : state.me.auth_kind;
      $("access-state").textContent = state.me.auth_kind;
      $("count").textContent = `${state.groups.length} groups`;
      $("groups").innerHTML = state.groups.map((group) => `
        <tr data-id="${group.id}" data-selected="${group.id === state.selected}">
          <td><span class="pill ${esc(group.status)}">${esc(group.status)}</span></td>
          <td class="${esc(group.severity)}">${esc(group.severity)}</td>
          <td>${esc(group.title)}<div class="muted">${esc(group.fingerprint)}</div></td>
          <td>${esc(group.source)}<div class="muted">${esc(group.integration)}</div></td>
          <td>${group.event_count}</td>
          <td>${esc(fmtTime(group.last_event_at))}</td>
          <td>${group.acknowledged_at ? esc(fmtTime(group.acknowledged_at)) : ""}</td>
        </tr>
      `).join("");
      document.querySelectorAll("#groups tr").forEach((row) => {
        row.addEventListener("click", () => { state.selected = Number(row.dataset.id); render(); });
      });
      renderDetail();
      renderAccess();
    }

    function renderDetail() {
      const group = state.groups.find((item) => item.id === state.selected);
      if (!group) {
        $("detail").innerHTML = `<div class="muted">No alert group selected.</div>`;
        return;
      }
      const events = state.events.filter((event) => event.alert_group_id === group.id);
      const deliveries = state.deliveries.filter((delivery) =>
        events.some((event) => event.id === delivery.alert_event_id)
      );
      const advisories = state.advisories.filter((item) => item.alert_group_id === group.id);
      const latest = events[0];
      $("detail").innerHTML = `
        <div class="actions">
          <button data-action="ack" ${canOperate() ? "" : "disabled"}>Ack</button>
          <button data-action="resolve" ${canOperate() ? "" : "disabled"}>Resolve</button>
          <button data-action="silence" ${canOperate() ? "" : "disabled"}>Silence</button>
        </div>
        <div class="kv">
          <div>Status</div><div>${esc(group.status)}</div>
          <div>Severity</div><div>${esc(group.severity)}</div>
          <div>Title</div><div>${esc(group.title)}</div>
          <div>Source</div><div>${esc(group.source)} / ${esc(group.integration)}</div>
          <div>Fingerprint</div><div>${esc(group.fingerprint)}</div>
          <div>Events</div><div>${group.event_count}</div>
        </div>
        <div class="stack">
          <h2>Advisory</h2>
          ${advisories.map((item) => `
            <div class="item">
              <strong>${esc(item.kind)}</strong>
              <span class="muted">${esc(item.provider)}</span>
              <div>${esc(item.value)}</div>
            </div>
          `).join("") || `<div class="muted">No advisory enrichment.</div>`}
        </div>
        <div class="stack">
          <h2>Deliveries</h2>
          ${deliveries.map((delivery) => `
            <div class="item">
              <strong>${esc(delivery.target)}</strong>
              <span class="pill">${esc(delivery.status)}</span>
              <span class="muted">attempts ${delivery.attempt_count}</span>
              ${delivery.last_error ? `<div>${esc(delivery.last_error)}</div>` : ""}
              <div class="actions"><button data-replay="${delivery.id}" ${canOperate() ? "" : "disabled"}>Replay</button></div>
            </div>
          `).join("") || `<div class="muted">No deliveries.</div>`}
        </div>
        <div class="stack">
          <h2>Route Explanation</h2>
          ${state.routes.map((route) => `
            <div class="item">${esc(route.name)} -> ${esc(route.receiver)}
              <span class="muted">${route.matcher_count} matchers</span>
            </div>
          `).join("")}
        </div>
        <div class="stack">
          <h2>Normalized Event</h2>
          <pre>${esc(JSON.stringify(latest ?? {}, null, 2))}</pre>
        </div>
        <div class="stack">
          <h2>Raw Payload</h2>
          <pre>${esc(JSON.stringify(latest?.raw_payload ?? {}, null, 2))}</pre>
        </div>
      `;
      document.querySelectorAll("[data-action]").forEach((button) => {
        button.addEventListener("click", async () => {
          await api(`/api/alert-groups/${group.id}/${button.dataset.action}`, { method: "POST" });
          await load();
        });
      });
      document.querySelectorAll("[data-replay]").forEach((button) => {
        button.addEventListener("click", async () => {
          await api(`/api/deliveries/${button.dataset.replay}/replay`, { method: "POST" });
          await load();
        });
      });
    }

    function renderAccess() {
      const teamOptions = state.teams.map((team) => `<option value="${team.id}">${esc(team.name)}</option>`).join("");
      const userOptions = state.users.map((user) => `<option value="${user.id}">${esc(user.username)}</option>`).join("");
      $("access").innerHTML = `
        <div class="item">
          <h3>Session</h3>
          <div>${state.me.user ? esc(state.me.user.username) : esc(state.me.auth_kind)}</div>
        </div>
        ${canAdmin() ? `
          <div class="item">
            <h3>Create User</h3>
            <div class="row">
              <input id="new-user" placeholder="Username">
              <input id="new-display" placeholder="Display name">
              <input id="new-password" type="password" placeholder="Password">
              <select id="new-role">
                <option value="viewer">Viewer</option>
                <option value="operator">Operator</option>
                <option value="admin">Admin</option>
              </select>
              <button id="create-user">Create</button>
            </div>
          </div>
          <div class="item">
            <h3>Users</h3>
            ${state.users.map((user) => `
              <div class="row">
                <strong>${esc(user.username)}</strong>
                <span>${esc(user.display_name)}</span>
                <span class="pill">${esc(user.global_role)}</span>
                <span class="muted">${esc(user.status)}</span>
                <input id="pw-${user.id}" type="password" placeholder="New password">
                <button data-password="${user.id}">Change password</button>
                <button data-disable="${user.id}">Disable</button>
              </div>
            `).join("") || `<div class="muted">No users.</div>`}
          </div>
          <div class="item">
            <h3>Create Team</h3>
            <div class="row">
              <input id="new-team" placeholder="Team name">
              <input id="new-team-desc" placeholder="Description">
              <button id="create-team">Create</button>
            </div>
          </div>
          <div class="item">
            <h3>Team Membership</h3>
            <div class="row">
              <select id="membership-team">${teamOptions}</select>
              <select id="membership-user">${userOptions}</select>
              <select id="membership-role">
                <option value="viewer">Viewer</option>
                <option value="operator">Operator</option>
                <option value="owner">Owner</option>
              </select>
              <button id="set-membership">Set</button>
            </div>
            ${state.memberships.map((membership) => `
              <div class="row">
                <strong>${esc(membership.team_name)}</strong>
                <span>${esc(membership.username)}</span>
                <span class="pill">${esc(membership.team_role)}</span>
                <button data-remove-membership="${membership.team_id}:${membership.user_id}">Remove</button>
              </div>
            `).join("") || `<div class="muted">No memberships.</div>`}
          </div>
        ` : `<div class="muted">Admin access is required to manage users and teams.</div>`}
      `;
      bindAccessActions();
    }

    function bindAccessActions() {
      if (!canAdmin()) return;
      $("create-user")?.addEventListener("click", async () => {
        await jsonApi("/api/users", {
          username: $("new-user").value,
          display_name: $("new-display").value,
          password: $("new-password").value,
          global_role: $("new-role").value,
        });
        await load();
      });
      $("create-team")?.addEventListener("click", async () => {
        await jsonApi("/api/teams", {
          name: $("new-team").value,
          description: $("new-team-desc").value,
        });
        await load();
      });
      $("set-membership")?.addEventListener("click", async () => {
        await jsonApi(`/api/teams/${$("membership-team").value}/members/${$("membership-user").value}`, {
          team_role: $("membership-role").value,
        }, { method: "PUT" });
        await load();
      });
      document.querySelectorAll("[data-password]").forEach((button) => {
        button.addEventListener("click", async () => {
          const id = button.dataset.password;
          await jsonApi(`/api/users/${id}/password`, { password: $(`pw-${id}`).value });
          await load();
        });
      });
      document.querySelectorAll("[data-disable]").forEach((button) => {
        button.addEventListener("click", async () => {
          await api(`/api/users/${button.dataset.disable}/disable`, { method: "POST" });
          await load();
        });
      });
      document.querySelectorAll("[data-remove-membership]").forEach((button) => {
        button.addEventListener("click", async () => {
          const [teamId, userId] = button.dataset.removeMembership.split(":");
          await api(`/api/teams/${teamId}/members/${userId}`, { method: "DELETE" });
          await load();
        });
      });
    }

    $("login").addEventListener("click", async () => {
      try {
        const response = await jsonApi("/auth/login", {
          username: $("login-user").value,
          password: $("login-password").value,
        });
        sessionStorage.removeItem(TOKEN_KEY);
        sessionStorage.setItem(CSRF_KEY, response.csrf_token);
        $("login-password").value = "";
        await load();
      } catch (error) {
        $("detail").innerHTML = `<div class="error">${esc(error.message)}</div>`;
      }
    });
    $("logout").addEventListener("click", async () => {
      await api("/auth/logout", { method: "POST" }).catch(() => null);
      sessionStorage.removeItem(CSRF_KEY);
      await load().catch(() => location.reload());
    });
    $("refresh").addEventListener("click", load);
    $("save-token").addEventListener("click", async () => {
      const token = $("token").value.trim();
      if (token) sessionStorage.setItem(TOKEN_KEY, token);
      else sessionStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(CSRF_KEY);
      await load();
    });
    $("forget-token").addEventListener("click", async () => {
      sessionStorage.removeItem(TOKEN_KEY);
      $("token").value = "";
      await load();
    });
    load().catch((error) => {
      $("identity").textContent = "not authenticated";
      $("detail").innerHTML = `<div class="error">${esc(error.message)}</div>`;
      $("access").innerHTML = `<div class="muted">Log in with a local user or save a management token.</div>`;
    });
  </script>
</body>
</html>
"##;
