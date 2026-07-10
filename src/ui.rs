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
    h1 {
      margin: 0;
      font-size: 18px;
      font-weight: 700;
    }
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
    input {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 7px 10px;
      min-height: 34px;
      min-width: 220px;
    }
    .toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; justify-content: flex-end; }
    main {
      display: grid;
      grid-template-columns: minmax(320px, 1.1fr) minmax(360px, .9fr);
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
    h2 { margin: 0; font-size: 15px; }
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
    .detail {
      display: grid;
      gap: 12px;
      padding: 14px;
    }
    .actions { display: flex; gap: 8px; flex-wrap: wrap; }
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
    .stack { display: grid; gap: 8px; }
    .item {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 9px;
      overflow-wrap: anywhere;
    }
    @media (max-width: 900px) {
      main { grid-template-columns: 1fr; padding: 10px; }
      header { padding: 12px; }
      table { min-width: 680px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Simple Alert Proxy</h1>
    <div class="toolbar">
      <input id="token" type="password" autocomplete="off" placeholder="Management token">
      <button id="save-token">Save</button>
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
      <div id="detail" class="detail"></div>
    </section>
  </main>
  <script>
    const TOKEN_KEY = "simple-alert-proxy.managementToken";
    const state = { groups: [], events: [], deliveries: [], advisories: [], routes: [], integrations: [], selected: null };
    const $ = (id) => document.getElementById(id);
    const authHeaders = () => {
      const token = sessionStorage.getItem(TOKEN_KEY);
      return token ? { "Authorization": `Bearer ${token}` } : {};
    };
    const api = (url, options = {}) => fetch(url, {
      ...options,
      headers: { ...authHeaders(), ...(options.headers || {}) },
    }).then((r) => {
      if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
      return r.status === 204 ? null : r.json().catch(() => null);
    });
    const fmtTime = (ms) => ms ? new Date(ms).toLocaleString() : "";
    const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"
    })[ch]);

    async function load() {
      const token = sessionStorage.getItem(TOKEN_KEY) || "";
      if ($("token").value !== token) $("token").value = token;
      [state.groups, state.events, state.deliveries, state.advisories, state.integrations, state.routes] = await Promise.all([
        api("/api/alert-groups"),
        api("/api/alert-events"),
        api("/api/deliveries"),
        api("/api/advisories"),
        api("/api/integrations"),
        api("/api/routes"),
      ]);
      if (!state.selected && state.groups[0]) state.selected = state.groups[0].id;
      render();
    }

    function render() {
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
          <button data-action="ack">Ack</button>
          <button data-action="resolve">Resolve</button>
          <button data-action="silence">Silence</button>
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
              <div class="actions"><button data-replay="${delivery.id}">Replay</button></div>
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

    $("refresh").addEventListener("click", load);
    $("save-token").addEventListener("click", async () => {
      const token = $("token").value.trim();
      if (token) sessionStorage.setItem(TOKEN_KEY, token);
      else sessionStorage.removeItem(TOKEN_KEY);
      await load();
    });
    $("forget-token").addEventListener("click", async () => {
      sessionStorage.removeItem(TOKEN_KEY);
      $("token").value = "";
      await load();
    });
    $("token").value = sessionStorage.getItem(TOKEN_KEY) || "";
    load().catch((error) => { $("detail").innerHTML = `<div class="item">${esc(error.message)}</div>`; });
  </script>
</body>
</html>
"##;
