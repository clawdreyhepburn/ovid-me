/**
 * Single-file forensics dashboard for OVID.
 * Returns complete HTML with embedded CSS and JS — no external dependencies.
 */
export function dashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OVID Forensics Dashboard</title>
<style>
  :root {
    --bg: #0a0a0a; --surface: #1a1a1a; --border: #2a2a2a;
    --gold: #c4a87c; --tiffany: #81d8d0; --yellow: #d4bc96; --red: #e06060;
    --text: #e8e0d8; --muted: #8a8078;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: system-ui, -apple-system, sans-serif; font-size: 14px; }
  a { color: var(--tiffany); text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* Layout */
  .container { max-width: 1920px; margin: 0 auto; padding: 16px; }
  h1 { color: var(--gold); font-size: 22px; letter-spacing: 1px; margin-bottom: 4px; }
  h2 { color: var(--gold); font-size: 15px; margin-bottom: 8px; letter-spacing: 0.5px; }
  .subtitle { color: var(--muted); font-size: 12px; margin-bottom: 16px; }

  /* Time Range */
  .time-bar { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 16px;
    background: var(--surface); padding: 10px 14px; border-radius: 6px; border: 1px solid var(--border); }
  .time-bar button { background: var(--border); color: var(--text); border: none; padding: 6px 12px;
    border-radius: 4px; cursor: pointer; font-size: 12px; transition: background 0.2s; }
  .time-bar button:hover, .time-bar button.active { background: var(--gold); color: #0a0a0a; }
  .time-bar input { background: var(--bg); color: var(--text); border: 1px solid var(--border);
    padding: 5px 8px; border-radius: 4px; font-size: 12px; }
  .time-bar label { color: var(--muted); font-size: 12px; }

  /* Cards */
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 16px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 14px; text-align: center; }
  .card .value { font-size: 28px; font-weight: 700; color: var(--gold); }
  .card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
  .card .pct { font-size: 12px; color: var(--muted); }
  .card.proven .value { color: var(--tiffany); }
  .card.unproven .value { color: var(--yellow); }
  .card.deny .value { color: var(--red); }
  .card.anomaly .value { color: var(--red); }

  /* Panels */
  .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 14px; margin-bottom: 12px; }
  .row { display: grid; gap: 12px; margin-bottom: 12px; }
  .row-2 { grid-template-columns: 1fr 2fr; }
  .row-3 { grid-template-columns: 1fr 1fr 1fr; }
  .full { grid-column: 1 / -1; }

  /* Timeline SVG */
  .timeline-wrap { width: 100%; overflow-x: auto; }
  .timeline-wrap svg { width: 100%; min-height: 200px; }

  /* Table */
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--gold); border-bottom: 1px solid var(--border); padding: 6px 8px; cursor: pointer; user-select: none; }
  th:hover { color: var(--tiffany); }
  td { padding: 6px 8px; border-bottom: 1px solid var(--border); }
  tr:hover td { background: rgba(196, 168, 124, 0.05); }
  .truncate { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* Badges */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }
  .badge-proven { background: rgba(129,216,208,0.15); color: var(--tiffany); }
  .badge-unproven { background: rgba(212,188,150,0.15); color: var(--yellow); }
  .badge-deny { background: rgba(224,96,96,0.15); color: var(--red); }
  .badge-role { background: rgba(196,168,124,0.15); color: var(--gold); }
  .anomaly-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--red); margin-right: 4px; }

  /* Decision stream */
  .stream { max-height: 400px; overflow-y: auto; }
  .stream-entry { display: flex; gap: 10px; align-items: center; padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
  .stream-entry .ts { color: var(--muted); font-size: 11px; min-width: 140px; }
  .stream-entry .action-text { color: var(--text); }
  .stream-entry .resource-text { color: var(--muted); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .filter-bar { display: flex; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }
  .filter-bar select, .filter-bar input { background: var(--bg); color: var(--text); border: 1px solid var(--border);
    padding: 4px 8px; border-radius: 4px; font-size: 12px; }
  .load-more { display: block; margin: 8px auto; background: var(--border); color: var(--text); border: none;
    padding: 6px 16px; border-radius: 4px; cursor: pointer; font-size: 12px; }
  .load-more:hover { background: var(--gold); color: #0a0a0a; }

  /* Tree */
  .tree { font-size: 13px; }
  .tree-node { padding: 3px 0 3px calc(var(--depth, 0) * 20px); cursor: pointer; display: flex; gap: 6px; align-items: center; }
  .tree-node:hover { background: rgba(196,168,124,0.05); }
  .tree-toggle { width: 16px; text-align: center; color: var(--muted); }
  .tree-id { font-family: monospace; font-size: 12px; }
  .tree-count { color: var(--muted); font-size: 11px; }

  /* Bars */
  .bar-chart .bar-row { display: flex; align-items: center; margin-bottom: 4px; }
  .bar-chart .bar-label { width: 180px; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-chart .bar-track { flex: 1; height: 18px; background: var(--border); border-radius: 3px; overflow: hidden; }
  .bar-chart .bar-fill { height: 100%; border-radius: 3px; transition: width 0.3s; }
  .bar-chart .bar-count { width: 50px; text-align: right; font-size: 12px; color: var(--muted); }

  /* Donut */
  .donut-wrap { display: flex; align-items: center; gap: 16px; }
  .donut-legend { font-size: 12px; }
  .donut-legend div { display: flex; align-items: center; gap: 6px; margin-bottom: 4px; }
  .donut-legend .swatch, .swatch { display: inline-block; width: 12px; height: 12px; border-radius: 2px; vertical-align: middle; margin-right: 4px; }
  .role-badge { background: var(--border); color: var(--gold); padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; font-family: monospace; cursor: pointer; }
  .role-badge:hover { background: var(--gold); color: var(--bg); }
  .clickable-row { cursor: pointer; } .clickable-row:hover { background: rgba(196,168,124,0.1); }

  /* Sankey */
  .sankey-wrap svg { width: 100%; min-height: 300px; }
  .sankey-wrap .s-node rect { cursor: pointer; }
  .sankey-wrap .s-node text { fill: var(--text); font-size: 11px; }
  .sankey-wrap .s-link { fill: none; stroke-opacity: 0.35; transition: stroke-opacity 0.2s; }
  .sankey-wrap .s-link:hover { stroke-opacity: 0.7; }

  /* Modal */
  .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 100; }
  .modal-overlay.open { display: flex; align-items: center; justify-content: center; }
  .modal { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; }
  .modal h2 { margin-bottom: 12px; }
  .modal pre { background: var(--bg); padding: 10px; border-radius: 4px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; color: var(--tiffany); }
  .modal .close-btn { float: right; background: none; border: none; color: var(--muted); font-size: 20px; cursor: pointer; }
  .modal .close-btn:hover { color: var(--text); }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
</style>
</head>
<body>
<div class="container">
  <h1>OVID Forensics Dashboard</h1>
  <div class="subtitle">Agent identity &amp; authorization forensics</div>

  <!-- Time Range -->
  <div class="time-bar" id="timeBar">
    <button data-range="3600" class="active">Last Hour</button>
    <button data-range="21600">6 Hours</button>
    <button data-range="86400">24 Hours</button>
    <button data-range="604800">7 Days</button>
    <button data-range="2592000">30 Days</button>
    <button data-range="0">All Time</button>
    <label>From:</label><input type="datetime-local" id="customFrom">
    <label>To:</label><input type="datetime-local" id="customTo">
    <button id="applyCustom">Apply</button>
  </div>

  <!-- Overview Cards -->
  <div class="cards" id="overviewCards"></div>

  <!-- Activity Timeline -->
  <div class="panel">
    <h2>Activity Timeline</h2>
    <div class="timeline-wrap" id="timeline"></div>
  </div>

  <!-- Tree + Leaderboard -->
  <div class="row row-2">
    <div class="panel">
      <h2>Delegation Tree</h2>
      <div class="tree" id="delegationTree"><em style="color:var(--muted)">Select an agent to view tree</em></div>
    </div>
    <div class="panel">
      <h2>Agent Leaderboard</h2>
      <div id="leaderboard"></div>
    </div>
  </div>

  <!-- Decision Stream -->
  <div class="panel">
    <h2>Decision Stream</h2>
    <div class="filter-bar" id="streamFilters">
      <input type="text" id="filterAgent" placeholder="Agent JTI...">
      <select id="filterAction"><option value="">All Actions</option></select>
      <select id="filterDecision">
        <option value="">All Decisions</option>
        <option value="allow-proven">Allow (Proven)</option>
        <option value="allow-unproven">Allow (Unproven)</option>
        <option value="deny">Deny</option>
      </select>
    </div>
    <div class="stream" id="decisionStream"></div>
    <button class="load-more" id="loadMore">Load More</button>
  </div>

  <!-- Role Breakdown -->
  <div class="row row-2">
    <div class="panel" style="flex:2">
      <h2>Role Breakdown</h2>
      <div id="roleBreakdown"></div>
    </div>
    <div class="panel" style="flex:1">
      <h2>Role Activity Over Time</h2>
      <div id="roleTimeline"></div>
    </div>
  </div>

  <!-- Bottom row: Policy Usage, Action Breakdown, Sankey -->
  <div class="row row-3">
    <div class="panel">
      <h2>Policy Usage</h2>
      <div class="bar-chart" id="policyUsage"></div>
    </div>
    <div class="panel">
      <h2>Action Breakdown</h2>
      <div class="donut-wrap" id="actionBreakdown"></div>
    </div>
    <div class="panel">
      <h2>Sankey Flow</h2>
      <div class="sankey-wrap" id="sankeyFlow"></div>
    </div>
  </div>
</div>

<!-- Agent Detail Modal -->
<div class="modal-overlay" id="agentModal">
  <div class="modal">
    <button class="close-btn" onclick="closeModal()">&times;</button>
    <h2 id="modalTitle">Agent Detail</h2>
    <div id="modalContent"></div>
  </div>
</div>

<script>
(function() {
  // State
  let timeFrom = null, timeTo = null;
  let streamPage = 1;
  let streamData = [];
  let sortCol = 'decision_count', sortDir = -1;
  let refreshTimer = null;
  const REFRESH_MS = 30000;

  // Time range
  function setRange(seconds) {
    document.querySelectorAll('#timeBar button[data-range]').forEach(b => b.classList.remove('active'));
    if (seconds === 0) { timeFrom = null; timeTo = null; }
    else {
      timeTo = Math.floor(Date.now() / 1000);
      timeFrom = timeTo - seconds;
    }
    event?.target?.classList?.add('active');
    streamPage = 1; streamData = [];
    refreshAll();
  }

  document.querySelectorAll('#timeBar button[data-range]').forEach(b => {
    b.addEventListener('click', () => setRange(parseInt(b.dataset.range)));
  });

  document.getElementById('applyCustom').addEventListener('click', () => {
    const f = document.getElementById('customFrom').value;
    const t = document.getElementById('customTo').value;
    if (f) timeFrom = Math.floor(new Date(f).getTime() / 1000);
    if (t) timeTo = Math.floor(new Date(t).getTime() / 1000);
    document.querySelectorAll('#timeBar button[data-range]').forEach(b => b.classList.remove('active'));
    streamPage = 1; streamData = [];
    refreshAll();
  });

  function qs(params) {
    const p = new URLSearchParams();
    if (timeFrom) p.set('from', timeFrom);
    if (timeTo) p.set('to', timeTo);
    if (params) Object.entries(params).forEach(([k,v]) => { if (v) p.set(k, v); });
    const s = p.toString();
    return s ? '?' + s : '';
  }

  async function api(path, params) {
    try { const r = await fetch('/api/' + path + qs(params)); return await r.json(); }
    catch(e) { console.error('API error', path, e); return null; }
  }

  // Format helpers
  function fmtTime(ts) { return new Date(ts * 1000).toLocaleString(); }
  function fmtId(jti) { return jti ? (jti.length > 16 ? jti.slice(0, 8) + '…' + jti.slice(-6) : jti) : '?'; }
  function decBadge(d) {
    const cls = d === 'allow-proven' ? 'badge-proven' : d === 'allow-unproven' ? 'badge-unproven' : 'badge-deny';
    return '<span class="badge ' + cls + '">' + d + '</span>';
  }
  function pct(n, total) { return total ? (n / total * 100).toFixed(1) + '%' : '0%'; }

  // Overview
  async function loadOverview() {
    const d = await api('overview');
    if (!d) return;
    const bk = {};
    (d.breakdown || []).forEach(r => bk[r.decision] = r.count);
    const t = d.totalDecisions || 0;
    document.getElementById('overviewCards').innerHTML =
      card(d.totalAgents, 'Agents', '') +
      card(t, 'Decisions', '') +
      card(bk['allow-proven'] || 0, 'Allow (Proven)', pct(bk['allow-proven']||0, t), 'proven') +
      card(bk['allow-unproven'] || 0, 'Allow (Unproven)', pct(bk['allow-unproven']||0, t), 'unproven') +
      card(bk['deny'] || 0, 'Deny', pct(bk['deny']||0, t), 'deny') +
      card(d.anomalyCount || 0, 'Anomalies', '', d.anomalyCount > 0 ? 'anomaly' : '');
  }
  function card(val, label, sub, cls) {
    return '<div class="card ' + (cls||'') + '"><div class="value">' + val + '</div><div class="label">' + label + '</div>' + (sub ? '<div class="pct">' + sub + '</div>' : '') + '</div>';
  }

  // Timeline
  async function loadTimeline() {
    const [activity, spawns] = await Promise.all([api('timeline'), api('spawn-rate')]);
    if (!activity || !activity.length) { document.getElementById('timeline').innerHTML = '<em style="color:var(--muted)">No data</em>'; return; }
    const el = document.getElementById('timeline');
    const W = el.clientWidth || 900, H = 200, pad = {t:20,r:20,b:30,l:50};
    const pw = W - pad.l - pad.r, ph = H - pad.t - pad.b;
    const hours = activity.map(r => r.hour);
    const minH = Math.min(...hours), maxH = Math.max(...hours);
    const rangeH = maxH - minH || 3600;
    const maxY = Math.max(...activity.map(r => r.total), 1);
    const x = h => pad.l + ((h - minH) / rangeH) * pw;
    const y = v => pad.t + ph - (v / maxY) * ph;

    // Build stacked areas
    function areaPath(data, valFn, baseFn) {
      let d = 'M';
      data.forEach((r, i) => { d += (i ? 'L' : '') + x(r.hour).toFixed(1) + ',' + y(valFn(r)).toFixed(1); });
      for (let i = data.length - 1; i >= 0; i--) d += 'L' + x(data[i].hour).toFixed(1) + ',' + y(baseFn(data[i])).toFixed(1);
      return d + 'Z';
    }

    const denyPath = areaPath(activity, r => r.deny + r.unproven + r.proven, () => 0);
    const unpPath = areaPath(activity, r => r.unproven + r.proven, () => 0);
    const provPath = areaPath(activity, r => r.proven, () => 0);

    // Spawn rate line
    const spawnMap = new Map((spawns||[]).map(s => [s.hour, s.count]));
    const maxSpawn = Math.max(...[...(spawnMap.values())], 1);
    let spawnLine = '';
    if (spawns && spawns.length) {
      spawnLine = '<path d="M' + spawns.map(s => x(s.hour).toFixed(1) + ',' + (pad.t + ph - (s.count / maxSpawn) * ph).toFixed(1)).join('L') +
        '" stroke="var(--gold)" stroke-width="2" fill="none" stroke-dasharray="4,3" opacity="0.7"/>';
    }

    // Y-axis labels
    let yLabels = '';
    for (let i = 0; i <= 4; i++) {
      const v = Math.round(maxY * i / 4);
      yLabels += '<text x="' + (pad.l - 6) + '" y="' + y(v).toFixed(1) + '" fill="var(--muted)" font-size="10" text-anchor="end" dominant-baseline="middle">' + v + '</text>';
    }

    // X-axis labels (a few)
    let xLabels = '';
    const step = Math.max(1, Math.floor(activity.length / 8));
    for (let i = 0; i < activity.length; i += step) {
      const d = new Date(activity[i].hour * 1000);
      const lbl = d.getMonth()+1 + '/' + d.getDate() + ' ' + String(d.getHours()).padStart(2,'0') + ':00';
      xLabels += '<text x="' + x(activity[i].hour).toFixed(1) + '" y="' + (H - 5) + '" fill="var(--muted)" font-size="10" text-anchor="middle">' + lbl + '</text>';
    }

    // Hover overlay rects
    let hoverRects = '';
    const bw = Math.max(2, pw / activity.length);
    activity.forEach((r, i) => {
      hoverRects += '<rect x="' + (x(r.hour) - bw/2).toFixed(1) + '" y="' + pad.t + '" width="' + bw.toFixed(1) + '" height="' + ph +
        '" fill="transparent" data-idx="' + i + '"><title>' + fmtTime(r.hour) + '\\nProven: ' + r.proven + ' Unproven: ' + r.unproven + ' Deny: ' + r.deny + '</title></rect>';
    });

    el.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '">' +
      '<path d="' + denyPath + '" fill="var(--red)" opacity="0.6"/>' +
      '<path d="' + unpPath + '" fill="var(--yellow)" opacity="0.6"/>' +
      '<path d="' + provPath + '" fill="var(--tiffany)" opacity="0.6"/>' +
      spawnLine + yLabels + xLabels + hoverRects + '</svg>';
  }

  // Leaderboard
  async function loadLeaderboard() {
    const agents = await api('agents');
    if (!agents || !agents.length) { document.getElementById('leaderboard').innerHTML = '<em style="color:var(--muted)">No agents</em>'; return; }
    const sorted = agents.sort((a, b) => (b[sortCol] - a[sortCol]) * sortDir || 0);
    let html = '<table><thead><tr>' +
      '<th data-col="agent_jti">Agent</th><th data-col="role">Role</th><th data-col="depth">Depth</th>' +
      '<th data-col="decision_count">Decisions</th><th data-col="deny_count">Deny%</th>' +
      '<th data-col="proven_count">Proven%</th><th data-col="last_active">Last Active</th>' +
      '</tr></thead><tbody>';
    for (const a of sorted) {
      const total = a.decision_count || 1;
      html += '<tr style="cursor:pointer" onclick="showAgent(&quot;' + encodeURIComponent(a.agent_jti||'') + '&quot;)">' +
        '<td class="truncate" style="font-family:monospace">' + fmtId(a.agent_jti) + '</td>' +
        '<td><span class="badge badge-role">' + (a.role||'?') + '</span></td>' +
        '<td>' + (a.depth ?? '?') + '</td><td>' + a.decision_count + '</td>' +
        '<td>' + pct(a.deny_count, total) + '</td><td>' + pct(a.proven_count, total) + '</td>' +
        '<td style="font-size:11px;color:var(--muted)">' + (a.last_active ? fmtTime(a.last_active) : '-') + '</td></tr>';
    }
    html += '</tbody></table>';
    document.getElementById('leaderboard').innerHTML = html;
    document.querySelectorAll('#leaderboard th').forEach(th => {
      th.addEventListener('click', () => {
        const col = th.dataset.col;
        if (sortCol === col) sortDir *= -1; else { sortCol = col; sortDir = -1; }
        loadLeaderboard();
      });
    });
  }

  // Decision Stream
  async function loadStream(append) {
    if (!append) { streamPage = 1; streamData = []; }
    const agent = document.getElementById('filterAgent').value;
    const action = document.getElementById('filterAction').value;
    const decision = document.getElementById('filterDecision').value;
    const data = await api('decisions', { page: streamPage, limit: 50, agent, action, decision });
    if (!data) return;
    streamData = append ? streamData.concat(data) : data;
    const el = document.getElementById('decisionStream');
    let html = '';
    for (const d of streamData) {
      html += '<div class="stream-entry">' +
        '<span class="ts">' + fmtTime(d.timestamp) + '</span>' +
        '<span class="badge badge-role">' + (d.role||'?') + '</span>' +
        '<span class="action-text">' + (d.action||'') + '</span>' +
        '<span class="resource-text" title="' + (d.resource||'').replace(/"/g,'&quot;') + '">' + fmtId(d.resource||'') + '</span>' +
        decBadge(d.decision) + '</div>';
    }
    el.innerHTML = html || '<em style="color:var(--muted)">No decisions</em>';
    document.getElementById('loadMore').style.display = data.length < 50 ? 'none' : 'block';
  }

  document.getElementById('loadMore').addEventListener('click', () => { streamPage++; loadStream(true); });
  ['filterAgent','filterAction','filterDecision'].forEach(id => {
    document.getElementById(id).addEventListener('change', () => loadStream(false));
  });
  document.getElementById('filterAgent').addEventListener('input', debounce(() => loadStream(false), 300));

  // Load action options
  async function loadActionOptions() {
    const data = await api('actions');
    if (!data) return;
    const sel = document.getElementById('filterAction');
    data.forEach(a => { const o = document.createElement('option'); o.value = a.action; o.textContent = a.action + ' (' + a.count + ')'; sel.appendChild(o); });
  }

  // Policy Usage
  async function loadPolicies() {
    const data = await api('policies');
    const el = document.getElementById('policyUsage');
    if (!data || !data.length) { el.innerHTML = '<em style="color:var(--muted)">No policy data</em>'; return; }
    const max = data[0].count;
    let html = '';
    for (const p of data.slice(0, 15)) {
      const mainDec = Object.entries(p.decisions || {}).sort((a,b) => b[1] - a[1])[0];
      const color = mainDec ? (mainDec[0] === 'allow-proven' ? 'var(--tiffany)' : mainDec[0] === 'deny' ? 'var(--red)' : 'var(--yellow)') : 'var(--gold)';
      html += '<div class="bar-row"><span class="bar-label" title="' + p.policy + '">' + p.policy + '</span>' +
        '<div class="bar-track"><div class="bar-fill" style="width:' + (p.count/max*100) + '%;background:' + color + '"></div></div>' +
        '<span class="bar-count">' + p.count + '</span></div>';
    }
    el.innerHTML = html;
  }

  // Action Breakdown (donut)
  async function loadActions() {
    const data = await api('actions');
    const el = document.getElementById('actionBreakdown');
    if (!data || !data.length) { el.innerHTML = '<em style="color:var(--muted)">No data</em>'; return; }
    const total = data.reduce((s, r) => s + r.count, 0);
    const colors = ['#81d8d0','#c4a87c','#e06060','#d4bc96','#60a0e0','#b090d0','#60c080','#e0a060'];
    const R = 60, cx = 70, cy = 70;
    let svg = '<svg width="140" height="140" viewBox="0 0 140 140">';
    let angle = 0;
    data.forEach((d, i) => {
      const slice = (d.count / total) * Math.PI * 2;
      const x1 = cx + R * Math.cos(angle), y1 = cy + R * Math.sin(angle);
      const x2 = cx + R * Math.cos(angle + slice), y2 = cy + R * Math.sin(angle + slice);
      const large = slice > Math.PI ? 1 : 0;
      svg += '<path d="M' + cx + ',' + cy + ' L' + x1.toFixed(2) + ',' + y1.toFixed(2) + ' A' + R + ',' + R + ' 0 ' + large + ' 1 ' + x2.toFixed(2) + ',' + y2.toFixed(2) + ' Z" fill="' + colors[i % colors.length] + '" opacity="0.8"><title>' + d.action + ': ' + d.count + '</title></path>';
      angle += slice;
    });
    svg += '<circle cx="' + cx + '" cy="' + cy + '" r="30" fill="var(--surface)"/></svg>';
    let legend = '<div class="donut-legend">';
    data.slice(0, 8).forEach((d, i) => {
      legend += '<div><span class="swatch" style="background:' + colors[i % colors.length] + '"></span>' + d.action + ' <span style="color:var(--muted)">(' + d.count + ')</span></div>';
    });
    legend += '</div>';
    el.innerHTML = svg + legend;
  }

  // Sankey
  async function loadSankey() {
    const data = await api('sankey');
    const el = document.getElementById('sankeyFlow');
    if (!data || !data.nodes || !data.nodes.length) { el.innerHTML = '<em style="color:var(--muted)">No data</em>'; return; }
    const nodes = data.nodes, links = data.links;
    // Minimal sankey layout
    const W = el.clientWidth || 600, H = Math.max(300, nodes.length * 20);
    const nodeW = 16, pad = {l:10,r:10,t:10,b:10};
    const pw = W - pad.l - pad.r - nodeW, ph = H - pad.t - pad.b;

    // Assign columns: nodes with no incoming = col 0, then BFS
    const incoming = new Set(links.map(l => l.target));
    const outgoing = new Set(links.map(l => l.source));
    const cols = new Array(nodes.length).fill(-1);
    // Col 0: sources only
    nodes.forEach((n, i) => { if (!incoming.has(i)) cols[i] = 0; });
    // Col 2: sinks only (no outgoing)
    nodes.forEach((n, i) => { if (!outgoing.has(i)) cols[i] = 2; });
    // Col 1: everything else
    nodes.forEach((n, i) => { if (cols[i] === -1) cols[i] = 1; });
    const maxCol = Math.max(...cols);

    // Group by column
    const colNodes = [];
    for (let c = 0; c <= maxCol; c++) colNodes.push(nodes.map((n, i) => i).filter(i => cols[i] === c));

    // Position nodes
    const nodePos = [];
    colNodes.forEach((col, c) => {
      const x = pad.l + (maxCol > 0 ? (c / maxCol) * pw : 0);
      const totalVal = col.map(i => {
        const val = links.filter(l => l.source === i || l.target === i).reduce((s, l) => s + l.value, 0);
        return Math.max(val, 1);
      });
      const totalH = totalVal.reduce((s, v) => s + v, 0);
      const scale = Math.min(ph / totalH, 5);
      let cy = pad.t;
      col.forEach((ni, j) => {
        const h = Math.max(totalVal[j] * scale, 4);
        nodePos[ni] = { x, y: cy, w: nodeW, h };
        cy += h + 4;
      });
    });

    // Render
    let svg = '<svg viewBox="0 0 ' + W + ' ' + H + '">';
    // Links
    const colorMap = {'allow-proven':'var(--tiffany)','allow-unproven':'var(--yellow)','deny':'var(--red)'};
    for (const l of links) {
      const s = nodePos[l.source], t = nodePos[l.target];
      if (!s || !t) continue;
      const sy = s.y + s.h / 2, ty = t.y + t.h / 2;
      const sx = s.x + s.w, tx = t.x;
      const sw = Math.max(1, Math.sqrt(l.value) * 2);
      const cp = (tx - sx) / 2;
      const name = nodes[l.target]?.name || '';
      const col = colorMap[name] || 'var(--gold)';
      svg += '<path class="s-link" d="M' + sx + ',' + sy + ' C' + (sx+cp) + ',' + sy + ' ' + (tx-cp) + ',' + ty + ' ' + tx + ',' + ty + '" stroke="' + col + '" stroke-width="' + sw.toFixed(1) + '"><title>' + (nodes[l.source]?.name||'') + ' → ' + name + ': ' + l.value + '</title></path>';
    }
    // Nodes
    for (let i = 0; i < nodes.length; i++) {
      const p = nodePos[i];
      if (!p) continue;
      const name = nodes[i].name;
      const fill = colorMap[name] || (name.startsWith('action:') ? 'var(--muted)' : 'var(--gold)');
      svg += '<g class="s-node"><rect x="' + p.x + '" y="' + p.y + '" width="' + p.w + '" height="' + p.h + '" fill="' + fill + '" rx="2"/>' +
        '<text x="' + (cols[i] < maxCol ? p.x + p.w + 4 : p.x - 4) + '" y="' + (p.y + p.h/2) + '" dominant-baseline="middle" text-anchor="' + (cols[i] < maxCol ? 'start' : 'end') + '" font-size="10">' + fmtId(name.replace('action:','')) + '</text></g>';
    }
    svg += '</svg>';
    el.innerHTML = svg;
  }

  // Agent detail modal
  window.showAgent = async function(rawJti) {
    const jti = decodeURIComponent(rawJti);
    const [agent, history] = await Promise.all([
      fetch('/api/agents/' + encodeURIComponent(jti) + qs()).then(r => r.json()).catch(() => null),
      fetch('/api/agents/' + encodeURIComponent(jti) + qs()).then(r => r.json()).catch(() => null)
    ]);
    const modal = document.getElementById('agentModal');
    const title = document.getElementById('modalTitle');
    const content = document.getElementById('modalContent');
    title.textContent = 'Agent: ' + fmtId(jti);
    let html = '';
    if (agent && agent.agent) {
      const a = agent.agent;
      html += '<h2 style="font-size:13px;margin:8px 0">Claims</h2><pre>' + JSON.stringify(a, null, 2) + '</pre>';
      if (a.parent_chain) {
        const chain = typeof a.parent_chain === 'string' ? JSON.parse(a.parent_chain) : a.parent_chain;
        if (chain.length) {
          html += '<h2 style="font-size:13px;margin:8px 0">Parent Chain</h2>';
          chain.forEach(p => { html += '<a href="#" onclick="showAgent(&quot;' + encodeURIComponent(p) + '&quot;);return false" style="margin-right:8px;font-family:monospace;font-size:12px">' + fmtId(p) + '</a>'; });
        }
      }
    }
    if (agent && agent.decisions) {
      html += '<h2 style="font-size:13px;margin:8px 0">Decisions (' + agent.decisions.length + ')</h2>';
      html += '<div class="stream" style="max-height:250px">';
      for (const d of agent.decisions.slice(0, 50)) {
        html += '<div class="stream-entry"><span class="ts">' + fmtTime(d.timestamp) + '</span><span class="action-text">' + (d.action||'') + '</span>' + decBadge(d.decision) + '</div>';
      }
      html += '</div>';
    }
    content.innerHTML = html;
    modal.classList.add('open');
  };

  window.closeModal = function() { document.getElementById('agentModal').classList.remove('open'); };
  document.getElementById('agentModal').addEventListener('click', (e) => { if (e.target === e.currentTarget) closeModal(); });

  // Delegation tree
  async function loadTree() {
    // Get top agents and show tree for the most active root
    const agents = await api('agents');
    if (!agents || !agents.length) return;
    // Find root-level agents (depth 0 or null)
    const roots = agents.filter(a => (a.depth ?? 0) === 0).slice(0, 5);
    if (!roots.length) return;
    let html = '';
    for (const root of roots) {
      const tree = await fetch('/api/agents/' + encodeURIComponent(root.agent_jti) + '/tree' + qs()).then(r => r.json()).catch(() => []);
      if (!tree || !tree.length) continue;
      for (const node of tree) {
        const d = node.depth || 0;
        html += '<div class="tree-node" style="--depth:' + d + '" onclick="showAgent(&quot;' + encodeURIComponent(node.jti||'') + '&quot;)">' +
          '<span class="tree-toggle">' + (d > 0 ? '└' : '●') + '</span>' +
          '<span class="tree-id">' + fmtId(node.jti) + '</span>' +
          (node.role ? '<span class="badge badge-role">' + node.role + '</span>' : '') +
          '<span class="tree-count">' + (node.decision_count || 0) + ' decisions</span></div>';
      }
    }
    document.getElementById('delegationTree').innerHTML = html || '<em style="color:var(--muted)">No delegation data</em>';
  }

  function debounce(fn, ms) { let t; return function() { clearTimeout(t); t = setTimeout(fn, ms); }; }

  // Role Breakdown
  async function loadRoles() {
    const data = await api('roles');
    const el = document.getElementById('roleBreakdown');
    if (!data || !data.length) { el.innerHTML = '<em style="color:var(--muted)">No role data</em>'; return; }
    let html = '<table class="leader-table"><thead><tr><th>Role</th><th>Agents</th><th>Decisions</th><th>Proven</th><th>Unproven</th><th>Denied</th><th>Deny %</th></tr></thead><tbody>';
    for (const r of data) {
      const total = r.decision_count || 1;
      const denyPct = ((r.deny_count / total) * 100).toFixed(1);
      const denyColor = r.deny_count > 0 ? 'var(--red)' : 'var(--muted)';
      html += '<tr class="clickable-row" onclick="showRoleDetail(&quot;' + encodeURIComponent(r.role) + '&quot;)">' +
        '<td><span class="role-badge">' + (r.role || 'unknown') + '</span></td>' +
        '<td>' + r.agent_count + '</td>' +
        '<td>' + r.decision_count + '</td>' +
        '<td style="color:var(--tiffany)">' + (r.proven_count || 0) + '</td>' +
        '<td style="color:var(--yellow)">' + (r.unproven_count || 0) + '</td>' +
        '<td style="color:' + denyColor + '">' + (r.deny_count || 0) + '</td>' +
        '<td style="color:' + denyColor + '">' + denyPct + '%</td></tr>';
    }
    html += '</tbody></table>';
    el.innerHTML = html;
  }

  // Role Activity Over Time
  async function loadRoleTimeline() {
    const data = await api('roles/timeline');
    const el = document.getElementById('roleTimeline');
    if (!data || !data.length) { el.innerHTML = '<em style="color:var(--muted)">No data</em>'; return; }
    // Group by role, plot stacked bars per hour
    const roles = [...new Set(data.map(d => d.role || 'unknown'))];
    const hours = [...new Set(data.map(d => d.hour))].sort((a,b) => a - b);
    const roleColors = ['#81d8d0','#c4a87c','#e06060','#d4bc96','#60a0e0','#b090d0','#60c080','#e0a060'];
    const byHourRole = new Map();
    data.forEach(d => byHourRole.set(d.hour + ':' + (d.role||'unknown'), d.count));
    const maxPerHour = hours.map(h => roles.reduce((s, r) => s + (byHourRole.get(h+':'+r) || 0), 0));
    const maxVal = Math.max(...maxPerHour, 1);
    const W = 400, H = 200, pad = 40;
    const barW = Math.max(2, Math.min(20, (W - pad * 2) / hours.length - 1));
    let svg = '<svg width="100%" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet">';
    // Y axis
    svg += '<line x1="' + pad + '" y1="10" x2="' + pad + '" y2="' + (H-pad) + '" stroke="var(--border)" stroke-width="1"/>';
    hours.forEach((h, i) => {
      const x = pad + i * ((W - pad * 2) / hours.length);
      let y = H - pad;
      roles.forEach((r, ri) => {
        const val = byHourRole.get(h + ':' + r) || 0;
        if (val > 0) {
          const barH = (val / maxVal) * (H - pad - 10);
          y -= barH;
          svg += '<rect x="' + x + '" y="' + y + '" width="' + barW + '" height="' + barH + '" fill="' + roleColors[ri % roleColors.length] + '" opacity="0.85"><title>' + r + ': ' + val + ' @ ' + new Date(h*1000).toLocaleTimeString() + '</title></rect>';
        }
      });
    });
    svg += '</svg>';
    // Legend
    let legend = '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px">';
    roles.forEach((r, i) => {
      legend += '<div style="font-size:0.8rem"><span class="swatch" style="background:' + roleColors[i % roleColors.length] + '"></span>' + r + '</div>';
    });
    legend += '</div>';
    el.innerHTML = svg + legend;
  }

  // Role detail modal
  window.showRoleDetail = async function(encodedRole) {
    const role = decodeURIComponent(encodedRole);
    const data = await api('roles/' + encodedRole);
    if (!data) return;
    const modal = document.getElementById('agentModal');
    document.getElementById('modalTitle').textContent = 'Role: ' + role;
    let html = '<table class="leader-table"><thead><tr><th>Action</th><th>Decision</th><th>Count</th></tr></thead><tbody>';
    for (const r of data) {
      const color = r.decision === 'deny' ? 'var(--red)' : r.decision === 'allow-proven' ? 'var(--tiffany)' : 'var(--yellow)';
      html += '<tr><td>' + r.action + '</td><td style="color:' + color + '">' + r.decision + '</td><td>' + r.count + '</td></tr>';
    }
    html += '</tbody></table>';
    document.getElementById('modalContent').innerHTML = html;
    modal.classList.add('active');
  };

  async function refreshAll() {
    await Promise.all([loadOverview(), loadTimeline(), loadLeaderboard(), loadStream(false), loadPolicies(), loadActions(), loadSankey(), loadActionOptions(), loadTree(), loadRoles(), loadRoleTimeline()]);
  }

  // Initial load (default: last hour)
  timeTo = Math.floor(Date.now() / 1000);
  timeFrom = timeTo - 3600;
  refreshAll();
  refreshTimer = setInterval(refreshAll, REFRESH_MS);
})();
</script>
</body>
</html>`;
}
