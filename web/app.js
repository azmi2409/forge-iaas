// forge-iaas dashboard: plain JS, no framework. Calls the REST API
// with the fiak_ key stored in localStorage. Read-first: no config
// editor exists here. State is always the API's redacted view.
(function () {
  'use strict';
  var keyInput = document.getElementById('key');
  var keyState = document.getElementById('keyState');
  var errorBox = document.getElementById('error');

  function getKey() { return localStorage.getItem('fiaas_key') || ''; }
  function showError(msg) {
    errorBox.hidden = !msg;
    errorBox.textContent = msg || '';
  }
  function api(path, opts) {
    opts = opts || {};
    var headers = { 'Content-Type': 'application/json' };
    var k = getKey();
    if (k) headers['Authorization'] = 'Bearer ' + k;
    return fetch(path, {
      method: opts.method || 'GET',
      headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined
    }).then(function (res) {
      return res.json().then(function (body) {
        if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
        return body;
      });
    });
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function showView(id) {
    ['workspacesView', 'workspaceView', 'runView', 'auditView'].forEach(function (v) {
      document.getElementById(v).hidden = (v !== id);
    });
  }

  function refreshKeyState() {
    keyState.textContent = getKey() ? 'Key saved in this browser.' : 'No key saved — API calls will be anonymous.';
  }
  keyInput.value = getKey();
  refreshKeyState();
  document.getElementById('saveKey').onclick = function () {
    if (keyInput.value.trim()) localStorage.setItem('fiaas_key', keyInput.value.trim());
    refreshKeyState(); showError('');
  };
  document.getElementById('clearKey').onclick = function () {
    localStorage.removeItem('fiaas_key'); keyInput.value = ''; refreshKeyState();
  };

  var currentWs = null;
  var currentRun = null;

  function loadWorkspaces() {
    showView('workspacesView'); showError('');
    api('/api/v1/organizations').then(function (orgs) {
      var list = orgs.organizations || [];
      var jobs = list.map(function (o) {
        return api('/api/v1/organizations/' + encodeURIComponent(o.slug) + '/workspaces')
          .then(function (w) { return { org: o, workspaces: w.workspaces || [] }; });
      });
      return Promise.all(jobs);
    }).then(function (groups) {
      var html = '';
      groups.forEach(function (g) {
        html += '<h3>' + esc(g.org.name) + ' (' + esc(g.org.slug) + ')</h3>';
        if (!g.workspaces.length) html += '<p>No workspaces.</p>';
        g.workspaces.forEach(function (w) {
          html += '<div class="card"><h4>' + esc(w.name) + '</h4><p>slug: ' + esc(w.slug) +
            ' · mode: ' + esc(w.execution_mode) + ' · auto-apply: ' + (w.auto_apply ? 'on' : 'off') +
            '</p><button data-ws="' + esc(w.id) + '">Open</button></div>';
        });
      });
      document.getElementById('workspaces').innerHTML = html || '<p>No organizations yet.</p>';
      document.querySelectorAll('[data-ws]').forEach(function (b) {
        b.onclick = function () { loadWorkspace(b.getAttribute('data-ws')); };
      });
    }).catch(function (e) { showError('Failed to load workspaces: ' + e.message); });
  }

  function loadWorkspace(wsId) {
    showView('workspaceView'); showError('');
    currentWs = wsId;
    api('/api/v1/workspaces/' + encodeURIComponent(wsId)).then(function (w) {
      document.getElementById('wsTitle').textContent = w.name + ' (' + w.slug + ')';
      document.getElementById('wsMeta').innerHTML = '<p>mode: ' + esc(w.execution_mode) +
        ' · auto-apply: ' + (w.auto_apply ? 'on' : 'off') +
        (w.vcs_repo ? ' · repo: ' + esc(w.vcs_repo) : '') + '</p>';
      return api('/api/v1/workspaces/' + encodeURIComponent(wsId) + '/runs');
    }).then(function (r) {
      var html = '';
      (r.runs || []).forEach(function (run) {
        html += '<div class="card"><h4>' + esc(run.type) + ' run</h4><p>id: ' + esc(run.id) +
          ' · status: <span class="badge">' + esc(run.status) + '</span>' +
          (run.policy ? ' · policy: ' + esc(run.policy.result) : '') +
          '</p><button data-run="' + esc(run.id) + '">Open run</button></div>';
      });
      document.getElementById('runs').innerHTML = html || '<p>No runs yet.</p>';
      document.querySelectorAll('[data-run]').forEach(function (b) {
        b.onclick = function () { loadRun(b.getAttribute('data-run')); };
      });
      return api('/api/v1/workspaces/' + encodeURIComponent(wsId) + '/state/versions');
    }).then(function (sv) {
      var html = (sv.versions || []).map(function (v) {
        return '<div class="card">version ' + esc(v.version) + ' · id ' + esc(v.id) +
          ' · ' + esc(v.created_at) + ' (metadata only — raw state is never shown)</div>';
      }).join('');
      document.getElementById('stateVersions').innerHTML = html || '<p>No state versions.</p>';
      return api('/api/v1/workspaces/' + encodeURIComponent(wsId) + '/state');
    }).then(function (st) {
      var html = '<p>state version ' + esc(st.state_version) + '</p><ul>' +
        (st.resources || []).map(function (r) {
          return '<li>' + esc(r.address) + ' (' + esc(r.type) + ' / ' + esc(r.name) + ')</li>';
        }).join('') + '</ul>';
      document.getElementById('stateCurrent').innerHTML = html;
    }).catch(function (e) {
      // Missing state is normal for a fresh workspace; surface other errors.
      if (!/no state/.test(e.message)) showError('Failed to load workspace: ' + e.message);
      else document.getElementById('stateCurrent').innerHTML = '<p>No state yet.</p>';
    });
  }

  function planDiffHtml(plan) {
    if (!plan) return '<p>No plan summary yet (run may still be queued).</p>';
    var rows = (plan.resources || []).map(function (r) {
      return '<tr><td><span class="badge ' + esc(r.action) + '">' + esc(r.action) +
        '</span></td><td>' + esc(r.address) + '</td><td>' + esc(r.type) + '</td></tr>';
    }).join('');
    return '<p>add ' + plan.add + ' · change ' + plan.change + ' · destroy ' + plan.destroy +
      '</p><table><tr><th>action</th><th>address</th><th>type</th></tr>' + rows + '</table>' +
      '<p class="note">Attribute values are never shown here; sensitive attributes are redacted server-side.</p>';
  }

  function loadRun(runId) {
    showView('runView'); showError('');
    currentRun = runId;
    api('/api/v1/runs/' + encodeURIComponent(runId)).then(function (run) {
      document.getElementById('runTitle').textContent = run.type + ' run ' + run.id;
      var gate = 'Approval gate: ';
      if (run.status === 'awaiting_approval') {
        gate += run.policy && run.policy.result === 'advisory'
          ? 'policy is advisory — approval needs an override note and an apply-scoped key.'
          : run.policy && run.policy.result === 'fail'
            ? 'policy FAILED — apply is blocked.'
            : 'awaiting approval — approve with an apply-scoped key. Plan-scoped keys can never approve.';
      } else if (run.status === 'applied') gate += 'already applied.';
      else gate += 'status ' + run.status + ' — nothing is applied unless status is applied.';
      document.getElementById('runMeta').innerHTML = '<p>status: <span class="badge">' + esc(run.status) +
        '</span> · workspace: ' + esc(run.workspace_id) +
        (run.policy ? ' · policy: ' + esc(run.policy.result) : '') +
        (run.cost ? ' · est. $' + esc(run.cost.monthly_usd) + '/mo (estimate, not a bill)' : '') +
        '</p><p>' + esc(gate) + '</p>';
      document.getElementById('planDiff').innerHTML = planDiffHtml(run.plan);
    }).catch(function (e) { showError('Failed to load run: ' + e.message); });
  }

  document.getElementById('approveBtn').onclick = function () {
    if (!currentRun) return;
    var body = {};
    var note = document.getElementById('overrideNote').value.trim();
    if (note) body.override_note = note;
    api('/api/v1/runs/' + encodeURIComponent(currentRun) + '/approve', { method: 'POST', body: body })
      .then(function (r) { showError(''); alert('Approved — apply run ' + r.apply_run_id + ' queued.'); loadRun(currentRun); })
      .catch(function (e) { showError('Approve failed: ' + e.message); });
  };
  document.getElementById('discardBtn').onclick = function () {
    if (!currentRun) return;
    api('/api/v1/runs/' + encodeURIComponent(currentRun) + '/discard', { method: 'POST', body: {} })
      .then(function () { showError(''); loadRun(currentRun); })
      .catch(function (e) { showError('Discard failed: ' + e.message); });
  };
  document.getElementById('backToWorkspaces').onclick = loadWorkspaces;
  document.getElementById('backToWorkspace').onclick = function () { if (currentWs) loadWorkspace(currentWs); };
  document.getElementById('navWorkspaces').onclick = loadWorkspaces;
  document.getElementById('navAudit').onclick = function () {
    showView('auditView'); showError('');
    api('/api/v1/audit').then(function (a) {
      document.getElementById('audit').innerHTML = (a.audit || []).map(function (e) {
        return '<div class="card"><p>' + esc(e.created_at) + ' · ' + esc(e.actor) + ' · ' + esc(e.action) +
          '</p><p>' + esc(e.detail) + '</p></div>';
      }).join('') || '<p>No audit entries.</p>';
    }).catch(function (e) { showError('Failed to load audit: ' + e.message); });
  };

  loadWorkspaces();
})();
