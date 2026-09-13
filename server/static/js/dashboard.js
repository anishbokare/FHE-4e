/**
 * Confidential SIEM Dashboard Controller.
 * Handles real-time zero-knowledge pipeline visualization, attack simulations,
 * MITRE 160-rule circuit filtering, and compliance auditing.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const gpuNameLabel = document.getElementById('gpu-name-label');
  const statLatency = document.getElementById('stat-latency');
  const selectBatchSize = document.getElementById('select-batch-size');
  const clientTelemetryBox = document.getElementById('client-telemetry-box');
  const msspCiphertextBox = document.getElementById('mssp-ciphertext-box');
  const cipherCodePreview = document.getElementById('cipher-code-preview');
  const byteCounter = document.getElementById('byte-counter');
  const alertsContainer = document.getElementById('alerts-container');
  const activeAlertsPill = document.getElementById('active-alerts-pill');
  const rulesTableBody = document.getElementById('rules-table-body');
  const ruleSearchInput = document.getElementById('rule-search-input');
  const tacticFilter = document.getElementById('tactic-filter');
  const severityFilter = document.getElementById('severity-filter');
  const btnRunBenchmark = document.getElementById('btn-run-benchmark');
  const btnComplianceModal = document.getElementById('btn-compliance-modal');
  const complianceModal = document.getElementById('compliance-modal');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const complianceModalBody = document.getElementById('compliance-modal-body');

  // Timings
  const timeEnc = document.getElementById('time-enc');
  const timeRules = document.getElementById('time-rules');
  const timeMl = document.getElementById('time-ml');
  const timeTotal = document.getElementById('time-total');
  const pipelineSlaBadge = document.getElementById('pipeline-sla-badge');

  let allRules = [];

  // 1. Initialize System Status
  async function fetchSystemStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      if (data.acceleration_device) {
        gpuNameLabel.textContent = data.acceleration_device;
      }
    } catch (err) {
      console.warn('Status fetch failed:', err);
    }
  }

  // 2. Load 160 Detection Rules Catalog
  async function fetchRules() {
    try {
      const res = await fetch('/api/rules');
      const data = await res.json();
      allRules = [];
      for (const [tactic, rules] of Object.entries(data.tactics)) {
        allRules.push(...rules);
      }
      renderRulesTable(allRules);
    } catch (err) {
      rulesTableBody.innerHTML = `<tr><td colspan="8" class="text-center text-red">Failed to load detection rules.</td></tr>`;
    }
  }

  function renderRulesTable(rules) {
    if (!rules.length) {
      rulesTableBody.innerHTML = `<tr><td colspan="8" class="text-center">No rules match search filter.</td></tr>`;
      return;
    }

    rulesTableBody.innerHTML = rules.map(r => {
      const sevClass = r.severity === 'CRITICAL' ? 'sev-critical' : (r.severity === 'HIGH' ? 'sev-high' : 'sev-medium');
      const compStr = r.compliance_controls.join(' &bull; ');
      const flagsStr = r.required_flags.join(' &bull; ');

      return `
        <tr>
          <td><strong class="text-cyan">${r.rule_id}</strong></td>
          <td><strong>${escapeHtml(r.name)}</strong></td>
          <td><span class="text-muted">${escapeHtml(r.tactic)}</span></td>
          <td><code class="text-cyan">${escapeHtml(r.technique_id)}</code></td>
          <td><span class="sev-badge ${sevClass}">${r.severity}</span></td>
          <td class="text-muted">${compStr}</td>
          <td><code style="font-size:0.68rem; color:#88a0c4;">${flagsStr}</code></td>
          <td><span class="rule-active-pill">ACTIVE CIRCUIT</span></td>
        </tr>
      `;
    }).join('');
  }

  // Filter Rules Table
  function filterRules() {
    const searchVal = (ruleSearchInput.value || '').toLowerCase();
    const tacticVal = tacticFilter.value;
    const sevVal = severityFilter.value;

    const filtered = allRules.filter(r => {
      const matchSearch = r.name.toLowerCase().includes(searchVal) ||
                          r.technique_id.toLowerCase().includes(searchVal) ||
                          r.rule_id.toLowerCase().includes(searchVal) ||
                          r.compliance_controls.some(c => c.toLowerCase().includes(searchVal));
      const matchTactic = (tacticVal === 'ALL') || (r.tactic === tacticVal);
      const matchSev = (sevVal === 'ALL') || (r.severity === sevVal);
      return matchSearch && matchTactic && matchSev;
    });

    renderRulesTable(filtered);
  }

  ruleSearchInput.addEventListener('input', filterRules);
  tacticFilter.addEventListener('change', filterRules);
  severityFilter.addEventListener('change', filterRules);

  // 3. Attack Simulation Trigger
  const attackButtons = document.querySelectorAll('.attack-btn');
  attackButtons.forEach(btn => {
    btn.addEventListener('click', async () => {
      const attackType = btn.getAttribute('data-attack');
      const batchSize = parseInt(selectBatchSize.value, 10) || 4;

      // Highlight active button
      attackButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      // Update UI state to loading
      cipherCodePreview.textContent = '// INGESTING STREAM & EXECUTING 160 RULES IN ZERO-KNOWLEDGE...';
      clientTelemetryBox.innerHTML = '<div class="placeholder-telemetry">Encrypting logs on enterprise edge...</div>';

      try {
        const res = await fetch('/api/simulate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            attack_type: attackType,
            batch_size: batchSize,
          }),
        });

        const data = await res.json();
        renderSimulationResults(data);
      } catch (err) {
        alert('Simulation failed: ' + err.message);
      }
    });
  });

  function renderSimulationResults(data) {
    const events = data.events || [];
    if (!events.length) return;

    const primaryEvent = events[0];

    // Timings
    const tEnc = primaryEvent.timings_ms.client_encryption_ms;
    const tRules = primaryEvent.timings_ms.rules_circuit_ms;
    const tMl = primaryEvent.timings_ms.ml_inference_ms;
    const tTotal = data.total_pipeline_time_ms;

    timeEnc.textContent = `${tEnc} ms`;
    timeRules.textContent = `${tRules} ms`;
    timeMl.textContent = `${tMl} ms`;
    timeTotal.textContent = `${tTotal} ms`;

    statLatency.textContent = `${primaryEvent.timings_ms.cloud_eval_ms} ms`;

    if (tTotal < 500) {
      pipelineSlaBadge.textContent = `SLA PASS (${tTotal}ms < 500ms)`;
      pipelineSlaBadge.style.color = 'var(--accent-green)';
    } else {
      pipelineSlaBadge.textContent = `SLA EXCEEDED (${tTotal}ms)`;
      pipelineSlaBadge.style.color = 'var(--accent-red)';
    }

    // 1. Client View (Plaintext Telemetry)
    clientTelemetryBox.innerHTML = events.map((ev, i) => {
      const p = ev.client_plaintext_view;
      return `
        <div class="telemetry-item">
          <div class="tel-header">
            <span>[${ev.event_id}] ${escapeHtml(p.category)} &bull; ${escapeHtml(p.protocol)}:${p.port}</span>
            <span class="text-green">SK_LOCAL</span>
          </div>
          <div class="tel-grid">
            <div>Auth: <span class="tel-val">${p.auth_status}</span></div>
            <div>Role: <span class="tel-val">${p.user_role}</span></div>
            <div>Source: <span class="tel-val">${p.src_ip_type}</span></div>
            <div>Failed Logins: <span class="tel-val">${p.failed_logins}</span></div>
            <div>Entropy: <span class="tel-val">${p.file_entropy} / 8.0</span></div>
            <div>Beacon Jitter: <span class="tel-val">${p.beacon_jitter}</span></div>
          </div>
        </div>
      `;
    }).join('');

    // 2. MSSP Cloud View (Ciphertext Only)
    const totalBytes = events.reduce((acc, ev) => acc + ev.mssp_cloud_encrypted_view.ckks_ciphertext_length, 0);
    byteCounter.textContent = `${(totalBytes / 1024).toFixed(1)} KB Ingested`;

    cipherCodePreview.innerHTML = events.map(ev => {
      const c = ev.mssp_cloud_encrypted_view;
      return `[EVENT: ${ev.event_id}]
SEAL_CKKS_SLOT_PACKING [8192 deg]:
${c.ckks_ciphertext_sample}
TFHE_LWE_GATES: ${c.tfhe_flags_encrypted_count} Encrypted Bit Circuits Active
PLAINTEXT_REVEALED: ${c.plaintext_revealed_to_cloud ? 'TRUE' : 'FALSE (ZERO-KNOWLEDGE)'}
CLOUD_SECRET_KEY: ${c.cloud_has_secret_key ? 'YES' : 'NONE (MATHEMATICALLY BLIND)'}
----------------------------------------------------------------`;
    }).join('\n\n');

    // 3. Client Decrypted Threat Alerts
    const allAlerts = [];
    events.forEach(ev => {
      const d = ev.client_decrypted_detection;
      if (d.threat_detected) {
        allAlerts.push({
          event_id: ev.event_id,
          ml_score: d.ml_anomaly_score,
          ml_alert: d.ml_anomaly_alert,
          rules: d.matched_rules,
          max_severity: d.max_severity,
        });
      }
    });

    activeAlertsPill.textContent = `${allAlerts.length} Incident(s) Detected`;
    activeAlertsPill.className = allAlerts.length > 0 ? 'alert-count-pill' : 'alert-count-pill text-green';

    if (allAlerts.length === 0) {
      alertsContainer.innerHTML = `
        <div class="no-alerts-state" style="color: var(--accent-green);">
          &check; ZERO THREATS DETECTED &bull; Homomorphic ML and 160 Rule circuits confirmed telemetry within normal benign bounds.
        </div>
      `;
    } else {
      alertsContainer.innerHTML = allAlerts.map(alert => {
        const sevClass = alert.max_severity === 'CRITICAL' ? 'sev-critical' : (alert.max_severity === 'HIGH' ? 'sev-high' : 'sev-medium');
        const scorePercent = Math.min(100, Math.round(alert.ml_score * 100));

        const rulesList = alert.rules.length > 0
          ? alert.rules.map(r => `
              <div style="margin-top:6px; font-size:0.8rem; color:#fff;">
                &bull; <strong class="text-cyan">[${r.rule_id}]</strong> ${escapeHtml(r.name)} 
                <span class="sev-badge ${r.severity === 'CRITICAL' ? 'sev-critical' : 'sev-high'}">${r.severity}</span>
                <span class="text-muted" style="margin-left:8px;">MITRE ${r.technique_id} &bull; Depth ${r.circuit_depth}</span>
              </div>
            `).join('')
          : `<div class="text-muted" style="font-size:0.75rem; margin-top:4px;">No rule circuits triggered; anomaly detected by CKKS ML PolyNet.</div>`;

        return `
          <div class="alert-card">
            <div class="alert-top">
              <div class="alert-title-row">
                <span class="sev-badge ${sevClass}">${alert.max_severity}</span>
                <div class="alert-title">CONFIDENTIAL INCIDENT: ${alert.event_id}</div>
              </div>
              <div class="status-pill status-online" style="border-color:rgba(255,51,102,0.4); color:var(--accent-red); background:rgba(255,51,102,0.1);">
                BLIND DETECTION CONFIRMED
              </div>
            </div>

            <!-- ML Radar Bar -->
            <div class="ml-radar-bar">
              <span class="radar-label">CKKS Neural Anomaly Score:</span>
              <div class="radar-track">
                <div class="radar-fill" style="width: ${scorePercent}%;"></div>
              </div>
              <span class="radar-score">${alert.ml_score.toFixed(3)} (${scorePercent}%)</span>
            </div>

            <!-- Matched Rules Breakdown -->
            <div style="border-top:1px solid rgba(255,255,255,0.06); padding-top:8px;">
              <strong style="font-size:0.78rem; color:var(--text-muted); font-family:var(--font-mono);">
                MATCHED HOMOMORPHIC CIRCUITS (${alert.rules.length}):
              </strong>
              ${rulesList}
            </div>
          </div>
        `;
      }).join('');
    }
  }

  // 4. Live Benchmark Action
  btnRunBenchmark.addEventListener('click', async () => {
    btnRunBenchmark.disabled = true;
    btnRunBenchmark.textContent = 'Benchmarking...';

    try {
      const res = await fetch('/api/benchmark?batch_size=8&workers=4');
      const data = await res.json();
      alert(`FHE BENCHMARK RESULTS:\n\nBatch Size: ${data.batch_size} logs\nAvg Latency per Event: ${data.latency_per_event_ms} ms\nRules Latency: ${data.rules_latency_ms} ms (160 rules)\nML Latency: ${data.ml_latency_ms} ms (SEAL CKKS)\nThroughput: ${data.throughput_events_per_sec} events/sec\nSub-500ms SLA: ${data.sub_500ms_compliant ? 'PASS' : 'FAIL'}\nDevice: ${data.acceleration_device}`);
      statLatency.textContent = `${data.latency_per_event_ms} ms`;
    } catch (err) {
      alert('Benchmark error: ' + err.message);
    } finally {
      btnRunBenchmark.disabled = false;
      btnRunBenchmark.innerHTML = `
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
        </svg> Run Benchmark`;
    }
  });

  // 5. Compliance Modal
  btnComplianceModal.addEventListener('click', async () => {
    complianceModal.classList.add('open');
    complianceModalBody.innerHTML = '<p>Verifying zero-knowledge compliance posture...</p>';

    try {
      const res = await fetch('/api/compliance');
      const data = await res.json();

      let html = '';
      for (const [standard, details] of Object.entries(data.regulations)) {
        html += `
          <div style="background:rgba(255,255,255,0.03); border:1px solid var(--border-subtle); border-radius:8px; padding:16px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
              <strong style="color:var(--accent-cyan); font-size:1.1rem;">${standard} COMPLIANCE</strong>
              <span class="status-pill status-online">&check; ${details.status}</span>
            </div>
        `;

        const items = details.articles || details.rules || details.controls || [];
        items.forEach(item => {
          const title = item.article || item.section || item.control;
          html += `
            <div style="margin-top:8px; padding:8px; background:rgba(0,0,0,0.2); border-radius:6px;">
              <div style="font-weight:700; color:#fff; font-size:0.85rem;">${title}</div>
              <div style="color:var(--text-muted); font-size:0.78rem; margin-top:3px;">${item.evidence}</div>
            </div>
          `;
        });

        html += `</div>`;
      }

      complianceModalBody.innerHTML = html;
    } catch (err) {
      complianceModalBody.innerHTML = '<p class="text-red">Failed to load compliance report.</p>';
    }
  });

  btnCloseModal.addEventListener('click', () => {
    complianceModal.classList.remove('open');
  });

  window.addEventListener('click', (e) => {
    if (e.target === complianceModal) {
      complianceModal.classList.remove('open');
    }
  });

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // Initial Boot
  fetchSystemStatus();
  fetchRules();

  // Auto-trigger default Ransomware simulation after 1 second for rich instant impression
  setTimeout(() => {
    const btn = document.getElementById('btn-attack-ransomware');
    if (btn) btn.click();
  }, 1000);
});
