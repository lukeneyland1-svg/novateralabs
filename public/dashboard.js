const root = document.documentElement;

/* ---------------- Clock ---------------- */
function tickClock(){
  const d = new Date();
  const hh = String(d.getUTCHours()).padStart(2,'0');
  const mm = String(d.getUTCMinutes()).padStart(2,'0');
  const ss = String(d.getUTCSeconds()).padStart(2,'0');
  document.getElementById('clock').textContent = `${hh}:${mm}:${ss} UTC`;
}
tickClock();
setInterval(tickClock, 1000);

/* ---------------- Gauges ---------------- */
const gaugeIds = { cpu:'cpuArc', ram:'ramArc', load:'tempArc' };
const gaugeValIds = { cpu:'cpuGaugeVal', ram:'ramGaugeVal', load:'tempGaugeVal' };
const gaugeLengths = {};
Object.keys(gaugeIds).forEach(k => {
  const path = document.getElementById(gaugeIds[k]);
  const len = path.getTotalLength();
  gaugeLengths[k] = len;
  path.style.strokeDasharray = len;
  path.style.strokeDashoffset = len;
});

function colorFor(value){
  const s = getComputedStyle(root);
  if(value >= 90) return s.getPropertyValue('--crit');
  if(value >= 70) return s.getPropertyValue('--warn');
  return s.getPropertyValue('--accent');
}

function setGauge(metric, pctValue, displayText){
  const pct = Math.min(1, Math.max(0, pctValue / 100));
  const len = gaugeLengths[metric];
  const path = document.getElementById(gaugeIds[metric]);
  path.style.strokeDashoffset = len * (1 - pct);
  path.style.stroke = colorFor(pctValue);
  document.getElementById(gaugeValIds[metric]).textContent = displayText;
}

/* ---------------- Sparkline history (client-side rolling window) ---------------- */
const history = { cpu: [], ram: [], disk: [] };
const HIST_LEN = 24;

function pushHistory(k, value){
  history[k].push(value);
  if(history[k].length > HIST_LEN) history[k].shift();
}

function updatePerfTag(cpu, ram, disk){
  const worst = Math.max(cpu, ram, disk);
  const tag = document.getElementById('perfTag');
  if(worst >= 90){ tag.textContent='Elevated'; tag.className='tag crit'; }
  else if(worst >= 70){ tag.textContent='Busy'; tag.className='tag warn'; }
  else { tag.textContent='Stable'; tag.className='tag'; }
}

function updateHealthTag(cpu, ram, loadPct){
  const worst = Math.max(cpu, ram, loadPct);
  const tag = document.getElementById('healthTag');
  if(worst >= 90){ tag.textContent='Degraded'; tag.className='tag crit'; }
  else if(worst >= 70){ tag.textContent='Elevated'; tag.className='tag warn'; }
  else { tag.textContent='Nominal'; tag.className='tag'; }
}

function setOffline(){
  const healthTag = document.getElementById('healthTag');
  healthTag.textContent = 'Offline';
  healthTag.className = 'tag crit';
  const perfTag = document.getElementById('perfTag');
  perfTag.textContent = 'No data';
  perfTag.className = 'tag crit';
}

/* ---------------- Poll: /api/dashboard ---------------- */
async function fetchDashboard(){
  try{
    const res = await fetch('/api/dashboard');
    if(!res.ok) throw new Error('bad response');
    const { system, metrics } = await res.json();

    const cpu = system.cpu_load ?? 0;
    const ram = system.ram_usage ?? 0;
    const diskPct = metrics.disk?.total ? (metrics.disk.used / metrics.disk.total) * 100 : 0;

    const loadAvg = system.load_avg;
    const cpuCount = system.cpu_count || 1;
    const hasLoad = typeof loadAvg === 'number';
    const loadPct = hasLoad ? (loadAvg / cpuCount) * 100 : 0;

    setGauge('cpu', cpu, Math.round(cpu));
    setGauge('ram', ram, Math.round(ram));
    if(hasLoad){
      setGauge('load', loadPct, loadAvg.toFixed(2));
    } else {
      document.getElementById('tempGaugeVal').textContent = 'N/A';
      document.getElementById('tempArc').style.strokeDashoffset = gaugeLengths.load;
    }

    document.getElementById('uptime').textContent = system.uptime ?? '—';
    document.getElementById('battery').textContent = system.battery ?? 'N/A';
    const osRow = document.querySelector('.meta-list > div:first-child dd');
    if(osRow) osRow.textContent = system.os ?? '—';

    pushHistory('cpu', cpu);
    pushHistory('ram', ram);
    pushHistory('disk', diskPct);
    document.getElementById('cpuSpark').setAttribute('points', sparkPoints(history.cpu, HIST_LEN));
    document.getElementById('ramSpark').setAttribute('points', sparkPoints(history.ram, HIST_LEN));
    document.getElementById('diskSpark').setAttribute('points', sparkPoints(history.disk, HIST_LEN));
    document.getElementById('cpuSparkVal').textContent = Math.round(cpu)+'%';
    document.getElementById('ramSparkVal').textContent = Math.round(ram)+'%';
    document.getElementById('diskSparkVal').textContent = Math.round(diskPct)+'%';

    updatePerfTag(cpu, ram, diskPct);
    updateHealthTag(cpu, ram, hasLoad ? loadPct : 0);
  } catch(err){
    console.error('Dashboard fetch failed:', err);
    setOffline();
  }
}
fetchDashboard();
setInterval(fetchDashboard, 4000);

/* ---------------- Poll: /api/security ---------------- */
const SEV_CLASS = { critical: 'crit', high: 'warn', medium: 'info', low: 'low' };

function renderAlertFeed(alerts){
  const feed = document.getElementById('alertFeed');
  if(!alerts.length){
    feed.innerHTML = `<div class="alert"><span class="sev-dot low"></span><span class="alert-time">—</span><span class="alert-msg">No security events recorded.</span></div>`;
  } else {
    feed.innerHTML = alerts.slice(0, 12).map(a => `
      <div class="alert">
        <span class="sev-dot ${SEV_CLASS[a.severity] || 'low'}"></span>
        <span class="alert-time">${relativeTime(a.timestamp)}</span>
        <span class="alert-msg"><b>${escapeHtml(a.type || 'Event')}</b> — ${escapeHtml(a.message)}${a.ip ? ` <span style="color:var(--text-dim)">(${escapeHtml(a.ip)})</span>` : ''}</span>
      </div>
    `).join('');
  }

  const active = alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length;
  const tag = document.getElementById('alertTag');
  tag.textContent = active === 0 ? 'All clear' : `${active} active`;
  tag.className = active === 0 ? 'tag' : (alerts.some(a=>a.severity==='critical') ? 'tag crit' : 'tag warn');
}

function connectAlertStream(){
  const es = new EventSource('/api/security/stream');
  let connected = false;

  es.onmessage = (e) => {
    connected = true;
    renderAlertFeed(JSON.parse(e.data));
  };

  es.onerror = () => {
    if(!connected){
      document.getElementById('alertFeed').innerHTML = `<div class="alert"><span class="sev-dot crit"></span><span class="alert-time">—</span><span class="alert-msg">Couldn't reach the security feed.</span></div>`;
    }
    // EventSource auto-reconnects; `connected` resets are handled by the next onmessage.
  };
}
connectAlertStream();

/* ---------------- Infrastructure simulation ---------------- */
const simCpuBtn = document.getElementById('simCpuBtn');
const simAttackBtn = document.getElementById('simAttackBtn');
const simResult = document.getElementById('simResult');

if(simCpuBtn){
  simCpuBtn.addEventListener('click', async () => {
    simCpuBtn.disabled = true;
    simCpuBtn.textContent = 'Running for 10s...';
    simResult.style.display = 'block';
    simResult.innerHTML = `<p style="color:var(--text-muted);font-size:13.5px;">CPU spike running across all cores — watch the LOAD gauge above update in real time...</p>`;
    try {
      const res = await fetch('/api/simulation/cpu-spike', { method: 'POST' });
      const data = await res.json();
      if(!res.ok) throw new Error(data.error || 'Simulation failed.');

      simResult.innerHTML = `
        <div class="panel" style="padding:14px 16px;">
          <p style="font-size:13.5px;color:var(--text);margin:0 0 8px;">
            Ran a ${data.durationSeconds}-second load test across ${data.workerCount} CPU core${data.workerCount === 1 ? '' : 's'}.
          </p>
          <p style="font-size:13.5px;margin:0;color:var(--accent);">
            <b>Load average:</b> ${data.beforeLoad.toFixed(2)} → ${data.afterLoad.toFixed(2)}
          </p>
        </div>
      `;
    } catch(err){
      simResult.innerHTML = `<p style="color:var(--crit);font-size:13.5px;">${escapeHtml(err.message)}</p>`;
    } finally {
      simCpuBtn.disabled = false;
      simCpuBtn.textContent = 'Simulate CPU load spike (10s)';
    }
  });
}

if(simAttackBtn){
  simAttackBtn.addEventListener('click', async () => {
    simAttackBtn.disabled = true;
    simAttackBtn.textContent = 'Simulating...';
    try {
      const res = await fetch('/api/simulation/attack', { method: 'POST' });
      const data = await res.json();
      if(!res.ok) throw new Error(data.error || 'Failed to run simulation.');

      simResult.style.display = 'block';
      simResult.innerHTML = `
        <div class="panel" style="padding:14px 16px;">
          <p style="font-size:13.5px;color:var(--text);margin:0 0 8px;">
            Simulated <b>${data.attemptCount} failed login attempts</b> from <code>${data.simulatedIp}</code> (a reserved documentation IP, not a real address) over ${data.windowSeconds} seconds.
          </p>
          ${renderAttackChart(data.buckets)}
          <p style="font-size:13.5px;margin:8px 0;color:${data.detected ? 'var(--accent)' : 'var(--crit)'};">
            <b>${data.detected ? '✓ Detected' : '✗ Not detected'}</b> — ${data.flaggedCount} of ${data.attemptCount} events classified as high-severity${data.detected ? ', crossing the brute-force threshold.' : ', below the detection threshold.'}
          </p>
          <p style="font-family:'IBM Plex Mono',monospace;font-size:11.5px;color:var(--text-dim);margin:0;">
            Sample: ${escapeHtml(data.sampleEvents[0].message)}
          </p>
        </div>
      `;
    } catch(err){
      simResult.style.display = 'block';
      simResult.innerHTML = `<p style="color:var(--crit);font-size:13.5px;">${escapeHtml(err.message)}</p>`;
    } finally {
      simAttackBtn.disabled = false;
      simAttackBtn.textContent = 'Simulate brute-force attack';
    }
  });
}

/* ---------------- Automation tasks ---------------- */
let tasks = [];

function renderTasks(){
  const body = document.getElementById('taskBody');
  if(!tasks.length){
    body.innerHTML = `<tr><td colspan="6" style="color:var(--text-dim);">No automation tasks yet.</td></tr>`;
    return;
  }
  body.innerHTML = tasks.map(t => `
    <tr>
      <td class="task-name">${escapeHtml(t.name)}</td>
      <td class="task-sched">${escapeHtml(t.schedule)}</td>
      <td><span class="pill ${statusPill(t.status)}">${escapeHtml(t.status)}</span></td>
      <td class="task-lastrun">${escapeHtml(formatDateTime(t.lastRun))}</td>
      <td class="task-lastrun">${escapeHtml(formatDateTime(t.nextRun))}</td>
      <td class="task-lastrun" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(t.lastResult || '')}">${escapeHtml(t.lastResult || '—')}</td>
    </tr>
  `).join('');
}

async function fetchTasks(){
  try{
    const res = await fetch('/api/automation');
    if(!res.ok) throw new Error('bad response');
    const data = await res.json();
    tasks = data.tasks || [];
    renderTasks();
  } catch(err){
    console.error('Automation fetch failed:', err);
    document.getElementById('taskBody').innerHTML = `<tr><td colspan="6" style="color:var(--crit);">Couldn't reach the automation service.</td></tr>`;
  }
}
fetchTasks();

document.getElementById('refreshBtn').addEventListener('click', (e) => {
  e.currentTarget.classList.remove('spinning');
  void e.currentTarget.offsetWidth;
  e.currentTarget.classList.add('spinning');
  fetchTasks();
  fetchDashboard();
  fetchAlerts();
});

/* ---------------- New automation modal ---------------- */
const automationModal = document.getElementById('automationModal');
const automationForm = document.getElementById('automationForm');
const autoFormError = document.getElementById('autoFormError');

function openAutomationModal(){
  automationForm.reset();
  autoFormError.classList.remove('show');
  automationModal.classList.add('open');
  document.getElementById('autoName').focus();
}
function closeAutomationModal(){ automationModal.classList.remove('open'); }

document.getElementById('newAutomationBtn').addEventListener('click', openAutomationModal);
document.getElementById('closeAutomationModal').addEventListener('click', closeAutomationModal);
document.getElementById('cancelAutomation').addEventListener('click', closeAutomationModal);
automationModal.addEventListener('click', (e) => { if(e.target === automationModal) closeAutomationModal(); });
document.addEventListener('keydown', (e) => { if(e.key === 'Escape') closeAutomationModal(); });

automationForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const name = document.getElementById('autoName').value.trim();
  const schedule = document.getElementById('autoSchedule').value.trim();
  const type = document.getElementById('autoType').value;

  try{
    const res = await fetch('/api/automation', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, schedule, type }),
    });
    const data = await res.json();
    if(!res.ok) throw new Error(data.error || 'Save failed');
    autoFormError.classList.remove('show');
    closeAutomationModal();
    fetchTasks();
  } catch(err){
    console.error(err);
    autoFormError.textContent = err.message;
    autoFormError.classList.add('show');
  }
});
