async function fetchStatus(){
  try{
    const res = await fetch('/api/status');
    const data = await res.json();
    renderStatus(data);
  } catch(err){
    document.getElementById('overallStatusText').textContent = 'Could not load status';
    document.getElementById('overallStatusTag').textContent = 'Unknown';
  }
}

function renderStatus(data){
  const textEl = document.getElementById('overallStatusText');
  const tagEl = document.getElementById('overallStatusTag');
  const operational = data.overall === 'operational';

  textEl.textContent = operational ? 'All Systems Operational' : 'Degraded Performance';
  tagEl.textContent = operational ? 'Operational' : 'Degraded';
  tagEl.className = operational ? 'tag' : 'tag warn';

  document.getElementById('componentsList').innerHTML = data.components.map(c => {
    const dotClass = c.isUp === null ? 'low' : (c.isUp ? 'low' : 'crit');
    const stateText = c.isUp === null ? 'No data yet' : (c.isUp ? 'Operational' : 'Down');
    const uptimeText = c.uptimePercent === null ? '' : ` <span style="color:var(--text-dim);">— ${c.uptimePercent.toFixed(2)}% over 30 days</span>`;
    return `
      <div class="alert">
        <span class="sev-dot ${dotClass}"></span>
        <span class="alert-msg"><b>${c.name}</b> — ${stateText}${uptimeText}</span>
      </div>
    `;
  }).join('');
}

fetchStatus();
setInterval(fetchStatus, 60000);
