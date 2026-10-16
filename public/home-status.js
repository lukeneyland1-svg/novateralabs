// Homepage status panel — fed by the same real uptime checks as status.html.
async function loadHomeStatus(){
  const tag = document.getElementById('homeStatusTag');
  const text = document.getElementById('homeStatusText');
  try{
    const res = await fetch('/api/status');
    const data = await res.json();
    const site = data.components.find(c => c.name === 'Website');
    const operational = data.overall === 'operational';
    tag.textContent = operational ? 'Operational' : 'Degraded';
    tag.className = operational ? 'tag' : 'tag warn';
    text.textContent = !site || site.isUp === null ? 'No data yet' : (site.isUp ? `Up — ${site.responseTimeMs} ms` : 'Down');
    if (site && site.uptimePercent !== null) document.getElementById('homeUptime').textContent = `${site.uptimePercent.toFixed(2)}%`;
    if (site && site.checkedAt) {
      const mins = Math.round((Date.now() - new Date(site.checkedAt)) / 60000);
      document.getElementById('homeChecked').textContent = mins < 1 ? 'just now' : `${mins} min ago`;
    }
  } catch(err){
    tag.textContent = 'Unknown';
    tag.className = 'tag warn';
    text.textContent = 'Could not load status';
  }
}

loadHomeStatus();
setInterval(loadHomeStatus, 60000);
