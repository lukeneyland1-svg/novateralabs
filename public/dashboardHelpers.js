/* Pure formatting/escaping helpers shared by the dashboard page.
   Kept dependency-free (no DOM, no fetch) so they can run both in the
   browser (as globals, via a plain <script> tag) and under Node's test
   runner (via require()) without any build step. */
(function (global) {
  function escapeHtml(s){
    return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function relativeTime(iso){
    const diffMs = Date.now() - new Date(iso).getTime();
    const mins = Math.round(diffMs / 60000);
    if(mins < 1) return 'just now';
    if(mins < 60) return `${mins}m ago`;
    const hrs = Math.round(mins/60);
    if(hrs < 24) return `${hrs}h ago`;
    return `${Math.round(hrs/24)}d ago`;
  }

  function sparkPoints(arr, histLen){
    const w = 120, h = 30, max = 100;
    return arr.map((v,i) => {
      const x = (i/(histLen-1)) * w;
      const y = h - (Math.min(100,Math.max(0,v))/max) * h;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');
  }

  function statusPill(status){
    const s = (status || '').toLowerCase();
    if(s === 'running' || s === 'success') return 'success';
    if(s === 'failed' || s === 'error') return 'failed';
    return 'paused';
  }

  function formatDateTime(iso){
    if(!iso || iso === '—') return '—';
    const d = new Date(iso);
    if(isNaN(d.getTime())) return iso;
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: 'numeric', minute: '2-digit'
    });
  }

  function renderAttackChart(buckets){
    const width = 300, height = 50;
    const max = Math.max(...buckets, 1);
    const barGap = 2;
    const barWidth = (width / buckets.length) - barGap;
    const bars = buckets.map((v, i) => {
      const barHeight = (v / max) * height;
      const x = i * (width / buckets.length);
      const y = height - barHeight;
      return `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barWidth.toFixed(1)}" height="${barHeight.toFixed(1)}" fill="var(--crit)" opacity="0.85" rx="2"/>`;
    }).join('');
    return `<svg viewBox="0 0 ${width} ${height}" style="width:100%;height:50px;display:block;margin:10px 0;">${bars}</svg>`;
  }

  const helpers = { escapeHtml, relativeTime, sparkPoints, statusPill, formatDateTime, renderAttackChart };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = helpers;
  } else {
    Object.assign(global, helpers);
  }
})(typeof window !== 'undefined' ? window : globalThis);
