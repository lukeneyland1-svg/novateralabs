document.getElementById('breachForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('bc-email').value;
  const btn = document.getElementById('bc-submit');
  const resultBox = document.getElementById('bc-result');

  btn.disabled = true;
  btn.textContent = 'Checking...';
  resultBox.style.display = 'none';

  try {
    const res = await fetch('/api/breach-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Something went wrong.');

    if (data.found) {
      resultBox.innerHTML = `
        <div class="tag crit" style="margin-bottom:14px;">${data.breaches.length} breach${data.breaches.length === 1 ? '' : 'es'} found</div>
        <p style="color:var(--text-muted);font-size:14px;line-height:1.6;margin:0 0 12px;">
          This email appeared in the following known breaches. If you reused a password from any of these anywhere else, change it now.
        </p>
        <ul style="margin:0;padding-left:18px;color:var(--text);font-size:14px;line-height:1.8;">
          ${data.breaches.map(b => `<li>${b}</li>`).join('')}
        </ul>
      `;
    } else {
      resultBox.innerHTML = `
        <div class="tag" style="margin-bottom:14px;">No known breaches found</div>
        <p style="color:var(--text-muted);font-size:14px;line-height:1.6;margin:0;">
          This email doesn't appear in any breaches in the current database. That's good news, but it isn't a guarantee — check back periodically.
        </p>
      `;
    }
    resultBox.style.display = 'block';
  } catch (err) {
    resultBox.innerHTML = `<p style="color:var(--crit);font-size:14px;">${err.message}</p>`;
    resultBox.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Check now';
  }
});
