// Builds an element with optional inline style and text. Text always goes in
// via textContent, so breach names and error messages can't inject markup.
function el(tag, { className, style, text } = {}) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (style) node.style.cssText = style;
  if (text !== undefined) node.textContent = text;
  return node;
}

document.getElementById('breachForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('bc-email').value;
  const btn = document.getElementById('bc-submit');
  const resultBox = document.getElementById('bc-result');

  btn.disabled = true;
  btn.textContent = 'Checking...';
  resultBox.style.display = 'none';

  try {
    const turnstileToken = await Turnstile.token(e.target);
    const res = await fetch('/api/breach-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, turnstileToken }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Something went wrong.');

    if (data.found) {
      const count = data.breaches.length;
      const list = el('ul', { style: 'margin:0;padding-left:18px;color:var(--text);font-size:14px;line-height:1.8;' });
      data.breaches.forEach(b => list.appendChild(el('li', { text: b })));
      resultBox.replaceChildren(
        el('div', { className: 'tag crit', style: 'margin-bottom:14px;', text: `${count} breach${count === 1 ? '' : 'es'} found` }),
        el('p', {
          style: 'color:var(--text-muted);font-size:14px;line-height:1.6;margin:0 0 12px;',
          text: 'This email appeared in the following known breaches. If you reused a password from any of these anywhere else, change it now.',
        }),
        list,
      );
    } else {
      resultBox.replaceChildren(
        el('div', { className: 'tag', style: 'margin-bottom:14px;', text: 'No known breaches found' }),
        el('p', {
          style: 'color:var(--text-muted);font-size:14px;line-height:1.6;margin:0;',
          text: "This email doesn't appear in any breaches in the current database. That's good news, but it isn't a guarantee — check back periodically.",
        }),
      );
    }
    resultBox.style.display = 'block';
  } catch (err) {
    resultBox.replaceChildren(el('p', { style: 'color:var(--crit);font-size:14px;', text: err.message }));
    resultBox.style.display = 'block';
  } finally {
    Turnstile.reset(e.target);
    btn.disabled = false;
    btn.textContent = 'Check now';
  }
});
