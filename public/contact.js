document.getElementById('contactForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = e.target;
  const btn = form.querySelector('button[type="submit"]');
  const status = document.getElementById('cf-status');

  const payload = {
    name: document.getElementById('cf-name').value,
    email: document.getElementById('cf-email').value,
    message: document.getElementById('cf-message').value,
    website: document.getElementById('cf-website').value,
  };

  btn.disabled = true;
  btn.textContent = 'Sending...';
  status.style.display = 'none';

  try {
    const res = await fetch('/api/contact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Something went wrong.');

    status.textContent = 'Message sent — thanks for reaching out! I\'ll get back to you soon.';
    status.style.color = 'var(--accent)';
    status.style.display = 'block';
    form.reset();
  } catch (err) {
    status.textContent = err.message;
    status.style.color = 'var(--crit)';
    status.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Send message';
  }
});
