document.getElementById('forgotForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const btn = document.getElementById('submitBtn');
  const msg = document.getElementById('formMessage');

  btn.disabled = true;
  btn.textContent = 'Sending...';
  try {
    const turnstileToken = await Turnstile.token(e.target);
    const res = await fetch('/api/auth/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, turnstileToken }),
    });
    // 429 = too many requests, 403 = bot check failed; show the server's message.
    if (res.status === 429 || res.status === 403) throw new Error((await res.json()).error);
    msg.style.color = 'var(--accent)';
    msg.textContent = "If that email matches an account, a reset link has been sent.";
    msg.style.display = 'block';
    btn.textContent = 'Sent';
  } catch (err) {
    Turnstile.reset(e.target);
    msg.style.color = 'var(--crit)';
    // Our own messages are plain Errors; network/JSON failures are TypeError/SyntaxError.
    msg.textContent = err.name === 'Error' ? err.message : 'Something went wrong. Please try again later.';
    msg.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Send reset link';
  }
});
