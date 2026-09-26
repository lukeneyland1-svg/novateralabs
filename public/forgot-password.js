document.getElementById('forgotForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const btn = document.getElementById('submitBtn');
  const msg = document.getElementById('formMessage');

  btn.disabled = true;
  btn.textContent = 'Sending...';
  try {
    await fetch('/api/auth/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    msg.style.color = 'var(--accent)';
    msg.textContent = "If that email matches an account, a reset link has been sent.";
    msg.style.display = 'block';
    btn.textContent = 'Sent';
  } catch (err) {
    msg.style.color = 'var(--crit)';
    msg.textContent = 'Something went wrong. Please try again later.';
    msg.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Send reset link';
  }
});
