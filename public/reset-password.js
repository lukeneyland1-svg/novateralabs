const token = new URLSearchParams(window.location.search).get('token');
const form = document.getElementById('resetForm');
const msg = document.getElementById('formMessage');

if (!token) {
  form.style.display = 'none';
  msg.style.color = 'var(--crit)';
  msg.textContent = 'This reset link is missing its token. Please request a new one.';
  msg.style.display = 'block';
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = document.getElementById('password').value;
  const confirmPassword = document.getElementById('confirmPassword').value;
  const btn = document.getElementById('submitBtn');

  if (password !== confirmPassword) {
    msg.style.color = 'var(--crit)';
    msg.textContent = "Passwords don't match.";
    msg.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Saving...';
  try {
    const res = await fetch('/api/auth/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Something went wrong.');

    msg.style.color = 'var(--accent)';
    msg.textContent = 'Password updated. You can now sign in.';
    msg.style.display = 'block';
    form.style.display = 'none';
  } catch (err) {
    msg.style.color = 'var(--crit)';
    msg.textContent = err.message;
    msg.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Set new password';
  }
});
