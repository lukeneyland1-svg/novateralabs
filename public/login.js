document.getElementById('loginCancelBtn').addEventListener('click', () => {
  // Only trust document.referrer if it actually points back into this site —
  // it could otherwise be an external page, which isn't a safe "back" target.
  let sameOriginReferrer = null;
  if (document.referrer) {
    try {
      const ref = new URL(document.referrer);
      if (ref.origin === window.location.origin) sameOriginReferrer = ref.href;
    } catch { /* malformed referrer, ignore */ }
  }
  window.location.href = sameOriginReferrer || '/index.html';
});

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const errorBox = document.getElementById('loginError');
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error('Invalid credentials');
    if (data.mfaRequired) {
      document.getElementById('loginForm').style.display = 'none';
      document.getElementById('mfaForm').style.display = 'block';
      document.getElementById('mfaCode').focus();
      return;
    }
    window.location.href = '/dashboard.html';
  } catch (err) {
    errorBox.textContent = 'Invalid username or password.';
    errorBox.style.display = 'block';
  }
});

document.getElementById('mfaForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = document.getElementById('mfaCode').value;
  const errorBox = document.getElementById('mfaError');
  try {
    const res = await fetch('/api/auth/login/verify-mfa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    if (!res.ok) throw new Error('Invalid code');
    window.location.href = '/dashboard.html';
  } catch (err) {
    errorBox.textContent = 'Invalid code. Please try again.';
    errorBox.style.display = 'block';
  }
});
