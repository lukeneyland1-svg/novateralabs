// Cloudflare Turnstile bot check for the public forms. Each form that needs
// it has an empty <div data-turnstile></div>; this renders the widget there.
// The site key comes from the server, and while none is configured the
// widget is skipped and Turnstile.token() resolves to undefined, so the
// forms behave exactly as they did before.
//
// Form scripts call:
//   await Turnstile.token(form)  -> token to send as turnstileToken
//   Turnstile.reset(form)        -> after each submit (tokens are single-use)
(function () {
  const widgets = new Map(); // form -> widget id

  const ready = fetch('/api/turnstile/config')
    .then(res => res.json())
    .then(({ siteKey }) => {
      if (!siteKey) return null;
      return new Promise((resolve, reject) => {
        window.onTurnstileLoad = () => resolve(siteKey);
        const script = document.createElement('script');
        script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileLoad&render=explicit';
        script.async = true;
        script.onerror = reject;
        document.head.appendChild(script);
      });
    })
    .then(siteKey => {
      if (!siteKey) return null;
      document.querySelectorAll('[data-turnstile]').forEach(slot => {
        const id = window.turnstile.render(slot, {
          sitekey: siteKey,
          theme: document.documentElement.dataset.theme === 'light' ? 'light' : 'dark',
        });
        widgets.set(slot.closest('form'), id);
      });
      return siteKey;
    })
    .catch(() => null);

  window.Turnstile = {
    async token(form) {
      if (!(await ready)) return undefined;
      const token = window.turnstile.getResponse(widgets.get(form));
      if (!token) throw new Error('Please wait for the bot check to finish, then try again.');
      return token;
    },
    reset(form) {
      if (widgets.has(form) && window.turnstile) window.turnstile.reset(widgets.get(form));
    },
  };
})();
