/* Shared theme toggle — NovaTeraLabs Theme Engine */
(function(){
  const root = document.documentElement;
  const toggle = document.getElementById('themeToggle');

  // Restore the saved theme preference (if any) so it persists across pages.
  const saved = localStorage.getItem('novateralabs-theme');
  if(saved === 'light' || saved === 'dark'){
    root.setAttribute('data-theme', saved);
    if(toggle) toggle.textContent = saved === 'dark' ? '☾' : '☀';
  }

  if(!toggle) return;
  toggle.addEventListener('click', () => {
    const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    toggle.textContent = next === 'dark' ? '☾' : '☀';
    localStorage.setItem('novateralabs-theme', next);
  });
})();

/* Subtle network/node background — faint drifting particles that connect
   with thin lines when close together. Reads as "infrastructure/network"
   rather than a literal movie reference. Sits behind all content. */
(function(){
  if(window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  const canvas = document.createElement('canvas');
  canvas.id = 'matrixRain'; // keeps existing CSS opacity/positioning rule working as-is
  document.body.prepend(canvas);
  const ctx = canvas.getContext('2d');

  let width, height, particles;
  const PARTICLE_COUNT = 55;
  const MAX_DIST = 130;

  function resize(){
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  }
  window.addEventListener('resize', resize);
  resize();

  function makeParticles(){
    particles = [];
    for(let i = 0; i < PARTICLE_COUNT; i++){
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.25,
        vy: (Math.random() - 0.5) * 0.25,
      });
    }
  }
  makeParticles();

  function hexToRgba(hex, alpha){
    hex = hex.replace('#', '').trim();
    if(hex.length === 3){
      hex = hex.split('').map(c => c + c).join('');
    }
    const r = parseInt(hex.substring(0, 2), 16);
    const g = parseInt(hex.substring(2, 4), 16);
    const b = parseInt(hex.substring(4, 6), 16);
    return `rgba(${r},${g},${b},${alpha})`;
  }

  function draw(){
    const accent = getComputedStyle(document.documentElement)
      .getPropertyValue('--accent').trim() || '#39FF6A';

    ctx.clearRect(0, 0, width, height);

    for(const p of particles){
      p.x += p.vx;
      p.y += p.vy;
      if(p.x < 0 || p.x > width) p.vx *= -1;
      if(p.y < 0 || p.y > height) p.vy *= -1;
    }

    for(let i = 0; i < particles.length; i++){
      for(let j = i + 1; j < particles.length; j++){
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if(dist < MAX_DIST){
          const opacity = (1 - dist / MAX_DIST) * 0.6;
          ctx.strokeStyle = hexToRgba(accent, opacity);
          ctx.lineWidth = 1;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }

    for(const p of particles){
      ctx.fillStyle = hexToRgba(accent, 0.75);
      ctx.beginPath();
      ctx.arc(p.x, p.y, 1.8, 0, Math.PI * 2);
      ctx.fill();
    }

    requestAnimationFrame(draw);
  }

  requestAnimationFrame(draw);
})();
