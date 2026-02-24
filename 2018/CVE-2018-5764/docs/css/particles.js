// === SyncShield Cyber Particle Mesh Background ===
// Subtle moving particles with glowing connection lines
// Creates a futuristic "cyber network" effect behind all content

window.addEventListener("load", () => {
  const canvas = document.getElementById('particles');
  if (!canvas) return; // safety check
  const ctx = canvas.getContext('2d');
  let particlesArray = [];

  // === Resize canvas dynamically ===
  window.addEventListener('resize', resizeCanvas);
  resizeCanvas();

  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    initParticles();
  }

  // === Initialize particles ===
  function initParticles() {
    particlesArray = [];
    const numberOfParticles = Math.floor(window.innerWidth / 16); // density based on screen width

    for (let i = 0; i < numberOfParticles; i++) {
      particlesArray.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        size: Math.random() * 1.8 + 0.8, // particle size range
        speedX: (Math.random() - 0.5) * 0.3,
        speedY: (Math.random() - 0.5) * 0.3,
        alpha: Math.random() * 0.5 + 0.4
      });
    }
  }

  // === Draw connecting lines between nearby particles ===
  function connectParticles() {
    const maxDistance = 100;
    for (let a = 0; a < particlesArray.length; a++) {
      for (let b = a; b < particlesArray.length; b++) {
        const dx = particlesArray[a].x - particlesArray[b].x;
        const dy = particlesArray[a].y - particlesArray[b].y;
        const distance = Math.sqrt(dx * dx + dy * dy);

        if (distance < maxDistance) {
          const opacity = 1 - distance / maxDistance;
          ctx.strokeStyle = `rgba(102, 252, 241, ${opacity * 0.15})`;
          ctx.lineWidth = 0.6;
          ctx.beginPath();
          ctx.moveTo(particlesArray[a].x, particlesArray[a].y);
          ctx.lineTo(particlesArray[b].x, particlesArray[b].y);
          ctx.stroke();
        }
      }
    }
  }

  // === Particle animation loop ===
  function animateParticles() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw particles
    particlesArray.forEach(p => {
      ctx.beginPath();
      ctx.globalAlpha = p.alpha;
      ctx.fillStyle = 'rgba(102, 252, 241, 0.25)'; // lower opacity
      ctx.shadowColor = '#45a29e';
      ctx.shadowBlur = 4; // smaller glow radius
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fill();

      // Update particle position
      p.x += p.speedX;
      p.y += p.speedY;

      // Wrap edges (cyber network flow)
      if (p.x > canvas.width) p.x = 0;
      if (p.x < 0) p.x = canvas.width;
      if (p.y > canvas.height) p.y = 0;
      if (p.y < 0) p.y = canvas.height;
    });

    // Draw connections
    connectParticles();

    requestAnimationFrame(animateParticles);
  }

  animateParticles();
});
