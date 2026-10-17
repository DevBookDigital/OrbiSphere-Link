// Falling-glyph backdrop in the SphereChain style. Purely decorative; it
// pauses while hidden and stays still for users who prefer reduced motion.

const GLYPHS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$%&@<>/\\[]{}=+~ΣΩΨΦΛΞΠβγδλμπφψЖЩЯЮБДФ';
const FONT_PX = 14;

export function startRain(canvas) {
  const ctx = canvas.getContext('2d');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let columns = [];
  let frame = 0;
  let raf = 0;

  function resize() {
    const dpr = Math.min(devicePixelRatio || 1, 2);
    canvas.width = canvas.clientWidth * dpr;
    canvas.height = canvas.clientHeight * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const count = Math.ceil(canvas.clientWidth / (FONT_PX * 1.6));
    columns = Array.from({ length: count }, () => ({
      y: Math.random() * canvas.clientHeight,
      speed: 0.6 + Math.random() * 1.6,
      len: 6 + Math.floor(Math.random() * 18),
    }));
  }

  function draw() {
    if (canvas.getClientRects().length === 0) return; // hidden: stop until shown again
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    ctx.clearRect(0, 0, w, h);
    ctx.font = `${FONT_PX}px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`;
    ctx.textAlign = 'center';
    columns.forEach((col, i) => {
      const x = i * FONT_PX * 1.6 + FONT_PX / 2;
      for (let k = 0; k < col.len; k++) {
        const y = col.y - k * FONT_PX;
        if (y < -FONT_PX || y > h + FONT_PX) continue;
        const alpha = k === 0 ? 0.85 : 0.5 * (1 - k / col.len);
        ctx.fillStyle = `rgba(231, 0, 11, ${alpha.toFixed(3)})`;
        ctx.fillText(GLYPHS[(i * 7 + k * 13 + Math.floor(frame / 8)) % GLYPHS.length], x, y);
      }
      if (!reduced) {
        col.y += col.speed;
        if (col.y - col.len * FONT_PX > h) col.y = -Math.random() * h * 0.3;
      }
    });
    frame++;
    if (!reduced) raf = requestAnimationFrame(draw);
  }

  resize();
  draw();
  addEventListener('resize', () => {
    resize();
    if (reduced) draw();
  });
  document.addEventListener('visibilitychange', () => {
    cancelAnimationFrame(raf);
    if (!document.hidden && !reduced) raf = requestAnimationFrame(draw);
  });
  return () => cancelAnimationFrame(raf);
}
