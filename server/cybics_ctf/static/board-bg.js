// Scoreboard backdrop: an industrial network drawn on a canvas.
//
// Nodes (PLCs, HMIs, sensors) drift slowly; nearby ones are linked, and data
// packets travel along the links, like Modbus traffic in the CybICS plant.
// Kept cheap for a projector machine running all day: capped node count,
// ~30 fps, paused while the tab is hidden, and a single still frame under
// prefers-reduced-motion. Colours follow the light/dark theme.
(function () {
  "use strict";
  const canvas = document.getElementById("network");
  if (!canvas || !canvas.getContext) return;
  const ctx = canvas.getContext("2d");
  const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const LINK = 190;          // px: nodes closer than this are linked
  const FRAME_MS = 33;

  let width = 0, height = 0, nodes = [], packets = [], colors = {};

  function readColors() {
    const light = document.documentElement.dataset.theme === "light";
    colors = light
      ? { node: "rgba(194, 65, 12, 0.55)", hub: "rgba(194, 65, 12, 0.85)", link: "194, 65, 12", packet: "#c2410c" }
      : { node: "rgba(255, 140, 66, 0.55)", hub: "rgba(255, 165, 0, 0.9)", link: "255, 120, 30", packet: "#ffb347" };
  }

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = canvas.clientWidth;
    height = canvas.clientHeight;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const count = Math.max(18, Math.min(70, Math.round(width * height / 26000)));
    nodes = Array.from({ length: count }, (_, i) => ({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.25,
      vy: (Math.random() - 0.5) * 0.25,
      hub: i % 9 === 0,                    // a few bigger "PLC" nodes
      phase: Math.random() * Math.PI * 2,
    }));
    packets = [];
  }

  function step() {
    for (const n of nodes) {
      n.x += n.vx; n.y += n.vy; n.phase += 0.03;
      if (n.x < -20 || n.x > width + 20) n.vx *= -1;
      if (n.y < -20 || n.y > height + 20) n.vy *= -1;
    }
    // Now and then a packet leaves a node for a linked neighbour.
    if (packets.length < 26 && Math.random() < 0.18) {
      const a = nodes[Math.floor(Math.random() * nodes.length)];
      const near = nodes.filter((b) => b !== a && Math.hypot(a.x - b.x, a.y - b.y) < LINK);
      if (near.length) packets.push({ a, b: near[Math.floor(Math.random() * near.length)], t: 0 });
    }
    for (const p of packets) p.t += 0.012;
    packets = packets.filter((p) => p.t < 1 && Math.hypot(p.a.x - p.b.x, p.a.y - p.b.y) < LINK * 1.2);
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);
    ctx.lineWidth = 1;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < LINK) {
          ctx.strokeStyle = `rgba(${colors.link}, ${(0.22 * (1 - d / LINK)).toFixed(3)})`;
          ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
        }
      }
    }
    for (const n of nodes) {
      const r = n.hub ? 3.2 + Math.sin(n.phase) * 0.8 : 1.8;
      ctx.fillStyle = n.hub ? colors.hub : colors.node;
      if (n.hub) {
        ctx.fillRect(n.x - r, n.y - r, r * 2, r * 2);   // PLCs are boxes
      } else {
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2); ctx.fill();
      }
    }
    ctx.fillStyle = colors.packet;
    ctx.shadowColor = colors.packet;
    ctx.shadowBlur = 8;
    for (const p of packets) {
      const x = p.a.x + (p.b.x - p.a.x) * p.t, y = p.a.y + (p.b.y - p.a.y) * p.t;
      ctx.beginPath(); ctx.arc(x, y, 1.8, 0, Math.PI * 2); ctx.fill();
    }
    ctx.shadowBlur = 0;
  }

  let last = 0;
  function loop(now) {
    if (!document.hidden && now - last >= FRAME_MS) {
      last = now;
      step();
      draw();
    }
    requestAnimationFrame(loop);
  }

  readColors();
  resize();
  window.addEventListener("resize", resize);
  // The theme toggle flips data-theme on <html>; follow it.
  new MutationObserver(() => { readColors(); if (reduced) draw(); })
    .observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  if (reduced) {
    draw();
    window.addEventListener("resize", draw);
  } else {
    requestAnimationFrame(loop);
  }
})();
