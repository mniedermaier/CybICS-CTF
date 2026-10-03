// Live projector scoreboard.
//
// Polls the JSON API every few seconds and animates what changed:
//   - rows glide to their new place when ranks change (FLIP: measure the old
//     positions, reorder the DOM, then animate from old to new), with a
//     green or red flash and a "+2" / "-1" chip;
//   - scores count up to their new value;
//   - new solves slide into the feed; a first blood takes over the screen.
// Nothing animates on the first load, only changes after it. Under
// prefers-reduced-motion everything updates in place.
(function () {
  "use strict";
  const root = document.querySelector("[data-scoreboard]");
  if (!root) return;
  const url = root.dataset.scoreboard;
  const rowsEl = document.getElementById("scores");
  const feed = document.getElementById("feed");
  const state = document.getElementById("state");
  const live = document.getElementById("live");
  const updated = document.getElementById("updated");
  const status = document.getElementById("board-status");
  const elapsed = document.getElementById("elapsed");
  const reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const POLL_MS = 5000;

  let previous = null;            // team name -> {rank, score} from the last poll
  const seenSolves = new Set();   // "team|challenge|time" already shown
  const announceQueue = [];
  let announcing = false;
  let offset = 0;                 // server clock minus local clock, in seconds

  // ---------- helpers ----------

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function ago(ts, serverNow) {
    const s = Math.max(0, Math.round(serverNow - ts));
    if (s >= 86400) return Math.floor(s / 86400) + " d ago";
    if (s >= 3600) return Math.floor(s / 3600) + " h ago";
    if (s >= 60) return Math.floor(s / 60) + " min ago";
    return s + " s ago";
  }

  // Always 24-hour HH:MM:SS, whatever the projector's browser locale is.
  function clock24(date) {
    const pad = (n) => String(n).padStart(2, "0");
    return pad(date.getHours()) + ":" + pad(date.getMinutes()) + ":" + pad(date.getSeconds());
  }

  function restartAnimation(node, cls) {
    node.classList.remove(cls);
    void node.offsetWidth;   // reflow, so the same animation can play again
    node.classList.add(cls);
  }

  function countUp(node, from, to) {
    if (reduced || from === to) { node.textContent = to; return; }
    restartAnimation(node, "bump");
    const start = performance.now(), duration = 1100;
    (function step(now) {
      // rAF timestamps can be slightly older than performance.now(): clamp.
      const t = Math.min(1, Math.max(0, (now - start) / duration));
      const eased = 1 - Math.pow(1 - t, 3);
      node.textContent = Math.round(from + (to - from) * eased);
      if (t < 1) requestAnimationFrame(step);
    })(start);
  }

  // ---------- ranking ----------

  function buildRow(entry) {
    const li = el("li", "row");
    li.dataset.team = entry.name;
    const team = el("span", "team");
    const line = el("span", "line");   // name, and the rank-change chip right after it
    line.append(el("span", "name", entry.name));
    team.append(line);
    const bar = el("span", "bar");
    bar.append(el("span", "fill"));
    team.append(bar);
    li.append(el("span", "rank"), team, el("span", "solves num"), el("span", "score num", "0"));
    return li;
  }

  function renderRanking(board) {
    document.getElementById("scores-empty").hidden = board.length > 0;
    const existing = new Map([...rowsEl.children].map((li) => [li.dataset.team, li]));
    const first = new Map();   // FLIP "first": where every row is now
    existing.forEach((li, name) => {
      first.set(name, li.getBoundingClientRect().top);
    });
    const leader = board.length ? Math.max(1, board[0].score) : 1;

    const ordered = board.map((entry) => {
      let li = existing.get(entry.name);
      const isNew = !li;
      if (isNew) li = buildRow(entry);
      existing.delete(entry.name);

      li.className = "row" + (entry.rank <= 3 && entry.score > 0 ? " top" + entry.rank : "");
      li.querySelector(".rank").textContent = entry.rank;
      li.querySelector(".solves").textContent = entry.solves;
      li.querySelector(".fill").style.width = (100 * entry.score / leader).toFixed(1) + "%";
      const before = previous && previous.has(entry.name) ? previous.get(entry.name) : null;
      // First poll: show the values as they are; afterwards count up from the old score.
      countUp(li.querySelector(".score"), before ? before.score : (previous ? 0 : entry.score), entry.score);

      if (previous && !reduced) {
        if (isNew) {
          restartAnimation(li, "is-new");
        } else if (before && before.rank !== entry.rank) {
          const up = entry.rank < before.rank;
          restartAnimation(li, up ? "went-up" : "went-down");
          li.querySelectorAll(".chip").forEach((c) => c.remove());
          const chip = el("span", "chip " + (up ? "up" : "down"),
                          (up ? "▲ " : "▼ ") + Math.abs(before.rank - entry.rank));
          li.querySelector(".line").append(chip);
          setTimeout(() => chip.remove(), 7200);
        }
      }
      return li;
    });
    existing.forEach((li) => li.remove());   // teams gone (deleted or disqualified)
    rowsEl.replaceChildren(...ordered);
    layoutRanking();

    // FLIP "last, invert, play": slide every moved row from where it was
    // (rows scrolled out of view move too; the list clips them).
    if (!reduced) {
      ordered.forEach((li) => {
        if (!first.has(li.dataset.team)) return;
        const delta = first.get(li.dataset.team) - li.getBoundingClientRect().top;
        if (Math.abs(delta) < 1) return;
        li.animate([{ transform: `translateY(${delta}px)` }, { transform: "translateY(0)" }],
                   { duration: 900, easing: "cubic-bezier(.2, .8, .2, 1)" });
      });
    }
    previous = new Map(board.map((e) => [e.name, { rank: e.rank, score: e.score }]));
    requestAnimationFrame(() => rowsEl.classList.add("ready"));   // bars animate from now on
  }

  // ---------- feed and announcements ----------

  function renderFeed(solves, serverNow, initial) {
    document.getElementById("feed-empty").hidden = solves.length > 0;
    const fresh = [];
    feed.replaceChildren(...solves.map((s) => {
      const key = s.team + "|" + s.challenge + "|" + s.time;
      const li = el("li", s.first_blood ? "blood-item" : "");
      li.append(el("strong", "", s.team), " solved ", el("span", "chal", s.challenge),
                el("span", "pts", "+" + s.points));
      if (s.bonus) li.append(el("span", "bonus", "+" + s.bonus + " bonus"));
      if (s.first_blood) li.append(el("span", "blood", "first blood"));
      li.append(el("span", "when", ago(s.time, serverNow)));
      if (!seenSolves.has(key)) {
        seenSolves.add(key);
        if (!initial) {
          if (!reduced) li.classList.add("fresh");
          fresh.push(s);
        }
      }
      return li;
    }));
    layoutFeed();
    // Oldest first, so several first bloods at once play in order.
    fresh.reverse().filter((s) => s.first_blood).forEach((s) => announceQueue.push(s));
    // Many at once (e.g. held solves released by a catalog fix) must not
    // lock the projector for minutes: show the latest three.
    announceQueue.splice(0, Math.max(0, announceQueue.length - 3));
    playAnnouncements();
  }

  function playAnnouncements() {
    if (announcing || !announceQueue.length) return;
    announcing = true;
    const s = announceQueue.shift();
    const box = document.getElementById("announce");
    document.getElementById("announce-team").textContent = s.team;
    document.getElementById("announce-chal").textContent =
      s.challenge + "  +" + s.points + (s.bonus ? "  (+" + s.bonus + " first blood bonus)" : "");
    box.hidden = false;
    restartAnimation(box, "show");
    setTimeout(() => {
      box.hidden = true;
      box.classList.remove("show");
      announcing = false;
      playAnnouncements();
    }, reduced ? 3000 : 5000);
  }

  // ---------- header ----------

  function showElapsed() {
    if (elapsed.dataset.state === "paused") return;   // the clock stands still during a pause
    const started = parseFloat(elapsed.dataset.started);
    if (!started) { elapsed.textContent = "--:--:--"; return; }
    const end = parseFloat(elapsed.dataset.finished) || (Date.now() / 1000 + offset);
    const total = Math.max(0, Math.floor(end - started));
    const pad = (n) => String(n).padStart(2, "0");
    elapsed.textContent = pad(Math.floor(total / 3600)) + ":" + pad(Math.floor(total / 60) % 60) + ":" + pad(total % 60);
  }

  function renderHeader(data) {
    state.textContent = data.event.state;
    const pct = data.event.first_blood_bonus || 0;
    document.getElementById("bonus-rule").hidden = !pct;
    document.getElementById("bonus-pct").textContent = pct;
    live.classList.toggle("is-live", data.event.state === "running");
    // The clock runs on server time, so a wrong projector clock does not matter.
    offset = data.server_time - Date.now() / 1000;
    elapsed.dataset.started = data.event.started_at || "";
    elapsed.dataset.finished = data.event.finished_at || "";
    elapsed.dataset.state = "";
    showElapsed();
    elapsed.dataset.state = data.event.state;
  }

  // ---------- polling ----------

  // Keep showing the last good data when the server is unreachable, but say
  // so: a projector silently showing a stale board is worse than no board.
  let lastOk = new Date();
  function stale() {
    updated.textContent = "connection lost, last update " + clock24(lastOk);
    updated.className = "stale";
    if (status && !status.textContent) status.textContent = "Scoreboard connection lost.";
  }

  let initial = true;
  async function refresh() {
    try {
      const r = await fetch(url, { cache: "no-store" });
      if (!r.ok) return stale();
      const data = await r.json();
      renderHeader(data);
      renderRanking(data.scoreboard);
      renderFeed(data.recent_solves, data.server_time, initial);
      initial = false;
      lastOk = new Date();
      updated.textContent = clock24(lastOk);
      updated.className = "";
      if (status && status.textContent) status.textContent = "Scoreboard connection restored.";
    } catch (e) {
      stale();
    }
  }

  refresh();
  // A hidden tab does not poll; it catches up as soon as it is shown again.
  setInterval(() => { if (!document.hidden) refresh(); }, POLL_MS);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  setInterval(showElapsed, 1000);
  showElapsed();

  // ---------- fit to the screen ----------
  //
  // On a projector (wider than 1000 px) the board fills exactly one screen.
  // Rows get the height that fits every team. If that would drop below a
  // readable size, the ranking shows as many whole rows as fit and scrolls
  // smoothly down by up to one screenful, just as far as there are teams
  // left (one more team: one row), pauses, and goes back to the top. The
  // feed shows only the entries that fit completely.
  const pagesEl = document.getElementById("pages");
  const MIN_ROW = 48, MAX_ROW = 104, GAP = 0.14, STEP_MS = 7000, SCROLL_MS = 1400;
  let pitch = 0, perScreen = 0, maxOffset = 0;

  function fitMode() { return window.innerWidth > 1000; }

  function showRange() {
    pagesEl.replaceChildren();
    const total = rowsEl.children.length;
    if (maxOffset <= 0) return;
    const from = Math.round(rowsEl.scrollTop / pitch) + 1;
    const to = Math.min(total, from + perScreen - 1);
    pagesEl.append(el("span", "", from + "\u2013" + to + " of " + total),
                   el("span", "pip" + (from === 1 ? " on" : "")),
                   el("span", "pip" + (to === total ? " on" : "")));
  }

  function layoutRanking() {
    const rows = [...rowsEl.children];
    const fit = fitMode();
    rowsEl.classList.toggle("fit", fit);
    rowsEl.style.maxHeight = "";             // measure the full space again
    if (!fit || !rows.length) {
      maxOffset = 0;
      rowsEl.scrollTop = 0;
      showRange();
      return;
    }
    const avail = rowsEl.clientHeight;
    let h = Math.min(MAX_ROW, avail / (rows.length * (1 + GAP)));
    perScreen = rows.length;
    if (h < MIN_ROW) {
      h = MIN_ROW;
      perScreen = Math.max(1, Math.floor(avail / (h * (1 + GAP))));
    }
    pitch = h * (1 + GAP);
    rowsEl.style.setProperty("--row-h", h.toFixed(2) + "px");
    rowsEl.style.setProperty("--row-gap", (h * GAP).toFixed(2) + "px");
    if (perScreen < rows.length) {
      // A window of exactly perScreen whole rows: never half a row at the bottom.
      rowsEl.style.maxHeight = (perScreen * pitch - h * GAP).toFixed(2) + "px";
      maxOffset = (rows.length - perScreen) * pitch;
    } else {
      maxOffset = 0;
    }
    // Keep the position across updates, snapped to a whole row.
    rowsEl.scrollTop = Math.min(maxOffset, Math.round(rowsEl.scrollTop / pitch) * pitch);
    showRange();
  }

  function scrollRowsTo(target) {
    const from = rowsEl.scrollTop;
    if (reduced || Math.abs(target - from) < 1) { rowsEl.scrollTop = target; showRange(); return; }
    const start = performance.now();
    (function step(now) {
      const t = Math.min(1, Math.max(0, (now - start) / SCROLL_MS));
      const eased = t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;   // ease in-out
      rowsEl.scrollTop = from + (target - from) * eased;
      if (t < 1) requestAnimationFrame(step); else showRange();
    })(start);
  }

  setInterval(function () {
    if (maxOffset <= 0) return;
    const atBottom = rowsEl.scrollTop >= maxOffset - 1;
    // Down by one screenful at most, only as far as there are rows left;
    // from the bottom, back to the top.
    scrollRowsTo(atBottom ? 0 : Math.min(maxOffset, rowsEl.scrollTop + perScreen * pitch));
  }, STEP_MS);

  function layoutFeed() {
    const items = [...feed.children];
    items.forEach((li) => li.classList.remove("off"));
    if (!fitMode()) return;
    const limit = feed.clientHeight;
    let hidden = false;
    items.forEach((li) => {
      if (hidden || li.offsetTop + li.offsetHeight > limit) { hidden = true; li.classList.add("off"); }
    });
  }

  function layout() { layoutRanking(); layoutFeed(); }
  window.addEventListener("resize", layout);
  layout();
})();
