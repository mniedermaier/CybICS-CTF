// Theme switching: "system" (follow the OS), "light" or "dark".
//
// Loaded synchronously in <head> so the page never paints in the wrong theme.
// The choice is a per-browser convenience kept in localStorage; a ?theme=light
// or ?theme=dark URL parameter overrides it without being saved, so a
// projector tab can be pinned to one theme.
(function () {
  "use strict";
  var KEY = "cybics-mgmt-theme";
  var ORDER = ["system", "light", "dark"];
  var LABELS = { system: "System theme", light: "Light theme", dark: "Dark theme" };
  var root = document.documentElement;
  var media = window.matchMedia ? window.matchMedia("(prefers-color-scheme: light)") : null;

  function stored() {
    try {
      var value = window.localStorage.getItem(KEY);
      return ORDER.indexOf(value) >= 0 ? value : "system";
    } catch (e) {
      return "system";
    }
  }

  function save(pref) {
    try {
      window.localStorage.setItem(KEY, pref);
    } catch (e) {
      /* private mode or blocked storage: the choice just is not remembered */
    }
  }

  var forced = new URLSearchParams(window.location.search).get("theme");
  var pref = ORDER.indexOf(forced) >= 0 ? forced : stored();

  function resolve(p) {
    if (p === "system") return media && media.matches ? "light" : "dark";
    return p;
  }

  function apply() {
    root.dataset.theme = resolve(pref);
    root.dataset.themePref = pref;
    var button = document.querySelector("[data-theme-toggle]");
    if (button) {
      var next = ORDER[(ORDER.indexOf(pref) + 1) % ORDER.length];
      button.dataset.pref = pref;
      button.setAttribute("aria-label", LABELS[pref] + " (switch to " + next + ")");
      button.title = LABELS[pref] + " - click for " + next;
    }
  }

  apply();
  if (media && media.addEventListener) {
    media.addEventListener("change", function () {
      if (pref === "system") apply();
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var button = document.querySelector("[data-theme-toggle]");
    if (!button) return;
    apply();
    button.addEventListener("click", function () {
      pref = ORDER[(ORDER.indexOf(pref) + 1) % ORDER.length];
      save(pref);
      apply();
    });
  });
})();
