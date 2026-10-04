// Confirmation for admin actions that are hard to undo. Any form with a
// data-confirm attribute asks before it submits. External file because the
// CSP allows no inline script.
(function () {
  "use strict";
  document.addEventListener("submit", function (event) {
    var form = event.target;
    var question = form.getAttribute("data-confirm");
    if (!question && event.submitter) question = event.submitter.getAttribute("data-confirm");
    if (question && !window.confirm(question)) event.preventDefault();
  });

  // Pages marked "autorefresh" (the instance and device lists) reload every
  // 30 s, but never while the organiser has a status open, is typing, or has
  // selected devices for a bulk action.
  if (document.body.classList.contains("autorefresh")) {
    setInterval(function () {
      var busy = document.querySelector("details[open]") ||
                 document.querySelector("input[type=checkbox][name=device_id]:checked") ||
                 (document.activeElement && /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName));
      if (!busy) window.location.reload();
    }, 30000);
  }
})();
