// Olympus THEMIS web control plane — progressive enhancement only.
// The pages work without JavaScript (forms POST and reload). This file adds a
// live job state feed over server-sent events on the job detail page. It is a
// same-origin static script so the Content-Security-Policy forbids inline JS.
(function () {
  "use strict";
  var status = document.getElementById("job-status");
  if (!status) {
    return;
  }
  if (status.getAttribute("data-terminal") === "true") {
    return;
  }
  var jobId = status.getAttribute("data-job-id");
  if (!jobId || !window.EventSource) {
    return;
  }
  var note = document.getElementById("job-stream-note");
  var source = new EventSource("/jobs/" + encodeURIComponent(jobId) + "/events");
  source.addEventListener("state", function (event) {
    var data;
    try {
      data = JSON.parse(event.data);
    } catch (error) {
      return;
    }
    // A delivered event means the stream is live again (WEB-A-01).
    status.setAttribute("data-connection", "live");
    if (note) {
      note.textContent = "";
    }
    var label = document.getElementById("job-state");
    if (label && typeof data.label === "string") {
      label.textContent = data.label;
    }
    if (data.terminal === true) {
      source.close();
      // Reload to render the final, authoritative server-rendered detail.
      window.location.reload();
    }
  });
  source.addEventListener("end", function () {
    source.close();
  });
  source.onerror = function () {
    // WEB-A-01 visible resume: do NOT close. The browser reconnects on its own
    // and re-sends Last-Event-ID, so the server resumes from the last delivered
    // state. Surface the drop instead of silently freezing the live feed.
    status.setAttribute("data-connection", "reconnecting");
    if (note) {
      note.textContent = "Connessione interrotta — riconnessione in corso…";
    }
  };
})();
