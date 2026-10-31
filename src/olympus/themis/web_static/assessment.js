// Olympus THEMIS — New Assessment guided flow (progressive enhancement only).
// The form works without JavaScript: every option is present and the server
// re-validates the activity/tool pairing on preview. This script only makes the
// tool list easier to use — filtering tools to the chosen activity and showing
// a plain-language hint. It is a same-origin static script so the
// Content-Security-Policy forbids inline JS.
(function () {
  "use strict";
  var activity = document.getElementById("activity");
  var scanner = document.getElementById("scanner");
  if (!activity || !scanner) {
    return;
  }
  var activityHint = document.getElementById("activity-hint");
  var scannerHint = document.getElementById("scanner-hint");
  var defaultScannerHint = scannerHint ? scannerHint.innerHTML : "";

  function selectedActivity() {
    return activity.value;
  }

  function syncActivityHint() {
    if (!activityHint) {
      return;
    }
    var option = activity.options[activity.selectedIndex];
    activityHint.textContent = option ? option.getAttribute("data-summary") || "" : "";
  }

  function filterTools() {
    var chosen = selectedActivity();
    var groups = scanner.getElementsByTagName("optgroup");
    for (var i = 0; i < groups.length; i += 1) {
      var match = groups[i].getAttribute("data-activity") === chosen;
      groups[i].style.display = match ? "" : "none";
      var options = groups[i].getElementsByTagName("option");
      for (var j = 0; j < options.length; j += 1) {
        options[j].hidden = !match;
      }
    }
    // If the current tool belongs to another activity, fall back to automatic.
    var current = scanner.options[scanner.selectedIndex];
    if (current && current.value && current.getAttribute("data-activity") !== chosen) {
      scanner.value = "";
    }
  }

  function syncScannerHint() {
    if (!scannerHint) {
      return;
    }
    var option = scanner.options[scanner.selectedIndex];
    if (!option || !option.value) {
      scannerHint.innerHTML = defaultScannerHint;
      return;
    }
    var risk = option.getAttribute("data-risk-label") || "";
    var summary = option.getAttribute("data-summary") || "";
    scannerHint.textContent = risk ? risk + " — " + summary : summary;
  }

  activity.addEventListener("change", function () {
    syncActivityHint();
    filterTools();
    syncScannerHint();
  });
  scanner.addEventListener("change", syncScannerHint);

  syncActivityHint();
  filterTools();
  syncScannerHint();
})();
