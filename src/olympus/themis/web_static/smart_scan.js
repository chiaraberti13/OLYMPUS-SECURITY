// Olympus THEMIS — Smart Scan (progressive enhancement only).
// The form works without JavaScript: the objective summary is also rendered by
// the server and the proposal is produced entirely server-side. This script only
// mirrors the chosen objective's one-line summary into a hint as the operator
// changes the select. It is a same-origin static script so the
// Content-Security-Policy forbids inline JS.
(function () {
  "use strict";
  var objective = document.getElementById("objective");
  var hint = document.getElementById("objective-hint");
  if (!objective || !hint) {
    return;
  }

  function syncHint() {
    var option = objective.options[objective.selectedIndex];
    hint.textContent = option ? option.getAttribute("data-summary") || "" : "";
  }

  objective.addEventListener("change", syncHint);
  syncHint();
})();
