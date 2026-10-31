"use strict";
(function () {
  var root = document.getElementById("demo");
  if (!root) { return; }
  var start = document.getElementById("demo-start");
  var stages = Array.prototype.slice.call(root.querySelectorAll(".stage"));
  var STEP_MS = 700;
  root.classList.add("js");
  function setState(stage, state) {
    stage.setAttribute("data-state", state);
    stage.querySelector(".state").textContent = state;
  }
  function reset() {
    stages.forEach(function (s) { setState(s, "queued"); });
  }
  reset();
  var running = false;
  start.addEventListener("click", function () {
    if (running) { return; }
    running = true;
    start.disabled = true;
    reset();
    var i = 0;
    function next() {
      if (i > 0) { setState(stages[i - 1], "succeeded"); }
      if (i >= stages.length) {
        running = false; start.disabled = false;
        document.getElementById("demo-done").hidden = false;
        return;
      }
      setState(stages[i], "running");
      i += 1;
      window.setTimeout(next, STEP_MS);
    }
    document.getElementById("demo-done").hidden = true;
    next();
  });
})();
