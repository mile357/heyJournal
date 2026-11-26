/* CSP-compliant print trigger for heyJo's client-side printable clinician summary */
(function () {
  var btn = document.getElementById("btnPrintSummaryDoc");
  if (btn) {
    btn.addEventListener("click", function () {
      window.print();
    });
  }
})();
