/**
 * "Quick note" banner — a sitewide feature that lets a user drop a short
 * reminder note for themselves into the page URL (e.g. to paste into a
 * bookmark), shown back to them at the top of the page.
 *
 * VULNERABLE (DOM-based XSS): the value is read straight from
 * location.hash and written into the DOM with innerHTML. This never
 * touches the server at all — the whole bug is in this client-side code.
 *
 * Try:  http://localhost:5000/#note=<img src=x onerror=alert(document.cookie)>
 */
(function () {
  const hash = window.location.hash;
  if (!hash || hash.length < 2) return;
  const params = new URLSearchParams(hash.slice(1));
  const note = params.get("note");
  if (note) {
    document.getElementById("quick-note").innerHTML =
      "📝 Note to self: " + decodeURIComponent(note);
  }
})();
