/**
 * "Quick note" banner — same feature as the vulnerable version: reads a
 * short note from the URL hash fragment and shows it at the top of the
 * page.
 *
 * FIXED (DOM-based XSS): the value is written using `textContent`
 * instead of `innerHTML`. textContent always treats the value as plain
 * text, never as HTML/script, so a payload like
 * <img src=x onerror=alert(1)> is just displayed as literal text and
 * never executed.
 */
(function () {
  const hash = window.location.hash;
  if (!hash || hash.length < 2) return;
  const params = new URLSearchParams(hash.slice(1));
  const note = params.get("note");
  if (note) {
    document.getElementById("quick-note").textContent =
      "📝 Note to self: " + decodeURIComponent(note);
  }
})();
