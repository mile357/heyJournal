/* HeyJournal Service Worker — Caches static shell only, NEVER caches /api/ responses */
const CACHE_NAME = "heyjournal-v1";
const SHELL_ASSETS = [
  "/",
  "/index.html",
  "/styles.css?v=1",
  "/theme-boot.js?v=1",
  "/app.js?v=1",
  "/crypto.js?v=1",
  "/quiz-engine.js?v=1",
  "/charts.js?v=1",
  "/theme-engine.js?v=1",
  "/export.js?v=1",
  "/icon.svg?v=1",
  "/manifest.json?v=1"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET") return;
  // Never cache API endpoints or auth responses
  if (url.pathname.startsWith("/api/")) return;

  event.respondWith(
    fetch(event.request)
      .then((res) => {
        if (res && res.status === 200 && url.origin === self.location.origin) {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy)).catch(() => {});
        }
        return res;
      })
      .catch(() => caches.match(event.request))
  );
});
