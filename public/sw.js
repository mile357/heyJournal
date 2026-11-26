/* heyJo Service Worker — Caches static shell only, NEVER caches /api/ responses */
const CACHE_NAME = "heyjournal-v7";
const SHELL_ASSETS = [
  "/",
  "/index.html",
  "/styles.css?v=7",
  "/theme-boot.js?v=7",
  "/app.js?v=7",
  "/crypto.js?v=7",
  "/quiz-engine.js?v=7",
  "/charts.js?v=7",
  "/theme-engine.js?v=7",
  "/export.js?v=7",
  "/print-summary.js?v=7",
  "/icon.svg?v=7",
  "/icon-192.png?v=7",
  "/icon-512.png?v=7",
  "/manifest.json?v=7"
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
