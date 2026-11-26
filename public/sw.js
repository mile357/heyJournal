/* heyJo Service Worker — Caches static shell only, NEVER caches /api/ responses */
const CACHE_NAME = "heyjournal-v6";
const SHELL_ASSETS = [
  "/",
  "/index.html",
  "/styles.css?v=6",
  "/theme-boot.js?v=6",
  "/app.js?v=6",
  "/crypto.js?v=6",
  "/quiz-engine.js?v=6",
  "/charts.js?v=6",
  "/theme-engine.js?v=6",
  "/export.js?v=6",
  "/print-summary.js?v=6",
  "/icon.svg?v=6",
  "/icon-192.png?v=6",
  "/icon-512.png?v=6",
  "/manifest.json?v=6"
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
