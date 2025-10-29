self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open("quiz-cache").then((cache) => {
      return cache.addAll([
        "/",
        "/static/css/style.css",
        "/static/js/script.js",
        "/static/icons/icon-192.png",
        "/static/icons/icon-512.png",
      ]);
    })
  );
});

self.addEventListener("fetch", (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request);
    })
  );
});
