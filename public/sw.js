// Service Worker for SecTrainer PWA.
// NOTE: bump CACHE_NAME on every deploy that changes cached assets, otherwise
// returning users can be served stale JS/CSS until a cache-miss network path.
const CACHE_NAME = 'sectrainer-v4';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/offline.html',
  '/favicon.svg',
  '/favicon.png',
  '/icon.png',
  '/manifest.json'
];

// Install event - cache static assets.
// Intentionally NO skipWaiting(): a new worker waits until existing tabs close,
// so we never swap the app out from under a user mid-session.
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS);
    })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name.startsWith('sectrainer-') && name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    })
  );
  self.clients.claim();
});

// Fetch event - network first, fall back to cache
self.addEventListener('fetch', (event) => {
  // Skip non-GET requests
  if (event.request.method !== 'GET') return;

  // Skip cross-origin requests
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  if (url.pathname.startsWith('/api/')) return;

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // Cache successful responses
        if (response.status === 200) {
          const copy = response.clone();
          event.waitUntil(caches.open(CACHE_NAME).then((cache) =>
            cache.put(event.request, copy)
          ).catch(() => {}));
        }

        return response;
      })
      .catch(() => {
        // Network failed, try cache
        return caches.match(event.request, { cacheName: CACHE_NAME }).then((cachedResponse) => {
          if (cachedResponse) {
            return cachedResponse;
          }

          // For navigation requests, serve the app shell if cached, else the
          // dedicated offline page (instead of a bare 503 text response).
          if (event.request.mode === 'navigate') {
            return caches.match('/index.html', { cacheName: CACHE_NAME }).then(
              (shell) => shell || caches.match('/offline.html', { cacheName: CACHE_NAME }),
            );
          }

          return new Response('Offline', { status: 503 });
        });
      })
  );
});
