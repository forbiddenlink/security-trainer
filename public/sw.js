// Service Worker for SecTrainer PWA.
// NOTE: bump CACHE_NAME on every deploy that changes cached assets, otherwise
// returning users can be served stale JS/CSS until a cache-miss network path.
const CACHE_NAME = 'sectrainer-v2';
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/offline.html',
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
          .filter((name) => name !== CACHE_NAME)
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
  if (!event.request.url.startsWith(self.location.origin)) return;

  // Skip API requests and chrome-extension requests
  if (event.request.url.includes('/api/') ||
      event.request.url.startsWith('chrome-extension://')) {
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // Clone the response before caching
        const responseClone = response.clone();

        // Cache successful responses
        if (response.status === 200) {
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseClone);
          });
        }

        return response;
      })
      .catch(() => {
        // Network failed, try cache
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) {
            return cachedResponse;
          }

          // For navigation requests, serve the app shell if cached, else the
          // dedicated offline page (instead of a bare 503 text response).
          if (event.request.mode === 'navigate') {
            return caches.match('/index.html').then(
              (shell) => shell || caches.match('/offline.html'),
            );
          }

          return new Response('Offline', { status: 503 });
        });
      })
  );
});
