/* Sentinel static-asset service worker.
 *
 * Served from /static/sw.js, so its scope is /static/ — it can ONLY ever
 * intercept /static/* GETs. Every HTML route, /login, /logout, every non-GET,
 * /events + /esp/stream (SSE) and all JSON/API live outside /static/ and are
 * therefore never seen here: they always hit the network, live and uncached.
 *
 * Helps only over the HTTPS tunnel (faster shell loads; resilience to brief
 * tunnel drops). It does NOT run over the plain-HTTP local AP — browsers
 * require a secure context — so it is not an offline solution for the AP.
 *
 * Cache is a VERSIONED name; bump CACHE on a deploy that changes static assets
 * to invalidate the old one. Trivially unregisterable from the browser.
 */
var CACHE = "sentinel-static-v1";

self.addEventListener("install", function () { self.skipWaiting(); });

self.addEventListener("activate", function (e) {
  e.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (k) {
        if (k !== CACHE) return caches.delete(k);          // drop old versions
      }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener("fetch", function (e) {
  var req = e.request;
  if (req.method !== "GET") return;                        // never touch writes
  var url;
  try { url = new URL(req.url); } catch (_) { return; }
  if (url.origin !== self.location.origin) return;         // same-origin only
  if (url.pathname.indexOf("/static/") !== 0) return;      // defensive: /static/* only
  e.respondWith(
    caches.open(CACHE).then(function (cache) {
      return cache.match(req).then(function (hit) {
        var net = fetch(req).then(function (resp) {
          if (resp && resp.status === 200 && resp.type === "basic") {
            try { cache.put(req, resp.clone()); } catch (_) {}
          }
          return resp;
        }).catch(function () { return hit; });             // offline -> cached copy
        return hit || net;                                 // cache-first, refresh in bg
      });
    }).catch(function () { return fetch(req); })           // cache API failure -> network
  );
});
