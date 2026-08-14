// ═══════════════════════════════════════════
// SERVICE WORKER — ROM_GUICHET
// Meme logique que ROM_BUSINESS/ROM_MONEY : reseau prioritaire pour la
// coquille de l'app (revalide toujours au reseau, cache:'reload', pour
// qu'une mise a jour deployee soit visible des la prochaine ouverture),
// repli sur le cache si hors ligne. Images en cache-first pour rester
// rapides.
// ═══════════════════════════════════════════

var CACHE_NAME = 'romgui-shell-v1';
var SHELL_FILES = ['./', './index.html', './manifest.json', './icon-source.jpg'];

self.addEventListener('install', function(event){
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache){
      return cache.add('./index.html').then(function(){
        var rest = SHELL_FILES.filter(function(f){ return f!=='./index.html'; });
        return Promise.all(rest.map(function(url){ return cache.add(url).catch(function(){}); }));
      });
    }).then(function(){ self.skipWaiting(); })
  );
});

self.addEventListener('activate', function(event){
  event.waitUntil(
    caches.keys().then(function(keys){
      return Promise.all(keys.filter(function(k){ return k!==CACHE_NAME; }).map(function(k){ return caches.delete(k); }));
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', function(event){
  var req = event.request;
  var url = new URL(req.url);
  if(url.origin !== self.location.origin) return;

  var isShellImage = SHELL_FILES.some(function(f){
    return f !== './' && f !== './index.html' && url.pathname.endsWith(f.replace('./',''));
  });
  var isShellRequest = req.mode === 'navigate'
    || url.pathname.endsWith('index.html')
    || url.pathname.endsWith('manifest.json')
    || url.pathname.endsWith('/')
    || isShellImage;

  if(!isShellRequest) return;

  var isCodeShell = req.mode === 'navigate' || url.pathname.endsWith('index.html') || url.pathname.endsWith('manifest.json') || url.pathname.endsWith('/');

  if(!isCodeShell){
    event.respondWith(
      caches.match(req).then(function(cached){
        var network = fetch(req).then(function(res){
          if(res && (res.type==='opaque' || (res.ok && res.status===200))){
            var resClone = res.clone();
            caches.open(CACHE_NAME).then(function(cache){ cache.put(req, resClone); });
          }
          return res;
        }).catch(function(){ return cached; });
        return cached || network;
      })
    );
    return;
  }

  event.respondWith(
    fetch(req, {cache:'reload'}).then(function(res){
      if(res && (res.type==='opaque' || (res.ok && res.status===200))){
        var resClone = res.clone();
        caches.open(CACHE_NAME).then(function(cache){ cache.put(req, resClone); });
      }
      return res;
    }).catch(function(){
      return caches.match(req).then(function(cached){
        if(cached) return cached;
        return caches.match('./index.html').then(function(shell){
          if(shell) return shell;
          return new Response(
            '<!doctype html><meta charset="utf-8"><title>Hors ligne</title>'
            +'<body style="font-family:sans-serif;padding:60px 24px;text-align:center;background:#4A2E00;color:#fff">'
            +'<h2>Connexion indisponible</h2><p>Reconnectez-vous a internet puis rouvrez l\'application.</p></body>',
            {status:503, statusText:'Offline', headers:{'Content-Type':'text/html; charset=utf-8'}}
          );
        });
      });
    })
  );
});

// Notifications push : aucune infrastructure d'abonnement agent cote backend
// pour l'instant (voir plan) - ce handler reste dormant tant qu'aucun
// abonnement n'est jamais cree, garde pour reference/extension future.
self.addEventListener('push', function(event){
  var data = {};
  try{ data = event.data ? event.data.json() : {}; }catch(e){}
  var title = data.title || 'ROM_GUICHET';
  var options = {
    body: data.body || '',
    icon: './icon-source.jpg',
    badge: './icon-source.jpg',
    data: { url: data.url || './' },
    vibrate: [100, 50, 100],
    requireInteraction: true
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function(event){
  event.notification.close();
  var targetUrl = (event.notification.data && event.notification.data.url) || './';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList){
      for(var i=0; i<clientList.length; i++){
        var c = clientList[i];
        if('focus' in c) return c.focus();
      }
      if(clients.openWindow) return clients.openWindow(targetUrl);
    })
  );
});
