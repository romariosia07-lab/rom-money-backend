// ═══════════════════════════════════════════
// SERVICE WORKER — ROM_BUSINESS
// Meme logique que celui de ROM_MONEY (voir ses commentaires pour le detail) :
// reseau prioritaire pour la coquille de l'app, repli sur le cache si hors
// ligne. Le code (index.html/manifest) revalide TOUJOURS aupres du reseau
// (cache:'reload') pour qu'une mise a jour deployee soit visible des la
// prochaine ouverture ; les images restent en cache normal pour rester
// rapides (les forcer aussi ralentirait l'app pour rien).
// ═══════════════════════════════════════════

var CACHE_NAME = 'rombiz-shell-v7';
var SHELL_FILES = ['./', './index.html', './manifest.json',
  './favicon.png', './apple-touch-icon.png', './logo.jpg',
  './icon-encaisser.png', './icon-envoyer.png', './wallet-icon.jpg',
  './icon-watermark.png'];
var CDN_SHELL_FILES = [
  'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js',
  'https://cdn.jsdelivr.net/npm/jsqr@1.3.1/dist/jsQR.min.js'
];

self.addEventListener('install', function(event){
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache){
      return Promise.all(SHELL_FILES.concat(CDN_SHELL_FILES).map(function(url){
        return cache.add(url).catch(function(){});
      }));
    })
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
  var isKnownCdnLib = CDN_SHELL_FILES.indexOf(req.url) !== -1;

  if(url.origin !== self.location.origin && !isKnownCdnLib) return;

  var isShellImage = SHELL_FILES.some(function(f){
    return f !== './' && f !== './index.html' && url.pathname.endsWith(f.replace('./',''));
  });
  var isShellRequest = isKnownCdnLib
    || req.mode === 'navigate'
    || url.pathname.endsWith('index.html')
    || url.pathname.endsWith('manifest.json')
    || url.pathname.endsWith('/')
    || isShellImage;

  if(!isShellRequest) return;

  var isCodeShell = req.mode === 'navigate' || url.pathname.endsWith('index.html') || url.pathname.endsWith('manifest.json') || url.pathname.endsWith('/');
  var fetchOpts = isCodeShell ? {cache:'reload'} : {};

  event.respondWith(
    fetch(req, fetchOpts).then(function(res){
      if(res && (res.type==='opaque' || (res.ok && res.status===200))){
        var resClone = res.clone();
        caches.open(CACHE_NAME).then(function(cache){ cache.put(req, resClone); });
      }
      return res;
    }).catch(function(){
      // Hors ligne (ou reseau en echec) : tente d'abord la requete exacte,
      // puis la coquille (index.html) pour toute navigation/shell. Ne DOIT
      // jamais resoudre vers undefined ici - respondWith() exige un vrai
      // Response, sinon Chrome affiche une erreur brute (ERR_FAILED) au lieu
      // d'une page hors-ligne, meme quand le cache existe mais rate juste
      // cette cle precise (ex: manifest.json dont req.mode n'est pas
      // 'navigate', donc jamais couvert par l'ancien fallback).
      return caches.match(req).then(function(cached){
        if(cached) return cached;
        return caches.match('./index.html').then(function(shell){
          if(shell) return shell;
          return new Response(
            '<!doctype html><meta charset="utf-8"><title>Hors ligne</title>'
            +'<body style="font-family:sans-serif;padding:60px 24px;text-align:center;background:#012B1B;color:#fff">'
            +'<h2>Connexion indisponible</h2><p>Reconnectez-vous a internet puis rouvrez l\'application.</p></body>',
            {status:503, statusText:'Offline', headers:{'Content-Type':'text/html; charset=utf-8'}}
          );
        });
      });
    })
  );
});

// ═══════════════════════════════════════════
// NOTIFICATIONS PUSH REELLES — meme mecanique que ROM_MONEY (voir ses
// commentaires) : reception/affichage meme app fermee, ouverture au clic.
// ═══════════════════════════════════════════
self.addEventListener('push', function(event){
  var data = {};
  try{ data = event.data ? event.data.json() : {}; }catch(e){}
  var title = data.title || 'ROM_BUSINESS';
  var options = {
    body: data.body || '',
    icon: './icon-192.png',
    badge: './icon-192.png',
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
