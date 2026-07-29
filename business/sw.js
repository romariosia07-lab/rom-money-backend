// ═══════════════════════════════════════════
// SERVICE WORKER — ROM_BUSINESS
// Meme logique que celui de ROM_MONEY (voir ses commentaires pour le detail) :
// reseau prioritaire pour la coquille de l'app, repli sur le cache si hors
// ligne. Le code (index.html/manifest) revalide TOUJOURS aupres du reseau
// (cache:'reload') pour qu'une mise a jour deployee soit visible des la
// prochaine ouverture ; les images restent en cache normal pour rester
// rapides (les forcer aussi ralentirait l'app pour rien).
// ═══════════════════════════════════════════

var CACHE_NAME = 'rombiz-shell-v1';
var SHELL_FILES = ['./', './index.html', './manifest.json',
  './favicon.png', './apple-touch-icon.png', './logo.jpg',
  './icon-encaisser.png', './icon-envoyer.png', './wallet-icon.jpg'];
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
      return caches.match(req).then(function(cached){
        if(cached) return cached;
        return req.mode==='navigate' ? caches.match('./index.html') : undefined;
      });
    })
  );
});
