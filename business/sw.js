// ═══════════════════════════════════════════
// SERVICE WORKER — ROM_BUSINESS
// Meme logique que celui de ROM_MONEY (voir ses commentaires pour le detail) :
// reseau prioritaire pour la coquille de l'app, repli sur le cache si hors
// ligne. Le code (index.html/manifest) revalide TOUJOURS aupres du reseau
// (cache:'reload') pour qu'une mise a jour deployee soit visible des la
// prochaine ouverture ; les images restent en cache normal pour rester
// rapides (les forcer aussi ralentirait l'app pour rien).
// ═══════════════════════════════════════════

var CACHE_NAME = 'rombiz-shell-v9';
var SHELL_FILES = ['./', './index.html', './manifest.json',
  './favicon.png', './apple-touch-icon.png', './logo.jpg',
  './icon-encaisser.png', './icon-envoyer.png', './wallet-icon.jpg',
  './icon-watermark.png', './icon-96.png'];
var CDN_SHELL_FILES = [
  'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js',
  'https://cdn.jsdelivr.net/npm/jsqr@1.3.1/dist/jsQR.min.js'
];

self.addEventListener('install', function(event){
  // index.html est OBLIGATOIRE : si sa mise en cache echoue (coupure reseau
  // pile pendant l'install), toute l'installation echoue et le navigateur
  // garde l'ancien service worker actif (avec son cache encore valide) au
  // lieu d'activer une version fraiche dont la coquille serait absente.
  // skipWaiting() n'est appele qu'apres ce succes, jamais avant : sinon
  // "activate" peut se declencher et supprimer l'ancien (bon) cache alors
  // que le nouveau est encore incomplet - c'est exactement ce qui pouvait
  // rendre l'app inutilisable hors ligne apres une mise a jour malchanceuse.
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache){
      return cache.add('./index.html').then(function(){
        var rest = SHELL_FILES.filter(function(f){ return f!=='./index.html'; }).concat(CDN_SHELL_FILES);
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

  if(!isCodeShell){
    // Images/bibliotheques CDN : cache-first (avec revalidation en arriere
    // plan). Le reseau-prioritaire utilise pour le code ci-dessous les ferait
    // toujours attendre un aller-retour reseau avant de s'afficher meme quand
    // la version est deja en cache - d'ou l'impression d'icones qui "chargent
    // progressivement" a chaque ouverture au lieu d'apparaitre instantanement.
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
