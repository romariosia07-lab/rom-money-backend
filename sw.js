// ═══════════════════════════════════════════
// SERVICE WORKER — ROM_MONEY
// Met en cache la coquille de l'app (index.html, manifest.json) ainsi que
// les quelques bibliotheques externes statiques necessaires au QR code
// (generation + scan), pour qu'elles marchent aussi hors connexion, comme
// pour Wave. N'intercepte JAMAIS les appels vers le backend PHP : les
// donnees financieres ne sont jamais mises en cache par ce fichier.
// Strategie : reseau prioritaire, repli sur le cache seulement en cas
// d'echec reseau. Le cache se met a jour a chaque chargement en ligne
// reussi, donc pas de version figee : toujours la derniere connue.
// ═══════════════════════════════════════════

var CACHE_NAME = 'rommoney-shell-v5';
var SHELL_FILES = ['./', './index.html', './manifest.json',
  './favicon.png', './apple-touch-icon.png', './header-bg.jpg',
  './icon-envoyer.png', './icon-payer.png', './icon-encaisser.png',
  './icon-banque.png', './wallet-icon.png', './logo.png'];
// Bibliotheques CDN externes (autre origine) explicitement autorisees en
// cache : uniquement du JS statique et sans risque pour le QR code. Toute
// autre requete cross-origine (notamment le backend API) reste exclue.
var CDN_SHELL_FILES = [
  'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js',
  'https://cdn.jsdelivr.net/npm/jsqr@1.3.1/dist/jsQR.min.js'
];

self.addEventListener('install', function(event){
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache){
      // Chaque fichier est mis en cache independamment : si l'un d'eux
      // echoue (ex: manifest.json absent a cet emplacement, ou CDN
      // temporairement indisponible), ca ne bloque pas la mise en cache
      // des autres (notamment index.html, essentiel).
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

  // Ne jamais intercepter les requetes vers une autre origine, SAUF les
  // bibliotheques CDN explicitement autorisees ci-dessus. Le backend PHP
  // (autre origine lui aussi) continue donc de toujours passer par le
  // reseau, jamais par un cache local.
  if(url.origin !== self.location.origin && !isKnownCdnLib) return;

  // Coquille de l'app (chargement de page + manifest) et bibliotheques QR :
  // reseau prioritaire ; si indisponible, repli sur la derniere version
  // mise en cache avec succes. Inclut aussi les 9 images extraites du
  // fichier principal (favicon, header, icones, logo) : sans cette ligne,
  // elles etaient bien stockees en cache a l'installation mais JAMAIS lues
  // depuis ce cache au chargement suivant - retelechargees a chaque fois,
  // sans aucun benefice, d'ou lenteur/icones cassees sur reseau faible.
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

  event.respondWith(
    fetch(req).then(function(res){
      // Ne met en cache que les reponses completes et valides (200 OK pour
      // le meme-origine, ou opaque pour les CDN cross-origine sans header
      // CORS explicite). Une coupure reseau en plein telechargement peut
      // produire une reponse tronquee/corrompue : la mettre en cache
      // remplacerait la derniere bonne version par une version cassee,
      // rendant l'app figee et non-interactive au prochain chargement hors
      // ligne. On protege donc le cache contre ce cas.
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

// ═══════════════════════════════════════════
// NOTIFICATIONS PUSH REELLES — reception et affichage d'une notification
// meme quand l'app est fermee (ou en arriere-plan), et ouverture de l'app
// au clic dessus. Le contenu (titre/texte) est fourni par le backend au
// moment de l'envoi, chiffre selon RFC 8291 et dechiffre automatiquement
// par le navigateur avant d'arriver ici.
// ═══════════════════════════════════════════
self.addEventListener('push', function(event){
  var data = {};
  try{ data = event.data ? event.data.json() : {}; }catch(e){}
  var title = data.title || 'ROM_MONEY';
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
