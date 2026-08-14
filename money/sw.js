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

var CACHE_NAME = 'rommoney-shell-v13';
var SHELL_FILES = ['./', './index.html', './manifest.json',
  './favicon.png', './apple-touch-icon.png', './header-bg.jpg',
  './icon-envoyer.png', './icon-payer.png', './icon-encaisser.png',
  './icon-banque.png', './wallet-icon.jpg', './logo.jpg', './icon-watermark.png',
  './icon-96.png'];
// Bibliotheques CDN externes (autre origine) explicitement autorisees en
// cache : uniquement du JS statique et sans risque pour le QR code. Toute
// autre requete cross-origine (notamment le backend API) reste exclue.
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
        // Coquille garantie : le reste est du confort, chacun independant
        // (un CDN indisponible ne doit pas faire echouer toute l'install).
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

  // cache:'reload' force une revalidation reseau complete, sans jamais
  // accepter la copie HTTP locale du navigateur - necessaire pour le CODE de
  // l'app (index.html/manifest), qui doit toujours refleter le dernier
  // deploiement.
  var isCodeShell = req.mode === 'navigate' || url.pathname.endsWith('index.html') || url.pathname.endsWith('manifest.json') || url.pathname.endsWith('/');

  if(!isCodeShell){
    // Images/bibliotheques CDN : cache-first (avec revalidation en arriere
    // plan), contrairement au code ci-dessous qui reste reseau-prioritaire.
    // Attendre systematiquement un aller-retour reseau avant d'afficher une
    // icone deja en cache donnait l'impression qu'elle "chargeait
    // progressivement" a chaque ouverture au lieu d'apparaitre instantanement
    // - ces images changent rarement, et CACHE_NAME suffit deja a les
    // rafraichir quand elles changent vraiment.
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
            +'<body style="font-family:sans-serif;padding:60px 24px;text-align:center;background:#085041;color:#fff">'
            +'<h2>Connexion indisponible</h2><p>Reconnectez-vous a internet puis rouvrez l\'application.</p></body>',
            {status:503, statusText:'Offline', headers:{'Content-Type':'text/html; charset=utf-8'}}
          );
        });
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
