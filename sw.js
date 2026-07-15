// ═══════════════════════════════════════════
// SERVICE WORKER — ROM_MONEY
// Met en cache uniquement la coquille de l'app (index.html, manifest.json)
// pour qu'elle puisse se charger meme sans connexion. N'intercepte JAMAIS
// les appels vers le backend PHP (autre origine) : les donnees financieres
// ne sont jamais mises en cache par ce fichier.
// Strategie : reseau prioritaire, repli sur le cache seulement en cas
// d'echec reseau. Le cache se met a jour a chaque chargement en ligne
// reussi, donc pas de version figee : toujours la derniere connue.
// ═══════════════════════════════════════════

var CACHE_NAME = 'rommoney-shell-v1';
var SHELL_FILES = ['./', './index.html', './manifest.json'];

self.addEventListener('install', function(event){
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache){
      // Chaque fichier est mis en cache independamment : si l'un d'eux
      // echoue (ex: manifest.json absent a cet emplacement), ca ne bloque
      // pas la mise en cache des autres (notamment index.html, essentiel).
      return Promise.all(SHELL_FILES.map(function(url){
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

  // Ne jamais intercepter les requetes vers une autre origine (le backend
  // PHP notamment) : elles doivent toujours passer par le reseau, jamais
  // par un cache local.
  if(url.origin !== self.location.origin) return;

  // Seule la coquille de l'app (chargement de page + manifest) beneficie
  // du mode hors ligne. Reseau prioritaire ; si indisponible, repli sur
  // la derniere version mise en cache avec succes.
  var isShellRequest = req.mode === 'navigate'
    || url.pathname.endsWith('index.html')
    || url.pathname.endsWith('manifest.json')
    || url.pathname.endsWith('/');

  if(!isShellRequest) return;

  event.respondWith(
    fetch(req).then(function(res){
      // Ne met en cache que les reponses completes et valides (200 OK).
      // Une coupure reseau en plein telechargement (ex: mode avion reactive
      // trop vite) peut produire une reponse tronquee/corrompue : la mettre
      // en cache remplacerait la derniere bonne version par une version
      // cassee, rendant l'app figee et non-interactive au prochain chargement
      // hors ligne. On protege donc le cache contre ce cas.
      if(res && res.ok && res.status===200){
        var resClone = res.clone();
        caches.open(CACHE_NAME).then(function(cache){ cache.put(req, resClone); });
      }
      return res;
    }).catch(function(){
      return caches.match(req).then(function(cached){
        return cached || caches.match('./index.html');
      });
    })
  );
});
