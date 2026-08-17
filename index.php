<?php
// ============================================================
// Rom_money - Backend complet PostgreSQL
// ============================================================

define('DB_HOST',    getenv('DB_HOST')    ?: 'localhost');
define('DB_NAME',    getenv('DB_NAME')    ?: 'rom_money_db');
define('DB_USER',    getenv('DB_USER')    ?: 'root');
define('DB_PASS',    getenv('DB_PASS')    ?: '');
define('DB_PORT',    getenv('DB_PORT')    ?: '5432');
define('JWT_SECRET', getenv('JWT_SECRET') ?: null);
define('ADMIN_PASSWORD', getenv('ADMIN_PASSWORD') ?: null);
// Code distinct de ADMIN_PASSWORD, connu uniquement du proprietaire : plusieurs
// personnes peuvent se connecter avec le mot de passe admin partage sans pour
// autant devoir voir les gains/retraits personnels du proprietaire. Optionnel
// (contrairement a JWT_SECRET/ADMIN_PASSWORD) - si non configuree, l'onglet
// Gains ROM refuse simplement l'acces plutot que d'etre ouvert a tous.
define('EARNINGS_PASSWORD', getenv('EARNINGS_PASSWORD') ?: null);
// Aucune valeur de repli codee en dur pour ces deux secrets : un secret
// visible dans le code source (donc dans l'historique Git, ici public)
// n'est plus un secret. Si l'une de ces deux variables d'environnement
// n'est pas configuree sur Render, l'app s'arrete immediatement plutot que
// de se rabattre silencieusement sur une valeur compromise.
if (!JWT_SECRET || !ADMIN_PASSWORD) {
    http_response_code(500);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['success'=>false,'message'=>'Configuration serveur incomplete : JWT_SECRET et/ou ADMIN_PASSWORD non definis sur Render.'], JSON_UNESCAPED_UNICODE);
    exit;
}
define('JWT_EXPIRY', 43200); // 12h (etait 24h/86400s)
define('APP_ENV',    getenv('APP_ENV')    ?: 'development');
define('APP_DEBUG',  APP_ENV === 'development');
define('CANCEL_MINS', 5);
// Types de documents "entreprise" (KYB) acceptes - meme liste des deux
// cotes (upload marchand + affichage admin). Photo chiffree au repos avec
// la meme fonction que les photos KYC personnelles (kyc_encrypt/decrypt) :
// meme sensibilite, meme protection. Doit rester defini avant le routeur
// ($module/switch plus bas) : un define() est execute dans l'ordre du
// fichier, contrairement aux fonctions qui sont disponibles partout.
define('MERCHANT_DOC_TYPES', ['id_recto','id_verso','rccm','dfe','patente','shop_photo']);
// Documents d'agrement agent (ROM_GUICHET) : piece d'identite + photo du
// local. Meme chiffrement (kyc_encrypt/decrypt), meme table-par-type que
// MERCHANT_DOC_TYPES ci-dessus, mais ici le compte reste INACTIF
// (agents.status='pending_approval') tant que ces documents n'ont pas ete
// examines et approuves par un admin - contrairement au marchand, ou
// l'envoi de documents ne fait que debloquer un badge declaratif.
define('AGENT_DOC_TYPES', ['id_recto','id_verso','shop_photo','request_letter']);
// Documents supplementaires FACULTATIFS (jamais bloquants pour l'agrement) -
// memes types que les documents "entreprise" deja utilises cote marchand
// (MERCHANT_DOC_TYPES), pour beneficier des memes libelles admin
// (ADMIN_KYB_DOC_LABELS cote index.html). Un agent qui les fournit
// volontairement inspire plus confiance : ça peut justifier d'augmenter son
// plafond de float (decision manuelle de l'admin, voir DISTRIBUTOR_DEFAULT_FLOAT_CAP).
define('AGENT_OPTIONAL_DOC_TYPES', ['rccm','dfe','patente']);

// Cles VAPID pour les notifications Web Push (RFC 8292). Generees une seule
// fois via OpenSSL (courbe prime256v1) - NE JAMAIS LES CHANGER une fois en
// production : ca invaliderait tous les abonnements push existants et
// forcerait chaque utilisateur a se reabonner. Peuvent etre surchargees
// par variables d'environnement si besoin de les faire tourner un jour.
define('VAPID_PUBLIC_KEY',  getenv('VAPID_PUBLIC_KEY')  ?: 'BKdX0VYx7EkhmZmKkErhdT4jXqigeNOTb-nKS0n3ZceHocyN36sYDE5ABBfp6ZZrqDEoHuNLxoMQsQhfK6T3hc8');
define('VAPID_PRIVATE_KEY', getenv('VAPID_PRIVATE_KEY') ?: 'd_bCbqnSxZAhmDatuvpxxrfUrhic778mfV4oGJW2LCo');
define('VAPID_SUBJECT',     getenv('VAPID_SUBJECT')     ?: 'mailto:supportrommoney@gmail.com');

// CORS restreint : seules les origines listees ici peuvent appeler l'API
// directement depuis un navigateur. Avant, "*" autorisait n'importe quel
// site au monde a faire des requetes vers cette API depuis le navigateur
// d'un visiteur. Les appels hors-navigateur (curl, Postman, l'endpoint
// /install ouvert directement) ne sont pas concernes par le CORS - cette
// restriction ne protege que contre les appels caches depuis un site tiers.
$ALLOWED_ORIGINS = [
    'https://romariosia07-lab.github.io',
    // A ajouter ici le jour ou l'app Android (Capacitor) est publiee, si
    // elle appelle l'API depuis un contexte WebView avec un Origin distinct
    // (ex: 'capacitor://localhost' ou 'https://localhost').
];
$requestOrigin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($requestOrigin, $ALLOWED_ORIGINS, true)) {
    header("Access-Control-Allow-Origin: $requestOrigin");
} elseif (APP_ENV === 'development') {
    header("Access-Control-Allow-Origin: *"); // confort en developpement local uniquement
}
header("Vary: Origin");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json; charset=utf-8");
// En-tetes de securite standards (defense en profondeur, cout nul) :
// - nosniff : empeche le navigateur de deviner un type de fichier different
//   de celui declare, ce qui peut etre detourne pour executer du contenu
//   inattendu.
// - X-Frame-Options DENY : empeche que cette API (ou une reponse HTML
//   d'erreur) soit chargee cachee dans un <iframe> sur un site tiers
//   (technique de clickjacking).
// - Referrer-Policy : evite de divulguer l'URL complete (potentiellement
//   avec des parametres sensibles) au site suivant lors d'une navigation.
// - Strict-Transport-Security : indique au navigateur de ne plus jamais
//   essayer cette API en HTTP non chiffre, meme si quelqu'un tente de le
//   forcer plus tard.
// - Permissions-Policy : cette API ne renvoie que du JSON/PDF, jamais de
//   page utilisant camera/micro/localisation - autant le déclarer.
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
header("Permissions-Policy: geolocation=(), camera=(), microphone=()");
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

function ok($data = null, $msg = 'OK', $code = 200) {
    http_response_code($code);
    echo json_encode(['success'=>true,'message'=>$msg,'data'=>$data], JSON_UNESCAPED_UNICODE);
    exit;
}
function fail($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(['success'=>false,'message'=>$msg], JSON_UNESCAPED_UNICODE);
    exit;
}
// Comme fail(), mais pour les blocs catch(Exception $e) : le message reel de
// l'exception part dans le journal d'erreurs PHP (visible cote Render meme
// quand APP_DEBUG est false et que l'utilisateur ne voit qu'un message
// generique) au lieu d'etre purement et simplement perdu comme c'etait le cas
// avant. $userMsg reste ce qui est montre a l'utilisateur (en clair si
// APP_DEBUG, sinon le message generique fourni par l'appelant).
function log_and_fail($e, $userMsg, $code = 500) {
    error_log('[ROM_MONEY] '.$userMsg.' :: '.$e->getMessage());
    fail(APP_DEBUG ? $e->getMessage() : $userMsg, $code);
}
function body() {
    $d = json_decode(file_get_contents('php://input'), true);
    return is_array($d) ? $d : [];
}
// Lit un parametre depuis le corps JSON (POST) en priorite, sinon depuis la
// query string (GET). Sert aux routes d'export : le mot de passe admin doit
// pouvoir voyager dans le corps de la requete (POST), jamais dans l'URL,
// qui elle peut se retrouver dans l'historique du navigateur ou des logs.
function bg($key, $default=null) {
    $b = body();
    if (array_key_exists($key, $b)) return $b[$key];
    return $_GET[$key] ?? $default;
}
function b64e($d) { return rtrim(strtr(base64_encode($d),'+/','-_'),'='); }
function b64d($d) { return base64_decode(strtr($d,'-_','+/').str_repeat('=',(3+strlen($d))%4)); }
function jwt_make($payload) {
    $h = b64e(json_encode(['alg'=>'HS256','typ'=>'JWT']));
    $payload['iat'] = time(); $payload['exp'] = time()+JWT_EXPIRY;
    $b = b64e(json_encode($payload));
    return "$h.$b.".b64e(hash_hmac('sha256',"$h.$b",JWT_SECRET,true));
}
function jwt_check($token) {
    $p = explode('.',$token);
    if(count($p)!==3) return null;
    if(!hash_equals(b64e(hash_hmac('sha256',"$p[0].$p[1]",JWT_SECRET,true)),$p[2])) return null;
    $pl = json_decode(b64d($p[1]),true);
    return ($pl && $pl['exp']>time()) ? $pl : null;
}
function auth() {
    $h = $_SERVER["HTTP_AUTHORIZATION"] ?? $_SERVER["REDIRECT_HTTP_AUTHORIZATION"] ?? (function_exists("getallheaders") ? (getallheaders()["Authorization"] ?? "") : "") ?? "";
    if(!str_starts_with($h,'Bearer ')) fail('Token manquant',401);
    $pl = jwt_check(substr($h,7));
    // Un jeton ROM_BUSINESS (typ=merchant) ou ROM_GUICHET (typ=agent) ne doit
    // jamais etre accepte ici : ce sont des identites distinctes (voir
    // merchant_auth()/agent_auth()), meme si tous partagent le meme moteur
    // de transactions.
    if(!$pl || in_array(($pl['typ']??''), ['merchant','agent'], true)) fail('Token invalide ou expire',401);
    // Verifie le statut du compte a CHAQUE appel authentifie, pas seulement
    // au login, pour qu'un blocage admin coupe l'acces immediatement meme
    // si l'utilisateur a deja un token valide en cours de session.
    $status = q("SELECT status FROM users WHERE id=?",[$pl['sub']])->fetchColumn();
    if($status !== false && $status !== 'active') fail('Compte suspendu ou bloque', 403);
    // Meme principe pour un appareil precis : permet a l'utilisateur de couper
    // a distance la session d'un telephone vole/perdu ("Mes appareils"), sans
    // attendre l'expiration naturelle du jeton (12h).
    if(!empty($pl['device_id'])){
        $revoked = q("SELECT revoked FROM known_devices WHERE user_id=? AND device_id=?",[$pl['sub'],$pl['device_id']])->fetchColumn();
        if($revoked) fail('Session revoquee depuis un autre appareil. Reconnectez-vous.', 401);
    }
    return $pl;
}
// Equivalent de auth() pour les comptes ROM_BUSINESS (table merchants,
// distincte de users). Un jeton personnel (sans typ=merchant) est refuse ici
// tout comme un jeton marchand est refuse par auth() - les deux identites
// ne se substituent jamais l'une a l'autre.
function merchant_auth() {
    $h = $_SERVER["HTTP_AUTHORIZATION"] ?? $_SERVER["REDIRECT_HTTP_AUTHORIZATION"] ?? (function_exists("getallheaders") ? (getallheaders()["Authorization"] ?? "") : "") ?? "";
    if(!str_starts_with($h,'Bearer ')) fail('Token manquant',401);
    $pl = jwt_check(substr($h,7));
    if(!$pl || ($pl['typ']??'')!=='merchant') fail('Token invalide ou expire',401);
    $status = q("SELECT status FROM merchants WHERE id=?",[$pl['sub']])->fetchColumn();
    if($status !== false && $status !== 'active') fail('Compte suspendu ou bloque', 403);
    // Meme principe que auth() cote personnel : "Mes appareils" permet de
    // couper a distance la session d'un appareil precis sans attendre
    // l'expiration naturelle du jeton.
    if(!empty($pl['device_id'])){
        $revoked = q("SELECT revoked FROM merchant_known_devices WHERE merchant_id=? AND device_id=?",[$pl['sub'],$pl['device_id']])->fetchColumn();
        if($revoked) fail('Session revoquee depuis un autre appareil. Reconnectez-vous.', 401);
    }
    return $pl;
}
// Equivalent de auth()/merchant_auth() pour les comptes ROM_GUICHET (table
// agents, distincte de users et merchants) - troisieme identite mutuellement
// exclusive avec les deux autres.
function agent_auth() {
    $h = $_SERVER["HTTP_AUTHORIZATION"] ?? $_SERVER["REDIRECT_HTTP_AUTHORIZATION"] ?? (function_exists("getallheaders") ? (getallheaders()["Authorization"] ?? "") : "") ?? "";
    if(!str_starts_with($h,'Bearer ')) fail('Token manquant',401);
    $pl = jwt_check(substr($h,7));
    if(!$pl || ($pl['typ']??'')!=='agent') fail('Token invalide ou expire',401);
    $status = q("SELECT status FROM agents WHERE id=?",[$pl['sub']])->fetchColumn();
    if($status !== false && $status !== 'active') fail('Compte suspendu ou bloque', 403);
    if(!empty($pl['device_id'])){
        $revoked = q("SELECT revoked FROM agent_known_devices WHERE agent_id=? AND device_id=?",[$pl['sub'],$pl['device_id']])->fetchColumn();
        if($revoked) fail('Session revoquee depuis un autre appareil. Reconnectez-vous.', 401);
    }
    return $pl;
}
// Identique a agent_auth() mais SANS le controle de statut - reservee aux
// deux seules actions qu'un compte 'pending_approval' (ou 'rejected') doit
// pouvoir faire malgre tout : envoyer ses documents d'agrement et consulter
// l'etat de sa demande. Toute action sensible (cash-in, cash-out, recharge)
// continue d'utiliser agent_auth() sans aucune modification.
function agent_auth_allow_pending() {
    $h = $_SERVER["HTTP_AUTHORIZATION"] ?? $_SERVER["REDIRECT_HTTP_AUTHORIZATION"] ?? (function_exists("getallheaders") ? (getallheaders()["Authorization"] ?? "") : "") ?? "";
    if(!str_starts_with($h,'Bearer ')) fail('Token manquant',401);
    $pl = jwt_check(substr($h,7));
    if(!$pl || ($pl['typ']??'')!=='agent') fail('Token invalide ou expire',401);
    if(!empty($pl['device_id'])){
        $revoked = q("SELECT revoked FROM agent_known_devices WHERE agent_id=? AND device_id=?",[$pl['sub'],$pl['device_id']])->fetchColumn();
        if($revoked) fail('Session revoquee depuis un autre appareil. Reconnectez-vous.', 401);
    }
    return $pl;
}
function ref() { return 'REF-'.strtoupper(date('Ymd')).'-'.strtoupper(substr(uniqid(),-6)); }
function uid() { return bin2hex(random_bytes(8)); }

// ============================================================
// WEB PUSH — notifications push reelles (app fermee), conformes RFC 8291
// (chiffrement) et RFC 8292 (VAPID). Implementees en PHP pur via OpenSSL,
// sans dependance Composer. Testees et validees bit-a-bit contre les
// vecteurs de test officiels de la RFC 8291 avant integration.
// ============================================================

function wp_b64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function wp_b64url_decode($data) {
    $data = strtr($data, '-_', '+/');
    $pad = strlen($data) % 4;
    if ($pad) $data .= str_repeat('=', 4 - $pad);
    return base64_decode($data);
}
function wp_ec_pem_from_raw($d, $x, $y) {
    $oid_prime256v1 = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
    $pubBit = "\x00\x04" . $x . $y;
    $der = "\x02\x01\x01" . "\x04\x20" . $d . "\xa0\x0a" . $oid_prime256v1 . "\xa1\x44\x03\x42" . $pubBit;
    $seq = "\x30" . chr(strlen($der)) . $der;
    $b64 = chunk_split(base64_encode($seq), 64, "\n");
    return "-----BEGIN EC PRIVATE KEY-----\n" . $b64 . "-----END EC PRIVATE KEY-----\n";
}
function wp_ec_public_pem_from_raw($x, $y) {
    $oid_ecPublicKey = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
    $oid_prime256v1  = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
    $algId = "\x30" . chr(strlen($oid_ecPublicKey . $oid_prime256v1)) . $oid_ecPublicKey . $oid_prime256v1;
    $pubBit = "\x00\x04" . $x . $y;
    $bitString = "\x03" . chr(strlen($pubBit)) . $pubBit;
    $der = $algId . $bitString;
    $seq = "\x30" . chr(strlen($der)) . $der;
    $b64 = chunk_split(base64_encode($seq), 64, "\n");
    return "-----BEGIN PUBLIC KEY-----\n" . $b64 . "-----END PUBLIC KEY-----\n";
}
// Convertit une signature ECDSA DER (produite par openssl_sign) au format
// "raw" R||S (64 octets) attendu par un JWT ES256 (JOSE).
function wp_der_to_raw_signature($der) {
    $offset = 2; // saute 0x30 + longueur globale
    $offset++; // 0x02 (INTEGER r)
    $rlen = ord($der[$offset]); $offset++;
    $r = substr($der, $offset, $rlen); $offset += $rlen;
    $offset++; // 0x02 (INTEGER s)
    $slen = ord($der[$offset]); $offset++;
    $s = substr($der, $offset, $slen);
    $strip = function($v){ while(strlen($v)>0 && ord($v[0])===0x00) $v=substr($v,1); return $v; };
    $r = str_pad($strip($r), 32, "\x00", STR_PAD_LEFT);
    $s = str_pad($strip($s), 32, "\x00", STR_PAD_LEFT);
    return $r . $s;
}
// Construit le jeton VAPID (JWT ES256) prouvant au service push que cette
// notification provient bien de notre serveur.
function wp_build_vapid_jwt($audience) {
    $header = wp_b64url_encode(json_encode(['typ'=>'JWT','alg'=>'ES256']));
    $payload = wp_b64url_encode(json_encode(['aud'=>$audience,'exp'=>time()+12*3600,'sub'=>VAPID_SUBJECT]));
    $signingInput = $header.'.'.$payload;

    $d = wp_b64url_decode(VAPID_PRIVATE_KEY);
    $pub = wp_b64url_decode(VAPID_PUBLIC_KEY);
    $x = substr($pub,1,32); $y = substr($pub,33,32);
    $pkey = openssl_pkey_get_private(wp_ec_pem_from_raw($d,$x,$y));
    if(!$pkey) return null;

    $derSig = '';
    if(!openssl_sign($signingInput, $derSig, $pkey, OPENSSL_ALGO_SHA256)) return null;
    return $signingInput.'.'.wp_b64url_encode(wp_der_to_raw_signature($derSig));
}
// Chiffre le message selon aes128gcm (RFC 8291) pour un abonnement donne.
function wp_encrypt($p256dhB64, $authKeyB64, $payload) {
    $uaPublic = wp_b64url_decode($p256dhB64);
    $authSecret = wp_b64url_decode($authKeyB64);
    if(strlen($uaPublic)!==65 || strlen($authSecret)!==16) return null;

    $eph = openssl_pkey_new(['curve_name'=>'prime256v1','private_key_type'=>OPENSSL_KEYTYPE_EC]);
    $ephDetails = openssl_pkey_get_details($eph);
    $asPublic = "\x04".$ephDetails['ec']['x'].$ephDetails['ec']['y'];

    $uaX = substr($uaPublic,1,32); $uaY = substr($uaPublic,33,32);
    $uaKey = openssl_pkey_get_public(wp_ec_public_pem_from_raw($uaX,$uaY));
    if(!$uaKey) return null;

    $sharedSecret = openssl_pkey_derive($uaKey, $eph);
    if($sharedSecret===false) return null;
    $sharedSecret = str_pad($sharedSecret, 32, "\x00", STR_PAD_LEFT);
    if(strlen($sharedSecret)>32) $sharedSecret = substr($sharedSecret,-32);

    $prkKey = hash_hmac('sha256', $sharedSecret, $authSecret, true);
    $keyInfo = "WebPush: info\x00".$uaPublic.$asPublic;
    $ikm = substr(hash_hmac('sha256', $keyInfo."\x01", $prkKey, true), 0, 32);

    $salt = openssl_random_pseudo_bytes(16);
    $prk = hash_hmac('sha256', $ikm, $salt, true);
    $cek = substr(hash_hmac('sha256', "Content-Encoding: aes128gcm\x00\x01", $prk, true), 0, 16);
    $nonce = substr(hash_hmac('sha256', "Content-Encoding: nonce\x00\x01", $prk, true), 0, 12);

    $plaintext = $payload."\x02";
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-128-gcm', $cek, OPENSSL_RAW_DATA, $nonce, $tag);
    if($ciphertext===false) return null;

    $rs = 4096;
    $header = $salt.pack('N',$rs).chr(65).$asPublic;
    return $header.$ciphertext.$tag;
}
// Envoie une notification push a UN abonnement. $subscription doit contenir
// endpoint, p256dh_key, auth_key. Ne leve jamais d'exception : une erreur
// d'envoi (abonnement expire, service indisponible...) ne doit jamais faire
// echouer la transaction financiere qui a declenche cette notification.
function web_push_send($subscription, $title, $body, $extra = []) {
    try {
        $payload = json_encode(array_merge(['title'=>$title,'body'=>$body], $extra));
        $encrypted = wp_encrypt($subscription['p256dh_key'], $subscription['auth_key'], $payload);
        if(!$encrypted) return false;

        $endpoint = $subscription['endpoint'];
        $origin = parse_url($endpoint, PHP_URL_SCHEME).'://'.parse_url($endpoint, PHP_URL_HOST);
        $jwt = wp_build_vapid_jwt($origin);
        if(!$jwt) return false;

        $ch = curl_init($endpoint);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $encrypted,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/octet-stream',
                'Content-Encoding: aes128gcm',
                'TTL: 60',
                'Urgency: high',
                'Authorization: vapid t='.$jwt.', k='.VAPID_PUBLIC_KEY,
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
        ]);
        $res = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        // 404/410 = abonnement expire/revoque cote navigateur : on le supprime
        if($code===404 || $code===410){
            q("DELETE FROM push_subscriptions WHERE endpoint=?", [$endpoint]);
        }
        return $code>=200 && $code<300;
    } catch(Exception $e) { return false; }
}
// Envoie une notification push a TOUS les appareils abonnes d'un utilisateur.
function web_push_send_to_user($userId, $title, $body, $extra = [], $category = 'general') {
    // Persiste toujours une trace dans la table notifications (lue par l'ecran
    // "Notifications" de l'app), independamment du push : avant ce correctif,
    // rien n'y etait jamais enregistre et l'historique in-app restait vide en
    // permanence, meme pour un utilisateur ayant active les notifications push.
    // $category='credit' = deja reconstruit par le frontend via l'historique
    // des transactions (evite un doublon visible une fois recuperee ici).
    try {
        q("INSERT INTO notifications (user_id,title,body,category) VALUES (?,?,?,?)",[$userId,$title,$body,$category]);
    } catch(Exception $e) {}
    try {
        $subs = q("SELECT * FROM push_subscriptions WHERE user_id=?", [$userId])->fetchAll();
        foreach($subs as $sub){ web_push_send($sub, $title, $body, $extra); }
    } catch(Exception $e) {}
}

// Equivalent de web_push_send_to_user() pour un compte ROM_BUSINESS - table
// dediee (merchant_push_subscriptions) puisque l'identite marchand est
// separee de celle des utilisateurs personnels.
function web_push_send_to_merchant($merchantId, $title, $body, $extra = []) {
    try {
        $subs = q("SELECT * FROM merchant_push_subscriptions WHERE merchant_id=?", [$merchantId])->fetchAll();
        foreach($subs as $sub){ web_push_send($sub, $title, $body, $extra); }
    } catch(Exception $e) {}
}

function web_push_send_to_agent($agentId, $title, $body, $extra = []) {
    try {
        $subs = q("SELECT * FROM agent_push_subscriptions WHERE agent_id=?", [$agentId])->fetchAll();
        foreach($subs as $sub){ web_push_send($sub, $title, $body, $extra); }
    } catch(Exception $e) {}
}

// Alerte push vers TOI (admin), pour les actions les plus sensibles - pour
// ne pas devoir aller consulter le journal d'audit pour t'en rendre compte.
function web_push_send_to_admin($title, $body, $extra = []) {
    try {
        $subs = q("SELECT * FROM admin_push_subscriptions")->fetchAll();
        foreach($subs as $sub){ web_push_send($sub, $title, $body, $extra); }
    } catch(Exception $e) {}
}

// Verifie que creditier $userId de $incomingNet ne depasse pas son plafond
// mensuel de reception (remis a zero chaque mois calendaire, comme les stats).
// Bloque avec fail() si le plafond serait depasse. $selfFacing indique si la
// personne qui appelle l'API est elle-meme le destinataire (Encaisser, Depot
// bancaire) ou une autre personne (Envoyer -> le message s'adresse a l'emetteur).
function check_receive_limit($userId, $incomingNet, $selfFacing=true) {
    $u = q("SELECT is_kyc FROM users WHERE id=?",[$userId])->fetch();
    $limitXof = ($u && $u['is_kyc']) ? (float)get_setting('limit_verified', 100000000) : (float)get_setting('limit_unverified', 2000000);
    $wallet = q("SELECT id, currency FROM wallets WHERE user_id=?",[$userId])->fetch();
    if (!$wallet) return;
    $wid = $wallet['id'];
    $currency = $wallet['currency'] ?: 'XOF';
    // Les plafonds sont toujours definis en XOF par l'admin (habitude et
    // reference actuelles) : on les convertit vers la devise reelle du
    // destinataire avant de comparer. Si la conversion echoue (source de
    // taux indisponible), on garde le plafond en XOF tel quel plutot que de
    // bloquer completement l'utilisateur - filet de securite, pas un blocage.
    $limit = $limitXof;
    if ($currency !== 'XOF') {
        $converted = convert_currency($limitXof, 'XOF', $currency);
        if ($converted !== null) $limit = $converted;
    }
    // receiver_amount (Phase 3) reflete ce qui est REELLEMENT credite au
    // destinataire dans SA devise ; net_amount/amount sont un repli pour les
    // transactions plus anciennes ou les types qui ne le renseignent pas
    // encore (Encaisser, Payer).
    $row = q("SELECT COALESCE(SUM(COALESCE(receiver_amount, net_amount, amount)),0) total FROM transactions
        WHERE receiver_wallet_id=? AND status='completed' AND type!='fee'
        AND EXTRACT(MONTH FROM created_at)=EXTRACT(MONTH FROM NOW())
        AND EXTRACT(YEAR FROM created_at)=EXTRACT(YEAR FROM NOW())",[$wid])->fetch();
    $currentTotal = (float)($row['total'] ?? 0);
    if($currentTotal + $incomingNet > $limit){
        if($selfFacing){
            fail('Vous avez atteint votre plafond mensuel. Faites-vous identifier pour deplafonner.', 403);
        } else {
            fail('Votre destinataire a atteint son plafond mensuel.', 403);
        }
    }
}


const PIN_MAX_ATTEMPTS = 5;
const PIN_LOCK_MINUTES = 60;
// Plafond de float applique automatiquement a un agent la toute premiere
// fois qu'il devient distributeur (montee en confiance progressive) - voir
// admin_agent_toggle_distributor(). Ajustable ensuite au cas par cas par
// l'admin via admin_agent_set_float_cap().
const DISTRIBUTOR_DEFAULT_FLOAT_CAP = 500000;
const REFERRAL_BONUS_PCT = 0.30;

// Verse au parrain 30% des frais generes par la PREMIERE transaction a frais
// (>= 4000 F) de son filleul. Ne se declenche qu'une seule fois par filleul
// (verifie via referral_bonuses). Le lien de parrainage etant fixe a
// l'inscription (users.referred_by, jamais modifiable ensuite), un compte
// deja existant ne peut jamais devenir "parraine" retroactivement.
function apply_referral_bonus($senderId, $fee, $feeCurrency='XOF') {
    if($fee <= 0) return;
    $u = q("SELECT referred_by FROM users WHERE id=?",[$senderId])->fetch();
    if(!$u || !$u['referred_by']) return;
    $referrerId = $u['referred_by'];

    $already = q("SELECT id FROM referral_bonuses WHERE referee_id=?",[$senderId])->fetch();
    if($already) return;

    $bonus = round($fee * REFERRAL_BONUS_PCT);
    if($bonus <= 0) return;

    $referrerW = q("SELECT id,currency FROM wallets WHERE user_id=?",[$referrerId])->fetch();
    if(!$referrerW) return;

    // $bonus est calcule dans la devise du filleul (celle de ses frais) : il
    // faut le convertir vers la devise du parrain avant de le crediter, sinon
    // le montant verse est faux quand parrain et filleul sont dans des pays
    // differents.
    $referrerCurrency = $referrerW['currency'] ?: 'XOF';
    $bonusConverted = $bonus;
    if($referrerCurrency !== $feeCurrency){
        $c = convert_currency($bonus, $feeCurrency, $referrerCurrency);
        if($c !== null) $bonusConverted = round($c, 2);
    }

    $bonusId = uid(); $txid = uid(); $ref = ref();
    q("INSERT INTO referral_bonuses (id,referrer_id,referee_id,transaction_id,bonus_amount) VALUES (?,?,?,?,?)",
      [$bonusId,$referrerId,$senderId,$txid,$bonusConverted]);
    q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'referral_bonus','completed',?,'Bonus de parrainage')",
      [$txid,null,$referrerW['id'],$bonusConverted,$ref]);
    q("UPDATE wallets SET balance=balance+? WHERE id=?",[$bonusConverted,$referrerW['id']]);
}



// Verifies $pin against $hash for $userId, with attempt counting + temporary lockout.
// Stops execution via fail() if locked or incorrect; resets the counter on success.
function pin_check($userId, $pin, $hash) {
    $u = q("SELECT pin_attempts, pin_locked_until FROM users WHERE id=?",[$userId])->fetch();
    $lockedUntil = $u['pin_locked_until'] ?? null;
    if($lockedUntil && strtotime($lockedUntil) > time()){
        $mins = (int)ceil((strtotime($lockedUntil) - time())/60);
        fail("Compte temporairement bloque suite a plusieurs PIN incorrects. Reessayez dans $mins min.", 423);
    }
    if(!password_verify($pin, $hash)){
        $attempts = (int)($u['pin_attempts'] ?? 0) + 1;
        if($attempts >= PIN_MAX_ATTEMPTS){
            q("UPDATE users SET pin_attempts=0, pin_locked_until=? WHERE id=?",
              [date('Y-m-d H:i:s', time()+PIN_LOCK_MINUTES*60), $userId]);
            fail('Trop de tentatives incorrectes. Compte bloque '.PIN_LOCK_MINUTES.' minutes.', 423);
        }
        q("UPDATE users SET pin_attempts=? WHERE id=?",[$attempts, $userId]);
        $restantes = PIN_MAX_ATTEMPTS - $attempts;
        fail('PIN incorrect ('.$restantes.' tentative'.($restantes>1?'s':'').' restante'.($restantes>1?'s':'').')', 401);
    }
    if(($u['pin_attempts'] ?? 0) > 0){
        q("UPDATE users SET pin_attempts=0, pin_locked_until=NULL WHERE id=?",[$userId]);
    }
    return true;
}
// Equivalent de pin_check() pour un compte marchand (table merchants).
function merchant_pin_check($merchantId, $pin, $hash) {
    $m = q("SELECT pin_attempts, pin_locked_until FROM merchants WHERE id=?",[$merchantId])->fetch();
    $lockedUntil = $m['pin_locked_until'] ?? null;
    if($lockedUntil && strtotime($lockedUntil) > time()){
        $mins = (int)ceil((strtotime($lockedUntil) - time())/60);
        fail("Compte temporairement bloque suite a plusieurs PIN incorrects. Reessayez dans $mins min.", 423);
    }
    if(!password_verify($pin, $hash)){
        $attempts = (int)($m['pin_attempts'] ?? 0) + 1;
        if($attempts >= PIN_MAX_ATTEMPTS){
            q("UPDATE merchants SET pin_attempts=0, pin_locked_until=? WHERE id=?",
              [date('Y-m-d H:i:s', time()+PIN_LOCK_MINUTES*60), $merchantId]);
            fail('Trop de tentatives incorrectes. Compte bloque '.PIN_LOCK_MINUTES.' minutes.', 423);
        }
        q("UPDATE merchants SET pin_attempts=? WHERE id=?",[$attempts, $merchantId]);
        $restantes = PIN_MAX_ATTEMPTS - $attempts;
        fail('PIN incorrect ('.$restantes.' tentative'.($restantes>1?'s':'').' restante'.($restantes>1?'s':'').')', 401);
    }
    if(($m['pin_attempts'] ?? 0) > 0){
        q("UPDATE merchants SET pin_attempts=0, pin_locked_until=NULL WHERE id=?",[$merchantId]);
    }
    return true;
}
// Equivalent de pin_check() pour un compte agent ROM_GUICHET (table agents).
function agent_pin_check($agentId, $pin, $hash) {
    $a = q("SELECT pin_attempts, pin_locked_until FROM agents WHERE id=?",[$agentId])->fetch();
    $lockedUntil = $a['pin_locked_until'] ?? null;
    if($lockedUntil && strtotime($lockedUntil) > time()){
        $mins = (int)ceil((strtotime($lockedUntil) - time())/60);
        fail("Compte temporairement bloque suite a plusieurs PIN incorrects. Reessayez dans $mins min.", 423);
    }
    if(!password_verify($pin, $hash)){
        $attempts = (int)($a['pin_attempts'] ?? 0) + 1;
        if($attempts >= PIN_MAX_ATTEMPTS){
            q("UPDATE agents SET pin_attempts=0, pin_locked_until=? WHERE id=?",
              [date('Y-m-d H:i:s', time()+PIN_LOCK_MINUTES*60), $agentId]);
            fail('Trop de tentatives incorrectes. Compte bloque '.PIN_LOCK_MINUTES.' minutes.', 423);
        }
        q("UPDATE agents SET pin_attempts=? WHERE id=?",[$attempts, $agentId]);
        $restantes = PIN_MAX_ATTEMPTS - $attempts;
        fail('PIN incorrect ('.$restantes.' tentative'.($restantes>1?'s':'').' restante'.($restantes>1?'s':'').')', 401);
    }
    if(($a['pin_attempts'] ?? 0) > 0){
        q("UPDATE agents SET pin_attempts=0, pin_locked_until=NULL WHERE id=?",[$agentId]);
    }
    return true;
}

function db(): PDO {
    static $pdo = null;
    if(!$pdo) {
        try {
            $pdo = new PDO(
                "pgsql:host=".DB_HOST.";port=".DB_PORT.";dbname=".DB_NAME,
                DB_USER, DB_PASS,
                [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES=>true]
            );
        } catch(PDOException $e) {
            error_log('[ROM_MONEY] Erreur serveur :: BDD: '.$e->getMessage());
            fail(APP_DEBUG ? 'BDD: '.$e->getMessage() : 'Erreur serveur', 500);
        }
    }
    return $pdo;
}

function q($sql, $params=[]) {
    $s = db()->prepare($sql);
    $s->execute($params);
    return $s;
}

// ============================================================
// LIMITATION DE DEBIT (rate limiting) — filet de securite generique par IP,
// utilisable pour n'importe quel endpoint via un "bucket" (nom arbitraire).
// Complementaire, pas redondant, avec les protections deja en place :
// le PIN a deja son propre verrou par COMPTE (pin_check), l'admin a deja
// son verrou par IP (admin_bruteforce_check) - ceci couvre tout le reste
// (inscription, verification de numero, etc.) qui n'avait aucune limite.
// ============================================================
function rate_limit_check($bucket, $maxRequests, $windowSeconds) {
    // Cette protection ne doit JAMAIS pouvoir mettre l'app hors service.
    // Si la table n'existe pas encore (avant le tout premier /install) ou
    // pour toute autre erreur imprevue, on laisse simplement passer la
    // requete plutot que de faire planter l'app entiere (echec silencieux
    // et sans consequence, contrairement a un echec qui bloquerait tout).
    try {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        // Nettoyage opportuniste (1% de chance par appel), pour eviter que la
        // table grossisse indefiniment sans avoir besoin d'une tache planifiee.
        if (mt_rand(1, 100) === 1) {
            q("DELETE FROM rate_limit_hits WHERE created_at < NOW() - INTERVAL '1 hour'");
        }
        $row = q("SELECT COUNT(*) c FROM rate_limit_hits
                  WHERE bucket=? AND ip_address=?
                  AND created_at > NOW() - (?::text || ' seconds')::interval",
                  [$bucket, $ip, $windowSeconds])->fetch();
        if ($row && (int)$row['c'] >= $maxRequests) {
            fail('Trop de requetes depuis cette adresse. Reessayez dans quelques instants.', 429);
        }
        q("INSERT INTO rate_limit_hits (bucket, ip_address) VALUES (?,?)", [$bucket, $ip]);
    } catch (PDOException $e) { /* table pas encore prete : on laisse passer */ }
}

$uri    = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
$parts  = explode('/', $uri);
$module = $parts[1] ?? ($parts[0] ?? '');
$action = $_GET['action'] ?? '';

// Filet de securite general : large marge (120 requetes/min/IP) pour ne
// jamais genrer un utilisateur normal, mais qui bloque un script qui
// bombarderait l'API. Les endpoints les plus sensibles a l'enumeration
// (verification de numero, inscription, connexion) ont en plus leur PROPRE
// limite, plus stricte, directement dans leur fonction. "health" est exclu
// car utilise par les outils de supervision Render, potentiellement souvent.
if ($module !== 'health') {
    rate_limit_check('global', 120, 60);
}

switch($module) {
    case 'auth':        route_auth($action); break;
    case 'wallet':      route_wallet($action); break;
    case 'merchant':    route_merchant($action); break;
    case 'agent':       route_agent($action); break;
    case 'transactions':route_tx($action); break;
    case 'profile':     route_profile($action); break;
    case 'kyc':         route_kyc($action); break;
    case 'announce':    route_announce($action); break;
    case 'admin':       route_admin($action); break;
    case 'export':      route_export($action); break;
    case 'push':        route_push($action); break;
    case 'health':
        // Touche la base de donnees (requete minimale) pour que ce endpoint,
        // appele regulierement par un service de surveillance externe,
        // maintienne aussi Neon eveille - pas seulement le serveur PHP sur
        // Render. Sans ce petit aller-retour, un ping ici ne reveillerait
        // que la moitie du systeme.
        $dbOk = true;
        try { q("SELECT 1"); } catch (Exception $e) { $dbOk = false; }
        ok(['status'=>'ok','app'=>'Rom_money','version'=>'1.0','time'=>date('Y-m-d H:i:s'),'db'=>$dbOk?'ok':'unreachable']);
    case 'install':     route_install(); break;
    default:
        ok(['app'=>'Rom_money API','version'=>'1.0','routes'=>['/auth','/wallet','/transactions','/profile','/bank','/kyc','/health','/install']]);
}

// AUTH
function route_auth($action) {
    match($action) {
        'register'    => auth_register(),
        'login'       => auth_login(),
        'logout'      => auth_logout(),
        'change-pin'  => auth_change_pin(),
        'countries'   => auth_active_countries(),
        'check-phone' => auth_check_phone(),
        'check-referral-code' => auth_check_referral_code(),
        default       => fail('Action inconnue',404)
    };
}

// Route publique legere : verifie juste si un numero est deja associe a un
// compte, sans rien creer - utilisee des l'etape 1 de l'inscription pour
// avertir immediatement au lieu de laisser l'utilisateur traverser tout le
// flux (PIN, biometrie) avant de decouvrir le doublon a la toute fin.
function auth_check_phone() {
    rate_limit_check('check_phone', 20, 60);
    $b = body();
    $phone = trim($b['phone'] ?? '');
    if(!$phone) fail('Telephone requis');
    $exists = q("SELECT id FROM users WHERE phone_number=?",[$phone])->fetch();
    ok(['exists' => (bool)$exists]);
}

// Route publique : verifie un code de parrainage pendant la saisie a
// l'inscription, et renvoie le nom du parrain si le code est valide - pour
// eviter qu'une faute de frappe passe totalement inapercue (avant, un code
// invalide etait accepte silencieusement, sans jamais prevenir personne).
function auth_check_referral_code() {
    rate_limit_check('check_refcode', 30, 60);
    $b = body();
    $code = trim($b['code'] ?? '');
    if(!$code) ok(['valid'=>false]);
    $u = q("SELECT full_name, verified_name FROM users WHERE referral_code=?",[strtoupper($code)])->fetch();
    if(!$u) ok(['valid'=>false]);
    ok(['valid'=>true, 'name'=>$u['verified_name'] ?: $u['full_name']]);
}

// Route publique (pas d'authentification requise) : liste des pays actifs,
// utilisee pour le formulaire d'inscription avant que l'utilisateur ait un
// compte, et aussi reutilisable pour l'ecran Transfert Afrique une fois connecte.
function auth_active_countries() {
    $rows = q("SELECT name FROM active_countries WHERE is_active=1 ORDER BY name ASC")->fetchAll();
    ok(['countries' => array_column($rows, 'name')]);
}

function generate_referral_code() {
    do {
        $code = 'ROM'.strtoupper(substr(bin2hex(random_bytes(3)),0,6));
        $exists = q("SELECT id FROM users WHERE referral_code=?",[$code])->fetch();
    } while($exists);
    return $code;
}

// PIN faibles interdits : chiffres identiques (0000, 1111...) et
// suites logiques evidentes (croissantes ou decroissantes). Reste un code
// a 4 chiffres classique pour l'utilisateur, sans nouvelle contrainte de
// lecture - juste quelques combinaisons trop simples ecartees.
function is_weak_pin($pin) {
    if (preg_match('/^(\d)\1{3}$/', $pin)) return true; // 0000, 1111, ...
    $sequencesUp = '01234567890123456789';
    $sequencesDown = '98765432109876543210';
    if (strpos($sequencesUp, $pin) !== false) return true;   // 123456, 234567, ...
    if (strpos($sequencesDown, $pin) !== false) return true; // 987654, 654321, ...
    return false;
}

// Miroir exact de COUNTRY_CURRENCY cote frontend (index.html) - garder les
// deux synchronises si la liste de pays evolue. Determine la devise du
// portefeuille a la creation du compte, selon le pays choisi.
function country_to_currency($country) {
    $map = [
        "Côte d'Ivoire"=>'XOF','Sénégal'=>'XOF','Mali'=>'XOF','Burkina Faso'=>'XOF','Niger'=>'XOF','Togo'=>'XOF','Bénin'=>'XOF','Guinée-Bissau'=>'XOF',
        'Cameroun'=>'XAF','Congo-Brazzaville'=>'XAF','Gabon'=>'XAF','Centrafrique'=>'XAF','Tchad'=>'XAF','Guinée Équatoriale'=>'XAF',
        'Comores'=>'KMF','Algérie'=>'DZD','Angola'=>'AOA','Burundi'=>'BIF','Botswana'=>'BWP','Congo-Kinshasa'=>'CDF','Djibouti'=>'DJF',
        'Égypte'=>'EGP','Érythrée'=>'ERN','Éthiopie'=>'ETB','Ghana'=>'GHS','Guinée Conakry'=>'GNF','Kenya'=>'KES','Lesotho'=>'LSL',
        'Liberia'=>'LRD','Libye'=>'LYD','Madagascar'=>'MGA','Malawi'=>'MWK','Mauritanie'=>'MRU','Maurice'=>'MUR','Maroc'=>'MAD',
        'Mozambique'=>'MZN','Namibie'=>'NAD','Nigeria'=>'NGN','Rwanda'=>'RWF','São Tomé'=>'STN','Seychelles'=>'SCR','Sierra Leone'=>'SLE',
        'Somalie'=>'SOS','Afrique du Sud'=>'ZAR','Soudan du Sud'=>'SSP','Soudan'=>'SDG','Eswatini'=>'SZL','Tanzanie'=>'TZS','Tunisie'=>'TND',
        'Ouganda'=>'UGX','Zambie'=>'ZMW','Zimbabwe'=>'ZWG',
    ];
    return $map[$country] ?? 'XOF';
}

// ============================================================
// TAUX DE CHANGE — plutot que de stocker un taux pour CHAQUE paire de
// devises possibles (des centaines de combinaisons), on stocke chaque
// devise face au dollar americain (USD), et on calcule n'importe quelle
// conversion a partir de ces deux valeurs de reference - exactement comme
// procedent les vraies banques (le "cross rate").
// Source : fawazahmed0/exchange-api, gratuite, sans cle ni compte,
// mise a jour quotidiennement, 200+ devises. Deux URLs (CDN principal +
// repli Cloudflare) pour la resilience, comme recommande par la doc de
// l'API elle-meme.
// ============================================================
function fetch_rates_from_api() {
    $urls = [
        'https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@latest/v1/currencies/usd.json',
        'https://latest.currency-api.pages.dev/v1/currencies/usd.json',
    ];
    foreach ($urls as $url) {
        try {
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 8);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            $resp = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($resp && $httpCode === 200) {
                $json = json_decode($resp, true);
                if (isset($json['usd']) && is_array($json['usd']) && count($json['usd']) > 50) {
                    return $json['usd'];
                }
            }
        } catch (Exception $e) { /* on tente l'URL suivante */ }
    }
    return null; // les deux sources ont echoue : on continuera avec les taux deja en cache
}

// Ne rafraichit que si les taux en cache ont plus de 12h - evite d'appeler
// l'API externe a chaque transaction. Si l'API est injoignable, on garde
// simplement les derniers taux connus plutot que de bloquer quoi que ce
// soit : mieux vaut un taux legerement ancien qu'un transfert qui echoue.
function refresh_exchange_rates_if_stale() {
    $lastUpdate = q("SELECT MAX(updated_at) AS m FROM exchange_rates")->fetch();
    if ($lastUpdate && $lastUpdate['m'] && (time() - strtotime($lastUpdate['m'])) < 12 * 3600) {
        return; // encore frais, rien a faire
    }
    $rates = fetch_rates_from_api();
    if (!$rates) return; // API indisponible : on garde le cache existant tel quel
    foreach ($rates as $code => $rate) {
        if (!is_numeric($rate) || $rate <= 0) continue;
        q("INSERT INTO exchange_rates (currency_code, rate_to_usd) VALUES (?,?)
           ON CONFLICT (currency_code) DO UPDATE SET rate_to_usd=EXCLUDED.rate_to_usd, updated_at=NOW()",
          [strtoupper($code), $rate]);
    }
}

// Convertit un montant d'une devise vers une autre, via le dollar comme
// intermediaire commun. Renvoie null si l'une des deux devises n'a pas
// (encore) de taux connu - a gerer explicitement par l'appelant, jamais
// de conversion silencieuse a 1:1 qui ferait perdre ou gagner de l'argent
// a quelqu'un par erreur.
function convert_currency($amount, $fromCode, $toCode) {
    // 'FCFA' n'est pas un vrai code ISO (donc jamais present dans
    // exchange_rates, qui ne contient que les codes renvoyes par l'API) -
    // mais certains comptes crees avant country_to_currency() l'ont encore
    // stocke tel quel (ancienne valeur par defaut de wallets.currency).
    // Normalise ici en plus de la migration de donnees, pour que ça marche
    // immediatement meme si le /install correctif n'a pas encore tourne.
    if(strtoupper($fromCode)==='FCFA') $fromCode='XOF';
    if(strtoupper($toCode)==='FCFA') $toCode='XOF';
    $fromCode = strtoupper($fromCode); $toCode = strtoupper($toCode);
    if ($fromCode === $toCode) return $amount;
    refresh_exchange_rates_if_stale();
    $fromRate = q("SELECT rate_to_usd FROM exchange_rates WHERE currency_code=?",[$fromCode])->fetchColumn();
    $toRate = q("SELECT rate_to_usd FROM exchange_rates WHERE currency_code=?",[$toCode])->fetchColumn();
    if (!$fromRate || !$toRate) return null;
    $usdAmount = $amount / (float)$fromRate;
    return $usdAmount * (float)$toRate;
}

function auth_register() {
    rate_limit_check('register', 10, 60);
    $b = body();
    $name  = trim($b['full_name'] ?? '');
    $phone = trim($b['phone']     ?? '');
    $pin   = trim($b['pin']       ?? '');
    $email = trim($b['email']     ?? '');
    $op    = trim($b['operator']  ?? '');
    $country = trim($b['country'] ?? '');
    $refCodeInput = trim($b['referral_code'] ?? '');
    $deviceId = trim($b['device_id'] ?? '');
    if(!$name) fail('Nom requis');
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $phone))) fail('Telephone invalide');
    if(!preg_match('/^\d{4}$/', $pin)) fail('PIN doit avoir 4 chiffres');
    if(is_weak_pin($pin)) fail('Ce code est trop simple, choisissez une autre combinaison');
    // Plus de liste figee a 3 operateurs ivoiriens : les operateurs varient
    // par pays (voir COUNTRY_OPERATORS cote frontend), et l'utilisateur peut
    // aussi saisir librement le sien ("Autre"). Validation generique a la
    // place : juste une longueur raisonnable, pour eviter un champ vide ou
    // un texte visiblement invalide.
    if(mb_strlen($op) < 2 || mb_strlen($op) > 60) fail('Operateur invalide');
    if(!$country) fail('Le pays est requis');
    $countryRow = q("SELECT is_active FROM active_countries WHERE name=?",[$country])->fetch();
    if(!$countryRow || !$countryRow['is_active']) fail('ROM_MONEY n\'est pas encore disponible dans ce pays');
    $exist = q("SELECT id FROM users WHERE phone_number=?", [$phone])->fetch();
    if($exist) fail('Ce numero est deja enregistre');

    // Parrainage : uniquement resolu a l'inscription, jamais modifiable apres coup
    // (un compte deja existant ne peut donc jamais devenir "parraine" retroactivement).
    $referredBy = null;
    if($refCodeInput){
        $referrer = q("SELECT id FROM users WHERE referral_code=?",[strtoupper($refCodeInput)])->fetch();
        if($referrer) $referredBy = $referrer['id'];
    }

    db()->beginTransaction();
    try {
        $uid    = uid();
        $wid    = uid();
        $qrseed = strtoupper(bin2hex(random_bytes(5)));
        $pinh   = password_hash($pin, PASSWORD_BCRYPT);
        $passh  = password_hash(bin2hex(random_bytes(12)), PASSWORD_BCRYPT);
        $myReferralCode = generate_referral_code();
        q("INSERT INTO users (id,full_name,phone_number,email,operator,password_hash,pin_hash,referral_code,referred_by,country) VALUES (?,?,?,?,?,?,?,?,?,?)",
          [$uid,$name,$phone,$email?:null,$op?:null,$passh,$pinh,$myReferralCode,$referredBy,$country]);
        q("INSERT INTO wallets (id,user_id,balance,vault_balance,currency,qr_seed) VALUES (?,?,0,0,?,?)",
          [$wid,$uid,country_to_currency($country),$qrseed]);
        if($deviceId){
            $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
            q("INSERT INTO known_devices (user_id,device_id,user_agent) VALUES (?,?,?)
               ON CONFLICT (user_id, device_id) DO UPDATE SET last_seen=CURRENT_TIMESTAMP, revoked=0",
              [$uid, $deviceId, $ua]);
        }
        $token = jwt_make(['sub'=>$uid,'phone'=>$phone,'device_id'=>$deviceId]);
        db()->commit();
        ok(['token'=>$token,'user_id'=>$uid,'name'=>$name,'phone'=>$phone,'qr_seed'=>$qrseed,'referral_code'=>$myReferralCode],'Compte cree', 201);
    } catch(Exception $e) {
        db()->rollBack();
        log_and_fail($e, 'Erreur creation compte', 500);
    }
}

function auth_login() {
    rate_limit_check('login', 15, 60);
    $b = body();
    $phone = trim($b['phone'] ?? '');
    $pin   = trim($b['pin']   ?? '');
    $deviceId = trim($b['device_id'] ?? '');
    if(!$phone || !$pin) fail('Telephone et PIN requis');
    $user = q("SELECT u.*,w.id wid,w.balance,w.vault_balance,w.vault_locked,w.vault_lock_date,w.qr_seed FROM users u LEFT JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?", [$phone])->fetch();
    if(!$user) fail('Numero ou PIN incorrect', 401);
    // Meme verrou que pour les confirmations de transfert : 5 tentatives puis
    // blocage de 60 min. Avant, la connexion elle-meme n'avait aucune limite
    // par compte (seulement la limite generale par IP ajoutee plus tot).
    pin_check($user['id'], $pin, $user['pin_hash']);
    if($user['status'] !== 'active') fail('Compte suspendu', 403);

    // Alerte "nouvel appareil" : si cet identifiant d'appareil n'a jamais ete
    // vu pour ce compte, on notifie l'utilisateur (sur ses AUTRES appareils
    // deja connus, via push) puis on enregistre celui-ci comme connu.
    if($deviceId){
        $known = q("SELECT 1 FROM known_devices WHERE user_id=? AND device_id=?", [$user['id'], $deviceId])->fetch();
        if(!$known){
            $hasOtherDevices = q("SELECT 1 FROM known_devices WHERE user_id=?", [$user['id']])->fetch();
            if($hasOtherDevices){
                web_push_send_to_user($user['id'], 'ROM_MONEY',
                    'Nouvelle connexion detectee sur votre compte depuis un appareil non reconnu.');
            }
            $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
            q("INSERT INTO known_devices (user_id,device_id,user_agent) VALUES (?,?,?)
               ON CONFLICT (user_id, device_id) DO UPDATE SET last_seen=CURRENT_TIMESTAMP, revoked=0",
              [$user['id'], $deviceId, $ua]);
        } else {
            // Une connexion reussie (bon PIN) reprouve la legitimite de cet
            // appareil : si l'utilisateur l'avait revoque par erreur, ou s'il
            // recupere son propre telephone, il redevient actif normalement.
            q("UPDATE known_devices SET last_seen=CURRENT_TIMESTAMP, revoked=0 WHERE user_id=? AND device_id=?", [$user['id'], $deviceId]);
        }
    }

    $token = jwt_make(['sub'=>$user['id'],'phone'=>$phone,'device_id'=>$deviceId]);
    ok(['token'=>$token,'user_id'=>$user['id'],'name'=>$user['full_name'],'phone'=>$user['phone_number'],
        'wallet_id'=>$user['wid'],'balance'=>(float)$user['balance'],'vault_balance'=>(float)$user['vault_balance'],
        'vault_locked'=>(bool)$user['vault_locked'],'vault_lock_date'=>$user['vault_lock_date'],
        'qr_seed'=>$user['qr_seed'],'is_kyc'=>(bool)$user['is_kyc'],'bio_enabled'=>(bool)$user['bio_enabled']],'Connexion reussie');
}

function auth_logout() { auth(); ok(null,'Deconnecte'); }

function auth_change_pin() {
    $pl = auth(); $b = body();
    $cur = trim($b['current_pin'] ?? '');
    $new = trim($b['new_pin']     ?? '');
    if(!preg_match('/^\d{4}$/',$cur)) fail('PIN actuel invalide');
    if(!preg_match('/^\d{4}$/',$new)) fail('Nouveau PIN invalide');
    if(is_weak_pin($new)) fail('Ce code est trop simple, choisissez une autre combinaison');
    $user = q("SELECT pin_hash FROM users WHERE id=?", [$pl['sub']])->fetch();
    if(!password_verify($cur, $user['pin_hash'])) fail('PIN actuel incorrect', 401);
    q("UPDATE users SET pin_hash=? WHERE id=?", [password_hash($new,PASSWORD_BCRYPT), $pl['sub']]);
    ok(null,'PIN mis a jour');
}

function merchant_change_pin() {
    $pl = merchant_auth(); $b = body();
    $cur = trim($b['current_pin'] ?? '');
    $new = trim($b['new_pin']     ?? '');
    if(!preg_match('/^\d{4}$/',$cur)) fail('PIN actuel invalide');
    if(!preg_match('/^\d{4}$/',$new)) fail('Nouveau PIN invalide');
    if(is_weak_pin($new)) fail('Ce code est trop simple, choisissez une autre combinaison');
    $m = q("SELECT pin_hash FROM merchants WHERE id=?", [$pl['sub']])->fetch();
    if(!password_verify($cur, $m['pin_hash'])) fail('PIN actuel incorrect', 401);
    q("UPDATE merchants SET pin_hash=? WHERE id=?", [password_hash($new,PASSWORD_BCRYPT), $pl['sub']]);
    ok(null,'PIN mis a jour');
}

// "Mes appareils" cote marchand - meme principe que profile_devices()/
// profile_revoke_device() cote personnel, table separee (merchant_known_devices).
function merchant_devices() {
    $pl = merchant_auth();
    $rows = q("SELECT device_id,user_agent,first_seen,last_seen,revoked FROM merchant_known_devices WHERE merchant_id=? ORDER BY last_seen DESC",[$pl['sub']])->fetchAll();
    foreach($rows as &$r){ $r['is_current'] = ($pl['device_id'] ?? '') !== '' && $r['device_id'] === $pl['device_id']; $r['revoked']=(bool)$r['revoked']; }
    unset($r);
    ok(['devices'=>$rows]);
}
function merchant_revoke_device() {
    $pl = merchant_auth(); $b = body();
    $deviceId = trim($b['device_id'] ?? '');
    if(!$deviceId) fail('Appareil requis');
    $n = q("UPDATE merchant_known_devices SET revoked=1 WHERE merchant_id=? AND device_id=?",[$pl['sub'],$deviceId])->rowCount();
    if(!$n) fail('Appareil introuvable',404);
    ok(null,'Appareil deconnecte');
}

// Un merchant_documents.doc_type par marchand : reenvoyer le meme type
// remplace simplement l'ancien (ON CONFLICT), pas d'historique de versions -
// ce n'est pas necessaire ici (contrairement au KYC personnel qui garde tout
// l'historique de demandes pour l'audit).
function merchant_document_upload() {
    $pl = merchant_auth(); $b = body();
    $docType = trim($b['doc_type'] ?? '');
    $photo = trim($b['photo'] ?? '');
    if(!in_array($docType, MERCHANT_DOC_TYPES, true)) fail('Type de document invalide');
    if(!$photo) fail('Photo requise');
    if(strlen($photo) > 8*1024*1024) fail('Image trop volumineuse');
    // Creneau deja occupe : un admin doit explicitement supprimer le
    // document existant (avec raison) pour permettre un nouvel envoi.
    $existing = q("SELECT id FROM merchant_documents WHERE merchant_id=? AND doc_type=?",[$pl['sub'],$docType])->fetch();
    if($existing) fail('Ce document est deja envoye - contactez un administrateur pour le remplacer');
    $encrypted = kyc_encrypt($photo);
    // Toujours un INSERT, jamais un remplacement : chaque envoi reste
    // consultable indefiniment (peut servir de preuve des annees plus tard),
    // meme si un document plus recent du meme type est envoye ensuite.
    try {
        q("INSERT INTO merchant_documents (merchant_id,doc_type,photo,uploaded_at) VALUES (?,?,?,NOW())",
          [$pl['sub'],$docType,$encrypted]);
    } catch(Exception $e) {
        log_and_fail($e, 'Service indisponible (base non initialisee).', 503);
    }
    ok(['uploaded_at'=>date('c')], 'Document enregistre');
}

function merchant_document_list() {
    $pl = merchant_auth();
    try {
        $rows = q("SELECT doc_type, uploaded_at FROM merchant_documents WHERE merchant_id=? ORDER BY doc_type, uploaded_at DESC",[$pl['sub']])->fetchAll();
    } catch(Exception $e) {
        $rows = [];
    }
    ok(['documents'=>$rows]);
}

// WALLET
function route_wallet($action) {
    match($action) {
        'balance'        => wallet_balance(),
        'vault-deposit'  => vault_deposit(),
        'vault-withdraw' => vault_withdraw(),
        'vault-lock'     => vault_lock(),
        'subvault-list'     => subvault_list(),
        'subvault-create'   => subvault_create(),
        'subvault-deposit'  => subvault_deposit(),
        'subvault-withdraw' => subvault_withdraw(),
        'subvault-lock'     => subvault_lock(),
        'subvault-unlock'   => subvault_unlock(),
        'subvault-delete'   => subvault_delete(),
        'renew-qr'       => wallet_renew_qr(),
        'resolve-qr'     => wallet_resolve_qr(),
        'resolve-merchant-qr' => wallet_resolve_merchant_qr(),
        'stats'          => wallet_stats(),
        'stats-full'     => wallet_stats_full(),
        'limit-status'   => wallet_limit_status(),
        'fee-config'     => wallet_fee_config(),
        default          => fail('Action inconnue',404)
    };
}

// Expose les taux de frais actuels (authentifie, pas besoin du mot de passe
// admin) : permet a l'app de calculer un apercu des frais TOUJOURS identique
// au montant reellement debite cote serveur, meme si l'admin a modifie ces
// taux depuis le panneau de reglages.
function wallet_fee_config() {
    $pl = auth();
    $settings = get_public_settings();
    // Reliquat de gratuite restant aujourd'hui pour CET utilisateur (voir
    // tx_send() : la gratuite est cumulee par jour/expediteur, pas par
    // transaction). Permet a l'aperçu de frais cote client de refleter la
    // meme regle que le calcul serveur, plutot que de toujours supposer le
    // plein seuil disponible.
    $sw = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    $sentToday = 0.0;
    if($sw){
        $sentToday = (float)(q("SELECT COALESCE(SUM(amount),0) t FROM transactions
            WHERE sender_wallet_id=? AND type='transfer' AND channel='national' AND status='completed'
            AND created_at::date=CURRENT_DATE",[$sw['id']])->fetch()['t']??0);
    }
    $settings['remaining_free_today'] = max(0, $settings['fee_free_threshold_national'] - $sentToday);
    ok($settings);
}

function wallet_balance() {
    $pl = auth();
    $w = q("SELECT w.*,u.full_name,u.phone_number,u.is_kyc,u.bio_enabled FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.user_id=?",[$pl['sub']])->fetch();
    if(!$w) fail('Portefeuille introuvable',404);
    ok(['balance'=>(float)$w['balance'],'vault_balance'=>(float)$w['vault_balance'],
        'vault_locked'=>(bool)$w['vault_locked'],'vault_lock_date'=>$w['vault_lock_date'],
        'qr_seed'=>$w['qr_seed'],'name'=>$w['full_name'],'phone'=>$w['phone_number'],
        'is_kyc'=>(bool)$w['is_kyc'],'currency'=>$w['currency']]);
}

function vault_deposit() {
    $pl = auth(); $b = body();
    $amt = (float)($b['amount']??0);
    if($amt<=0) fail('Montant invalide');
    $w = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    db()->beginTransaction();
    try {
        // Garde atomique (WHERE balance>=?) : deux depots simultanes ne peuvent
        // plus tous les deux passer si le solde ne suffit qu'une fois.
        $n = q("UPDATE wallets SET balance=balance-?,vault_balance=vault_balance+? WHERE id=? AND balance>=?",[$amt,$amt,$w['id'],$amt])->rowCount();
        if(!$n){ db()->rollBack(); fail('Solde insuffisant'); }
        q("INSERT INTO transactions (id,sender_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'vault_deposit','completed',?,'Depot coffre')",[uid(),$w['id'],$amt,ref()]);
        db()->commit();
        $fresh = q("SELECT balance,vault_balance FROM wallets WHERE id=?",[$w['id']])->fetch();
        ok(['amount'=>$amt,'new_balance'=>(float)$fresh['balance'],'vault_balance'=>(float)$fresh['vault_balance']],'Depose dans le coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur depot',500); }
}

function vault_withdraw() {
    $pl = auth(); $b = body();
    $amt = (float)($b['amount']??0); $pin = trim($b['pin']??'');
    if($amt<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/',$pin)) fail('PIN invalide');
    $user = q("SELECT pin_hash FROM users WHERE id=?",[$pl['sub']])->fetch();
    pin_check($pl['sub'], $pin, $user['pin_hash']);
    $w = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    if($w['vault_locked'] && strtotime($w['vault_lock_date']??'0')>time())
        fail("Coffre verrouille jusqu'au ".date('d/m/Y',strtotime($w['vault_lock_date'])));
    db()->beginTransaction();
    try {
        $n = q("UPDATE wallets SET vault_balance=vault_balance-?,balance=balance+?,vault_locked=0 WHERE id=? AND vault_balance>=?",[$amt,$amt,$w['id'],$amt])->rowCount();
        if(!$n){ db()->rollBack(); fail('Solde coffre insuffisant'); }
        q("INSERT INTO transactions (id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'vault_withdrawal','completed',?,'Retrait coffre')",[uid(),$w['id'],$amt,ref()]);
        db()->commit();
        $fresh = q("SELECT balance,vault_balance FROM wallets WHERE id=?",[$w['id']])->fetch();
        ok(['amount'=>$amt,'new_balance'=>(float)$fresh['balance'],'vault_balance'=>(float)$fresh['vault_balance']],'Retire du coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur retrait',500); }
}

function vault_lock() {
    $pl = auth(); $b = body();
    $date = trim($b['lock_date']??'');
    if(!$date || strtotime($date)<=time()) fail('Date invalide');
    q("UPDATE wallets SET vault_locked=1,vault_lock_date=? WHERE user_id=?",[$date,$pl['sub']]);
    ok(['lock_date'=>$date],'Coffre verrouille');
}

// ============================================================
// SOUS-COFFRES — plusieurs tirelires nommees a l'interieur du coffre
// principal d'un wallet. Chaque montant depose/retire d'un sous-coffre
// transite obligatoirement par vault_balance (le coffre principal), jamais
// directement par balance : ca garde une seule porte d'entree/sortie pour
// l'argent qui rentre dans l'univers "epargne".
// ============================================================

function subvault_owned($wid, $id) {
    $sv = q("SELECT * FROM sub_vaults WHERE id=? AND wallet_id=?",[$id,$wid])->fetch();
    if(!$sv) fail('Sous-coffre introuvable',404);
    return $sv;
}

function subvault_list() {
    $pl = auth();
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();
    $rows = q("SELECT id,name,balance,goal_amount,locked,lock_date FROM sub_vaults WHERE wallet_id=? ORDER BY created_at ASC",[$wid])->fetchAll();
    ok($rows);
}

function subvault_create() {
    $pl = auth(); $b = body();
    $name = trim($b['name'] ?? '');
    $amt  = (float)($b['amount'] ?? 0);
    $goal = isset($b['goal']) && $b['goal']!=='' ? (float)$b['goal'] : null;
    if(!$name) fail('Nom requis');
    if($amt<0) fail('Montant invalide');
    $w = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    db()->beginTransaction();
    try {
        $n = q("UPDATE wallets SET vault_balance=vault_balance-? WHERE id=? AND vault_balance>=?",[$amt,$w['id'],$amt])->rowCount();
        if(!$n){ db()->rollBack(); fail('Solde du coffre principal insuffisant'); }
        $id = uid();
        q("INSERT INTO sub_vaults (id,wallet_id,name,balance,goal_amount) VALUES (?,?,?,?,?)",[$id,$w['id'],$name,$amt,$goal]);
        db()->commit();
        $bal = (float)q("SELECT vault_balance FROM wallets WHERE id=?",[$w['id']])->fetchColumn();
        ok(['id'=>$id,'name'=>$name,'balance'=>$amt,'goal_amount'=>$goal,
            'vault_balance'=>$bal],'Sous-coffre cree');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur creation',500); }
}

function subvault_deposit() {
    $pl = auth(); $b = body();
    $id = trim($b['id'] ?? ''); $amt = (float)($b['amount'] ?? 0);
    if($amt<=0) fail('Montant invalide');
    $w = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    subvault_owned($w['id'], $id);
    db()->beginTransaction();
    try {
        $n = q("UPDATE wallets SET vault_balance=vault_balance-? WHERE id=? AND vault_balance>=?",[$amt,$w['id'],$amt])->rowCount();
        if(!$n){ db()->rollBack(); fail('Solde du coffre principal insuffisant'); }
        q("UPDATE sub_vaults SET balance=balance+? WHERE id=?",[$amt,$id]);
        db()->commit();
        $bal   = (float)q("SELECT vault_balance FROM wallets WHERE id=?",[$w['id']])->fetchColumn();
        $svBal = (float)q("SELECT balance FROM sub_vaults WHERE id=?",[$id])->fetchColumn();
        ok(['vault_balance'=>$bal,'sub_balance'=>$svBal],'Depose dans le sous-coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur depot',500); }
}

function subvault_withdraw() {
    $pl = auth(); $b = body();
    $id = trim($b['id'] ?? ''); $amt = (float)($b['amount'] ?? 0); $pin = trim($b['pin'] ?? '');
    if($amt<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/',$pin)) fail('PIN invalide');
    $user = q("SELECT pin_hash FROM users WHERE id=?",[$pl['sub']])->fetch();
    pin_check($pl['sub'], $pin, $user['pin_hash']);
    $w  = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    $sv = subvault_owned($w['id'], $id);
    if($sv['locked'] && strtotime($sv['lock_date']??'0')>time())
        fail("Sous-coffre verrouille jusqu'au ".date('d/m/Y',strtotime($sv['lock_date'])));
    db()->beginTransaction();
    try {
        $n = q("UPDATE sub_vaults SET balance=balance-?,locked=0 WHERE id=? AND balance>=?",[$amt,$id,$amt])->rowCount();
        if(!$n){ db()->rollBack(); fail('Solde du sous-coffre insuffisant'); }
        q("UPDATE wallets SET vault_balance=vault_balance+? WHERE id=?",[$amt,$w['id']]);
        db()->commit();
        $bal   = (float)q("SELECT vault_balance FROM wallets WHERE id=?",[$w['id']])->fetchColumn();
        $svBal = (float)q("SELECT balance FROM sub_vaults WHERE id=?",[$id])->fetchColumn();
        ok(['vault_balance'=>$bal,'sub_balance'=>$svBal],'Retire du sous-coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur retrait',500); }
}

function subvault_lock() {
    $pl = auth(); $b = body();
    $id = trim($b['id'] ?? ''); $date = trim($b['lock_date'] ?? '');
    if(!$date || strtotime($date)<=time()) fail('Date invalide');
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();
    subvault_owned($wid, $id);
    q("UPDATE sub_vaults SET locked=1,lock_date=? WHERE id=?",[$date,$id]);
    ok(['lock_date'=>$date],'Sous-coffre verrouille');
}

function subvault_unlock() {
    $pl = auth(); $b = body();
    $id = trim($b['id'] ?? '');
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();
    $sv = subvault_owned($wid, $id);
    if($sv['locked'] && strtotime($sv['lock_date']??'0')>time())
        fail("Verrouille jusqu'au ".date('d/m/Y',strtotime($sv['lock_date'])));
    q("UPDATE sub_vaults SET locked=0,lock_date=NULL WHERE id=?",[$id]);
    ok(null,'Sous-coffre deverrouille');
}

function subvault_delete() {
    $pl = auth(); $b = body();
    $id = trim($b['id'] ?? '');
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();
    $sv = subvault_owned($wid, $id);
    db()->beginTransaction();
    try {
        q("UPDATE wallets SET vault_balance=vault_balance+? WHERE id=?",[$sv['balance'],$wid]);
        q("DELETE FROM sub_vaults WHERE id=?",[$id]);
        db()->commit();
        $bal = (float)q("SELECT vault_balance FROM wallets WHERE id=?",[$wid])->fetchColumn();
        ok(['vault_balance'=>$bal],'Sous-coffre supprime');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur suppression',500); }
}

// ============================================================
// ROM_BUSINESS — moteur marchand. Reutilise le meme moteur de transactions
// et de sous-coffres (sub_vaults) que ROM_MONEY, mais avec une identite
// (table merchants/merchant_wallets) totalement separee des comptes
// personnels : un meme numero de telephone peut donc avoir les deux types
// de compte independamment (utile pour le virement gratuit "vers mon
// numero", voir merchant_withdraw ci-dessous).
// ============================================================
function route_merchant($action) {
    match($action) {
        'register'          => merchant_register(),
        'login'              => merchant_login(),
        'balance'            => merchant_balance(),
        'renew-qr'           => merchant_renew_qr(),
        'collect'            => merchant_collect(),
        'withdraw'           => merchant_withdraw(),
        'pay-merchant'       => merchant_pay_merchant(),
        'resolve-merchant-qr' => merchant_resolve_merchant_qr(),
        'create-payment-link' => merchant_create_payment_link(),
        'cancel-payment-link' => merchant_cancel_payment_link(),
        'list-payment-links'  => merchant_list_payment_links(),
        'vault-deposit'      => merchant_vault_deposit(),
        'vault-withdraw'     => merchant_vault_withdraw(),
        'vault-lock'         => merchant_vault_lock(),
        'subvault-list'      => merchant_subvault_list(),
        'subvault-create'    => merchant_subvault_create(),
        'subvault-deposit'   => merchant_subvault_deposit(),
        'subvault-withdraw'  => merchant_subvault_withdraw(),
        'subvault-lock'      => merchant_subvault_lock(),
        'subvault-unlock'    => merchant_subvault_unlock(),
        'subvault-delete'    => merchant_subvault_delete(),
        'resolve-payer'      => merchant_resolve_payer(),
        'history'            => merchant_tx_history(),
        'stats'              => merchant_stats(),
        'export-xlsx'        => merchant_export_xlsx(),
        'export-pdf'         => merchant_export_pdf(),
        'change-pin'         => merchant_change_pin(),
        'devices'            => merchant_devices(),
        'revoke-device'      => merchant_revoke_device(),
        'doc-upload'         => merchant_document_upload(),
        'doc-list'           => merchant_document_list(),
        default              => fail('Action inconnue',404)
    };
}

function merchant_register() {
    rate_limit_check('merchant_register', 10, 60);
    $b = body();
    $businessName = trim($b['business_name'] ?? '');
    $phone = trim($b['phone'] ?? '');
    $pin = trim($b['pin'] ?? '');
    $locationType = ($b['location_type'] ?? 'online')==='physical' ? 'physical' : 'online';
    $address = trim($b['address'] ?? '');
    $deviceId = trim($b['device_id'] ?? '');
    $country = trim($b['country'] ?? '');
    if(!$businessName) fail('Nom de la boutique requis');
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $phone))) fail('Telephone invalide');
    if(!preg_match('/^\d{4}$/', $pin)) fail('PIN doit avoir 4 chiffres');
    if(is_weak_pin($pin)) fail('Ce code est trop simple, choisissez une autre combinaison');
    if($locationType==='physical' && !$address) fail('Adresse requise pour un local commercial');
    if(!$country) fail('Le pays est requis');
    $countryRow = q("SELECT is_active FROM active_countries WHERE name=?",[$country])->fetch();
    if(!$countryRow || !$countryRow['is_active']) fail('ROM_BUSINESS n\'est pas encore disponible dans ce pays');
    try {
        $exists = q("SELECT id FROM merchants WHERE phone_number=?",[$phone])->fetch();
    } catch(Exception $e) {
        // Table 'merchants' pas encore creee sur cette base (migration SQL pas
        // encore executee) : message clair au lieu de laisser fuiter une page
        // d'erreur PHP brute (non-JSON) qui casse le parsing cote app.
        log_and_fail($e, 'Service marchand indisponible pour le moment (base de donnees non initialisee).', 503);
    }
    if($exists) fail('Ce numero est deja enregistre comme marchand');

    db()->beginTransaction();
    try {
        $mid = uid(); $wid = uid();
        $pinh = password_hash($pin, PASSWORD_BCRYPT);
        $qrseed = strtoupper(bin2hex(random_bytes(5)));
        q("INSERT INTO merchants (id,phone_number,pin_hash,business_name,location_type,address,country) VALUES (?,?,?,?,?,?,?)",
          [$mid,$phone,$pinh,$businessName,$locationType,$address?:null,$country]);
        q("INSERT INTO merchant_wallets (id,merchant_id,qr_seed,currency) VALUES (?,?,?,?)",[$wid,$mid,$qrseed,country_to_currency($country)]);
        if($deviceId){
            $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
            q("INSERT INTO merchant_known_devices (merchant_id,device_id,user_agent) VALUES (?,?,?)
               ON CONFLICT (merchant_id, device_id) DO UPDATE SET last_seen=CURRENT_TIMESTAMP, revoked=0",
              [$mid, $deviceId, $ua]);
        }
        $token = jwt_make(['sub'=>$mid,'phone'=>$phone,'typ'=>'merchant','device_id'=>$deviceId]);
        db()->commit();
        ok(['token'=>$token,'merchant_id'=>$mid,'business_name'=>$businessName,
            'location_type'=>$locationType,'qr_seed'=>$qrseed],'Compte marchand cree',201);
    } catch(Exception $e) {
        db()->rollBack();
        log_and_fail($e, 'Erreur creation compte', 500);
    }
}

function merchant_login() {
    rate_limit_check('merchant_login', 15, 60);
    $b = body();
    $phone = trim($b['phone'] ?? '');
    $pin = trim($b['pin'] ?? '');
    $deviceId = trim($b['device_id'] ?? '');
    if(!$phone || !$pin) fail('Telephone et PIN requis');
    try {
        $m = q("SELECT * FROM merchants WHERE phone_number=?",[$phone])->fetch();
    } catch(Exception $e) {
        log_and_fail($e, 'Service marchand indisponible pour le moment (base de donnees non initialisee).', 503);
    }
    if(!$m) fail('Numero ou PIN incorrect', 401);
    merchant_pin_check($m['id'], $pin, $m['pin_hash']);
    if($m['status'] !== 'active') fail('Compte suspendu', 403);
    if($deviceId){
        $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
        q("INSERT INTO merchant_known_devices (merchant_id,device_id,user_agent) VALUES (?,?,?)
           ON CONFLICT (merchant_id, device_id) DO UPDATE SET last_seen=CURRENT_TIMESTAMP, revoked=0",
          [$m['id'], $deviceId, $ua]);
    }
    $w = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$m['id']])->fetch();
    $token = jwt_make(['sub'=>$m['id'],'phone'=>$phone,'typ'=>'merchant','device_id'=>$deviceId]);
    ok(['token'=>$token,'merchant_id'=>$m['id'],'business_name'=>$m['business_name'],
        'location_type'=>$m['location_type'],'address'=>$m['address'],
        'verified'=>(bool)($m['verified']??false),'country'=>$m['country']??null,
        'balance'=>(float)($w['balance']??0),'vault_balance'=>(float)($w['vault_balance']??0),
        'vault_locked'=>(bool)($w['vault_locked']??false),'vault_lock_date'=>$w['vault_lock_date']??null,
        'currency'=>$w['currency']??'XOF','qr_seed'=>$w['qr_seed']??null],'Connexion reussie');
}

function merchant_balance() {
    $pl = merchant_auth();
    $m = q("SELECT business_name,location_type,address,verified,country FROM merchants WHERE id=?",[$pl['sub']])->fetch();
    $w = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetch();
    if(!$w) fail('Portefeuille introuvable',404);
    ok(['balance'=>(float)$w['balance'],'vault_balance'=>(float)$w['vault_balance'],
        'vault_locked'=>(bool)$w['vault_locked'],'vault_lock_date'=>$w['vault_lock_date'],
        'qr_seed'=>$w['qr_seed'],'business_name'=>$m['business_name'],
        'location_type'=>$m['location_type'],'address'=>$m['address'],'currency'=>$w['currency'],
        'country'=>$m['country']??null,
        'verified'=>(bool)($m['verified']??false)]);
}

function merchant_renew_qr() {
    $pl = merchant_auth();
    $seed = strtoupper(bin2hex(random_bytes(5)));
    q("UPDATE merchant_wallets SET qr_seed=?,qr_renewed_at=NOW() WHERE merchant_id=?",[$seed,$pl['sub']]);
    ok(['qr_seed'=>$seed],'QR renouvele');
}

// Encaisser cote marchand : le marchand scanne le QR PERSONNEL d'un client
// (comme un ROM_MONEY qui encaisse un autre ROM_MONEY), le client tape son
// PIN sur l'appareil du marchand. Contrairement au paiement via QR marchand
// (tx_pay_merchant, gratuit), celui-ci suit la meme logique que tx_collect.
// Identifie le client AVANT l'encaissement (nom affiche pendant que le
// marchand tape le montant/PIN) - meme principe que tx_resolve() cote
// personnel, mais accessible avec un token marchand (merchant_auth()).
function merchant_resolve_payer() {
    merchant_auth();
    $phone = $_GET['phone']??'';
    if(!preg_match('/^\+?[0-9]{8,15}$/',preg_replace('/[\s\-]/','', $phone))) fail('Numero invalide');
    $u = q("SELECT full_name,phone_number,verified_name FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u) fail('Aucun compte trouve',404);
    ok(['full_name'=>$u['verified_name']?:$u['full_name'],'phone_number'=>$u['phone_number'],
        'is_verified'=>!empty($u['verified_name'])]);
}

function merchant_collect() {
    $pl = merchant_auth(); $b = body();
    $payerPhone = trim($b['payer_phone']??'');
    $amount = (float)($b['amount']??0);
    $pin = trim($b['pin']??'');
    $desc = trim($b['description']??'');
    if(!preg_match('/^\+?[0-9]{8,15}$/',preg_replace('/[\s\-]/','', $payerPhone))) fail('Numero invalide');
    if($amount<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/',$pin)) fail('PIN invalide');

    $payer = q("SELECT u.id,u.full_name,u.verified_name,u.pin_hash,w.id wid,w.balance,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$payerPhone])->fetch();
    if(!$payer) fail('Payeur introuvable');

    pin_check($payer['id'], $pin, $payer['pin_hash']);

    $m = q("SELECT business_name,phone_number FROM merchants WHERE id=?",[$pl['sub']])->fetch();
    $mw = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetch();
    if(!$mw) fail('Portefeuille marchand introuvable',404);
    if((float)$payer['balance'] < $amount) fail('Solde du payeur insuffisant');

    // Un encaissement marchand reste STRICTEMENT local : un client dans une
    // devise differente de celle du marchand ne peut pas etre encaisse
    // directement. Toute transaction internationale doit obligatoirement
    // passer par Transfert Afrique (virement personnel, channel=africa), qui
    // applique son propre tarif international sans exception.
    $payerCurrency = $payer['currency'] ?: 'XOF';
    $merchantCurrency = $mw['currency'] ?: 'XOF';
    if($payerCurrency !== $merchantCurrency){
        fail('Encaissement impossible : ce client est dans un autre pays/devise que votre compte marchand. Les encaissements marchand sont reserves aux transactions locales.', 422);
    }
    $fxRateApplied = null;

    // Le client paie toujours le montant plein (aucun frais de son cote) :
    // le frais eventuel est preleve sur ce que le MARCHAND recoit, une fois
    // son cumul du jour au-dela du seuil gratuit (voir merchant_receive_fee()).
    $feeCalc = merchant_receive_fee($mw['id'], $amount);
    $fee = $feeCalc['fee']; $net = $feeCalc['net'];

    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_wallet_id,receiver_merchant_wallet_id,amount,net_amount,fee,receiver_amount,fx_rate_applied,type,status,reference,description,cancel_deadline) VALUES (?,?,?,?,?,?,?,?,'merchant_payment','pending',?,?,?)",
          [$txid,$payer['wid'],$mw['id'],$amount,$net,$fee,$net,$fxRateApplied,$reference,$desc?:('Paiement '.$m['business_name']),$deadline]);
        $rows = q("UPDATE wallets SET balance=balance-? WHERE id=? AND balance>=?",[$amount,$payer['wid'],$amount])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        q("UPDATE merchant_wallets SET balance=balance+? WHERE id=?",[$net,$mw['id']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);
        credit_merchant_fee($mw['id'], $fee, 'Frais ROM_MONEY sur encaissement marchand');
        db()->commit();
        fraud_check_merchant_transaction($mw['id'], $payerPhone, $amount, $txid, $reference, $m['phone_number']);
        $bal = (float)q("SELECT balance FROM merchant_wallets WHERE id=?",[$mw['id']])->fetchColumn();
        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$amount,'fee'=>$fee,'net_amount'=>$net,
            'payer_name'=>$payer['verified_name']?:$payer['full_name'],'cancel_before'=>$deadline,
            'new_balance'=>$bal],'Encaissement effectue');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec encaissement', 500); }
}

// Virement sortant du marchand vers un numero ROM_MONEY personnel.
// Gratuit UNIQUEMENT si le destinataire est le numero utilise pour creer ce
// compte marchand (donc son propre compte personnel) ; 1% vers tout autre
// numero. Les frais rejoignent le meme compte systeme que les frais ROM_MONEY.
function merchant_withdraw() {
    $pl = merchant_auth(); $b = body();
    $toPhone = trim($b['phone'] ?? '');
    $amount = (float)($b['amount'] ?? 0);
    $pin = trim($b['pin'] ?? '');
    if(!preg_match('/^\+?[0-9]{8,15}$/',preg_replace('/[\s\-]/','', $toPhone))) fail('Numero invalide');
    if($amount<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/',$pin)) fail('PIN invalide');

    $m = q("SELECT * FROM merchants WHERE id=?",[$pl['sub']])->fetch();
    merchant_pin_check($pl['sub'], $pin, $m['pin_hash']);

    $mw = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetch();
    if(!$mw) fail('Portefeuille marchand introuvable',404);

    $recv = q("SELECT u.id,u.full_name,u.verified_name,w.id wid,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$toPhone])->fetch();
    if(!$recv) fail('Destinataire introuvable',404);

    $isOwnNumber = ($toPhone === $m['phone_number']);
    $fee = $isOwnNumber ? 0 : round($amount * 0.01);
    $totalDebit = $amount + $fee;
    if((float)$mw['balance'] < $totalDebit) fail('Solde insuffisant');

    // Un virement marchand vers un compte personnel reste STRICTEMENT local :
    // pas de conversion vers un destinataire dans une autre devise. Pour
    // envoyer vers un autre pays, le marchand doit d'abord se virer vers son
    // propre compte personnel local puis utiliser Transfert Afrique.
    $merchantCurrency = $mw['currency'] ?: 'XOF';
    $recvCurrency = $recv['currency'] ?: 'XOF';
    if($merchantCurrency !== $recvCurrency){
        fail('Virement impossible : ce destinataire est dans un autre pays/devise que votre compte marchand. Virez d\'abord vers votre compte personnel local, puis utilisez Transfert Afrique.', 422);
    }
    $creditedAmount = $amount;
    $fxRateApplied = null;

    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_merchant_wallet_id,receiver_wallet_id,amount,net_amount,fee,receiver_amount,fx_rate_applied,type,status,reference,description,cancel_deadline) VALUES (?,?,?,?,?,?,?,?,'merchant_withdraw','pending',?,?,?)",
          [$txid,$mw['id'],$recv['wid'],$totalDebit,$amount,$fee,$creditedAmount,$fxRateApplied,$reference,'Virement vers '.$toPhone,$deadline]);
        $rows = q("UPDATE merchant_wallets SET balance=balance-? WHERE id=? AND balance>=?",[$totalDebit,$mw['id'],$totalDebit])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$creditedAmount,$recv['wid']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);
        credit_merchant_fee($mw['id'], $fee, 'Frais ROM_BUSINESS 1%');
        db()->commit();
        $recvCurSuffix = ($recvCurrency==='XOF'||$recvCurrency==='XAF') ? 'F' : $recvCurrency;
        web_push_send_to_user($recv['id'], 'ROM_MONEY', 'Vous avez recu '.number_format($creditedAmount,0,',',' ').' '.$recvCurSuffix.' de '.$m['business_name'], [], 'credit');
        $bal = (float)q("SELECT balance FROM merchant_wallets WHERE id=?",[$mw['id']])->fetchColumn();
        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$amount,'fee'=>$fee,
            'receiver_name'=>$recv['verified_name']?:$recv['full_name'],'cancel_before'=>$deadline,
            'new_balance'=>$bal],'Virement effectue');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec virement', 500); }
}

// Un marchand paie un autre marchand a distance (numero choisi dans ses
// contacts, pas besoin de scanner son QR). Le marchand payeur paie
// exactement le montant indique, sans frais de son cote - le frais
// eventuel (voir merchant_receive_fee()) est preleve sur ce que le
// marchand RECEVEUR encaisse, exactement comme un paiement recu d'un
// client normal (meme cumul quotidien, meme seuil, meme table
// transactions type='merchant_payment' pour que ca compte bien dans son
// cumul du jour et s'affiche correctement dans son historique).
// Paiement d'un marchand vers un autre, uniquement via le scan du QR du
// marchand receveur (voir merchant_resolve_merchant_qr()) - PAS par numero
// de telephone. Raison : un meme numero peut porter a la fois un compte
// personnel et un compte marchand (design assume ailleurs dans l'app), donc
// resoudre "Envoyer" par numero serait ambigu (impossible de savoir avec
// certitude si l'expediteur visait la personne ou son commerce). Le QR
// encode directement l'identifiant du marchand, sans ambiguite possible.
function merchant_pay_merchant() {
    $pl = merchant_auth(); $b = body();
    $merchantId = trim($b['merchant_id'] ?? '');
    $amount = (float)($b['amount'] ?? 0);
    $pin = trim($b['pin'] ?? '');
    $desc = trim($b['description'] ?? '');
    if(!$merchantId) fail('Marchand requis');
    if($amount<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/',$pin)) fail('PIN invalide');

    $m = q("SELECT * FROM merchants WHERE id=?",[$pl['sub']])->fetch();
    merchant_pin_check($pl['sub'], $pin, $m['pin_hash']);
    if($merchantId === $pl['sub']) fail('Impossible de vous payer vous-meme');

    $mw = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetch();
    if(!$mw) fail('Portefeuille marchand introuvable',404);

    $recvM = q("SELECT * FROM merchants WHERE id=?",[$merchantId])->fetch();
    if(!$recvM) fail('Marchand introuvable',404);
    $recvMw = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$merchantId])->fetch();
    if(!$recvMw) fail('Marchand introuvable',404);

    if((float)$mw['balance'] < $amount) fail('Solde insuffisant');

    // Un paiement marchand-a-marchand reste STRICTEMENT local : deux
    // marchands dans des devises differentes ne peuvent pas se payer
    // directement. Toute transaction internationale doit obligatoirement
    // passer par Transfert Afrique (virement personnel, channel=africa),
    // qui applique son propre tarif international sans exception - jamais
    // en contournement via un paiement marchand.
    $payerCurrency = $mw['currency'] ?: 'XOF';
    $receiverCurrency = $recvMw['currency'] ?: 'XOF';
    if($payerCurrency !== $receiverCurrency){
        fail('Paiement impossible : les paiements marchand a marchand sont reserves aux transactions locales (meme devise). Pour un paiement international, utilisez Transfert Afrique depuis un compte personnel.', 422);
    }
    $fxRateApplied = null;

    $feeCalc = merchant_receive_fee($recvMw['id'], $amount);
    $fee = $feeCalc['fee']; $net = $feeCalc['net'];

    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_merchant_wallet_id,receiver_merchant_wallet_id,amount,net_amount,fee,receiver_amount,fx_rate_applied,type,status,reference,description,cancel_deadline) VALUES (?,?,?,?,?,?,?,?,'merchant_payment','pending',?,?,?)",
          [$txid,$mw['id'],$recvMw['id'],$amount,$net,$fee,$net,$fxRateApplied,$reference,$desc?:('Paiement vers '.$recvM['business_name']),$deadline]);
        $rows = q("UPDATE merchant_wallets SET balance=balance-? WHERE id=? AND balance>=?",[$amount,$mw['id'],$amount])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        q("UPDATE merchant_wallets SET balance=balance+? WHERE id=?",[$net,$recvMw['id']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);
        credit_merchant_fee($recvMw['id'], $fee, 'Frais ROM_MONEY sur encaissement marchand (paiement inter-marchand)');
        db()->commit();
        // Meme detection de fraude que pour un encaissement classique (voir
        // merchant_collect()) - scopee sur le portefeuille RECEVEUR, sinon un
        // paiement inter-marchand echappait totalement au controle de
        // velocite/montant inhabituel applique partout ailleurs.
        fraud_check_merchant_transaction($recvMw['id'], $m['phone_number'], $amount, $txid, $reference, $recvM['phone_number']);
        $recvCurSuffix = ($receiverCurrency==='XOF'||$receiverCurrency==='XAF') ? 'F' : $receiverCurrency;
        web_push_send_to_merchant($recvM['id'], 'ROM_BUSINESS',
            'Vous avez recu '.number_format($net,0,',',' ').' '.$recvCurSuffix.' de '.$m['business_name'].($fee>0?' (apres '.number_format($fee,0,',',' ').' '.$recvCurSuffix.' de frais)':''));
        $bal = (float)q("SELECT balance FROM merchant_wallets WHERE id=?",[$mw['id']])->fetchColumn();
        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$amount,
            'receiver_name'=>$recvM['business_name'],'cancel_before'=>$deadline,
            'new_balance'=>$bal],'Paiement effectue');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec paiement', 500); }
}

function merchant_vault_deposit() {
    $pl = merchant_auth(); $b = body();
    $amt = (float)($b['amount']??0);
    if($amt<=0) fail('Montant invalide');
    $w = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetch();
    db()->beginTransaction();
    try {
        $n = q("UPDATE merchant_wallets SET balance=balance-?,vault_balance=vault_balance+? WHERE id=? AND balance>=?",[$amt,$amt,$w['id'],$amt])->rowCount();
        if(!$n){ db()->rollBack(); fail('Solde insuffisant'); }
        q("INSERT INTO transactions (id,sender_merchant_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'vault_deposit','completed',?,'Depot coffre')",[uid(),$w['id'],$amt,ref()]);
        db()->commit();
        $fresh = q("SELECT balance,vault_balance FROM merchant_wallets WHERE id=?",[$w['id']])->fetch();
        ok(['amount'=>$amt,'new_balance'=>(float)$fresh['balance'],'vault_balance'=>(float)$fresh['vault_balance']],'Depose dans le coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur depot',500); }
}

function merchant_vault_withdraw() {
    $pl = merchant_auth(); $b = body();
    $amt = (float)($b['amount']??0); $pin = trim($b['pin']??'');
    if($amt<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/',$pin)) fail('PIN invalide');
    $m = q("SELECT pin_hash FROM merchants WHERE id=?",[$pl['sub']])->fetch();
    merchant_pin_check($pl['sub'], $pin, $m['pin_hash']);
    $w = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetch();
    if($w['vault_locked'] && strtotime($w['vault_lock_date']??'0')>time())
        fail("Coffre verrouille jusqu'au ".date('d/m/Y',strtotime($w['vault_lock_date'])));
    db()->beginTransaction();
    try {
        $n = q("UPDATE merchant_wallets SET vault_balance=vault_balance-?,balance=balance+?,vault_locked=0 WHERE id=? AND vault_balance>=?",[$amt,$amt,$w['id'],$amt])->rowCount();
        if(!$n){ db()->rollBack(); fail('Solde coffre insuffisant'); }
        q("INSERT INTO transactions (id,receiver_merchant_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'vault_withdrawal','completed',?,'Retrait coffre')",[uid(),$w['id'],$amt,ref()]);
        db()->commit();
        $fresh = q("SELECT balance,vault_balance FROM merchant_wallets WHERE id=?",[$w['id']])->fetch();
        ok(['amount'=>$amt,'new_balance'=>(float)$fresh['balance'],'vault_balance'=>(float)$fresh['vault_balance']],'Retire du coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur retrait',500); }
}

function merchant_vault_lock() {
    $pl = merchant_auth(); $b = body();
    $date = trim($b['lock_date']??'');
    if(!$date || strtotime($date)<=time()) fail('Date invalide');
    q("UPDATE merchant_wallets SET vault_locked=1,vault_lock_date=? WHERE merchant_id=?",[$date,$pl['sub']]);
    ok(['lock_date'=>$date],'Coffre verrouille');
}

function merchant_subvault_list() {
    $pl = merchant_auth();
    $wid = q("SELECT id FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetchColumn();
    $rows = q("SELECT id,name,balance,goal_amount,locked,lock_date FROM sub_vaults WHERE wallet_id=? ORDER BY created_at ASC",[$wid])->fetchAll();
    ok($rows);
}

function merchant_subvault_create() {
    $pl = merchant_auth(); $b = body();
    $name = trim($b['name'] ?? '');
    $amt  = (float)($b['amount'] ?? 0);
    $goal = isset($b['goal']) && $b['goal']!=='' ? (float)$b['goal'] : null;
    if(!$name) fail('Nom requis');
    if($amt<0) fail('Montant invalide');
    $w = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetch();
    db()->beginTransaction();
    try {
        $n = q("UPDATE merchant_wallets SET vault_balance=vault_balance-? WHERE id=? AND vault_balance>=?",[$amt,$w['id'],$amt])->rowCount();
        if(!$n){ db()->rollBack(); fail('Solde du coffre principal insuffisant'); }
        $id = uid();
        q("INSERT INTO sub_vaults (id,wallet_id,name,balance,goal_amount) VALUES (?,?,?,?,?)",[$id,$w['id'],$name,$amt,$goal]);
        db()->commit();
        $bal = (float)q("SELECT vault_balance FROM merchant_wallets WHERE id=?",[$w['id']])->fetchColumn();
        ok(['id'=>$id,'name'=>$name,'balance'=>$amt,'goal_amount'=>$goal,'vault_balance'=>$bal],'Sous-coffre cree');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur creation',500); }
}

function merchant_subvault_deposit() {
    $pl = merchant_auth(); $b = body();
    $id = trim($b['id'] ?? ''); $amt = (float)($b['amount'] ?? 0);
    if($amt<=0) fail('Montant invalide');
    $w = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetch();
    subvault_owned($w['id'], $id);
    db()->beginTransaction();
    try {
        $n = q("UPDATE merchant_wallets SET vault_balance=vault_balance-? WHERE id=? AND vault_balance>=?",[$amt,$w['id'],$amt])->rowCount();
        if(!$n){ db()->rollBack(); fail('Solde du coffre principal insuffisant'); }
        q("UPDATE sub_vaults SET balance=balance+? WHERE id=?",[$amt,$id]);
        db()->commit();
        $bal   = (float)q("SELECT vault_balance FROM merchant_wallets WHERE id=?",[$w['id']])->fetchColumn();
        $svBal = (float)q("SELECT balance FROM sub_vaults WHERE id=?",[$id])->fetchColumn();
        ok(['vault_balance'=>$bal,'sub_balance'=>$svBal],'Depose dans le sous-coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur depot',500); }
}

function merchant_subvault_withdraw() {
    $pl = merchant_auth(); $b = body();
    $id = trim($b['id'] ?? ''); $amt = (float)($b['amount'] ?? 0); $pin = trim($b['pin'] ?? '');
    if($amt<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/',$pin)) fail('PIN invalide');
    $m = q("SELECT pin_hash FROM merchants WHERE id=?",[$pl['sub']])->fetch();
    merchant_pin_check($pl['sub'], $pin, $m['pin_hash']);
    $w  = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetch();
    $sv = subvault_owned($w['id'], $id);
    if($sv['locked'] && strtotime($sv['lock_date']??'0')>time())
        fail("Sous-coffre verrouille jusqu'au ".date('d/m/Y',strtotime($sv['lock_date'])));
    db()->beginTransaction();
    try {
        $n = q("UPDATE sub_vaults SET balance=balance-?,locked=0 WHERE id=? AND balance>=?",[$amt,$id,$amt])->rowCount();
        if(!$n){ db()->rollBack(); fail('Solde du sous-coffre insuffisant'); }
        q("UPDATE merchant_wallets SET vault_balance=vault_balance+? WHERE id=?",[$amt,$w['id']]);
        db()->commit();
        $bal   = (float)q("SELECT vault_balance FROM merchant_wallets WHERE id=?",[$w['id']])->fetchColumn();
        $svBal = (float)q("SELECT balance FROM sub_vaults WHERE id=?",[$id])->fetchColumn();
        ok(['vault_balance'=>$bal,'sub_balance'=>$svBal],'Retire du sous-coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur retrait',500); }
}

function merchant_subvault_lock() {
    $pl = merchant_auth(); $b = body();
    $id = trim($b['id'] ?? ''); $date = trim($b['lock_date'] ?? '');
    if(!$date || strtotime($date)<=time()) fail('Date invalide');
    $wid = q("SELECT id FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetchColumn();
    subvault_owned($wid, $id);
    q("UPDATE sub_vaults SET locked=1,lock_date=? WHERE id=?",[$date,$id]);
    ok(['lock_date'=>$date],'Sous-coffre verrouille');
}

function merchant_subvault_unlock() {
    $pl = merchant_auth(); $b = body();
    $id = trim($b['id'] ?? '');
    $wid = q("SELECT id FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetchColumn();
    $sv = subvault_owned($wid, $id);
    if($sv['locked'] && strtotime($sv['lock_date']??'0')>time())
        fail("Verrouille jusqu'au ".date('d/m/Y',strtotime($sv['lock_date'])));
    q("UPDATE sub_vaults SET locked=0,lock_date=NULL WHERE id=?",[$id]);
    ok(null,'Sous-coffre deverrouille');
}

function merchant_subvault_delete() {
    $pl = merchant_auth(); $b = body();
    $id = trim($b['id'] ?? '');
    $wid = q("SELECT id FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetchColumn();
    $sv = subvault_owned($wid, $id);
    db()->beginTransaction();
    try {
        q("UPDATE merchant_wallets SET vault_balance=vault_balance+? WHERE id=?",[$sv['balance'],$wid]);
        q("DELETE FROM sub_vaults WHERE id=?",[$id]);
        db()->commit();
        $bal = (float)q("SELECT vault_balance FROM merchant_wallets WHERE id=?",[$wid])->fetchColumn();
        ok(['vault_balance'=>$bal],'Sous-coffre supprime');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur suppression',500); }
}

// Meme mecanique que export_get_rows()/export_xlsx()/export_pdf() cote
// personnel, adaptee aux colonnes merchant_wallet_id (sender/receiver) et
// sans les champs de frais (les operations marchand sont gratuites).
function merchant_export_get_rows($pl, $period, $from=null, $to=null) {
    $wid = q("SELECT id FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetchColumn();
    $where = "(t.sender_merchant_wallet_id=? OR t.receiver_merchant_wallet_id=?) AND t.type!='fee'";
    $params = [$wid,$wid];
    if($period==='month'){
        $where .= " AND EXTRACT(MONTH FROM t.created_at)=EXTRACT(MONTH FROM NOW()) AND EXTRACT(YEAR FROM t.created_at)=EXTRACT(YEAR FROM NOW())";
    } elseif($period==='custom' && preg_match('/^\d{4}-\d{2}$/',(string)$from) && preg_match('/^\d{4}-\d{2}$/',(string)$to)){
        $where .= " AND t.created_at >= ?::date AND t.created_at < (date_trunc('month', ?::date) + interval '1 month')";
        $params[] = $from.'-01';
        $params[] = $to.'-01';
    }
    $countRow = q("SELECT COUNT(*) cnt FROM transactions t WHERE $where",$params)->fetch();
    $total = (int)($countRow['cnt']??0);
    $LIMIT = 5000;
    $sql = "SELECT t.*,
        CASE WHEN t.receiver_merchant_wallet_id=? THEN 'credit' ELSE 'debit' END as direction,
        su.full_name sender_name, su.verified_name sender_verified_name,
        ru.full_name receiver_name, ru.verified_name receiver_verified_name,
        sm.business_name sender_merchant_name, rm.business_name receiver_merchant_name
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        WHERE $where ORDER BY t.created_at DESC LIMIT $LIMIT";
    $rows = q($sql, array_merge([$wid],$params))->fetchAll();
    return ['rows'=>$rows,'total'=>$total,'truncated'=>$total>$LIMIT,'limit'=>$LIMIT];
}
function merchant_export_type_label($type, $isCredit) {
    $map = ['merchant_payment'=>$isCredit?'Vente':'Paiement','merchant_withdraw'=>'Virement envoye',
            'vault_deposit'=>'Depot coffre','vault_withdraw'=>'Retrait coffre'];
    return $map[$type] ?? $type;
}
function merchant_export_xlsx() {
    $pl = merchant_auth();
    $periodRaw = $_GET['period']??'month';
    $period = in_array($periodRaw,['month','all','custom']) ? $periodRaw : 'month';
    $from = $_GET['from']??null; $to = $_GET['to']??null;
    $res = merchant_export_get_rows($pl, $period, $from, $to);
    $rows = $res['rows'];
    $merchantCurrency = q("SELECT currency FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetchColumn() ?: 'XOF';
    $curSuffix = ($merchantCurrency==='XOF'||$merchantCurrency==='XAF') ? 'F' : $merchantCurrency;

    $data = [];
    if($res['truncated']){
        $data[] = [[ 'Limite aux '.$res['limit'].' dernieres transactions sur '.$res['total'].' au total.', 0, 's' ]];
    }
    $data[] = [ ['Date',1,'s'], ['Type',1,'s'], ['Contact',1,'s'], ['Montant',1,'s'], ['Reference',1,'s'], ['Statut',1,'s'] ];
    foreach($rows as $t){
        $isCredit = $t['direction']==='credit';
        // Montant reellement credite/debite : le net (apres frais eventuel),
        // pas le brut envoye par l'autre partie - sinon un encaissement de
        // 50000F avec 250F de frais apparaitrait comme +50000F alors que
        // seuls 49750F ont vraiment atterri sur le solde du marchand.
        $montant = $isCredit ? (float)($t['net_amount']??$t['amount']) : -(float)$t['amount'];
        $contact = $isCredit ? ($t['sender_verified_name']?:$t['sender_name']?:$t['sender_merchant_name']?:'-') : ($t['receiver_verified_name']?:$t['receiver_name']?:$t['receiver_merchant_name']?:'-');
        $data[] = [
            [ date('d/m/Y H:i', strtotime($t['created_at'])), 2, 's' ],
            [ merchant_export_type_label($t['type'],$isCredit), 2, 's' ],
            [ $contact, 2, 's' ],
            [ number_format($montant,0,',',' ').' F', 2, 's' ],
            [ $t['reference'], 2, 's' ],
            [ $t['status'], 2, 's' ]
        ];
    }
    $sheetXml = xlsx_build_sheet($data);
    $xlsxData = xlsx_build($sheetXml);
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment; filename="rom_business_historique.xlsx"');
    header('Content-Length: '.strlen($xlsxData));
    echo $xlsxData;
    exit;
}
function merchant_export_pdf() {
    $pl = merchant_auth();
    $periodRaw = $_GET['period']??'month';
    $period = in_array($periodRaw,['month','all','custom']) ? $periodRaw : 'month';
    $from = $_GET['from']??null; $to = $_GET['to']??null;
    $res = merchant_export_get_rows($pl, $period, $from, $to);
    $rows = $res['rows'];
    $m = q("SELECT business_name,phone_number FROM merchants WHERE id=?",[$pl['sub']])->fetch();
    $merchantCurrency = q("SELECT currency FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetchColumn() ?: 'XOF';
    $curSuffix = ($merchantCurrency==='XOF'||$merchantCurrency==='XAF') ? 'F' : $merchantCurrency;

    $periodeLabel = 'Ce mois';
    if($period==='all') $periodeLabel = "Tout l'historique";
    elseif($period==='custom'){
        $fmtYm = function($ym){ $p=explode('-',(string)$ym); return count($p)===2 ? $p[1].'-'.$p[0] : $ym; };
        $periodeLabel = 'du '.$fmtYm($from).' au '.$fmtYm($to);
    }

    require_once __DIR__.'/fpdf.php';
    $pdf = new FPDF();
    $pdf->AddPage();
    $pdf->SetFont('Arial','B',14);
    $pdf->Cell(0,10,pdf_str('ROM_BUSINESS - Releve des ventes'),0,1);
    $infoTopY = $pdf->GetY();
    $logoPath = __DIR__.'/business/logo.jpg';
    if(file_exists($logoPath)){
        $pdf->Image($logoPath, 182, $infoTopY, 18, 18);
    }
    $pdf->SetFont('Arial','',10);
    $pdf->Cell(150,6,pdf_str('Boutique : '.($m['business_name']?:'').' ('.$m['phone_number'].')'),0,1);
    $pdf->Cell(150,6,pdf_str('Periode : '.$periodeLabel),0,1);
    $pdf->Cell(150,6,pdf_str('Genere le '.date('d/m/Y').' a '.date('H:i')),0,1);
    if(file_exists($logoPath)){
        $pdf->SetY(max($pdf->GetY(), $infoTopY+18));
    }
    if($res['truncated']){
        $pdf->SetTextColor(200,0,0);
        $pdf->Cell(0,6,pdf_str('Limite aux '.$res['limit'].' dernieres transactions sur '.$res['total'].' au total.'),0,1);
        $pdf->SetTextColor(0,0,0);
    }
    $pdf->Ln(4);

    $pdf->SetFont('Arial','B',9);
    $pdf->SetFillColor(230,241,251);
    $w = [30,34,50,32,34,28];
    $headers = ['Date','Type','Contact','Montant','Reference','Statut'];
    foreach($headers as $i=>$h){ $pdf->Cell($w[$i],8,pdf_str($h),1,0,'C',true); }
    $pdf->Ln();

    $pdf->SetFont('Arial','',8);
    foreach($rows as $t){
        $isCredit = $t['direction']==='credit';
        // Montant reellement credite/debite : le net (apres frais eventuel),
        // pas le brut envoye par l'autre partie - sinon un encaissement de
        // 50000F avec 250F de frais apparaitrait comme +50000F alors que
        // seuls 49750F ont vraiment atterri sur le solde du marchand.
        $montant = $isCredit ? (float)($t['net_amount']??$t['amount']) : -(float)$t['amount'];
        $contact = $isCredit ? ($t['sender_verified_name']?:$t['sender_name']?:$t['sender_merchant_name']?:'-') : ($t['receiver_verified_name']?:$t['receiver_name']?:$t['receiver_merchant_name']?:'-');
        $pdf->Cell($w[0],7,date('d/m/y H:i',strtotime($t['created_at'])),1);
        $pdf->Cell($w[1],7,pdf_str(merchant_export_type_label($t['type'],$isCredit)),1);
        $pdf->Cell($w[2],7,substr(pdf_str($contact),0,26),1);
        $pdf->Cell($w[3],7,number_format($montant,0,',',' ').' '.$curSuffix,1,0,'R');
        $pdf->Cell($w[4],7,pdf_str($t['reference']),1);
        $pdf->Cell($w[5],7,pdf_str($t['status']),1);
        $pdf->Ln();
    }

    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="rom_business_releve.pdf"');
    echo $pdf->Output('S');
    exit;
}

function merchant_tx_history() {
    $pl = merchant_auth();
    $wid = q("SELECT id FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetchColumn();
    $limit = min((int)($_GET['limit'] ?? 20), 100);
    // Joint aussi les tables marchand (en plus des tables client) pour
    // resoudre le nom de l'autre partie quand c'est un paiement inter-marchand
    // (voir merchant_pay_merchant()) - sans ca, un marchand qui en paie un
    // autre apparaissait comme "Client" generique dans l'historique du
    // receveur, faute de jointure sur merchant_wallets/merchants. Meme
    // logique deja utilisee par admin_merchant_search_tx_advanced().
    $rows = q("SELECT t.*,
        CASE WHEN t.receiver_merchant_wallet_id=? THEN 'credit' ELSE 'debit' END as direction,
        su.full_name sender_name, su.verified_name sender_verified_name,
        ru.full_name receiver_name, ru.verified_name receiver_verified_name,
        sm.business_name sender_merchant_name, sm.verified sender_merchant_verified,
        rm.business_name receiver_merchant_name, rm.verified receiver_merchant_verified
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        WHERE (t.sender_merchant_wallet_id=? OR t.receiver_merchant_wallet_id=?) AND t.type!='fee'
        ORDER BY t.created_at DESC LIMIT ?",[$wid,$wid,$wid,$limit])->fetchAll();
    ok(['transactions'=>$rows]);
}

// Tableau de bord marchand : ventes (encaissement + paiement QR marchand,
// les deux tombent sous type='merchant_payment') du jour/semaine/mois +
// repartition des 7 derniers jours pour le petit graphique. Les virements
// sortants et operations de coffre ne sont pas des "ventes", donc exclus.
function merchant_stats() {
    $pl = merchant_auth();
    $wid = q("SELECT id FROM merchant_wallets WHERE merchant_id=?",[$pl['sub']])->fetchColumn();
    if(!$wid) fail('Portefeuille introuvable',404);
    // SUM(COALESCE(net_amount,amount)) et non SUM(amount) : le marchand doit
    // voir ce qu'il a vraiment encaisse (apres frais eventuel), pas le brut
    // envoye par l'autre partie - sinon le chiffre d'affaires du jour sur
    // l'ecran d'accueil serait gonfle des que le seuil quotidien est depasse.
    $today = q("SELECT COALESCE(SUM(COALESCE(net_amount,amount)),0) total, COUNT(*) cnt FROM transactions
        WHERE receiver_merchant_wallet_id=? AND type='merchant_payment' AND status='completed'
        AND created_at::date = CURRENT_DATE",[$wid])->fetch();
    $week = q("SELECT COALESCE(SUM(COALESCE(net_amount,amount)),0) total, COUNT(*) cnt FROM transactions
        WHERE receiver_merchant_wallet_id=? AND type='merchant_payment' AND status='completed'
        AND created_at >= date_trunc('week', CURRENT_DATE)",[$wid])->fetch();
    $month = q("SELECT COALESCE(SUM(COALESCE(net_amount,amount)),0) total, COUNT(*) cnt FROM transactions
        WHERE receiver_merchant_wallet_id=? AND type='merchant_payment' AND status='completed'
        AND created_at >= date_trunc('month', CURRENT_DATE)",[$wid])->fetch();
    $daily = q("SELECT to_char(created_at,'YYYY-MM-DD') d, COALESCE(SUM(COALESCE(net_amount,amount)),0) total FROM transactions
        WHERE receiver_merchant_wallet_id=? AND type='merchant_payment' AND status='completed'
        AND created_at >= CURRENT_DATE - INTERVAL '6 days'
        GROUP BY d ORDER BY d",[$wid])->fetchAll();
    ok(['today'=>['total'=>(float)$today['total'],'count'=>(int)$today['cnt']],
        'week'=>['total'=>(float)$week['total'],'count'=>(int)$week['cnt']],
        'month'=>['total'=>(float)$month['total'],'count'=>(int)$month['cnt']],
        'daily'=>$daily]);
}

function wallet_renew_qr() {
    $pl = auth();
    $seed = strtoupper(bin2hex(random_bytes(5)));
    q("UPDATE wallets SET qr_seed=?,qr_renewed_at=NOW() WHERE user_id=?",[$seed,$pl['sub']]);
    ok(['qr_seed'=>$seed],'QR renouvele');
}

function wallet_resolve_qr() {
    $pl = auth();
    $qr = $_GET['qr'] ?? '';
    if(!$qr) fail('QR requis');
    $parts = explode('|',$qr);
    if(count($parts)<2) fail('QR invalide');
    $u = q("SELECT u.full_name,u.phone_number FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.id=? AND w.qr_seed=?",[$parts[0],$parts[1]])->fetch();
    if(!$u) fail('QR invalide',404);
    if($parts[0]===$pl['sub']) fail('Vous ne pouvez pas vous scanner vous-meme');
    ok($u,'Destinataire trouve');
}

// Resout un QR MARCHAND (prefixe "M|") scanne par un client ROM_MONEY normal
// (auth() personnel, pas merchant_auth()) - un client n'a pas besoin d'un
// compte ROM_BUSINESS pour payer un marchand.
function wallet_resolve_merchant_qr() {
    auth();
    $qr = $_GET['qr'] ?? '';
    if(!$qr) fail('QR requis');
    $parts = explode('|',$qr);
    if(count($parts)<3 || $parts[0]!=='M') fail('QR invalide');
    $m = q("SELECT m.id,m.business_name,m.location_type,m.verified FROM merchants m JOIN merchant_wallets mw ON mw.merchant_id=m.id WHERE m.id=? AND mw.qr_seed=?",[$parts[1],$parts[2]])->fetch();
    if(!$m) fail('QR invalide',404);
    $m['verified'] = (bool)($m['verified']??false);
    ok($m,'Marchand trouve');
}

// Equivalent de wallet_resolve_merchant_qr() mais pour un MARCHAND qui
// scanne le QR d'un AUTRE marchand (paiement inter-marchand, voir
// merchant_pay_merchant()) - merchant_auth() au lieu de auth(), sinon
// identique. Empeche aussi un marchand de "se payer" en scannant son
// propre QR.
function merchant_resolve_merchant_qr() {
    $pl = merchant_auth();
    $qr = $_GET['qr'] ?? '';
    if(!$qr) fail('QR requis');
    $parts = explode('|',$qr);
    if(count($parts)<3 || $parts[0]!=='M') fail('QR invalide');
    if($parts[1]===$pl['sub']) fail('Vous ne pouvez pas vous payer vous-meme');
    $m = q("SELECT m.id,m.business_name,m.location_type,m.verified FROM merchants m JOIN merchant_wallets mw ON mw.merchant_id=m.id WHERE m.id=? AND mw.qr_seed=?",[$parts[1],$parts[2]])->fetch();
    if(!$m) fail('QR invalide',404);
    $m['verified'] = (bool)($m['verified']??false);
    ok($m,'Marchand trouve');
}

// Real 12-month totals (in/out) + real full-history expense breakdown by category.
// Unlike wallet_stats() (current month only), this feeds the Stats screen chart
// and "Répartition dépenses" list with actual data instead of the old hardcoded
// demo numbers. Fee transactions are excluded to avoid double-counting (a transfer's
// brut amount already includes its fee).
// Statut du plafond mensuel de reception (pour la carte affichee dans Profil).
// Reutilise la meme logique que check_receive_limit(), en mode "lecture seule".
function wallet_limit_status() {
    $pl = auth();
    $u = q("SELECT is_kyc FROM users WHERE id=?",[$pl['sub']])->fetch();
    $isKyc = (bool)($u['is_kyc']??false);
    $limitXof = $isKyc ? (float)get_setting('limit_verified', 100000000) : (float)get_setting('limit_unverified', 2000000);
    $wallet = q("SELECT id, currency FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    $wid = $wallet['id']??null;
    $currency = $wallet['currency'] ?? 'XOF';
    $limit = $limitXof;
    if ($currency !== 'XOF') {
        $converted = convert_currency($limitXof, 'XOF', $currency);
        if ($converted !== null) $limit = $converted;
    }
    $row = q("SELECT COALESCE(SUM(COALESCE(receiver_amount, net_amount, amount)),0) total FROM transactions
        WHERE receiver_wallet_id=? AND status='completed' AND type!='fee'
        AND EXTRACT(MONTH FROM created_at)=EXTRACT(MONTH FROM NOW())
        AND EXTRACT(YEAR FROM created_at)=EXTRACT(YEAR FROM NOW())",[$wid])->fetch();
    $received = (float)($row['total']??0);
    $remaining = max(0, $limit - $received);
    ok(['limit'=>$limit,'received'=>$received,'remaining'=>$remaining,'is_kyc'=>$isKyc]);
}

function wallet_stats_full() {
    $pl = auth();
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();

    $rows = q("SELECT to_char(created_at,'YYYY-MM') ym,
        SUM(CASE WHEN receiver_wallet_id=? AND status='completed' THEN COALESCE(receiver_amount,net_amount,amount) ELSE 0 END) total_in,
        SUM(CASE WHEN sender_wallet_id=? AND status='completed' THEN amount ELSE 0 END) total_out
        FROM transactions
        WHERE (sender_wallet_id=? OR receiver_wallet_id=?) AND type!='fee'
        AND EXTRACT(YEAR FROM created_at)=EXTRACT(YEAR FROM NOW())
        GROUP BY ym",[$wid,$wid,$wid,$wid])->fetchAll();

    $byMonth = [];
    foreach($rows as $r){ $byMonth[$r['ym']] = $r; }

    $lang = ($_GET['lang']??'fr')==='en' ? 'en' : 'fr';
    $labels = $lang==='en'
        ? ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
        : ['Jan','Fev','Mar','Avr','Mai','Jun','Jul','Aou','Sep','Oct','Nov','Dec'];
    $year = date('Y');
    $months = [];
    for($m=1;$m<=12;$m++){
        $ym = $year.'-'.str_pad($m,2,'0',STR_PAD_LEFT);
        $row = $byMonth[$ym] ?? null;
        $months[] = [
            'ym'    => $ym,
            'label' => $labels[$m-1],
            'in'    => $row ? (float)$row['total_in']  : 0,
            'out'   => $row ? (float)$row['total_out'] : 0,
        ];
    }

    // Cartes du haut - "Ce mois" : remis a zero automatiquement au changement de mois
    // (calcule a la volee via EXTRACT, pas de tache planifiee necessaire).
    $current = q("SELECT
        SUM(CASE WHEN receiver_wallet_id=? AND status='completed' THEN COALESCE(receiver_amount,net_amount,amount) ELSE 0 END) total_in,
        SUM(CASE WHEN sender_wallet_id=? AND status='completed' THEN amount ELSE 0 END) total_out,
        COUNT(CASE WHEN (sender_wallet_id=? OR receiver_wallet_id=?) AND status='completed' THEN 1 END) tx_count,
        COUNT(CASE WHEN sender_wallet_id=? AND status='cancelled' THEN 1 END) cancelled
        FROM transactions WHERE type!='fee' AND (sender_wallet_id=? OR receiver_wallet_id=?)
        AND EXTRACT(MONTH FROM created_at)=EXTRACT(MONTH FROM NOW())
        AND EXTRACT(YEAR FROM created_at)=EXTRACT(YEAR FROM NOW())",
        [$wid,$wid,$wid,$wid,$wid,$wid,$wid])->fetch();

    // Cartes du haut - "Recap total" : cumul sur l'annee calendaire affichee dans le graphique.
    $cumulative = q("SELECT
        SUM(CASE WHEN receiver_wallet_id=? AND status='completed' THEN COALESCE(receiver_amount,net_amount,amount) ELSE 0 END) total_in,
        SUM(CASE WHEN sender_wallet_id=? AND status='completed' THEN amount ELSE 0 END) total_out,
        COUNT(CASE WHEN (sender_wallet_id=? OR receiver_wallet_id=?) AND status='completed' THEN 1 END) tx_count,
        COUNT(CASE WHEN sender_wallet_id=? AND status='cancelled' THEN 1 END) cancelled
        FROM transactions WHERE type!='fee' AND (sender_wallet_id=? OR receiver_wallet_id=?)
        AND EXTRACT(YEAR FROM created_at)=EXTRACT(YEAR FROM NOW())",
        [$wid,$wid,$wid,$wid,$wid,$wid,$wid])->fetch();

    // Repartition depenses : toujours le mois en cours uniquement, ne bascule jamais
    // avec le recap (demande explicite : la repartition reste mensuelle).
    $cats = q("SELECT type, SUM(amount) total FROM transactions
        WHERE sender_wallet_id=? AND status='completed' AND type!='fee'
        AND EXTRACT(MONTH FROM created_at)=EXTRACT(MONTH FROM NOW())
        AND EXTRACT(YEAR FROM created_at)=EXTRACT(YEAR FROM NOW())
        GROUP BY type",[$wid])->fetchAll();

    ok(['months'=>$months,'current'=>$current,'cumulative'=>$cumulative,'categories'=>$cats]);
}

function wallet_stats() {
    $pl = auth();
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();
    $stats = q("SELECT
        SUM(CASE WHEN receiver_wallet_id=? AND status='completed' THEN COALESCE(net_amount,amount) ELSE 0 END) as total_in,
        SUM(CASE WHEN sender_wallet_id=? AND status='completed' THEN amount ELSE 0 END) as total_out,
        COUNT(CASE WHEN (sender_wallet_id=? OR receiver_wallet_id=?) AND status='completed' THEN 1 END) as tx_count,
        COUNT(CASE WHEN sender_wallet_id=? AND status='cancelled' THEN 1 END) as cancelled
        FROM transactions WHERE EXTRACT(MONTH FROM created_at)=EXTRACT(MONTH FROM NOW())
        AND (sender_wallet_id=? OR receiver_wallet_id=?) AND type!='fee'",
        [$wid,$wid,$wid,$wid,$wid,$wid,$wid])->fetch();
    ok($stats);
}

// TRANSACTIONS
function route_tx($action) {
    match($action) {
        'send'    => tx_send(),
        'collect' => tx_collect(),
        'cancel'  => tx_cancel(),
        'history' => tx_history(),
        'detail'  => tx_detail(),
        'resolve' => tx_resolve(),
        'pay-merchant' => tx_pay_merchant(),
        'payment-link-detail' => payment_link_detail(),
        'payment-link-pay' => payment_link_pay(),
        'check-new-recipient' => tx_check_new_recipient(),
        'fx-preview' => tx_fx_preview(),
        default   => fail('Action inconnue',404)
    };
}

// Apercu, SANS EFFET DE BORD (aucune ecriture), du montant que recevra le
// destinataire si les devises different - utilise par le frontend pour
// afficher "le destinataire recevra environ X" avant meme de confirmer
// l'envoi. L'estimation applique les memes frais/marge que le vrai envoi
// utilisera, donc fidele au montant final (a la fluctuation du taux pres,
// entre l'aperçu et la confirmation reelle quelques secondes plus tard).
function tx_fx_preview() {
    $pl = auth(); $b = body();
    $to = trim($b['receiver_phone']??'');
    $amount = (float)($b['amount']??0);
    if(!$to || $amount<=0){ ok(['same_currency'=>true]); return; }
    $sw = q("SELECT currency FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    $recv = q("SELECT w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$to])->fetch();
    if(!$sw || !$recv){ ok(['same_currency'=>true]); return; }
    $senderCurrency = $sw['currency'] ?: 'XOF';
    $receiverCurrency = $recv['currency'] ?: 'XOF';
    if($senderCurrency === $receiverCurrency){ ok(['same_currency'=>true,'currency'=>$senderCurrency]); return; }
    $rateAfrica = (float)get_setting('fee_rate_africa', 0.015);
    $net = $amount - round($amount * $rateAfrica);
    $converted = convert_currency($net, $senderCurrency, $receiverCurrency);
    if($converted === null){ ok(['same_currency'=>false,'unavailable'=>true]); return; }
    $fxMargin = (float)get_setting('fx_margin_rate', 0.01);
    $receiverAmount = round($converted * (1 - $fxMargin), 2);
    ok(['same_currency'=>false,'sender_currency'=>$senderCurrency,'receiver_currency'=>$receiverCurrency,'receiver_amount_estimate'=>$receiverAmount]);
}

// Verification LEGERE, sans effet de bord (aucune ecriture), utilisee par
// le frontend AVANT l'envoi pour savoir s'il faut afficher un avertissement
// dans le meme ecran de confirmation par PIN (pas une etape en plus).
// Reutilise volontairement le meme seuil que la detection de fraude
// (fraud_new_recipient_min_amount) pour rester coherent entre ce qui est
// montre a l'utilisateur et ce qui remonte en alerte admin.
function tx_check_new_recipient() {
    $pl = auth(); $b = body();
    $receiverPhone = trim($b['receiver_phone'] ?? '');
    $amount = (float)($b['amount'] ?? 0);
    if (!$receiverPhone || $amount <= 0) { ok(['warn'=>false]); return; }
    $sw = q("SELECT id, currency FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    if (!$sw) { ok(['warn'=>false]); return; }
    $senderCurrency = $sw['currency'] ?: 'XOF';
    $newRecipientMinXof = (float)get_setting('fraud_new_recipient_min_amount', 50000);
    $newRecipientMin = $newRecipientMinXof;
    if ($senderCurrency !== 'XOF') {
        $converted = convert_currency($newRecipientMinXof, 'XOF', $senderCurrency);
        if ($converted !== null) $newRecipientMin = $converted;
    }
    if ($amount < $newRecipientMin) { ok(['warn'=>false]); return; }
    $prior = q("SELECT COUNT(*) c FROM transactions t
                JOIN wallets rw ON rw.id=t.receiver_wallet_id
                JOIN users ru ON ru.id=rw.user_id
                WHERE t.sender_wallet_id=? AND ru.phone_number=? AND t.status='completed'",
                [$sw['id'], $receiverPhone])->fetch();
    $isNew = $prior && (int)$prior['c'] === 0;
    ok(['warn' => $isNew]);
}

// ============================================================
// ROM_GUICHET — Agents de depot/retrait (cash-in/cash-out)
// Meme conception que ROM_BUSINESS (table agents/agent_wallets distincte des
// comptes personnels et marchands) : un meme numero de telephone peut donc
// avoir un compte personnel, marchand ET agent independamment.
//
// Depot/retrait restent GRATUITS pour le client (comme le transfert
// national sous le seuil, et comme Wave en pratique - verifie par recherche
// externe) : l'agent est remunere via un tableau de paliers de commission
// JOURNALIERE (agent_commission_tiers, toujours en XOF), pas par un frais
// preleve sur l'operation elle-meme. Voir agent_commission_for() : chaque
// operation ne credite que la DIFFERENCE entre le palier atteint aujourd'hui
// et ce qui a deja ete verse aujourd'hui, jamais le plein montant du palier
// a chaque transaction.
// ============================================================
function route_agent($action) {
    match($action) {
        'register'         => agent_register(),
        'login'             => agent_login(),
        'balance'           => agent_balance(),
        'devices'           => agent_devices(),
        'revoke-device'     => agent_revoke_device(),
        'change-pin'        => agent_change_pin(),
        'cash-in'           => agent_cash_in(),
        'cash-out'          => agent_cash_out(),
        'cash-out-request'  => agent_request_cash_out_code(),
        'cash-out-confirm'  => agent_confirm_cash_out(),
        'send-to-third-party'         => agent_send_to_third_party(),
        'send-to-third-party-request' => agent_request_send_to_third_party_code(),
        'send-to-third-party-confirm' => agent_confirm_send_to_third_party(),
        'resolve-customer-qr' => agent_resolve_customer_qr(),
        'resolve-customer'  => agent_resolve_customer(),
        'history'           => agent_tx_history(),
        'earnings-summary'  => agent_earnings_summary(),
        'send-earnings'     => agent_send_earnings(),
        'request-recharge'  => agent_request_recharge(),
        'recharge-history'  => agent_recharge_history(),
        'list-incoming-recharges' => agent_list_incoming_recharge_requests(),
        'approve-recharge-request' => agent_approve_recharge_request(),
        'distributor-history'      => agent_distributor_history(),
        'doc-upload'        => agent_document_upload(),
        'doc-list'          => agent_document_list(),
        'doc-view'          => agent_document_view(),
        'application-status' => agent_application_status(),
        'set-location'      => agent_set_location(),
        'find-distributors' => agent_find_distributors(),
        default             => fail('Action inconnue',404)
    };
}

function agent_register() {
    rate_limit_check('agent_register', 10, 60);
    $b = body();
    $fullName = trim($b['full_name'] ?? '');
    $phone = trim($b['phone'] ?? '');
    $pin = trim($b['pin'] ?? '');
    $address = trim($b['address'] ?? '');
    $deviceId = trim($b['device_id'] ?? '');
    $country = trim($b['country'] ?? '');
    $city = trim($b['city'] ?? '');
    $commune = trim($b['commune'] ?? '');
    $quartier = trim($b['quartier'] ?? '');
    if(!$fullName) fail('Nom requis');
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $phone))) fail('Telephone invalide');
    if(!preg_match('/^\d{4}$/', $pin)) fail('PIN doit avoir 4 chiffres');
    if(is_weak_pin($pin)) fail('Ce code est trop simple, choisissez une autre combinaison');
    if(!$country) fail('Le pays est requis');
    // Obligatoires (pas juste indicatif dans l'adresse libre) : c'est la
    // seule donnee qui permet a "Trouver un distributeur" de rester
    // utilisable a grande echelle (recherche precise ville/commune/quartier
    // plutot qu'une liste de tous les distributeurs, invivable des que le
    // reseau grossit). Avant ce correctif, ces champs etaient collectes a
    // l'inscription mais jamais transmis au backend - seulement fondus dans
    // le texte libre agents.address, illisible pour une recherche.
    if(!$city) fail('La ville est requise');
    if(!$commune) fail('La commune est requise');
    if(!$quartier) fail('Le quartier est requis');
    $countryRow = q("SELECT is_active FROM active_countries WHERE name=?",[$country])->fetch();
    if(!$countryRow || !$countryRow['is_active']) fail('ROM_GUICHET n\'est pas encore disponible dans ce pays');
    try {
        $exists = q("SELECT id FROM agents WHERE phone_number=?",[$phone])->fetch();
    } catch(Exception $e) {
        log_and_fail($e, 'Service agent indisponible pour le moment (base de donnees non initialisee).', 503);
    }
    if($exists) fail('Ce numero est deja enregistre comme agent');

    db()->beginTransaction();
    try {
        $aid = uid(); $wid = uid();
        $pinh = password_hash($pin, PASSWORD_BCRYPT);
        // Compte cree INACTIF : agrement obligatoire par un admin (documents
        // + validation) avant de pouvoir utiliser l'application, contrairement
        // au statut 'active' par defaut - voir agent_auth() qui bloque deja
        // tout statut different de 'active', aucune modification necessaire
        // la-bas.
        q("INSERT INTO agents (id,phone_number,pin_hash,full_name,address,country,city,commune,quartier,status) VALUES (?,?,?,?,?,?,?,?,?,'pending_approval')",
          [$aid,$phone,$pinh,$fullName,$address?:null,$country,$city,$commune,$quartier]);
        q("INSERT INTO agent_wallets (id,agent_id,currency) VALUES (?,?,?)",[$wid,$aid,country_to_currency($country)]);
        if($deviceId){
            $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
            q("INSERT INTO agent_known_devices (agent_id,device_id,user_agent) VALUES (?,?,?)
               ON CONFLICT (agent_id, device_id) DO UPDATE SET last_seen=CURRENT_TIMESTAMP, revoked=0",
              [$aid, $deviceId, $ua]);
        }
        $token = jwt_make(['sub'=>$aid,'phone'=>$phone,'typ'=>'agent','device_id'=>$deviceId]);
        db()->commit();
        ok(['token'=>$token,'agent_id'=>$aid,'full_name'=>$fullName,'address'=>$address,'status'=>'pending_approval'],
           'Compte agent cree, en attente de validation par un administrateur',201);
    } catch(Exception $e) {
        db()->rollBack();
        log_and_fail($e, 'Erreur creation compte', 500);
    }
}

function agent_login() {
    rate_limit_check('agent_login', 15, 60);
    $b = body();
    $phone = trim($b['phone'] ?? '');
    $pin = trim($b['pin'] ?? '');
    $deviceId = trim($b['device_id'] ?? '');
    if(!$phone || !$pin) fail('Telephone et PIN requis');
    try {
        $a = q("SELECT * FROM agents WHERE phone_number=?",[$phone])->fetch();
    } catch(Exception $e) {
        log_and_fail($e, 'Service agent indisponible pour le moment (base de donnees non initialisee).', 503);
    }
    if(!$a) fail('Numero ou PIN incorrect', 401);
    agent_pin_check($a['id'], $pin, $a['pin_hash']);
    // Contrairement a merchant_login()/auth() classique : un compte
    // 'pending_approval' ou 'rejected' PEUT se connecter (le PIN prouve son
    // identite) - seul agent_auth() (utilise par cash-in/cash-out/recharge)
    // reste ferme a tout statut different de 'active'. 'blocked' reste une
    // vraie fermeture de connexion (compte bloque par un admin, pas juste en
    // attente d'agrement).
    if($a['status'] === 'blocked') fail('Compte suspendu', 403);
    if($deviceId){
        $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255);
        q("INSERT INTO agent_known_devices (agent_id,device_id,user_agent) VALUES (?,?,?)
           ON CONFLICT (agent_id, device_id) DO UPDATE SET last_seen=CURRENT_TIMESTAMP, revoked=0",
          [$a['id'], $deviceId, $ua]);
    }
    $w = q("SELECT * FROM agent_wallets WHERE agent_id=?",[$a['id']])->fetch();
    $token = jwt_make(['sub'=>$a['id'],'phone'=>$phone,'typ'=>'agent','device_id'=>$deviceId]);
    ok(['token'=>$token,'agent_id'=>$a['id'],'full_name'=>$a['full_name'],'address'=>$a['address'],
        'verified'=>(bool)($a['verified']??false),'country'=>$a['country']??null,
        'balance'=>(float)($w['balance']??0),'currency'=>$w['currency']??'XOF',
        'status'=>$a['status'],'rejection_reason'=>$a['rejection_reason']??null,
        'is_distributor'=>(bool)($a['is_distributor']??false)],'Connexion reussie');
}

function agent_balance() {
    $pl = agent_auth();
    $a = q("SELECT full_name,address,verified,country,is_distributor FROM agents WHERE id=?",[$pl['sub']])->fetch();
    $w = q("SELECT * FROM agent_wallets WHERE agent_id=?",[$pl['sub']])->fetch();
    if(!$w) fail('Portefeuille introuvable',404);
    ok(['balance'=>(float)$w['balance'],'currency'=>$w['currency'],'full_name'=>$a['full_name'],
        'address'=>$a['address'],'country'=>$a['country']??null,'verified'=>(bool)($a['verified']??false),
        'is_distributor'=>(bool)($a['is_distributor']??false)]);
}

// ── Agrement agent (documents + statut) ── mirror de merchant_document_upload()/
// merchant_document_list() (index.php:963-988), avec agent_auth_allow_pending()
// au lieu de agent_auth() puisque ces deux actions doivent rester accessibles
// meme avant validation admin.
function agent_document_upload() {
    $pl = agent_auth_allow_pending(); $b = body();
    $docType = trim($b['doc_type'] ?? '');
    $photo = trim($b['photo'] ?? '');
    if(!in_array($docType, AGENT_DOC_TYPES, true) && !in_array($docType, AGENT_OPTIONAL_DOC_TYPES, true)) fail('Type de document invalide');
    if(!$photo) fail('Photo requise');
    if(strlen($photo) > 8*1024*1024) fail('Image trop volumineuse');
    // Creneau deja occupe : un admin doit explicitement supprimer le
    // document existant (avec raison) pour permettre un nouvel envoi -
    // empeche un remplacement silencieux d'une piece deja fournie.
    $existing = q("SELECT id FROM agent_documents WHERE agent_id=? AND doc_type=?",[$pl['sub'],$docType])->fetch();
    if($existing) fail('Ce document est deja envoye - contactez un administrateur pour le remplacer');
    $encrypted = kyc_encrypt($photo);
    // Toujours un INSERT, jamais un remplacement - meme raisonnement que
    // merchant_document_upload() ci-dessus.
    try {
        q("INSERT INTO agent_documents (agent_id,doc_type,photo,uploaded_at) VALUES (?,?,?,NOW())",
          [$pl['sub'],$docType,$encrypted]);
        // Le renvoi de ce type de document repond a la note laissee par
        // l'admin lors du retrait precedent - elle n'a plus lieu d'etre.
        q("DELETE FROM agent_document_notices WHERE agent_id=? AND doc_type=?",[$pl['sub'],$docType]);
    } catch(Exception $e) {
        log_and_fail($e, 'Service indisponible (base non initialisee).', 503);
    }
    ok(['uploaded_at'=>date('c')], 'Document enregistre');
}

function agent_document_list() {
    $pl = agent_auth_allow_pending();
    try {
        $rows = q("SELECT doc_type, uploaded_at FROM agent_documents WHERE agent_id=? ORDER BY doc_type, uploaded_at DESC",[$pl['sub']])->fetchAll();
    } catch(Exception $e) {
        $rows = [];
    }
    try {
        $notices = q("SELECT doc_type, reason, created_at FROM agent_document_notices WHERE agent_id=? ORDER BY created_at DESC",[$pl['sub']])->fetchAll();
    } catch(Exception $e) {
        $notices = [];
    }
    ok(['documents'=>$rows,'notices'=>$notices]);
}

// Permet a l'agent de revoir un document deja envoye (verification apres
// coup, meme des semaines plus tard) - a la demande, jamais inclus dans
// doc_list() pour ne pas dechiffrer/transferer toutes les photos a chaque
// rafraichissement de l'ecran d'agrement.
function agent_document_view() {
    $pl = agent_auth_allow_pending();
    $docType = trim($_GET['doc_type'] ?? '');
    if(!$docType) fail('Type de document requis');
    $d = q("SELECT photo FROM agent_documents WHERE agent_id=? AND doc_type=? ORDER BY uploaded_at DESC LIMIT 1",[$pl['sub'],$docType])->fetch();
    if(!$d) fail('Document introuvable',404);
    ok(['photo'=>kyc_decrypt($d['photo'])]);
}

// Permet a un agent 'pending_approval'/'rejected' de savoir ou en est sa
// demande, sans avoir besoin de se reconnecter (agent_login() renvoie deja
// le statut, mais un agent deja connecte doit pouvoir le revoir aussi).
function agent_application_status() {
    $pl = agent_auth_allow_pending();
    $a = q("SELECT status,rejection_reason FROM agents WHERE id=?",[$pl['sub']])->fetch();
    if(!$a) fail('Compte introuvable',404);
    ok(['status'=>$a['status'],'rejection_reason'=>$a['rejection_reason']]);
}

// Position fixe (jamais un suivi en direct) pour "Trouver un distributeur" -
// en pratique utile uniquement pour un distributeur (c'est lui qu'on
// recherche), mais pas techniquement reserve : n'importe quel agent peut
// l'appeler sans consequence puisque personne ne le cherche.
function agent_set_location() {
    $pl = agent_auth();
    $b = body();
    $city = trim($b['city'] ?? '');
    $commune = trim($b['commune'] ?? '');
    $quartier = trim($b['quartier'] ?? '');
    $lat = isset($b['latitude']) && $b['latitude'] !== '' ? (float)$b['latitude'] : null;
    $lng = isset($b['longitude']) && $b['longitude'] !== '' ? (float)$b['longitude'] : null;
    if(!$city && !$commune && !$quartier && $lat===null && $lng===null) fail('Ville, commune, quartier ou coordonnees requis');
    // COALESCE(NULLIF(...)) : un champ laisse vide ici ne doit pas effacer
    // la valeur deja renseignee obligatoirement a l'inscription - ce
    // formulaire ne sert qu'a corriger/preciser, jamais a vider.
    q("UPDATE agents SET city=COALESCE(NULLIF(?,''),city), commune=COALESCE(NULLIF(?,''),commune), quartier=COALESCE(NULLIF(?,''),quartier), latitude=?, longitude=? WHERE id=?",
      [$city,$commune,$quartier,$lat,$lng,$pl['sub']]);
    ok(null,'Position enregistree');
}

// Formule de Haversine (calcul pur PHP, pas d'API payante) pour trier les
// distributeurs par distance quand l'agent partage sa position ; repli sur
// une recherche ville/commune/quartier/pays sinon - le filtrage progressif
// (ville seule = large, +commune = plus precis, +quartier = tres precis)
// est ce qui permet a "Trouver un distributeur" de rester utilisable meme
// avec un grand nombre de distributeurs (voir agent_register(), ces trois
// champs sont obligatoires a l'inscription pour cette raison). Toujours
// ouvert (aucune restriction geographique forcee) - purement une aide a la
// decouverte.
function agent_find_distributors() {
    $pl = agent_auth();
    $lat = isset($_GET['lat']) && $_GET['lat'] !== '' ? (float)$_GET['lat'] : null;
    $lng = isset($_GET['lng']) && $_GET['lng'] !== '' ? (float)$_GET['lng'] : null;
    $city = trim($_GET['city'] ?? '');
    $commune = trim($_GET['commune'] ?? '');
    $quartier = trim($_GET['quartier'] ?? '');
    $country = trim($_GET['country'] ?? '');

    $where = "is_distributor=1 AND status='active'"; $params = [];
    if($city){ $where .= " AND city ILIKE ?"; $params[] = '%'.$city.'%'; }
    if($commune){ $where .= " AND commune ILIKE ?"; $params[] = '%'.$commune.'%'; }
    if($quartier){ $where .= " AND quartier ILIKE ?"; $params[] = '%'.$quartier.'%'; }
    if($country){ $where .= " AND country=?"; $params[] = $country; }
    $rows = q("SELECT id,full_name,phone_number,city,commune,quartier,country,latitude,longitude FROM agents WHERE $where",$params)->fetchAll();

    if($lat!==null && $lng!==null){
        foreach($rows as &$r){
            if($r['latitude']!==null && $r['longitude']!==null){
                $r['distance_km'] = haversine_km($lat,$lng,(float)$r['latitude'],(float)$r['longitude']);
            } else {
                $r['distance_km'] = null;
            }
        }
        unset($r);
        usort($rows, function($a,$b){
            if($a['distance_km']===null) return 1;
            if($b['distance_km']===null) return -1;
            return $a['distance_km'] <=> $b['distance_km'];
        });
    }
    ok(['distributors'=>$rows]);
}

function haversine_km($lat1,$lng1,$lat2,$lng2){
    $R = 6371;
    $dLat = deg2rad($lat2-$lat1);
    $dLng = deg2rad($lng2-$lng1);
    $a = sin($dLat/2)*sin($dLat/2) + cos(deg2rad($lat1))*cos(deg2rad($lat2))*sin($dLng/2)*sin($dLng/2);
    $c = 2*atan2(sqrt($a), sqrt(1-$a));
    return round($R*$c, 1);
}

function agent_devices() {
    $pl = agent_auth();
    $rows = q("SELECT device_id,user_agent,first_seen,last_seen,revoked FROM agent_known_devices WHERE agent_id=? ORDER BY last_seen DESC",[$pl['sub']])->fetchAll();
    foreach($rows as &$r){ $r['is_current'] = ($pl['device_id'] ?? '') !== '' && $r['device_id'] === $pl['device_id']; $r['revoked']=(bool)$r['revoked']; }
    unset($r);
    ok(['devices'=>$rows]);
}
function agent_revoke_device() {
    $pl = agent_auth(); $b = body();
    $deviceId = trim($b['device_id'] ?? '');
    if(!$deviceId) fail('Appareil requis');
    $n = q("UPDATE agent_known_devices SET revoked=1 WHERE agent_id=? AND device_id=?",[$pl['sub'],$deviceId])->rowCount();
    if(!$n) fail('Appareil introuvable',404);
    ok(null,'Appareil deconnecte');
}

function agent_change_pin() {
    $pl = agent_auth(); $b = body();
    $oldPin = trim($b['old_pin'] ?? '');
    $newPin = trim($b['new_pin'] ?? '');
    if(!preg_match('/^\d{4}$/', $newPin)) fail('PIN doit avoir 4 chiffres');
    if(is_weak_pin($newPin)) fail('Ce code est trop simple, choisissez une autre combinaison');
    $a = q("SELECT pin_hash FROM agents WHERE id=?",[$pl['sub']])->fetch();
    agent_pin_check($pl['sub'], $oldPin, $a['pin_hash']);
    q("UPDATE agents SET pin_hash=? WHERE id=?",[password_hash($newPin, PASSWORD_BCRYPT), $pl['sub']]);
    ok(null,'PIN modifie');
}

// Calcule et credite la commission journaliere de l'agent apres un
// cash-in/cash-out reussi. Volontairement APRES coup (jamais dans la meme
// transaction DB que l'operation principale) : une erreur ici ne doit
// jamais faire echouer un cash-in/cash-out qui a deja reussi, meme
// philosophie que fraud_check_merchant_transaction().
//
// "Commission journaliere" = un TOTAL pour toute la journee, pas par
// transaction : on ne credite que la difference entre le palier atteint
// AUJOURD'HUI (cumul de tous les cash-in/cash-out du jour, converti en
// XOF) et ce qui a deja ete verse aujourd'hui. Decision validee
// explicitement avec l'utilisateur.
function agent_commission_for($agentId, $agentWalletId) {
    try {
        $w = q("SELECT currency FROM agent_wallets WHERE id=?",[$agentWalletId])->fetch();
        $agentCurrency = $w['currency'] ?: 'XOF';

        $volumeToday = (float)(q("SELECT COALESCE(SUM(amount),0) t FROM transactions
            WHERE (sender_agent_wallet_id=? OR receiver_agent_wallet_id=?)
            AND type IN ('agent_cash_in','agent_cash_out') AND status='completed'
            AND created_at::date=CURRENT_DATE",[$agentWalletId,$agentWalletId])->fetch()['t'] ?? 0);

        $alreadyPaidToday = (float)(q("SELECT COALESCE(SUM(amount),0) t FROM transactions
            WHERE receiver_agent_wallet_id=? AND type='agent_commission' AND status='completed'
            AND created_at::date=CURRENT_DATE",[$agentWalletId])->fetch()['t'] ?? 0);

        if($agentCurrency !== 'XOF'){
            refresh_exchange_rates_if_stale();
            $volumeXof = convert_currency($volumeToday, $agentCurrency, 'XOF');
            $alreadyPaidXof = convert_currency($alreadyPaidToday, $agentCurrency, 'XOF');
            if($volumeXof === null || $alreadyPaidXof === null) return; // taux indisponible, on retente a la prochaine operation
        } else {
            $volumeXof = $volumeToday;
            $alreadyPaidXof = $alreadyPaidToday;
        }

        $tier = q("SELECT commission_xof FROM agent_commission_tiers
            WHERE band_min_xof<=? AND (band_max_xof IS NULL OR band_max_xof>=?)
            ORDER BY band_min_xof DESC LIMIT 1",[$volumeXof,$volumeXof])->fetch();
        if(!$tier) return; // volume sous le premier palier (ex: 0) - rien a verser

        $deltaXof = (float)$tier['commission_xof'] - $alreadyPaidXof;
        if($deltaXof <= 0) return; // palier du jour deja entierement paye

        $delta = ($agentCurrency !== 'XOF') ? convert_currency($deltaXof, 'XOF', $agentCurrency) : $deltaXof;
        if($delta === null || $delta <= 0) return;
        $delta = round($delta);
        if($delta <= 0) return;

        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,receiver_agent_wallet_id,amount,type,status,reference,description)
           VALUES (?,?,?,'agent_commission','completed',?,?)",
          [$txid,$agentWalletId,$delta,$reference,'Commission journaliere ROM_GUICHET']);
        q("UPDATE agent_wallets SET balance=balance+? WHERE id=?",[$delta,$agentWalletId]);
    } catch(Exception $e) {
        error_log('[ROM_GUICHET] Echec calcul commission agent :: '.$e->getMessage());
    }
}

// Envoie un SMS via Africa's Talking - utilise pour les codes de confirmation
// de retrait (voir agent_request_cash_out_code()). Cle API en variable
// d'environnement (meme principe que GOOGLE_VISION_API_KEY) : echoue
// proprement (false) si non configuree, ne bloque jamais le reste de l'app.
function send_sms_africastalking($phone, $message) {
    $username = getenv('AFRICASTALKING_USERNAME');
    $apiKey = getenv('AFRICASTALKING_API_KEY');
    if(!$username || !$apiKey) {
        error_log('[SMS] AFRICASTALKING_USERNAME/AFRICASTALKING_API_KEY absentes des variables d\'environnement');
        return false;
    }
    try {
        $ch = curl_init('https://api.africastalking.com/version1/messaging');
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => ['apiKey: '.$apiKey, 'Content-Type: application/x-www-form-urlencoded', 'Accept: application/json'],
            CURLOPT_POSTFIELDS => http_build_query(['username'=>$username, 'to'=>$phone, 'message'=>$message]),
            CURLOPT_TIMEOUT => 10,
        ]);
        $res = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if($code<200 || $code>=300){
            error_log('[SMS] Africa\'s Talking a repondu '.$code.' :: '.$res);
            return false;
        }
        return true;
    } catch(Exception $e) {
        error_log('[SMS] Echec envoi :: '.$e->getMessage());
        return false;
    }
}

// Resout un QR personnel ROM_MONEY (userId|qrSeed|phone, meme format que
// money/index.html shQr()/shReceive()/openQRMenu() - unifie sur ce seul
// format depuis la correction du bug "QR invalide" cote agent) en identite
// client complete - partage entre l'endpoint de resolution (apercu avant
// envoi) et le retrait immediat par QR.
// Le repli sur un numero brut (sans '|') reste gere ici pour les cartes QR
// deja imprimees AVANT cette unification (ancien format openQRMenu, numero
// seul) - meme valeur de preuve qu'une carte physique (peut etre
// copiee/perdue), donc verified_live=false : le retrait devra quand meme
// passer par le code SMS, jamais l'execution immediate reservee au vrai
// scan live. A retirer une fois qu'on est sur qu'aucune ancienne carte
// imprimee n'est plus en circulation.
function agent_resolve_customer_by_qr($qr) {
    $parts = explode('|', $qr);
    if(count($parts) >= 2){
        $customer = q("SELECT u.id,u.full_name,u.verified_name,u.phone_number,w.id wid,w.balance,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.id=? AND w.qr_seed=?",[$parts[0],$parts[1]])->fetch();
        if($customer){ $customer['verified_live'] = true; return $customer; }
    }
    $phone = trim($qr);
    if(preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $phone))){
        $customer = q("SELECT u.id,u.full_name,u.verified_name,u.phone_number,w.id wid,w.balance,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$phone])->fetch();
        if($customer){ $customer['verified_live'] = false; return $customer; }
    }
    fail('QR invalide',404);
}

function agent_resolve_customer_qr() {
    $pl = agent_auth();
    $qr = trim($_GET['qr'] ?? '');
    if(!$qr) fail('QR requis');
    $customer = agent_resolve_customer_by_qr($qr);
    ok(['user_id'=>$customer['id'],'full_name'=>$customer['verified_name']?:$customer['full_name'],
        'phone_number'=>$customer['phone_number'],'currency'=>$customer['currency'],
        'is_verified'=>!empty($customer['verified_name']),'verified_live'=>$customer['verified_live']]);
}

// Identification par numero (saisie manuelle) - simple apercu en lecture
// seule pour verification avant de lancer un depot/retrait, meme principe
// que agent_resolve_customer_qr() mais par numero plutot que QR.
function agent_resolve_customer() {
    $pl = agent_auth();
    $phone = trim($_GET['phone'] ?? '');
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $phone))) fail('Numero invalide');
    $customer = q("SELECT u.id,u.full_name,u.verified_name,u.phone_number,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$phone])->fetch();
    if(!$customer) fail('Client introuvable',404);
    ok(['user_id'=>$customer['id'],'full_name'=>$customer['verified_name']?:$customer['full_name'],
        'phone_number'=>$customer['phone_number'],'currency'=>$customer['currency'],
        'is_verified'=>!empty($customer['verified_name'])]);
}

// Cash-in : le client donne du cash physique a l'agent, qui le credite
// numeriquement. C'est le float de L'AGENT qui est debite, donc c'est
// l'agent qui confirme avec SON PROPRE PIN (recevoir de l'argent ne
// necessite aucune autorisation du client dans la vraie vie).
function agent_cash_in() {
    $pl = agent_auth(); $b = body();
    $customerPhone = trim($b['customer_phone'] ?? '');
    $amount = (float)($b['amount'] ?? 0);
    $pin = trim($b['pin'] ?? '');
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $customerPhone))) fail('Numero invalide');
    if($amount<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/', $pin)) fail('PIN invalide');

    $a = q("SELECT pin_hash FROM agents WHERE id=?",[$pl['sub']])->fetch();
    agent_pin_check($pl['sub'], $pin, $a['pin_hash']);

    $aw = q("SELECT * FROM agent_wallets WHERE agent_id=?",[$pl['sub']])->fetch();
    $customer = q("SELECT u.id,u.full_name,u.verified_name,w.id wid,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$customerPhone])->fetch();
    if(!$customer) fail('Client introuvable',404);
    if($customer['currency'] !== $aw['currency']) fail('Le depot doit se faire dans la meme devise que votre guichet.', 422);
    if((float)$aw['balance'] < $amount) fail('Solde du guichet insuffisant, demandez une recharge');

    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
        q("INSERT INTO transactions (id,sender_agent_wallet_id,receiver_wallet_id,amount,type,status,reference,description,cancel_deadline,currency)
           VALUES (?,?,?,?,'agent_cash_in','pending',?,?,?,?)",
          [$txid,$aw['id'],$customer['wid'],$amount,$reference,'Depot via agent',$deadline,$aw['currency']]);
        $rows = q("UPDATE agent_wallets SET balance=balance-? WHERE id=? AND balance>=?",[$amount,$aw['id'],$amount])->rowCount();
        if(!$rows) throw new Exception('Solde du guichet insuffisant');
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$amount,$customer['wid']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);
        db()->commit();
    } catch(Exception $e) {
        db()->rollBack();
        log_and_fail($e, 'Echec du depot', 500);
    }
    agent_commission_for($pl['sub'], $aw['id']);
    web_push_send_to_user($customer['id'], 'ROM_MONEY', 'Vous avez recu un depot de '.$amount.' '.$aw['currency'].' via un agent ROM_GUICHET.');
    $newBal = (float)q("SELECT balance FROM agent_wallets WHERE id=?",[$aw['id']])->fetchColumn();
    ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$amount,'customer_name'=>$customer['verified_name']?:$customer['full_name'],
        'cancel_before'=>$deadline,'new_balance'=>$newBal],'Depot effectue');
}

// Cash-out : le client donne du solde numerique, l'agent lui remet du cash
// physique. C'est le solde du CLIENT qui est debite - plus jamais autorise
// par un PIN client tape sur l'appareil de l'agent (retire completement,
// remplace par deux chemins distincts) :
//   - QR scanne depuis l'app du client (agent_cash_out() ci-dessous) :
//     execution immediate, aucun code demande - la presentation physique en
//     personne suffit.
//   - Numero saisi a la main / future carte physique (agent_request_cash_out_
//     code() + agent_confirm_cash_out()) : un code a 4 chiffres est envoye
//     par SMS au client, qui le communique de vive voix a l'agent.
// La logique transactionnelle (debit client + credit agent + commission) est
// partagee par les deux chemins via agent_execute_cash_out(), pour ne
// jamais la dupliquer.
function agent_execute_cash_out($agentId, $customer, $amount) {
    $aw = q("SELECT * FROM agent_wallets WHERE agent_id=?",[$agentId])->fetch();
    if($customer['currency'] !== $aw['currency']) fail('Le retrait doit se faire dans la meme devise que votre guichet.', 422);
    if((float)$customer['balance'] < $amount) fail('Solde du client insuffisant');

    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
        q("INSERT INTO transactions (id,sender_wallet_id,receiver_agent_wallet_id,amount,type,status,reference,description,cancel_deadline,currency)
           VALUES (?,?,?,?,'agent_cash_out','pending',?,?,?,?)",
          [$txid,$customer['wid'],$aw['id'],$amount,$reference,'Retrait via agent',$deadline,$aw['currency']]);
        $rows = q("UPDATE wallets SET balance=balance-? WHERE id=? AND balance>=?",[$amount,$customer['wid'],$amount])->rowCount();
        if(!$rows) throw new Exception('Solde du client insuffisant');
        q("UPDATE agent_wallets SET balance=balance+? WHERE id=?",[$amount,$aw['id']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);
        db()->commit();
    } catch(Exception $e) {
        db()->rollBack();
        log_and_fail($e, 'Echec du retrait', 500);
    }
    agent_commission_for($agentId, $aw['id']);
    $newBal = (float)q("SELECT balance FROM wallets WHERE id=?",[$customer['wid']])->fetchColumn();
    return ['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$amount,'customer_name'=>$customer['verified_name']?:$customer['full_name'],
        'cancel_before'=>$deadline,'customer_new_balance'=>$newBal];
}

function agent_cash_out() {
    $pl = agent_auth(); $b = body();
    $qr = trim($b['qr'] ?? '');
    $amount = (float)($b['amount'] ?? 0);
    if(!$qr) fail('QR requis');
    if($amount<=0) fail('Montant invalide');
    $customer = agent_resolve_customer_by_qr($qr);
    if(empty($customer['verified_live'])) fail("Ce QR n'autorise pas un retrait immediat - utilisez le code envoye par SMS.", 422);
    $result = agent_execute_cash_out($pl['sub'], $customer, $amount);
    ok($result, 'Retrait effectue');
}

// Etape 1/2 du chemin "numero manuel" : valide tout en amont (client existe,
// devise identique, solde suffisant) AVANT d'envoyer le SMS, pour ne jamais
// gaspiller un SMS sur une operation vouee a l'echec. Ne deplace aucun argent.
function agent_request_cash_out_code() {
    $pl = agent_auth(); $b = body();
    rate_limit_check('agent_cashout_request', 10, 60);
    $customerPhone = trim($b['customer_phone'] ?? '');
    $amount = (float)($b['amount'] ?? 0);
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $customerPhone))) fail('Numero invalide');
    if($amount<=0) fail('Montant invalide');

    $customer = q("SELECT u.id,u.full_name,u.verified_name,w.id wid,w.balance,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$customerPhone])->fetch();
    if(!$customer) fail('Client introuvable',404);

    $aw = q("SELECT * FROM agent_wallets WHERE agent_id=?",[$pl['sub']])->fetch();
    if($customer['currency'] !== $aw['currency']) fail('Le retrait doit se faire dans la meme devise que votre guichet.', 422);
    if((float)$customer['balance'] < $amount) fail('Solde du client insuffisant');

    $code = str_pad((string)random_int(0, 9999), 4, '0', STR_PAD_LEFT);
    $id = uid();
    $expiresAt = date('Y-m-d H:i:s', time()+600);
    $message = 'ROM_MONEY: code de confirmation pour un retrait de '.number_format($amount,0,',',' ').' '.$customer['currency']
        .' chez un agent : '.$code.'. Ne le partagez qu\'avec l\'agent en face de vous.';
    if(!send_sms_africastalking($customer['phone_number'] ?? $customerPhone, $message)) {
        fail('Envoi du SMS impossible, reessayez');
    }
    q("INSERT INTO agent_cashout_requests (id,agent_id,customer_user_id,customer_phone,amount,code,expires_at) VALUES (?,?,?,?,?,?,?)",
      [$id,$pl['sub'],$customer['id'],$customerPhone,$amount,$code,$expiresAt]);
    ok(['request_id'=>$id,'customer_name'=>$customer['verified_name']?:$customer['full_name']],'Code envoye au client');
}

// Etape 2/2 : le montant vient de la demande d'origine (jamais resaisi ici),
// donc impossible pour un agent de faire lire un code pour un petit montant
// puis de s'en servir pour un montant different.
function agent_confirm_cash_out() {
    $pl = agent_auth(); $b = body();
    $requestId = trim($b['request_id'] ?? '');
    $code = trim($b['code'] ?? '');
    if(!$requestId || !$code) fail('Demande et code requis');

    $r = q("SELECT * FROM agent_cashout_requests WHERE id=? AND agent_id=? AND status='pending'",[$requestId,$pl['sub']])->fetch();
    if(!$r) fail('Demande introuvable ou deja traitee',404);
    if(strtotime($r['expires_at']) < time()){
        q("UPDATE agent_cashout_requests SET status='expired' WHERE id=?",[$requestId]);
        fail('Code expire, refaites une demande');
    }
    if(!hash_equals($r['code'], $code)) fail('Code incorrect');

    $customer = q("SELECT u.id,u.full_name,u.verified_name,w.id wid,w.balance,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.id=?",[$r['customer_user_id']])->fetch();
    if(!$customer) fail('Client introuvable',404);

    $result = agent_execute_cash_out($pl['sub'], $customer, (float)$r['amount']);
    q("UPDATE agent_cashout_requests SET status='completed' WHERE id=?",[$requestId]);
    ok($result, 'Retrait effectue');
}

// "Envoyer a un tiers" : le client identifie par l'agent (comme pour un
// retrait) envoie de l'argent electronique a un tiers, pas de l'especes a
// lui-meme. Reprend le sous-ensemble "canal national" de tx_send() (frais 1%
// avec franchise quotidienne cumulee, meme compte systeme de frais) sans
// toucher a tx_send() elle-meme (deja en production pour les vrais transferts
// personnels) - duplication limitee et volontaire. Pas de canal Africa/
// conversion de devise : un guichet agent opere localement, donc expediteur
// et destinataire doivent avoir la meme devise.
// Calcule brut/net/frais pour un envoi a un tiers via agent, dans les DEUX
// sens (comme tx_send()/getAmountIntent() cote money/index.html) : mode
// 'brut' = l'agent a tape le montant total preleve sur le client ; mode
// 'net' = l'agent a tape le montant que le destinataire doit recevoir, et
// le brut necessaire est resolu a l'envers. Meme franchise quotidienne
// cumulee que tx_send() (montant deja envoye aujourd'hui par CE client,
// tous canaux "national" confondus - un envoi via guichet agent compte
// dans le meme cumul qu'un envoi depuis l'app, pour ne pas offrir une
// double franchise).
function agent_transfer_amounts($senderWalletId, $senderCurrency, $amount, $mode) {
    $rateNational = (float)get_setting('fee_rate_national', 0.01);
    $freeThreshold = (float)get_setting('fee_free_threshold_national', 4000);
    $sentTodayNational = (float)(q("SELECT COALESCE(SUM(amount),0) t FROM transactions
        WHERE sender_wallet_id=? AND type='transfer' AND channel='national' AND status='completed'
        AND created_at::date=CURRENT_DATE",[$senderWalletId])->fetch()['t']??0);
    if($senderCurrency === 'XOF'){
        $remainingFree = max(0, $freeThreshold - $sentTodayNational);
    } else {
        $sentTodayXof = convert_currency($sentTodayNational, $senderCurrency, 'XOF');
        if($sentTodayXof === null) fail('Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
        $remainingFreeXof = max(0, $freeThreshold - $sentTodayXof);
        $remainingFree = $remainingFreeXof;
        if($remainingFreeXof > 0){
            $rf = convert_currency($remainingFreeXof, 'XOF', $senderCurrency);
            if($rf === null) fail('Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
            $remainingFree = $rf;
        }
    }
    if($mode === 'net'){
        $net = $amount;
        if($net <= $remainingFree){
            $brut = $net; $fee = 0;
        } else {
            $brut = round(($net - $rateNational*$remainingFree) / (1-$rateNational));
            $feeable = max(0, $brut - $remainingFree);
            $fee = round($feeable * $rateNational);
            $net = $brut - $fee; // recalcule depuis le brut/frais arrondis, pour rester coherent au franc pres
        }
    } else {
        $brut = $amount;
        $feeable = max(0, $brut - $remainingFree);
        $fee = round($feeable * $rateNational);
        $net = $brut - $fee;
    }
    return ['brut'=>$brut,'net'=>$net,'fee'=>$fee];
}

function agent_execute_transfer($senderCustomer, $recipientPhone, $amount, $mode='brut') {
    $recv = q("SELECT u.id,u.full_name,u.verified_name,w.id wid,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$recipientPhone])->fetch();
    if(!$recv) fail('Destinataire introuvable',404);
    if($recv['id']===$senderCustomer['id']) fail('Envoi a soi-meme impossible');
    $senderCurrency = $senderCustomer['currency'] ?: 'XOF';
    $recvCurrency = $recv['currency'] ?: 'XOF';
    if($senderCurrency !== $recvCurrency) fail("L'envoi a un tiers via un guichet agent doit se faire dans la meme devise.", 422);

    $amounts = agent_transfer_amounts($senderCustomer['wid'], $senderCurrency, $amount, $mode);
    $brut = $amounts['brut']; $net = $amounts['net']; $fee = $amounts['fee'];
    if($net<=0) fail('Montant invalide');
    if((float)$senderCustomer['balance'] < $brut) fail('Solde du client insuffisant');

    check_receive_limit($recv['id'], $net, false);
    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,net_amount,receiver_amount,type,status,reference,description,cancel_deadline,channel,sender_currency,receiver_currency,currency) VALUES (?,?,?,?,?,?,'transfer','pending',?,?,?,?,?,?,?)",
          [$txid,$senderCustomer['wid'],$recv['wid'],$brut,$net,$net,$reference,'Envoi a un tiers via agent',$deadline,'national',$senderCurrency,$recvCurrency,$senderCurrency]);
        $rows = q("UPDATE wallets SET balance=balance-? WHERE id=? AND balance>=?",[$brut,$senderCustomer['wid'],$brut])->rowCount();
        if(!$rows) throw new Exception('Solde du client insuffisant');
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$net,$recv['wid']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);

        $fee_phone = '0160629502'; // Compte systeme ROM_MONEY
        if($fee > 0){
            $fee_recv = q("SELECT u.id,w.id wid,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$fee_phone])->fetch();
            if($fee_recv && $fee_recv['id'] !== $senderCustomer['id']){
                $fee_txid = uid(); $fee_ref = ref();
                $feeAccountCurrency = $fee_recv['currency'] ?: 'XOF';
                $feeConverted = $fee;
                if($feeAccountCurrency !== $senderCurrency){
                    $c = convert_currency($fee, $senderCurrency, $feeAccountCurrency);
                    if($c !== null) $feeConverted = round($c, 2);
                }
                q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'fee','completed',?,?)",
                  [$fee_txid,$senderCustomer['wid'],$fee_recv['wid'],$feeConverted,$fee_ref,'Frais ROM_MONEY 1% (envoi via agent)']);
                q("UPDATE wallets SET balance=balance+? WHERE id=?",[$feeConverted,$fee_recv['wid']]);
            }
        }
        apply_referral_bonus($senderCustomer['id'], $fee, $senderCurrency);
        db()->commit();
    } catch(Exception $e) {
        db()->rollBack();
        log_and_fail($e, "Echec de l'envoi", 500);
    }
    fraud_check_transaction($senderCustomer['wid'], $recipientPhone, $brut, $txid, $reference);
    web_push_send_to_user($recv['id'], 'ROM_MONEY',
        'Vous avez recu '.number_format($net,0,',',' ').' '.($recvCurrency==='XOF'||$recvCurrency==='XAF'?'F':$recvCurrency).' de '.($senderCustomer['verified_name']?:$senderCustomer['full_name']?:'un utilisateur'),
        [], 'credit');
    $newBal = (float)q("SELECT balance FROM wallets WHERE id=?",[$senderCustomer['wid']])->fetchColumn();
    return ['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$brut,'net_amount'=>$net,'fee'=>$fee,
        'recipient_name'=>$recv['verified_name']?:$recv['full_name'],'cancel_before'=>$deadline,
        'sender_new_balance'=>$newBal];
}

function agent_send_to_third_party() {
    $pl = agent_auth(); $b = body();
    $qr = trim($b['qr'] ?? '');
    $recipientPhone = trim($b['recipient_phone'] ?? '');
    $amount = (float)($b['amount'] ?? 0);
    $mode = ($b['mode'] ?? 'brut') === 'net' ? 'net' : 'brut';
    if(!$qr) fail('QR requis');
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $recipientPhone))) fail('Numero du destinataire invalide');
    if($amount<=0) fail('Montant invalide');
    $customer = agent_resolve_customer_by_qr($qr);
    if(empty($customer['verified_live'])) fail("Ce QR n'autorise pas un envoi immediat - utilisez le code envoye par SMS.", 422);
    $result = agent_execute_transfer($customer, $recipientPhone, $amount, $mode);
    ok($result, 'Envoi effectue');
}

// Etape 1/2 du chemin "numero manuel" (meme principe que
// agent_request_cash_out_code()) : valide tout en amont, envoie le code par
// SMS AU CLIENT (jamais a l'agent), et le SMS inclut le destinataire+frais
// pour que le client puisse verifier avant de communiquer le code.
function agent_request_send_to_third_party_code() {
    $pl = agent_auth(); $b = body();
    rate_limit_check('agent_transfer_request', 10, 60);
    $customerPhone = trim($b['customer_phone'] ?? '');
    $recipientPhone = trim($b['recipient_phone'] ?? '');
    $amount = (float)($b['amount'] ?? 0);
    $mode = ($b['mode'] ?? 'brut') === 'net' ? 'net' : 'brut';
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $customerPhone))) fail('Numero du client invalide');
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $recipientPhone))) fail('Numero du destinataire invalide');
    if($amount<=0) fail('Montant invalide');

    $customer = q("SELECT u.id,u.full_name,u.verified_name,w.id wid,w.balance,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$customerPhone])->fetch();
    if(!$customer) fail('Client introuvable',404);
    $recipient = q("SELECT u.id,u.full_name,u.verified_name,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$recipientPhone])->fetch();
    if(!$recipient) fail('Destinataire introuvable',404);
    if($recipient['id']===$customer['id']) fail('Envoi a soi-meme impossible');
    if(($recipient['currency']?:'XOF') !== ($customer['currency']?:'XOF')) fail("L'envoi a un tiers via un guichet agent doit se faire dans la meme devise.", 422);

    // Le montant BRUT (preleve reellement sur le client) est resolu et fige
    // ICI, quel que soit le mode tape par l'agent (brut ou net) - le meme
    // principe que pour le retrait : impossible de faire lire un code au
    // client pour un montant puis de l'executer pour un montant different.
    $amounts = agent_transfer_amounts($customer['wid'], $customer['currency']?:'XOF', $amount, $mode);
    $brut = $amounts['brut']; $net = $amounts['net']; $fee = $amounts['fee'];
    if($net<=0) fail('Montant invalide');
    if((float)$customer['balance'] < $brut) fail('Solde du client insuffisant');

    $code = str_pad((string)random_int(0, 9999), 4, '0', STR_PAD_LEFT);
    $id = uid();
    $expiresAt = date('Y-m-d H:i:s', time()+600);
    $cur = $customer['currency'] ?: 'XOF';
    $message = 'ROM_MONEY: code de confirmation pour un envoi de '.number_format($brut,0,',',' ').' '.$cur
        .' ('.number_format($net,0,',',' ').' '.$cur.' recus par le destinataire, '.number_format($fee,0,',',' ').' '.$cur.' de frais) vers '.$recipientPhone
        .' chez un agent : '.$code.'. Ne le partagez qu\'avec l\'agent en face de vous.';
    if(!send_sms_africastalking($customer['phone_number'] ?? $customerPhone, $message)) {
        fail('Envoi du SMS impossible, reessayez');
    }
    q("INSERT INTO agent_cashout_requests (id,agent_id,customer_user_id,customer_phone,amount,code,expires_at,request_type,recipient_phone) VALUES (?,?,?,?,?,?,?,'transfer',?)",
      [$id,$pl['sub'],$customer['id'],$customerPhone,$brut,$code,$expiresAt,$recipientPhone]);
    ok(['request_id'=>$id,'customer_name'=>$customer['verified_name']?:$customer['full_name'],
        'brut'=>$brut,'net'=>$net,'fee'=>$fee],'Code envoye au client');
}

// Etape 2/2 : fonction dediee separee de agent_confirm_cash_out() (plutot
// qu'un branchement interne) pour ne jamais risquer la fonction deja en
// production pour le retrait.
function agent_confirm_send_to_third_party() {
    $pl = agent_auth(); $b = body();
    $requestId = trim($b['request_id'] ?? '');
    $code = trim($b['code'] ?? '');
    if(!$requestId || !$code) fail('Demande et code requis');

    $r = q("SELECT * FROM agent_cashout_requests WHERE id=? AND agent_id=? AND status='pending' AND request_type='transfer'",[$requestId,$pl['sub']])->fetch();
    if(!$r) fail('Demande introuvable ou deja traitee',404);
    if(strtotime($r['expires_at']) < time()){
        q("UPDATE agent_cashout_requests SET status='expired' WHERE id=?",[$requestId]);
        fail('Code expire, refaites une demande');
    }
    if(!hash_equals($r['code'], $code)) fail('Code incorrect');

    $customer = q("SELECT u.id,u.full_name,u.verified_name,w.id wid,w.balance,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.id=?",[$r['customer_user_id']])->fetch();
    if(!$customer) fail('Client introuvable',404);

    $result = agent_execute_transfer($customer, $r['recipient_phone'], (float)$r['amount']);
    q("UPDATE agent_cashout_requests SET status='completed' WHERE id=?",[$requestId]);
    ok($result, 'Envoi effectue');
}

// Les commissions (type='agent_commission') sont exclues d'ici : trop
// nombreuses (une par operation) pour un historique general, remplacees par
// un ecran dedie "Gain" qui les regroupe par jour (voir
// agent_earnings_summary()). counterpart_agent_name resout le "distributeur
// ou Admin" pour une recharge de float (sender_agent_wallet_id NULL = credit
// direct Admin Principal, sinon le nom du distributeur qui a approuve) -
// avant ça, ces lignes affichaient "Client" par defaut cote frontend, ce qui
// n'avait aucun sens pour une recharge (aucun client implique).
function agent_tx_history() {
    $pl = agent_auth();
    $aw = q("SELECT id FROM agent_wallets WHERE agent_id=?",[$pl['sub']])->fetch();
    if(!$aw) fail('Portefeuille introuvable',404);
    $rows = q("SELECT t.*,
        CASE WHEN t.sender_agent_wallet_id=? THEN 'debit' ELSE 'credit' END as direction,
        cu.full_name customer_name, cu.phone_number customer_phone,
        ca.full_name counterpart_agent_name
        FROM transactions t
        LEFT JOIN wallets cw ON cw.id = COALESCE(t.sender_wallet_id, t.receiver_wallet_id)
        LEFT JOIN users cu ON cu.id = cw.user_id
        LEFT JOIN agent_wallets caw ON caw.id = (CASE WHEN t.receiver_agent_wallet_id=? THEN t.sender_agent_wallet_id ELSE t.receiver_agent_wallet_id END)
        LEFT JOIN agents ca ON ca.id = caw.agent_id
        WHERE (t.sender_agent_wallet_id=? OR t.receiver_agent_wallet_id=?) AND t.type != 'agent_commission'
        ORDER BY t.created_at DESC LIMIT 50",[$aw['id'],$aw['id'],$aw['id'],$aw['id']])->fetchAll();
    ok(['transactions'=>$rows]);
}

// Total cumule + detail par jour des commissions - remplace l'affichage
// d'une ligne par operation (illisible sur la duree) dans l'historique
// general. Fenetre limitee a 90 jours, largement suffisant pour un usage
// courant sans faire grossir la reponse indefiniment.
function agent_earnings_summary() {
    $pl = agent_auth();
    $aw = q("SELECT id FROM agent_wallets WHERE agent_id=?",[$pl['sub']])->fetch();
    if(!$aw) fail('Portefeuille introuvable',404);
    $total = (float)(q("SELECT COALESCE(SUM(amount),0) t FROM transactions
        WHERE receiver_agent_wallet_id=? AND type='agent_commission' AND status='completed'",[$aw['id']])->fetch()['t']??0);
    $days = q("SELECT created_at::date as day, SUM(amount) amount FROM transactions
        WHERE receiver_agent_wallet_id=? AND type='agent_commission' AND status='completed'
        AND created_at >= CURRENT_DATE - INTERVAL '90 days'
        GROUP BY created_at::date ORDER BY day DESC",[$aw['id']])->fetchAll();
    ok(['total'=>$total,'days'=>$days]);
}

// Envoi du gain (ou de n'importe quelle part du float, en pratique - l'ecran
// "Gain" n'est que le point d'entree) vers un compte personnel ROM_MONEY.
// Gratuit vers SON PROPRE numero (meme numero que le compte agent) ; 1% de
// frais sinon. Pas de franchise quotidienne comme tx_send() (ce n'est pas un
// transfert personnel client, juste un flux plus simple, tel que demande).
function agent_send_earnings() {
    $pl = agent_auth(); $b = body();
    $recipientPhone = trim($b['recipient_phone'] ?? '');
    $amount = (float)($b['amount'] ?? 0);
    $pin = trim($b['pin'] ?? '');
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $recipientPhone))) fail('Numero invalide');
    if($amount<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/', $pin)) fail('PIN invalide');

    $me = q("SELECT phone_number,pin_hash FROM agents WHERE id=?",[$pl['sub']])->fetch();
    agent_pin_check($pl['sub'], $pin, $me['pin_hash']);
    $aw = q("SELECT id,balance,currency FROM agent_wallets WHERE agent_id=?",[$pl['sub']])->fetch();
    if(!$aw) fail('Portefeuille introuvable',404);

    $recv = q("SELECT u.id,u.full_name,u.verified_name,w.id wid,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$recipientPhone])->fetch();
    if(!$recv) fail('Destinataire introuvable',404);
    if(($recv['currency']?:'XOF') !== ($aw['currency']?:'XOF')) fail("L'envoi doit se faire dans la meme devise que votre guichet.", 422);

    $isSelf = ($recipientPhone === $me['phone_number']);
    $brut = $amount;
    $fee = $isSelf ? 0 : round($brut * 0.01);
    $net = $brut - $fee;
    if($net<=0) fail('Montant invalide');
    if((float)$aw['balance'] < $brut) fail('Solde insuffisant');

    check_receive_limit($recv['id'], $net, false);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
        q("INSERT INTO transactions (id,sender_agent_wallet_id,receiver_wallet_id,amount,net_amount,type,status,reference,description,cancel_deadline,currency) VALUES (?,?,?,?,?,'agent_earnings_send','pending',?,?,?,?)",
          [$txid,$aw['id'],$recv['wid'],$brut,$net,$reference,'Envoi de gain via agent',$deadline,$aw['currency']]);
        $rows = q("UPDATE agent_wallets SET balance=balance-? WHERE id=? AND balance>=?",[$brut,$aw['id'],$brut])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$net,$recv['wid']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);

        if($fee > 0){
            $fee_recv = q("SELECT u.id,w.id wid,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",['0160629502'])->fetch();
            if($fee_recv){
                $fee_txid = uid(); $fee_ref = ref();
                q("INSERT INTO transactions (id,sender_agent_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'fee','completed',?,?)",
                  [$fee_txid,$aw['id'],$fee_recv['wid'],$fee,$fee_ref,'Frais ROM_MONEY 1% (envoi de gain agent)']);
                q("UPDATE wallets SET balance=balance+? WHERE id=?",[$fee,$fee_recv['wid']]);
            }
        }
        db()->commit();
    } catch(Exception $e) {
        db()->rollBack();
        log_and_fail($e, "Echec de l'envoi", 500);
    }
    web_push_send_to_user($recv['id'], 'ROM_MONEY',
        'Vous avez recu '.number_format($net,0,',',' ').' '.($aw['currency']==='XOF'||$aw['currency']==='XAF'?'F':$aw['currency']).' via un agent ROM_GUICHET.');
    $newBal = (float)q("SELECT balance FROM agent_wallets WHERE id=?",[$aw['id']])->fetchColumn();
    ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$brut,'net_amount'=>$net,'fee'=>$fee,
        'recipient_name'=>$recv['verified_name']?:$recv['full_name'],'new_balance'=>$newBal],'Envoi effectue');
}

// Demande de recharge du float, validee par l'admin (pas de credit direct) -
// meme state machine pending/approved/rejected que kyc_requests.
// Plus de ciblage d'un distributeur precis a la demande (retire - voir
// agent_list_incoming_recharge_requests() ci-dessous) : la seule vraie
// protection est le code de confirmation communique en personne, or
// l'admin pouvait deja approuver n'importe quelle demande sans etre cible
// (aucun controle de ciblage dans admin_agent_approve_recharge()) - incohe-
// rent avec le fait de restreindre les distributeurs a une seule demande
// choisie a l'avance. distributor_id reste sur la table mais n'est plus
// renseigne qu'A L'APPROBATION (par qui a effectivement servi la demande),
// jamais a la creation.
function agent_request_recharge() {
    $pl = agent_auth(); $b = body();
    // Meme limite que les autres demandes agent (cash-out-request,
    // send-to-third-party-request) : 10 tentatives par minute par compte.
    rate_limit_check('agent_recharge_request', 10, 60);
    $amount = (float)($b['amount'] ?? 0);
    $note = trim($b['note'] ?? '');
    if($amount<=0) fail('Montant invalide');
    // Une seule demande en attente a la fois : sinon deux codes differents
    // coexistent pour le meme agent, risque de confusion (mauvais code
    // communique) et de double recharge si les deux finissent approuvees.
    $existing = q("SELECT id FROM agent_recharge_requests WHERE agent_id=? AND status='pending'",[$pl['sub']])->fetch();
    if($existing) fail("Vous avez deja une demande de recharge en attente - attendez qu'elle soit traitee (ou refusee) avant d'en faire une nouvelle", 422);
    $id = uid();
    // Code a 6 chiffres que l'agent devra communiquer en personne (verbalement,
    // par appel...) a celui qui approuve - preuve d'un contact reel entre les
    // deux parties avant que l'argent ne bouge, jamais expose dans les listes.
    $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    q("INSERT INTO agent_recharge_requests (id,agent_id,amount,note,confirmation_code) VALUES (?,?,?,?,?)",[$id,$pl['sub'],$amount,$note?:null,$code]);
    ok(['id'=>$id,'confirmation_code'=>$code],'Demande de recharge envoyee');
}
// Annule automatiquement (avec raison) toute demande de recharge encore
// 'pending' passe 24h, pour la securite : un code de confirmation ne doit
// jamais rester utilisable indefiniment. Pas de tache planifiee dans ce
// projet - meme principe "verifie a l'usage" que agent_confirm_cash_out()
// pour agent_cashout_requests (expires_at, 10 min), applique ici a chaque
// point d'entree qui lit ou agit sur ces demandes.
// Le rejet manuel a ete retire (voir agent_reject_recharge_request() /
// admin_agent_reject_recharge(), supprimees) : cette expiration a 3h est
// desormais la SEULE facon dont une demande non traitee se termine, donc
// elle doit notifier l'agent (comme le faisait avant le rejet manuel) -
// sinon un agent ne saurait jamais que sa demande n'a pas abouti.
function agent_expire_stale_recharge_requests() {
    $stale = q("SELECT agent_id, amount FROM agent_recharge_requests WHERE status='pending' AND created_at < NOW() - INTERVAL '3 hours'")->fetchAll();
    if(!$stale) return;
    q("UPDATE agent_recharge_requests SET status='expired', reject_reason=?, reviewed_at=NOW()
       WHERE status='pending' AND created_at < NOW() - INTERVAL '3 hours'",
      ['Demande expiree automatiquement apres 3h sans traitement']);
    foreach($stale as $r){
        web_push_send_to_agent($r['agent_id'], 'ROM_GUICHET', 'Votre demande de recharge de '.number_format($r['amount'],0,',',' ').' a expire (non traitee dans les 3h).');
    }
}

function agent_recharge_history() {
    $pl = agent_auth();
    agent_expire_stale_recharge_requests();
    // confirmation_code inclus ici uniquement : c'est LE demandeur qui doit
    // pouvoir le retrouver pour le communiquer a celui qui approuve.
    // reference (uniquement renseignee une fois approuvee) sert de preuve
    // pour la comptabilite - contrairement au code, elle reste valable/utile
    // apres traitement.
    $rows = q("SELECT id,amount,note,status,created_at,reviewed_at,reject_reason,confirmation_code,reference FROM agent_recharge_requests WHERE agent_id=? ORDER BY created_at DESC",[$pl['sub']])->fetchAll();
    ok(['requests'=>$rows]);
}

// ── Hierarchie distributeurs ──
// File d'attente PARTAGEE entre tous les distributeurs (plus de ciblage a
// la demande) : n'importe quel distributeur peut servir n'importe quelle
// demande en attente, exactement comme l'admin pouvait deja le faire - le
// code de confirmation reste la seule vraie protection (preuve d'un contact
// reel avec le demandeur). Reserve aux comptes distributeur (sinon un agent
// normal pourrait voir les montants/noms de toutes les demandes du reseau).
function agent_list_incoming_recharge_requests() {
    $pl = agent_auth();
    $me = q("SELECT is_distributor FROM agents WHERE id=?",[$pl['sub']])->fetch();
    if(!$me || !$me['is_distributor']) fail("Vous n'etes pas enregistre comme distributeur", 403);
    agent_expire_stale_recharge_requests();
    $rows = q("SELECT r.id,r.amount,r.note,r.created_at,a.full_name,a.phone_number
        FROM agent_recharge_requests r JOIN agents a ON a.id=r.agent_id
        WHERE r.status='pending' AND r.agent_id!=? ORDER BY r.created_at ASC",[$pl['sub']])->fetchAll();
    ok(['requests'=>$rows]);
}

// Trace des propres operations du distributeur (ce qu'il a lui-meme
// approuve/rejete) - jusqu'ici totalement absent : un distributeur ne
// pouvait voir QUE sa file d'attente de demandes en cours, jamais un
// historique de ce qu'il avait deja traite.
function agent_distributor_history() {
    $pl = agent_auth();
    $me = q("SELECT is_distributor FROM agents WHERE id=?",[$pl['sub']])->fetch();
    if(!$me || !$me['is_distributor']) fail("Vous n'etes pas enregistre comme distributeur", 403);
    agent_expire_stale_recharge_requests();
    $rows = q("SELECT r.id,r.amount,r.note,r.status,r.created_at,r.reviewed_at,r.reject_reason,r.reference,a.full_name,a.phone_number
        FROM agent_recharge_requests r JOIN agents a ON a.id=r.agent_id
        WHERE r.distributor_id=? ORDER BY r.reviewed_at DESC LIMIT 100",[$pl['sub']])->fetchAll();
    ok(['requests'=>$rows]);
}

function agent_approve_recharge_request() {
    $pl = agent_auth(); $b = body();
    $id = trim($b['id'] ?? '');
    $code = trim($b['code'] ?? '');
    $pin = trim($b['pin'] ?? '');
    if(!$id) fail('Demande requise');
    if(!$code) fail('Code de confirmation requis');
    if(!preg_match('/^\d{4}$/', $pin)) fail('PIN invalide');
    $me = q("SELECT is_distributor,pin_hash FROM agents WHERE id=?",[$pl['sub']])->fetch();
    if(!$me || !$me['is_distributor']) fail("Vous n'etes pas enregistre comme distributeur", 403);
    // Le PIN du distributeur est redemande ICI, pas seulement a la connexion
    // (meme principe que requirePin() cote personnel/marchand) : c'est SON
    // argent qui sort de son float, une session deja ouverte ne suffit pas.
    agent_pin_check($pl['sub'], $pin, $me['pin_hash']);
    agent_expire_stale_recharge_requests();
    $r = q("SELECT * FROM agent_recharge_requests WHERE id=?",[$id])->fetch();
    if(!$r) fail('Demande introuvable',404);
    if($r['status'] === 'expired') fail('Cette demande a expire (plus de 3h sans traitement), le demandeur doit en refaire une', 410);
    if($r['status'] !== 'pending') fail('Cette demande a deja ete traitee');
    if($r['agent_id'] === $pl['sub']) fail('Vous ne pouvez pas approuver votre propre demande', 422);
    if(!hash_equals((string)$r['confirmation_code'], $code)) fail('Code de confirmation incorrect', 401);
    $distWallet = q("SELECT id,balance FROM agent_wallets WHERE agent_id=?",[$pl['sub']])->fetch();
    $reqWallet = q("SELECT id,balance FROM agent_wallets WHERE agent_id=?",[$r['agent_id']])->fetch();
    if(!$distWallet || !$reqWallet) fail('Portefeuille introuvable',404);
    if((float)$distWallet['balance'] < (float)$r['amount']) fail('Solde du distributeur insuffisant');
    // Meme plafond de float que admin_agent_approve_recharge() (protection
    // contre le risque qu'une trop grosse somme soit confiee d'un coup a un
    // distributeur) - sans ce controle ici, la file partagee permettait de
    // le contourner completement des qu'un AUTRE distributeur approuvait a
    // la place de l'admin.
    $targetAgent = q("SELECT is_distributor,max_float_cap FROM agents WHERE id=?",[$r['agent_id']])->fetch();
    if($targetAgent && $targetAgent['is_distributor'] && $targetAgent['max_float_cap'] !== null){
        $futureBalance = (float)$reqWallet['balance'] + (float)$r['amount'];
        if($futureBalance > (float)$targetAgent['max_float_cap']){
            fail('Ce montant depasserait le plafond de float autorise pour ce distributeur ('.$targetAgent['max_float_cap'].' XOF).', 422);
        }
    }
    // Genere AVANT le claim pour pouvoir l'enregistrer sur la demande
    // elle-meme (visible ensuite dans l'historique agent/distributeur pour
    // preuve/comptabilite - le code de confirmation n'a lui plus aucun
    // interet une fois la demande traitee).
    $txid = uid(); $reference = ref();
    db()->beginTransaction();
    // File d'attente partagee entre tous les distributeurs (plus de ciblage
    // a la demande) : ce "claim" atomique (UPDATE conditionne sur
    // status='pending') empeche deux distributeurs d'approuver la meme
    // demande en meme temps - sans ca, la seconde approbation debiterait un
    // distributeur pour une demande deja servie.
    $claimed = q("UPDATE agent_recharge_requests SET status='approved', distributor_id=?, reference=?, reviewed_at=NOW() WHERE id=? AND status='pending'",[$pl['sub'],$reference,$id])->rowCount();
    if(!$claimed){ db()->rollBack(); fail('Cette demande vient d\'etre traitee par quelqu\'un d\'autre', 409); }
    try {
        q("INSERT INTO transactions (id,sender_agent_wallet_id,receiver_agent_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'agent_recharge','completed',?,?)",
          [$txid,$distWallet['id'],$reqWallet['id'],$r['amount'],$reference,'Recharge via distributeur']);
        $rows = q("UPDATE agent_wallets SET balance=balance-? WHERE id=? AND balance>=?",[$r['amount'],$distWallet['id'],$r['amount']])->rowCount();
        if(!$rows) throw new Exception('Solde du distributeur insuffisant');
        q("UPDATE agent_wallets SET balance=balance+? WHERE id=?",[$r['amount'],$reqWallet['id']]);
        db()->commit();
        $bal = (float)q("SELECT balance FROM agent_wallets WHERE id=?",[$distWallet['id']])->fetchColumn();
        web_push_send_to_agent($r['agent_id'], 'ROM_GUICHET', 'Votre demande de recharge de '.number_format($r['amount'],0,',',' ').' a ete approuvee.');
        ok(['new_balance'=>$bal],'Recharge approuvee et creditee');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec de la recharge', 500); }
}

// ============================================================
// DETECTION DE FRAUDE — analyse chaque transaction APRES qu'elle soit
// executee (jamais avant : on ne bloque personne, cf decision produit).
// Trois signaux independants, chacun ajoute sa propre raison si declenche :
//  1) Velocite   : trop de transactions envoyees en peu de temps
//  2) Montant inhabituel : tres superieur a la moyenne habituelle de ce compte
//  3) Nouveau destinataire + montant eleve : jamais envoye a ce numero avant
// Les seuils sont modifiables par l'admin (Reglages) sans redeploiement.
// Toute erreur ici est avalee (try/catch) : la detection ne doit JAMAIS
// faire echouer un transfert qui a deja reussi.
// ============================================================
function fraud_check_transaction($senderWalletId, $receiverPhone, $amount, $txid, $reference) {
    try {
        $reasons = [];
        $senderCurrency = q("SELECT currency FROM wallets WHERE id=?",[$senderWalletId])->fetchColumn() ?: 'XOF';
        $curSuffix = ($senderCurrency==='XOF' || $senderCurrency==='XAF') ? 'F' : $senderCurrency;
        // Convertit un seuil defini en XOF (habitude admin actuelle) vers la
        // devise reelle de l'expediteur. Repli sur la valeur XOF telle quelle
        // si la conversion echoue (source de taux indisponible) : mieux vaut
        // une detection legerement imprecise que pas de detection du tout.
        $toSenderCurrency = function($xofValue) use ($senderCurrency) {
            if ($senderCurrency === 'XOF') return $xofValue;
            $c = convert_currency($xofValue, 'XOF', $senderCurrency);
            return $c !== null ? $c : $xofValue;
        };

        $velocityCount   = (int)get_setting('fraud_velocity_count', 5);
        $velocityMinutes = (int)get_setting('fraud_velocity_minutes', 10);
        $vc = q("SELECT COUNT(*) c FROM transactions
                 WHERE sender_wallet_id=? AND type='transfer' AND status='completed'
                 AND created_at > NOW() - (?::text || ' minutes')::interval",
                 [$senderWalletId, $velocityMinutes])->fetch();
        if ($vc && (int)$vc['c'] >= $velocityCount) {
            $reasons[] = (int)$vc['c']." transactions en {$velocityMinutes} min (seuil: {$velocityCount})";
        }

        $unusualMultiplier = (float)get_setting('fraud_unusual_multiplier', 5);
        $unusualMinAmount  = $toSenderCurrency((float)get_setting('fraud_unusual_min_amount', 20000));
        if ($amount >= $unusualMinAmount) {
            $avgRow = q("SELECT AVG(amount) a, COUNT(*) c FROM (
                            SELECT amount FROM transactions
                            WHERE sender_wallet_id=? AND type='transfer' AND status='completed' AND id!=?
                            ORDER BY created_at DESC LIMIT 20
                         ) sub", [$senderWalletId, $txid])->fetch();
            if ($avgRow && (int)$avgRow['c'] >= 3 && (float)$avgRow['a'] > 0) {
                $avg = (float)$avgRow['a'];
                if ($amount >= $avg * $unusualMultiplier) {
                    $reasons[] = 'Montant '.number_format($amount,0,',',' ').' '.$curSuffix.', tres superieur a la moyenne habituelle ('.number_format($avg,0,',',' ').' '.$curSuffix.')';
                }
            }
        }

        $newRecipientMin = $toSenderCurrency((float)get_setting('fraud_new_recipient_min_amount', 50000));
        if ($amount >= $newRecipientMin) {
            $prior = q("SELECT COUNT(*) c FROM transactions t
                        JOIN wallets rw ON rw.id=t.receiver_wallet_id
                        JOIN users ru ON ru.id=rw.user_id
                        WHERE t.sender_wallet_id=? AND ru.phone_number=? AND t.status='completed' AND t.id!=?",
                        [$senderWalletId, $receiverPhone, $txid])->fetch();
            if ($prior && (int)$prior['c'] === 0) {
                $reasons[] = 'Premier envoi a ce destinataire, montant eleve ('.number_format($amount,0,',',' ').' '.$curSuffix.')';
            }
        }

        if (!empty($reasons)) {
            $senderPhone = q("SELECT u.phone_number FROM users u JOIN wallets w ON w.user_id=u.id WHERE w.id=?",[$senderWalletId])->fetchColumn();
            q("INSERT INTO fraud_alerts (transaction_id,reference,sender_phone,receiver_phone,amount,reasons,currency) VALUES (?,?,?,?,?,?,?)",
              [$txid, $reference, $senderPhone, $receiverPhone, $amount, implode(' | ', $reasons), $senderCurrency]);
        }
    } catch (Exception $e) { /* la detection ne doit jamais casser un transfert deja reussi */ }
}

// Frais preleves sur ce que le MARCHAND recoit (jamais sur ce que paie le
// client, ni un autre marchand qui le paie a distance) : gratuit jusqu'a un
// cumul quotidien par marchand receveur, puis un taux configurable sur la
// partie qui depasse ce seuil. Meme principe que le plafond quotidien des
// virements personnels (tx_send()), applique ici cote reception plutot
// qu'envoi. Reutilise dans merchant_collect(), tx_pay_merchant() et
// merchant_pay_merchant().
function merchant_receive_fee($merchantWalletId, $amount){
    $rate = (float)get_setting('fee_rate_merchant', 0.01);
    $threshold = (float)get_setting('fee_free_threshold_merchant_daily', 25000); // toujours exprime en XOF
    $merchantCurrency = q("SELECT currency FROM merchant_wallets WHERE id=?",[$merchantWalletId])->fetchColumn() ?: 'XOF';
    // Le cumul du jour doit etre dans la meme devise que $amount (celle du
    // marchand) : receiver_amount est deja le montant reellement credite au
    // marchand pour chaque paiement passe, contrairement a amount qui reste
    // dans la devise de CHAQUE client d'origine et ne peut pas etre additionne
    // directement d'une ligne a l'autre.
    $receivedToday = (float)(q("SELECT COALESCE(SUM(COALESCE(receiver_amount,net_amount,amount)),0) t FROM transactions
        WHERE receiver_merchant_wallet_id=? AND type='merchant_payment' AND status='completed'
        AND created_at::date=CURRENT_DATE",[$merchantWalletId])->fetch()['t']??0);
    // Le seuil de gratuite est un reglage global exprime en XOF - pour un
    // marchand dans une autre devise, on convertit le cumul du jour et le
    // montant courant en XOF le temps de la comparaison au seuil, puis on
    // reconvertit le frais resultant dans la devise du marchand.
    $receivedTodayXof = $receivedToday; $amountXof = $amount;
    if($merchantCurrency !== 'XOF'){
        $r = convert_currency($receivedToday, $merchantCurrency, 'XOF');
        $a = convert_currency($amount, $merchantCurrency, 'XOF');
        if($r === null || $a === null) fail('Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
        $receivedTodayXof = $r; $amountXof = $a;
    }
    $remainingFreeXof = max(0, $threshold - $receivedTodayXof);
    $feeableXof = max(0, $amountXof - $remainingFreeXof);
    $feeXof = $feeableXof * $rate;
    $fee = $feeXof;
    if($merchantCurrency !== 'XOF'){
        $f = convert_currency($feeXof, 'XOF', $merchantCurrency);
        if($f === null) fail('Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
        $fee = $f;
    }
    $fee = round($fee);
    return ['fee'=>$fee, 'net'=>$amount-$fee];
}
// Credite le compte systeme ROM_MONEY du frais preleve sur un encaissement
// marchand - meme compte systeme que les frais de virement personnel
// (0160629502), meme table transactions (type='fee') pour rester coherent
// avec le reste de la comptabilite. sender_merchant_wallet_id (pas
// sender_wallet_id) puisque c'est bien un marchand qui "paie" ce frais,
// preleve sur ce qu'il vient de recevoir.
function credit_merchant_fee($merchantWalletId, $fee, $label){
    if($fee <= 0) return;
    $fee_recv = q("SELECT u.id,w.id wid,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",['0160629502'])->fetch();
    if(!$fee_recv) return;
    // $fee est calcule dans la devise du MARCHAND (merchant_wallets.currency) -
    // plus forcement XOF depuis que les marchands choisissent leur pays a
    // l'inscription. Il faut donc convertir vers la devise du compte systeme
    // si elles different, au lieu de supposer XOF des deux cotes (une
    // hypothese fausse silencieusement creditait/detruisait de la valeur).
    $merchantCurrency = q("SELECT currency FROM merchant_wallets WHERE id=?",[$merchantWalletId])->fetchColumn() ?: 'XOF';
    $feeAccountCurrency = $fee_recv['currency'] ?: 'XOF';
    $feeConverted = $fee;
    if($feeAccountCurrency !== $merchantCurrency){
        $c = convert_currency($fee, $merchantCurrency, $feeAccountCurrency);
        if($c === null) throw new Exception('Conversion de devise momentanement indisponible (frais marchand)');
        $feeConverted = round($c, 2);
    }
    $fee_txid = uid(); $fee_ref = ref();
    q("INSERT INTO transactions (id,sender_merchant_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'fee','completed',?,?)",
      [$fee_txid,$merchantWalletId,$fee_recv['wid'],$feeConverted,$fee_ref,$label]);
    q("UPDATE wallets SET balance=balance+? WHERE id=?",[$feeConverted,$fee_recv['wid']]);
}

// Equivalent de fraud_check_transaction() cote encaissement marchand
// (merchant_collect() et tx_pay_merchant()). Pas de verification "nouveau
// destinataire" ici : un marchand encaisse legitimement de nouveaux clients
// en permanence, ce serait juste du bruit. Reutilise la meme table
// fraud_alerts (vue unifiee admin, cote client=sender_phone, cote
// marchand=receiver_phone) plutot qu'une table separee.
function fraud_check_merchant_transaction($merchantWalletId, $payerPhone, $amount, $txid, $reference, $merchantPhone) {
    try {
        $reasons = [];
        $currency = q("SELECT currency FROM merchant_wallets WHERE id=?",[$merchantWalletId])->fetchColumn() ?: 'XOF';
        $curSuffix = ($currency==='XOF' || $currency==='XAF') ? 'F' : $currency;

        $velocityCount   = (int)get_setting('fraud_merchant_velocity_count', 15);
        $velocityMinutes = (int)get_setting('fraud_merchant_velocity_minutes', 10);
        $vc = q("SELECT COUNT(*) c FROM transactions
                 WHERE receiver_merchant_wallet_id=? AND type='merchant_payment' AND status='completed'
                 AND created_at > NOW() - (?::text || ' minutes')::interval",
                 [$merchantWalletId, $velocityMinutes])->fetch();
        if ($vc && (int)$vc['c'] >= $velocityCount) {
            $reasons[] = (int)$vc['c']." paiements en {$velocityMinutes} min (seuil: {$velocityCount})";
        }

        $unusualMultiplier = (float)get_setting('fraud_merchant_unusual_multiplier', 6);
        $unusualMinAmount  = (float)get_setting('fraud_merchant_unusual_min_amount', 30000);
        if ($amount >= $unusualMinAmount) {
            $avgRow = q("SELECT AVG(amount) a, COUNT(*) c FROM (
                            SELECT amount FROM transactions
                            WHERE receiver_merchant_wallet_id=? AND type='merchant_payment' AND status='completed' AND id!=?
                            ORDER BY created_at DESC LIMIT 20
                         ) sub", [$merchantWalletId, $txid])->fetch();
            if ($avgRow && (int)$avgRow['c'] >= 3 && (float)$avgRow['a'] > 0) {
                $avg = (float)$avgRow['a'];
                if ($amount >= $avg * $unusualMultiplier) {
                    $reasons[] = 'Montant '.number_format($amount,0,',',' ').' '.$curSuffix.', tres superieur a la moyenne habituelle de ce marchand ('.number_format($avg,0,',',' ').' '.$curSuffix.')';
                }
            }
        }

        if (!empty($reasons)) {
            q("INSERT INTO fraud_alerts (transaction_id,reference,sender_phone,receiver_phone,amount,reasons,currency) VALUES (?,?,?,?,?,?,?)",
              [$txid, $reference, $payerPhone, $merchantPhone, $amount, implode(' | ', $reasons), $currency]);
        }
    } catch (Exception $e) { /* la detection ne doit jamais casser un encaissement deja reussi */ }
}

function tx_send() {
    $pl = auth(); $b = body();
    $to     = trim($b['receiver_phone']??'');
    $amount = (float)($b['amount']??0);
    $mode   = ($b['mode']??'net')==='brut' ? 'brut' : 'net'; // default 'net' for backward compatibility
    $channel= ($b['channel']??'national')==='africa' ? 'africa' : 'national';
    $pin = trim($b['pin']??'');
    $desc= trim($b['description']??'');
    if(!preg_match('/^\+?[0-9]{8,15}$/',preg_replace('/[\s\-]/','', $to))) fail('Numero invalide');
    if($amount<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/',$pin)) fail('PIN invalide');
    $user = q("SELECT pin_hash,country,full_name FROM users WHERE id=?",[$pl['sub']])->fetch();
    pin_check($pl['sub'], $pin, $user['pin_hash']);

    $recv = q("SELECT u.id,u.full_name,u.verified_name,u.country,w.id wid,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$to])->fetch();
    if(!$recv) fail('Destinataire introuvable');
    if($recv['id']===$pl['sub']) fail('Envoi a soi-meme impossible');

    // Le canal "national" (bouton Envoyer classique) est reserve aux envois
    // a l'interieur du meme pays. Un envoi vers un autre pays doit passer
    // par Transfert Afrique (channel=africa), qui applique le vrai tarif
    // international - ca ferme la possibilite de contourner ce tarif en
    // utilisant simplement le bouton d'envoi national.
    if($channel==='national' && $user['country'] && $recv['country'] && $user['country']!==$recv['country']){
        fail('CROSS_COUNTRY: Ce destinataire est dans un autre pays ('.$recv['country'].'). Utilise Transfert Afrique pour cet envoi.', 422);
    }

    $sw = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();

    // Calcul du frais : national = taux configurable avec gratuite sous seuil
    // configurable. Africa = taux configurable sans palier de gratuite,
    // aligne par defaut sur le tarif international reel de Wave (verifie).
    $rateNational = (float)get_setting('fee_rate_national', 0.01);
    $freeThreshold = (float)get_setting('fee_free_threshold_national', 4000);
    $rateAfrica = (float)get_setting('fee_rate_africa', 0.015);
    if($channel==='africa'){
        if($mode==='brut'){
            $brut = $amount;
            $fee  = round($brut * $rateAfrica);
            $net  = $brut - $fee;
        } else {
            $net  = $amount;
            $fee  = round($net * $rateAfrica);
            $brut = $net + $fee;
        }
    } else {
        // La gratuite sous le seuil est CUMULEE par jour et par expediteur,
        // pas par transaction : sans ca, il suffit de fractionner un gros
        // virement en plusieurs petits (ex: 10x 2000 F au lieu de 20000 F
        // d'un coup) pour ne jamais payer de frais, ce qui cree une perte de
        // revenu pour ROM_MONEY. On calcule donc d'abord ce qu'il reste de
        // "gratuit" aujourd'hui, puis seule la partie qui depasse ce reliquat
        // est facturee au taux normal.
        $sentTodayNational = (float)(q("SELECT COALESCE(SUM(amount),0) t FROM transactions
            WHERE sender_wallet_id=? AND type='transfer' AND channel='national' AND status='completed'
            AND created_at::date=CURRENT_DATE",[$sw['id']])->fetch()['t']??0);
        // Le seuil de gratuite (fee_free_threshold_national) est un reglage
        // global exprime en XOF - "national" n'exige que le meme pays, pas
        // XOF (deux comptes au Ghana en GHS par exemple), il faut donc
        // convertir le cumul du jour en XOF le temps de la comparaison puis
        // reconvertir le reliquat gratuit dans la devise de l'expediteur -
        // meme principe que merchant_receive_fee().
        $senderCurrencyForThreshold = $sw['currency'] ?: 'XOF';
        if($senderCurrencyForThreshold === 'XOF'){
            $remainingFree = max(0, $freeThreshold - $sentTodayNational);
        } else {
            $sentTodayXof = convert_currency($sentTodayNational, $senderCurrencyForThreshold, 'XOF');
            if($sentTodayXof === null) fail('Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
            $remainingFreeXof = max(0, $freeThreshold - $sentTodayXof);
            $remainingFree = $remainingFreeXof;
            if($remainingFreeXof > 0){
                $rf = convert_currency($remainingFreeXof, 'XOF', $senderCurrencyForThreshold);
                if($rf === null) fail('Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
                $remainingFree = $rf;
            }
        }
        if($mode==='brut'){
            $brut = $amount;
            $feeable = max(0, $brut - $remainingFree);
            $fee  = round($feeable * $rateNational);
            $net  = $brut - $fee;
        } else {
            $net = $amount;
            if($net <= $remainingFree){
                $brut = $net; $fee = 0;
            } else {
                // Au-dela du reliquat gratuit, resout le brut necessaire pour
                // que (brut - frais_sur_la_partie_taxable) = net demande.
                $brut = round(($net - $rateNational*$remainingFree) / (1-$rateNational));
                $feeable = max(0, $brut - $remainingFree);
                $fee = round($feeable * $rateNational);
                $net = $brut - $fee; // recalcule depuis le brut/frais arrondis, pour rester coherent au franc pres
            }
        }
    }
    if($net<=0) fail('Montant invalide');

    if((float)$sw['balance']<$brut) fail('Solde insuffisant');

    // ── CONVERSION DE DEVISE (Transfert Afrique, pays a devises differentes) ──
    // $net (calcule ci-dessus) est dans la devise de L'EXPEDITEUR - c'est ce
    // qu'il paie reellement, frais deja retires. Si le destinataire est dans
    // un pays a devise differente, on convertit ce montant vers SA devise
    // avant de le crediter, puis on applique la marge de change (revenu
    // additionnel, distinct des frais de transfert) reglable dans Reglages.
    // Le taux effectif utilise est fige sur la transaction elle-meme : il ne
    // doit JAMAIS etre recalcule apres coup, meme si les taux de marche
    // bougent ensuite (traçabilite et equite envers l'utilisateur).
    $senderCurrency = $sw['currency'] ?: 'XOF';
    $receiverCurrency = $recv['currency'] ?: 'XOF';
    $fxRateApplied = null;
    if($channel==='africa' && $senderCurrency !== $receiverCurrency){
        $converted = convert_currency($net, $senderCurrency, $receiverCurrency);
        if($converted === null){
            fail('Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
        }
        $fxMargin = (float)get_setting('fx_margin_rate', 0.01);
        $receiverAmount = round($converted * (1 - $fxMargin), 2);
        $fxRateApplied = $net > 0 ? $receiverAmount / $net : null;
    } else {
        $receiverAmount = $net;
    }

    check_receive_limit($recv['id'], $receiverAmount, false);
    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        // Record the BRUT amount as the transaction amount (this is what sender sees deducted)
        q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,net_amount,type,status,reference,description,cancel_deadline,channel,sender_currency,receiver_currency,fx_rate_applied,receiver_amount) VALUES (?,?,?,?,?,'transfer','pending',?,?,?,?,?,?,?,?)",
          [$txid,$sw['id'],$recv['wid'],$brut,$net,$reference,$desc?:null,$deadline,$channel,$senderCurrency,$receiverCurrency,$fxRateApplied,$receiverAmount]);
        $rows = q("UPDATE wallets SET balance=balance-? WHERE id=? AND balance>=?",[$brut,$sw["id"],$brut])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        // Le destinataire recoit receiverAmount, dans SA devise (identique a
        // $net si meme devise que l'expediteur, converti+marge sinon).
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$receiverAmount,$recv['wid']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);

        // ── Transfer fees to ROM_MONEY system account
        $fee_phone = '0160629502'; // ROM_MONEY system account
        $fee_recv = null;
        if($fee > 0 || $fxRateApplied !== null){
            $fee_recv = q("SELECT u.id,w.id wid,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$fee_phone])->fetch();
        }
        if($fee > 0 && $fee_recv && $fee_recv['id'] !== $pl['sub']){
            $fee_txid = uid(); $fee_ref = ref();
            $feeLabel = $channel==='africa' ? 'Frais ROM_MONEY 1.5% (Transfert Afrique)' : 'Frais ROM_MONEY 1%';
            // $fee est dans la devise de l'expediteur ($senderCurrency) : il faut
            // le convertir vers la devise du compte systeme avant de le crediter,
            // sinon un transfert international credite un montant faux (meme
            // correctif deja applique plus bas a la marge de change).
            $feeAccountCurrency = $fee_recv['currency'] ?: 'XOF';
            $feeConverted = $fee;
            if($feeAccountCurrency !== $senderCurrency){
                $c = convert_currency($fee, $senderCurrency, $feeAccountCurrency);
                if($c !== null) $feeConverted = round($c, 2);
            }
            q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'fee','completed',?,?)",
              [$fee_txid,$sw['id'],$fee_recv['wid'],$feeConverted,$fee_ref,$feeLabel]);
            q("UPDATE wallets SET balance=balance+? WHERE id=?",[$feeConverted,$fee_recv['wid']]);
        }
        // ── Marge de change (revenu distinct des frais de transfert) : avant
        // ce correctif, elle etait simplement perdue - jamais creditee nulle
        // part. $converted (calcule plus haut, avant application de la
        // marge) moins $receiverAmount = ce que la marge represente, dans la
        // devise du DESTINATAIRE. On la convertit vers la devise du compte
        // systeme avant de la crediter, avec son propre enregistrement pour
        // que ce revenu soit visible separement des frais de transfert dans
        // la comptabilite.
        if($fxRateApplied !== null && $fee_recv && $fee_recv['id'] !== $pl['sub']){
            $marginInReceiverCurrency = round($converted - $receiverAmount, 2);
            if($marginInReceiverCurrency > 0){
                $feeAccountCurrency = $fee_recv['currency'] ?: 'XOF';
                $marginConverted = $marginInReceiverCurrency;
                if($feeAccountCurrency !== $receiverCurrency){
                    $c = convert_currency($marginInReceiverCurrency, $receiverCurrency, $feeAccountCurrency);
                    if($c !== null) $marginConverted = round($c, 2);
                }
                if($marginConverted > 0){
                    $fxTxid = uid(); $fxRef = ref();
                    q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'fx_margin','completed',?,?)",
                      [$fxTxid,$sw['id'],$fee_recv['wid'],$marginConverted,$fxRef,'Marge de change (Transfert Afrique '.$senderCurrency.'->'.$receiverCurrency.')']);
                    q("UPDATE wallets SET balance=balance+? WHERE id=?",[$marginConverted,$fee_recv['wid']]);
                }
            }
        }
        apply_referral_bonus($pl['sub'], $fee, $senderCurrency);

        db()->commit();

        fraud_check_transaction($sw['id'], $to, $brut, $txid, $reference);

        web_push_send_to_user($recv['id'], 'ROM_MONEY',
            'Vous avez recu '.number_format($receiverAmount,0,',',' ').' '.($receiverCurrency==='XOF'||$receiverCurrency==='XAF'?'F':$receiverCurrency).' de '.($user['full_name']?:'un utilisateur'),
            [], 'credit');

        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$brut,'net_amount'=>$net,'fee'=>$fee,
            'receiver_name'=>$recv['verified_name']?:$recv['full_name'],'cancel_before'=>$deadline,
            'new_balance'=>(float)$sw['balance']-$brut,
            'receiver_amount'=>$receiverAmount,'receiver_currency'=>$receiverCurrency,
            'sender_currency'=>$senderCurrency,'fx_rate_applied'=>$fxRateApplied],'Transfert effectue');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec transfert', 500); }
}

// Used by "Encaisser": the merchant (authenticated via token) scans a payer's QR
// (phone number only) and the payer types their own PIN on the merchant's device.
// Unlike tx_send, the debited party here is identified by phone number (the payer),
// NOT by the bearer token (which belongs to the merchant/receiver).
function tx_collect() {
    $pl = auth(); $b = body(); // $pl = merchant (authenticated caller, will be credited)
    $payerPhone = trim($b['payer_phone']??'');
    $amount = (float)($b['amount']??0);
    $mode   = ($b['mode']??'net')==='brut' ? 'brut' : 'net';
    $pin    = trim($b['pin']??'');
    $desc   = trim($b['description']??'');
    if(!preg_match('/^\+?[0-9]{8,15}$/',preg_replace('/[\s\-]/','', $payerPhone))) fail('Numero invalide');
    if($amount<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/',$pin)) fail('PIN invalide');

    $payer = q("SELECT u.id,u.full_name,u.verified_name,u.pin_hash,w.id wid,w.balance,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$payerPhone])->fetch();
    if(!$payer) fail('Payeur introuvable');
    if($payer['id']===$pl['sub']) fail('Encaissement de soi-meme impossible');

    // PIN is verified against the PAYER's own account (not the merchant's), with
    // anti-bruteforce lockout since this account is identified by phone, not by token.
    pin_check($payer['id'], $pin, $payer['pin_hash']);

    $rateNational = (float)get_setting('fee_rate_national', 0.01);
    $freeThreshold = (float)get_setting('fee_free_threshold_national', 4000);
    // Seuil global exprime en XOF - convertir le montant du payeur en XOF le
    // temps de la comparaison si sa devise n'est pas XOF (meme principe que
    // tx_send()/merchant_receive_fee()).
    $payerCurrencyForThreshold = $payer['currency'] ?: 'XOF';
    if($mode==='brut'){
        $brut = $amount;
        $brutXof = $brut;
        if($payerCurrencyForThreshold !== 'XOF'){
            $bx = convert_currency($brut, $payerCurrencyForThreshold, 'XOF');
            if($bx === null) fail('Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
            $brutXof = $bx;
        }
        $fee  = ($brutXof >= $freeThreshold) ? round($brut * $rateNational) : 0;
        $net  = $brut - $fee;
    } else {
        $net  = $amount;
        $netXof = $net;
        if($payerCurrencyForThreshold !== 'XOF'){
            $nx = convert_currency($net, $payerCurrencyForThreshold, 'XOF');
            if($nx === null) fail('Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
            $netXof = $nx;
        }
        $fee  = ($netXof >= $freeThreshold) ? round($net * $rateNational) : 0;
        $brut = $net + $fee;
    }
    if($net<=0) fail('Montant invalide');
    if((float)$payer['balance'] < $brut) fail('Solde du payeur insuffisant');

    $mw = q("SELECT id,currency FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    if(!$mw) fail('Wallet marchand introuvable');

    // Le payeur et le collecteur peuvent etre dans des devises differentes -
    // convertir le montant credite (net) AVANT de verifier le plafond de
    // reception (deja exprime dans la devise du collecteur par
    // check_receive_limit()) et avant de crediter son solde. Sans ca, un
    // collecteur GHS qui encaisse un payeur XOF recevait le meme CHIFFRE
    // directement en GHS, une distorsion de valeur enorme (meme bug que
    // celui deja corrige sur le circuit marchand ROM_BUSINESS).
    $payerCurrency = $payer['currency'] ?: 'XOF';
    $collectorCurrency = $mw['currency'] ?: 'XOF';
    $netInCollectorCurrency = $net;
    $fxRateApplied = null;
    if($payerCurrency !== $collectorCurrency){
        $converted = convert_currency($net, $payerCurrency, $collectorCurrency);
        if($converted === null) fail('Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
        $netInCollectorCurrency = round($converted, 2);
        $fxRateApplied = $net > 0 ? $netInCollectorCurrency / $net : null;
    }
    check_receive_limit($pl['sub'], $netInCollectorCurrency);

    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,net_amount,receiver_amount,fx_rate_applied,type,status,reference,description,cancel_deadline) VALUES (?,?,?,?,?,?,?,'transfer','pending',?,?,?)",
          [$txid,$payer['wid'],$mw['id'],$brut,$net,$netInCollectorCurrency,$fxRateApplied,$reference,$desc?:null,$deadline]);
        $rows = q("UPDATE wallets SET balance=balance-? WHERE id=? AND balance>=?",[$brut,$payer['wid'],$brut])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$netInCollectorCurrency,$mw['id']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);

        $fee_phone = '0160629502';
        if($fee > 0){
            $fee_recv = q("SELECT u.id,w.id wid,w.currency FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$fee_phone])->fetch();
            if($fee_recv && $fee_recv['id'] !== $payer['id']){
                $fee_txid = uid(); $fee_ref = ref();
                // $fee est dans la devise du payeur : conversion vers la devise du
                // compte systeme avant credit (meme logique que tx_send).
                $payerCurrency = $payer['currency'] ?: 'XOF';
                $feeAccountCurrency = $fee_recv['currency'] ?: 'XOF';
                $feeConverted = $fee;
                if($feeAccountCurrency !== $payerCurrency){
                    $c = convert_currency($fee, $payerCurrency, $feeAccountCurrency);
                    if($c !== null) $feeConverted = round($c, 2);
                }
                q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'fee','completed',?,'Frais ROM_MONEY 1%')",
                  [$fee_txid,$payer['wid'],$fee_recv['wid'],$feeConverted,$fee_ref]);
                q("UPDATE wallets SET balance=balance+? WHERE id=?",[$feeConverted,$fee_recv['wid']]);
            }
        }
        apply_referral_bonus($payer['id'], $fee, $payer['currency'] ?: 'XOF');

        db()->commit();

        $merchantPhone = q("SELECT phone_number FROM users WHERE id=?",[$pl['sub']])->fetchColumn();
        fraud_check_transaction($payer['wid'], $merchantPhone, $brut, $txid, $reference);

        web_push_send_to_user($pl['sub'], 'ROM_MONEY',
            'Vous avez recu '.number_format($netInCollectorCurrency,0,',',' ').' '.($collectorCurrency==='XOF'||$collectorCurrency==='XAF'?'F':$collectorCurrency).' de '.($payer['full_name']?:'un client'),
            [], 'credit');

        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$brut,'net_amount'=>$net,'fee'=>$fee,
            'receiver_amount'=>$netInCollectorCurrency,'receiver_currency'=>$collectorCurrency,
            'payer_name'=>$payer['verified_name']?:$payer['full_name'],'cancel_before'=>$deadline],'Encaissement effectue');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec encaissement', 500); }
}

function tx_cancel() {
    $pl = auth(); $b = body();
    $txid = trim($b['transaction_id']??'');
    $pin  = trim($b['pin']??'');
    if(!$txid) fail('ID requis');
    if(!preg_match('/^\d{4}$/',$pin)) fail('PIN invalide');
    $user = q("SELECT pin_hash FROM users WHERE id=?",[$pl['sub']])->fetch();
    pin_check($pl['sub'], $pin, $user['pin_hash']);
    $tx = q("SELECT t.*,w.user_id sender_uid FROM transactions t JOIN wallets w ON t.sender_wallet_id=w.id WHERE t.id=?",[$txid])->fetch();
    if(!$tx) fail('Transaction introuvable',404);
    if($tx['sender_uid']!==$pl['sub']) fail('Non autorise',403);
    if($tx['status']!=='completed') fail('Transaction non annulable');
    if($tx['cancelled_at']) fail('Deja annulee');
    if(strtotime($tx['cancel_deadline']??'0')<time()) fail('Delai annulation depasse');
    // Un paiement marchand ne peut PAS etre auto-annule par le client : (1) le
    // "receiver" est un merchant_wallet, pas un wallet - la logique ci-dessous
    // ne le debiterait jamais, ce qui creerait de l'argent (client rembourse
    // + marchand garde sa recette) ; (2) meme corrige techniquement, un
    // client ne doit pas pouvoir recuperer seul l'argent d'un achat deja
    // livre/consomme (fraude "achat puis auto-remboursement"). Seul un admin,
    // avec raison journalisee, peut annuler un paiement marchand.
    if($tx['type']==='merchant_payment'){
        fail('Un paiement marchand ne peut pas etre annule directement. Contactez le support.');
    }
    // Meme protection que l'annulation admin : si le destinataire a deja
    // depense cet argent (ou une partie), reprendre le montant integral
    // ferait passer son solde en negatif. On refuse plutot que de risquer ca.
    if($tx['type']==='transfer' && $tx['receiver_wallet_id']){
        $receiverWallet = q("SELECT balance FROM wallets WHERE id=?",[$tx['receiver_wallet_id']])->fetch();
        if(!$receiverWallet || (float)$receiverWallet['balance'] < (float)$tx['amount']){
            fail('Le destinataire a deja utilise une partie de ces fonds : annulation impossible automatiquement. Contactez le support.');
        }
    }
    db()->beginTransaction();
    try {
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$tx['amount'],$tx['sender_wallet_id']]);
        if($tx['type']==='transfer' && $tx['receiver_wallet_id'])
            q("UPDATE wallets SET balance=balance-? WHERE id=?",[$tx['amount'],$tx['receiver_wallet_id']]);
        q("UPDATE transactions SET status='cancelled',cancelled_at=NOW(),cancel_reason='user_request' WHERE id=?",[$txid]);
        db()->commit();
        $bal = (float)q("SELECT balance FROM wallets WHERE id=?",[$tx['sender_wallet_id']])->fetchColumn();
        ok(['refunded'=>(float)$tx['amount'],'new_balance'=>$bal],'Transaction annulee');
    } catch(Exception $e) { db()->rollBack(); fail('Echec annulation',500); }
}

// ag_s/ag_r (agents, via agent_wallets) resolvent le nom d'un agent
// ROM_GUICHET comme contrepartie - sans ca, un depot/retrait via agent ou un
// envoi de gain (sender_agent_wallet_id/receiver_agent_wallet_id, jamais un
// wallet personnel ni marchand) tombait dans aucune des jointures
// existantes : "Inconnu" cote credit, le champ description brut affiche a
// la place d'un nom cote debit (et le type de l'operation retombait sur la
// categorie generique par defaut cote frontend, voir txCatKey()/mapHistoryTx()).
function tx_history() {
    $pl  = auth();
    $page = max(1,(int)($_GET['page']??1));
    $lim  = min(50,max(5,(int)($_GET['limit']??20)));
    $fil  = $_GET['filter']??'all';
    $off  = ($page-1)*$lim;
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();
    $where = "WHERE (t.sender_wallet_id=? OR t.receiver_wallet_id=?) AND t.type!='fee'";
    $params = [$wid,$wid];
    if($fil==='credit'){$where.=" AND t.receiver_wallet_id=? AND t.status='completed'";$params[]=$wid;}
    elseif($fil==='debit'){$where.=" AND t.sender_wallet_id=? AND t.status='completed'";$params[]=$wid;}
    elseif($fil==='cancelled'){$where.=" AND t.status='cancelled'";}
    $txs = db()->prepare("SELECT t.*,
        CASE WHEN t.sender_wallet_id=? THEN 'debit' ELSE 'credit' END direction,
        COALESCE(su.full_name, sm.business_name, ag_s.full_name) sender_name, COALESCE(su.phone_number, sm.phone_number, ag_s.phone_number) sender_phone, su.verified_name sender_verified_name,
        COALESCE(ru.full_name, rm.business_name, ag_r.full_name) receiver_name, COALESCE(ru.phone_number, rm.phone_number, ag_r.phone_number) receiver_phone, ru.verified_name receiver_verified_name
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        LEFT JOIN agent_wallets agw_s ON t.sender_agent_wallet_id=agw_s.id LEFT JOIN agents ag_s ON agw_s.agent_id=ag_s.id
        LEFT JOIN agent_wallets agw_r ON t.receiver_agent_wallet_id=agw_r.id LEFT JOIN agents ag_r ON agw_r.agent_id=ag_r.id
        $where ORDER BY t.created_at DESC LIMIT $lim OFFSET $off");
    $txs->execute(array_merge([$wid],$params));
    ok(['transactions'=>$txs->fetchAll(),'page'=>$page,'limit'=>$lim]);
}

function tx_detail() {
    $pl = auth();
    $id = $_GET['id']??'';
    if(!$id) fail('ID requis');
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();
    $tx = q("SELECT t.*,
        CASE WHEN t.sender_wallet_id=? THEN 'debit' ELSE 'credit' END direction,
        COALESCE(su.full_name, sm.business_name, ag_s.full_name) sender_name, su.verified_name sender_verified_name, su.country sender_country,
        COALESCE(ru.full_name, rm.business_name, ag_r.full_name) receiver_name, ru.verified_name receiver_verified_name, ru.country receiver_country
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        LEFT JOIN agent_wallets agw_s ON t.sender_agent_wallet_id=agw_s.id LEFT JOIN agents ag_s ON agw_s.agent_id=ag_s.id
        LEFT JOIN agent_wallets agw_r ON t.receiver_agent_wallet_id=agw_r.id LEFT JOIN agents ag_r ON agw_r.agent_id=ag_r.id
        WHERE t.id=? AND (t.sender_wallet_id=? OR t.receiver_wallet_id=?)",[$wid,$id,$wid,$wid])->fetch();
    if(!$tx) fail('Transaction introuvable',404);
    $tx['can_cancel'] = $tx['status']==='completed' && $tx['direction']==='debit'
        && !$tx['cancelled_at'] && strtotime($tx['cancel_deadline']??'0')>time();
    ok($tx);
}

// Paiement d'un client vers un marchand ROM_BUSINESS, scanne via le QR
// marchand (prefixe "M|"). TOUJOURS gratuit pour le CLIENT (aucun frais de
// son cote, contrairement a un envoi d'argent classique) - le frais
// eventuel (voir merchant_receive_fee()) est preleve sur ce que le marchand
// recoit, une fois son cumul du jour au-dela du seuil gratuit.
// Coeur du paiement client->marchand, partage par tx_pay_merchant() (scan
// direct du QR marchand) et payment_link_pay() (lien de paiement a
// distance, voir plus bas) - memes regles dans les deux cas : gratuit pour
// le client, frais eventuel preleve sur ce que le marchand recoit une fois
// son cumul du jour depasse (voir merchant_receive_fee()). $source sert
// juste a personnaliser la notification push envoyee au marchand.
function execute_merchant_payment($pl, $merchantId, $amount, $pin, $desc, $source='direct', $amountCurrency=null){
    if($amount<=0) fail('Montant invalide');
    if(!preg_match('/^\d{4}$/',$pin)) fail('PIN invalide');

    $user = q("SELECT pin_hash FROM users WHERE id=?",[$pl['sub']])->fetch();
    pin_check($pl['sub'], $pin, $user['pin_hash']);

    $sw = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    $m  = q("SELECT * FROM merchants WHERE id=?",[$merchantId])->fetch();
    if(!$m) fail('Marchand introuvable',404);
    $mw = q("SELECT * FROM merchant_wallets WHERE merchant_id=?",[$merchantId])->fetch();
    if(!$mw) fail('Marchand introuvable',404);

    $payerCurrency = $sw['currency'] ?: 'XOF';
    $merchantCurrency = $mw['currency'] ?: 'XOF';
    // Un paiement marchand (direct via QR ou via un lien de paiement) reste
    // STRICTEMENT local : le client et le marchand doivent etre dans la meme
    // devise, sans conversion. $amountCurrency (devise dans laquelle $amount
    // est deja exprime - celle du marchand pour un lien de paiement, voir
    // payment_link_pay()) doit donc correspondre aux deux a la fois. Toute
    // transaction internationale doit obligatoirement passer par Transfert
    // Afrique (virement personnel, channel=africa).
    $amountCurrency = $amountCurrency ?: $payerCurrency;
    if($payerCurrency !== $merchantCurrency || $amountCurrency !== $payerCurrency){
        fail('Paiement impossible : ce marchand est dans un autre pays/devise que votre compte. Les paiements marchand sont reserves aux transactions locales. Pour un paiement international, utilisez Transfert Afrique depuis un compte personnel.', 422);
    }

    $debitAmount = $amount;
    if((float)$sw['balance'] < $debitAmount) fail('Solde insuffisant');

    $fxRateApplied = null;
    $feeCalc = merchant_receive_fee($mw['id'], $amount);
    $fee = $feeCalc['fee']; $net = $feeCalc['net'];

    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_wallet_id,receiver_merchant_wallet_id,amount,net_amount,fee,receiver_amount,fx_rate_applied,type,status,reference,description,cancel_deadline) VALUES (?,?,?,?,?,?,?,?,'merchant_payment','pending',?,?,?)",
          [$txid,$sw['id'],$mw['id'],$debitAmount,$net,$fee,$net,$fxRateApplied,$reference,$desc?:('Paiement '.$m['business_name']),$deadline]);
        $rows = q("UPDATE wallets SET balance=balance-? WHERE id=? AND balance>=?",[$debitAmount,$sw['id'],$debitAmount])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        q("UPDATE merchant_wallets SET balance=balance+? WHERE id=?",[$net,$mw['id']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);
        credit_merchant_fee($mw['id'], $fee, 'Frais ROM_MONEY sur encaissement marchand');
        db()->commit();
        fraud_check_merchant_transaction($mw['id'], $pl['phone'] ?? '', $debitAmount, $txid, $reference, $m['phone_number']);
        $srcLabel = $source==='link' ? ' via un lien de paiement' : ' via votre QR';
        $merchCurSuffix = ($merchantCurrency==='XOF'||$merchantCurrency==='XAF') ? 'F' : $merchantCurrency;
        web_push_send_to_merchant($mw['merchant_id'], 'ROM_BUSINESS',
            'Vous avez recu '.number_format($net,0,',',' ').' '.$merchCurSuffix.$srcLabel.($fee>0?' (apres '.number_format($fee,0,',',' ').' '.$merchCurSuffix.' de frais)':''));
        $bal = (float)q("SELECT balance FROM wallets WHERE id=?",[$sw['id']])->fetchColumn();
        return ['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$debitAmount,'fee'=>$fee,'net_amount'=>$net,
            'business_name'=>$m['business_name'],'cancel_before'=>$deadline,'new_balance'=>$bal];
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec paiement', 500); }
}

function tx_pay_merchant() {
    $pl = auth(); $b = body();
    $merchantId = trim($b['merchant_id'] ?? '');
    $amount = (float)($b['amount'] ?? 0);
    $pin = trim($b['pin'] ?? '');
    $desc = trim($b['description'] ?? '');
    if(!$merchantId) fail('Marchand requis');
    $result = execute_merchant_payment($pl, $merchantId, $amount, $pin, $desc, 'direct');
    ok($result, 'Paiement effectue');
}

// ── LIEN DE PAIEMENT A DISTANCE ──
// Le marchand indique un montant/motif, partage le lien genere par
// n'importe quel moyen hors-app (SMS, WhatsApp...) ; le client l'ouvre dans
// ROM_MONEY, voit le marchand/montant/motif, confirme avec son PIN comme un
// paiement normal. L'id du lien (uid(), deja imprevisible) sert de jeton -
// pas besoin d'un champ separe.
function merchant_create_payment_link() {
    $pl = merchant_auth(); $b = body();
    $amount = (float)($b['amount'] ?? 0);
    $desc = trim($b['description'] ?? '');
    if($amount<=0) fail('Montant invalide');
    $id = uid();
    // Expire au bout de 24h : evite qu'un lien oublie/abandonne reste
    // payable indefiniment.
    q("INSERT INTO merchant_payment_links (id,merchant_id,amount,description,status,expires_at) VALUES (?,?,?,?,'pending',?)",
      [$id,$pl['sub'],$amount,$desc?:null,date('Y-m-d H:i:s', time()+24*3600)]);
    ok(['id'=>$id], 'Lien cree');
}

function merchant_cancel_payment_link() {
    $pl = merchant_auth(); $b = body();
    $id = trim($b['id'] ?? '');
    if(!$id) fail('Lien requis');
    $n = q("UPDATE merchant_payment_links SET status='cancelled' WHERE id=? AND merchant_id=? AND status='pending'",[$id,$pl['sub']])->rowCount();
    if(!$n) fail('Lien introuvable ou deja utilise',404);
    ok(null,'Lien annule');
}

function merchant_list_payment_links() {
    $pl = merchant_auth();
    $rows = q("SELECT id,amount,description,status,created_at,paid_at FROM merchant_payment_links
        WHERE merchant_id=? ORDER BY created_at DESC LIMIT 50",[$pl['sub']])->fetchAll();
    ok(['links'=>$rows]);
}

// Vue publique (cote client, auth() personnel classique) d'un lien de
// paiement avant de decider de payer : nom du marchand/montant/motif, et le
// statut pour que l'app affiche le bon ecran (deja paye/annule/expire)
// plutot que de laisser tenter un paiement voue a l'echec.
function payment_link_detail() {
    auth();
    $id = trim($_GET['id'] ?? '');
    if(!$id) fail('Lien invalide');
    $link = q("SELECT l.*, m.business_name, m.verified merchant_verified, mw.currency merchant_currency FROM merchant_payment_links l
        JOIN merchants m ON l.merchant_id=m.id LEFT JOIN merchant_wallets mw ON mw.merchant_id=l.merchant_id WHERE l.id=?",[$id])->fetch();
    if(!$link) fail('Lien de paiement introuvable',404);
    $expired = $link['expires_at'] && strtotime($link['expires_at']) < time();
    ok(['id'=>$link['id'],'business_name'=>$link['business_name'],'merchant_verified'=>(bool)$link['merchant_verified'],
        'amount'=>(float)$link['amount'],'currency'=>$link['merchant_currency']?:'XOF','description'=>$link['description'],
        'status'=>$expired && $link['status']==='pending' ? 'expired' : $link['status'],
        'created_at'=>$link['created_at']]);
}

function payment_link_pay() {
    $pl = auth(); $b = body();
    $linkId = trim($b['id'] ?? '');
    $pin = trim($b['pin'] ?? '');
    if(!$linkId) fail('Lien invalide');
    $link = q("SELECT * FROM merchant_payment_links WHERE id=?",[$linkId])->fetch();
    if(!$link) fail('Lien de paiement introuvable',404);
    if($link['status']!=='pending') fail('Ce lien de paiement a deja ete utilise ou annule');
    if($link['expires_at'] && strtotime($link['expires_at']) < time()) fail('Ce lien de paiement a expire');
    // Un paiement marchand reste STRICTEMENT local (voir
    // execute_merchant_payment()) - on verifie la devise du payeur AVANT de
    // reclamer le lien : sinon une tentative internationale, de toute facon
    // rejetee plus loin, aurait quand meme consomme le lien (marque "paye")
    // sans qu'aucun argent n'ait reellement bouge.
    $sw = q("SELECT currency FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    $payerCurrency = $sw ? ($sw['currency'] ?: 'XOF') : 'XOF';
    $linkMw = q("SELECT currency FROM merchant_wallets WHERE merchant_id=?",[$link['merchant_id']])->fetch();
    $linkCurrency = $linkMw ? ($linkMw['currency'] ?: 'XOF') : 'XOF';
    if($payerCurrency !== $linkCurrency){
        fail('Paiement impossible : ce marchand est dans un autre pays/devise que votre compte. Les paiements marchand sont reserves aux transactions locales. Pour un paiement international, utilisez Transfert Afrique depuis un compte personnel.', 422);
    }
    // Reclame le lien de facon atomique (statut pending->paid conditionne sur
    // le statut ACTUEL en base) avant de deplacer l'argent : sans ce garde-fou,
    // deux requetes concurrentes (double-tap, retry reseau) passeraient toutes
    // les deux le check ci-dessus et executeraient chacune un paiement complet
    // pour le meme lien, debitant le payeur deux fois. Meme principe que les
    // UPDATE ... WHERE balance>=? utilises partout ailleurs pour l'argent.
    $claimed = q("UPDATE merchant_payment_links SET status='paid' WHERE id=? AND status='pending'",[$linkId])->rowCount();
    if(!$claimed) fail('Ce lien de paiement a deja ete utilise ou annule');
    $result = execute_merchant_payment($pl, $link['merchant_id'], (float)$link['amount'], $pin, $link['description'], 'link', $linkCurrency);
    q("UPDATE merchant_payment_links SET transaction_id=?, paid_at=NOW() WHERE id=?",[$result['transaction_id'],$linkId]);
    ok($result, 'Paiement effectue');
}

function tx_resolve() {
    $pl = auth();
    $phone = $_GET['phone']??'';
    if(!preg_match('/^\+?[0-9]{8,15}$/',preg_replace('/[\s\-]/','', $phone))) fail('Numero invalide');
    $u = q("SELECT full_name,phone_number,is_kyc,verified_name FROM users WHERE phone_number=? AND id!=?",[$phone,$pl['sub']])->fetch();
    if($u){
        // Priorite au nom verifie KYC (comme partout ailleurs dans l'app : historique,
        // recus PDF, panneau admin) plutot qu'au seul nom de profil, librement
        // modifiable par n'importe qui vers n'importe quoi. Avant ce correctif,
        // c'etait la seule fonction de toute l'app a ne pas suivre cette regle -
        // exactement l'endroit ou ca compte le plus, puisque c'est le nom que
        // l'expediteur voit juste avant de confirmer l'envoi de son argent.
        ok([
            'full_name'   => $u['verified_name'] ?: $u['full_name'],
            'phone_number'=> $u['phone_number'],
            'is_kyc'      => $u['is_kyc'],
            'is_verified' => !empty($u['verified_name']),
            'is_merchant' => false,
        ], 'Compte trouve');
    }
    // Pas de compte personnel sur ce numero : verifie si c'est un compte
    // marchand. "Envoyer" (virement personnel classique, tx_send()) ne peut
    // pas atteindre un merchant_wallet - seul "Payer" (scan du QR marchand,
    // tx_pay_merchant()) le peut. Avant ce correctif, l'utilisateur se
    // retrouvait juste face a un champ vide sans aucune explication.
    $m = q("SELECT business_name FROM merchants WHERE phone_number=?",[$phone])->fetch();
    if($m){
        ok([
            'full_name'   => $m['business_name'],
            'phone_number'=> $phone,
            'is_kyc'      => false,
            'is_verified' => false,
            'is_merchant' => true,
        ], 'Compte marchand trouve');
    }
    fail('Aucun compte trouve',404);
}

// PROFILE
function route_profile($action) {
    match($action) {
        'get'            => profile_get(),
        'update'         => profile_update(),
        'notifications'  => profile_notif(),
        'toggle-bio'     => profile_bio(),
        'waitlist'       => profile_waitlist(),
        'waitlist-stats' => profile_waitlist_stats(),
        'referral-status'=> profile_referral_status(),
        'devices'        => profile_devices(),
        'revoke-device'  => profile_revoke_device(),
        default          => fail('Action inconnue',404)
    };
}

// "Mes appareils" : liste les appareils connus, indique si chacun est deja
// revoque, et signale lequel est celui utilise pour cet appel (device_id du
// jeton en cours), pour que le frontend n'affiche pas de bouton "deconnecter"
// sur l'appareil que l'utilisateur est en train d'utiliser.
function profile_devices() {
    $pl = auth();
    $rows = q("SELECT device_id,user_agent,first_seen,last_seen,revoked FROM known_devices WHERE user_id=? ORDER BY last_seen DESC",[$pl['sub']])->fetchAll();
    foreach($rows as &$r){ $r['is_current'] = ($pl['device_id'] ?? '') !== '' && $r['device_id'] === $pl['device_id']; $r['revoked']=(bool)$r['revoked']; }
    unset($r);
    ok(['devices'=>$rows]);
}

function profile_revoke_device() {
    $pl = auth(); $b = body();
    $deviceId = trim($b['device_id'] ?? '');
    if(!$deviceId) fail('Appareil requis');
    $n = q("UPDATE known_devices SET revoked=1 WHERE user_id=? AND device_id=?",[$pl['sub'],$deviceId])->rowCount();
    if(!$n) fail('Appareil introuvable',404);
    ok(null,'Appareil deconnecte');
}

function profile_referral_status() {
    $pl = auth();
    $u = q("SELECT referral_code FROM users WHERE id=?",[$pl['sub']])->fetch();
    $code = $u['referral_code'] ?? null;
    if(!$code){
        // Compte cree avant l'existence du parrainage : on lui attribue un code maintenant
        $code = generate_referral_code();
        q("UPDATE users SET referral_code=? WHERE id=?",[$code,$pl['sub']]);
    }
    $referredCount = (int)(q("SELECT COUNT(*) c FROM users WHERE referred_by=?",[$pl['sub']])->fetch()['c']??0);
    $totalEarned = (float)(q("SELECT COALESCE(SUM(bonus_amount),0) t FROM referral_bonuses WHERE referrer_id=?",[$pl['sub']])->fetch()['t']??0);
    ok(['referral_code'=>$code,'referred_count'=>$referredCount,'total_earned'=>$totalEarned]);
}

function profile_get() {
    $pl = auth();
    $u = q("SELECT u.id,u.full_name,u.phone_number,u.email,u.operator,u.bio_enabled,u.is_kyc,u.status,u.created_at,u.photo_url,u.notif_tx,u.notif_promo,u.verified_name,u.country,w.id wid,w.currency FROM users u LEFT JOIN wallets w ON w.user_id=u.id WHERE u.id=?",[$pl['sub']])->fetch();
    if(!$u) fail('Introuvable',404);
    ok(['id'=>$u['id'],'name'=>$u['full_name'],'phone'=>$u['phone_number'],'email'=>$u['email'],
        'operator'=>$u['operator'],'bio_enabled'=>(bool)$u['bio_enabled'],'is_kyc'=>(bool)$u['is_kyc'],
        'status'=>$u['status'],'member_since'=>$u['created_at'],'wallet_id'=>$u['wid'],'photo_url'=>$u['photo_url'],
        'notif_tx'=>(bool)($u['notif_tx']??true),'notif_promo'=>(bool)($u['notif_promo']??true),
        'legal_name'=>$u['verified_name'],'country'=>$u['country'],'currency'=>$u['currency']?:'XOF']);
}

function profile_update() {
    $pl = auth(); $b = body();
    $sets=[]; $vals=[];
    if(!empty($b['full_name'])){$sets[]="full_name=?";$vals[]=$b['full_name'];}
    if(!empty($b['email'])){$sets[]="email=?";$vals[]=$b['email'];}
    if(!empty($b['operator'])){
        $opVal = trim($b['operator']);
        if(mb_strlen($opVal) < 2 || mb_strlen($opVal) > 60) fail('Operateur invalide');
        $sets[]="operator=?";$vals[]=$opVal;
    }
    if(array_key_exists('photo_url',$b)){$sets[]="photo_url=?";$vals[]=$b['photo_url'];}
    if(array_key_exists('notif_tx',$b)){$sets[]="notif_tx=?";$vals[]=$b['notif_tx']?'t':'f';}
    if(array_key_exists('notif_promo',$b)){$sets[]="notif_promo=?";$vals[]=$b['notif_promo']?'t':'f';}
    if(!$sets) fail('Rien a mettre a jour');
    $vals[]=$pl['sub'];
    try {
        q("UPDATE users SET ".implode(',',$sets)." WHERE id=?",$vals);
    } catch(Exception $e) {
        log_and_fail($e, 'Echec de la sauvegarde du profil', 500);
    }
    ok(null,'Profil mis a jour');
}

function profile_notif() {
    $pl = auth();
    $notifs = q("SELECT * FROM notifications WHERE user_id=? ORDER BY sent_at DESC LIMIT 20",[$pl['sub']])->fetchAll();
    $unread = (int)q("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0",[$pl['sub']])->fetchColumn();
    ok(['notifications'=>$notifs,'unread'=>$unread]);
}

function profile_bio() {
    $pl = auth(); $b = body();
    $ena = (int)(bool)($b['enabled']??false);
    q("UPDATE users SET bio_enabled=? WHERE id=?",[$ena,$pl['sub']]);
    ok(['bio_enabled'=>(bool)$ena]);
}

function profile_waitlist() {
    $b = body();
    $phone = trim($b['phone'] ?? '');
    $pays  = trim($b['pays']  ?? '');
    $email = trim($b['email'] ?? '');
    if(!$phone) fail('Numero requis');
    if(!$pays)  fail('Pays requis');
    // Create table if not exists
    try {
        db()->exec("CREATE TABLE IF NOT EXISTS waitlist (
            id SERIAL PRIMARY KEY,
            phone VARCHAR(20) NOT NULL,
            pays VARCHAR(100) NOT NULL,
            email VARCHAR(150),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
    } catch(Exception $e) {}
    // Check if already registered
    $exists = q("SELECT id FROM waitlist WHERE phone=? AND pays=?", [$phone, $pays])->fetch();
    if($exists) {
        ok(['already_registered'=>true], 'Deja inscrit pour '.$pays);
        return;
    }
    q("INSERT INTO waitlist (phone, pays, email) VALUES (?,?,?)", [$phone, $pays, $email?:null]);
    $total = (int)q("SELECT COUNT(*) FROM waitlist WHERE pays=?", [$pays])->fetchColumn();
    ok(['total_waitlist'=>$total], 'Inscription confirmee pour '.$pays);
}

function profile_waitlist_stats() {
    // Public stats - no auth required
    try {
        $stats = q("SELECT pays, COUNT(*) as total FROM waitlist GROUP BY pays ORDER BY total DESC")->fetchAll();
        $total = array_sum(array_column($stats, 'total'));
        ok(['stats'=>$stats, 'total'=>$total]);
    } catch(Exception $e) {
        ok(['stats'=>[], 'total'=>0]);
    }
}


// ============================================================
// KYC — verification d'identite (parcours basique + admin manuel)
// L'utilisateur soumet recto + verso de sa piece d'identite.
// Un admin (protege par un mot de passe simple, pas un vrai systeme
// de comptes admin) approuve ou refuse manuellement. Approuver met
// users.is_kyc=1, deplafonnant le compte.
// ============================================================
function route_kyc($action) {
    match($action) {
        'submit'             => kyc_submit(),
        'status'             => kyc_status(),
        'ocr-extract'        => kyc_ocr_extract(),
        'admin_list'         => kyc_admin_list(),
        'admin_approve'      => kyc_admin_approve(),
        'admin_reject'       => kyc_admin_reject(),
        'admin_pending_count'=> kyc_pending_count(),
        default              => fail('Action inconnue',404)
    };
}

function check_admin_password($b) {
    check_admin_password_str((string)($b['admin_password'] ?? ''));
}
// Resout QUEL admin correspond a ce mot de passe : soit ADMIN_PASSWORD (le
// mot de passe partage d'origine, toujours valable - attribue a "Admin
// Principal"), soit l'un des comptes nommes admin_accounts (mot de passe
// individuel par personne, pour que le journal d'audit indique qui a fait
// quoi). Tous les comptes ont exactement les memes acces - aucune
// restriction par compte, uniquement une identification. Retourne null si
// aucune correspondance.
// Renvoie ['name'=>..., 'countries'=>...] : countries=null signifie "aucune
// restriction" (Admin Principal, ou un compte nomme sans pays assigne n'est
// PAS traite comme illimite ici - voir plus bas, le null "illimite" est
// reserve a Admin Principal uniquement). Retourne null si aucune
// correspondance.
function resolve_admin_identity($pw) {
    if($pw !== '' && hash_equals(ADMIN_PASSWORD, $pw)) return ['name'=>'Admin Principal','countries'=>null];
    $accounts = q("SELECT name, password_hash, countries FROM admin_accounts WHERE active=1")->fetchAll();
    foreach($accounts as $a){
        if(password_verify($pw, $a['password_hash'])){
            $countries = $a['countries'] ? (json_decode($a['countries'], true) ?: []) : [];
            return ['name'=>$a['name'],'countries'=>$countries];
        }
    }
    return null;
}
// Conserve pour compatibilite (utilise ailleurs pour l'attribution du
// journal d'audit) - mirror de resolve_admin_identity() cote nom seul.
function resolve_admin_name($pw) {
    $id = resolve_admin_identity($pw);
    return $id ? $id['name'] : null;
}
// Verifie le mot de passe admin ET applique le meme verrou anti-devinette
// que l'ecran de connexion (partage le meme compteur audit_logs) : avant,
// seul admin/login etait protege contre le brute-force, les ~34 autres
// actions admin (recherche, export, blocage de compte...) ne l'etaient pas
// et pouvaient servir a deviner le mot de passe sans jamais declencher de
// verrou.
function check_admin_password_str($pw) {
    admin_bruteforce_check();
    $id = resolve_admin_identity($pw);
    if($id === null) {
        admin_log('admin_login','failed',null,dk('d_wrong_password'));
        fail('Mot de passe admin incorrect',401);
    }
    // Ramasse par admin_log() / admin_check_country_access() /
    // check_super_admin_only() ci-dessous pour attribuer chaque entree du
    // journal et appliquer les restrictions de la bonne personne, sans
    // devoir modifier la signature de check_admin_password() dans ses
    // ~80 points d'appel.
    $GLOBALS['_current_admin_name'] = $id['name'];
    $GLOBALS['_current_admin_countries'] = $id['countries'];
}
// A appeler juste apres avoir resolu le pays ($targetCountry) d'un
// utilisateur/agent/marchand precis, avant de renvoyer ou modifier ses
// donnees. Admin Principal (countries===null) n'est jamais restreint. Un
// compte nomme sans aucun pays assigne (tableau vide) ne peut rien
// consulter tant qu'un pays ne lui a pas ete assigne explicitement -
// filet de securite pour ne jamais laisser un compte fraichement cree
// tout voir par defaut.
function admin_check_country_access($targetCountry) {
    $countries = $GLOBALS['_current_admin_countries'] ?? null;
    if($countries === null) return; // Admin Principal : acces total
    if(!$targetCountry || !in_array($targetCountry, $countries, true)) {
        admin_log('country_access_denied','failed',null,dk('d_ref_with_reason',['ref'=>(string)$targetCountry,'reason'=>'Pays hors du perimetre de ce compte admin']));
        fail("Vous n'etes pas autorise a agir sur ce pays.", 403);
    }
}
// Reserve certaines actions sensibles (reglages globaux, activation d'un
// pays, gestion des comptes admin) au seul mot de passe partage
// ADMIN_PASSWORD - jamais a un compte nomme, quel que soit son perimetre
// pays. A appeler apres check_admin_password($b).
function check_super_admin_only() {
    if(($GLOBALS['_current_admin_name'] ?? null) !== 'Admin Principal') {
        fail('Cette action est reservee a Admin Principal.', 403);
    }
}

// Equivalent de admin_check_country_access() pour une LISTE (recherche/export
// paginee) plutot qu'un compte unique : renvoie un fragment SQL (deja prefixe
// de " AND ") + les parametres a fusionner dans une clause WHERE existante,
// pour qu'un compte admin nomme ne voie jamais dans ses listes des comptes
// hors de son perimetre pays. No-op (fragment vide) pour Admin Principal.
// Un compte nomme sans aucun pays assigne ne doit rien voir du tout (1=0),
// jamais tout par defaut - meme filet de securite que admin_check_country_access().
function admin_country_scope_clause($countryCol) {
    $countries = $GLOBALS['_current_admin_countries'] ?? null;
    if($countries === null) return ['', []];
    if(empty($countries)) return [' AND 1=0', []];
    $placeholders = implode(',', array_fill(0, count($countries), '?'));
    return [" AND $countryCol IN ($placeholders)", $countries];
}

// Variante pour une transaction (ou une alerte liee a une transaction) qui
// implique deux parties, parfois de pays differents (Transfert Afrique) :
// autorise si AU MOINS l'une des deux colonnes pays correspond, pour ne pas
// bloquer un admin qui doit justement aider un compte de son pays ayant
// envoye/recu de l'etranger.
function admin_country_scope_clause_either($col1, $col2) {
    $countries = $GLOBALS['_current_admin_countries'] ?? null;
    if($countries === null) return ['', []];
    if(empty($countries)) return [' AND 1=0', []];
    $placeholders = implode(',', array_fill(0, count($countries), '?'));
    return [" AND (COALESCE($col1,'') IN ($placeholders) OR COALESCE($col2,'') IN ($placeholders))", array_merge($countries, $countries)];
}

// Equivalent de admin_check_country_access() mais accepte plusieurs pays
// candidats (transaction a deux parties) - autorise si AU MOINS l'un des
// pays candidats est dans le perimetre de l'admin.
function admin_check_country_access_any($candidateCountries) {
    $countries = $GLOBALS['_current_admin_countries'] ?? null;
    if($countries === null) return;
    foreach($candidateCountries as $c){
        if($c && in_array($c, $countries, true)) return;
    }
    admin_log('country_access_denied','failed',null,dk('d_ref_with_reason',['ref'=>(implode('/',array_filter($candidateCountries))?:'-'),'reason'=>'Aucune des parties impliquees n\'est dans le perimetre de ce compte admin']));
    fail("Vous n'etes pas autorise a agir sur cette transaction.", 403);
}

// Jointures pays (expediteur ET destinataire, personnel ou marchand) pour
// les agregats du tableau de bord - voir admin_dash_xof_sum()/admin_dash_count().
// Alias dedies (ds*/dr*) pour ne jamais entrer en collision avec les alias
// deja utilises par ailleurs dans admin_dashboard_get_data() (erw/ermw/errate...).
function admin_dash_country_join_sql() {
    return " LEFT JOIN wallets dsw ON transactions.sender_wallet_id = dsw.id
        LEFT JOIN merchant_wallets dsmw ON transactions.sender_merchant_wallet_id = dsmw.id
        LEFT JOIN users dsu ON dsw.user_id = dsu.id
        LEFT JOIN merchants dsm ON dsmw.merchant_id = dsm.id
        LEFT JOIN wallets drw2 ON transactions.receiver_wallet_id = drw2.id
        LEFT JOIN merchant_wallets drmw2 ON transactions.receiver_merchant_wallet_id = drmw2.id
        LEFT JOIN users dru ON drw2.user_id = dru.id
        LEFT JOIN merchants drm ON drmw2.merchant_id = drm.id";
}
function admin_dash_country_scope_where() {
    return admin_country_scope_clause_either('dsu.country,dsm.country', 'dru.country,drm.country');
}
// Remplace admin_dash_xof_sum_sql() : execute directement (au lieu de
// renvoyer juste le texte SQL) pour pouvoir fusionner proprement les
// parametres du filtre de perimetre pays avec ceux du $where appelant -
// tous les appelants faisaient de toute facon q(...)->fetchColumn() aussitot.
function admin_dash_xof_sum($where, $params = []) {
    list($scopeSql, $scopeParams) = admin_dash_country_scope_where();
    $sql = "SELECT COALESCE(SUM(
            COALESCE(transactions.receiver_amount,transactions.net_amount,transactions.amount)
            * COALESCE(NULLIF(erxof.rate_to_usd,0),1)
            / COALESCE(NULLIF(errate.rate_to_usd,0), NULLIF(erxof.rate_to_usd,0), 1)
        ),0)
        FROM transactions
        LEFT JOIN wallets erw ON transactions.receiver_wallet_id = erw.id
        LEFT JOIN merchant_wallets ermw ON transactions.receiver_merchant_wallet_id = ermw.id
        LEFT JOIN exchange_rates errate ON errate.currency_code = UPPER(COALESCE(erw.currency, ermw.currency, 'XOF'))
        LEFT JOIN exchange_rates erxof ON erxof.currency_code = 'XOF'"
        .admin_dash_country_join_sql()."
        WHERE $where".$scopeSql;
    return (float)q($sql, array_merge($params, $scopeParams))->fetchColumn();
}
// Meme principe que admin_dash_xof_sum() mais pour un simple COUNT(*),
// utilise partout ou le tableau de bord compte des transactions plutot que
// d'en sommer le montant.
function admin_dash_count($where, $params = []) {
    list($scopeSql, $scopeParams) = admin_dash_country_scope_where();
    $sql = "SELECT COUNT(*) FROM transactions".admin_dash_country_join_sql()." WHERE $where".$scopeSql;
    return (int)q($sql, array_merge($params, $scopeParams))->fetchColumn();
}

// Le journal d'audit (audit_logs.target_phone) ne stocke qu'un numero de
// telephone brut, potentiellement personnel/marchand/agent OU absent (actions
// systeme : connexion admin, reglages, activation pays...). Pour un compte
// admin nomme, une ligne SANS numero (action non liee a un compte precis)
// reste visible (utile pour sa propre accountabilite - ex: ses propres
// tentatives d'acces refusees), mais une ligne AVEC numero n'est visible que
// si ce compte est dans son perimetre pays.
function admin_audit_scope_sql() {
    $joinSql = " LEFT JOIN users au ON au.phone_number = audit_logs.target_phone
        LEFT JOIN merchants am ON am.phone_number = audit_logs.target_phone
        LEFT JOIN agents aa ON aa.phone_number = audit_logs.target_phone";
    $countries = $GLOBALS['_current_admin_countries'] ?? null;
    if ($countries === null) return [$joinSql, '', []];
    if (empty($countries)) return [$joinSql, " AND audit_logs.target_phone IS NULL", []];
    $placeholders = implode(',', array_fill(0, count($countries), '?'));
    return [$joinSql, " AND (audit_logs.target_phone IS NULL OR COALESCE(au.country,am.country,aa.country) IN ($placeholders))", $countries];
}

// Resout les pays des deux parties d'une transaction (personnel OU
// marchand des deux cotes) - utilise par admin_freeze_transaction()/
// admin_unfreeze_transaction()/admin_confirm_cancel_frozen(), qui ne
// joignent pas deja users/merchants dans leur requete initiale.
function admin_tx_involved_countries($tx) {
    $countries = [];
    if(!empty($tx['sender_wallet_id'])){
        $c = q("SELECT u.country FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.id=?",[$tx['sender_wallet_id']])->fetchColumn();
        if($c) $countries[] = $c;
    } elseif(!empty($tx['sender_merchant_wallet_id'])){
        $c = q("SELECT m.country FROM merchant_wallets mw JOIN merchants m ON mw.merchant_id=m.id WHERE mw.id=?",[$tx['sender_merchant_wallet_id']])->fetchColumn();
        if($c) $countries[] = $c;
    }
    if(!empty($tx['receiver_wallet_id'])){
        $c = q("SELECT u.country FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.id=?",[$tx['receiver_wallet_id']])->fetchColumn();
        if($c) $countries[] = $c;
    } elseif(!empty($tx['receiver_merchant_wallet_id'])){
        $c = q("SELECT m.country FROM merchant_wallets mw JOIN merchants m ON mw.merchant_id=m.id WHERE mw.id=?",[$tx['receiver_merchant_wallet_id']])->fetchColumn();
        if($c) $countries[] = $c;
    }
    return $countries;
}

// Meme logique anti-devinette que admin_bruteforce_check(), mais comptee
// separement (action='earnings_login') pour ne pas partager son compteur
// avec le mot de passe admin partage.
function earnings_bruteforce_check() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $maxAttempts = (int)get_setting('admin_bf_max_attempts', 3);
    $blockMinutes = (int)get_setting('admin_bf_block_minutes', 60);
    $row = q("SELECT COUNT(*) c FROM audit_logs
              WHERE action='earnings_login' AND result='failed' AND ip_address=?
              AND created_at > NOW() - (?::text || ' minutes')::interval",
              [$ip, $blockMinutes])->fetch();
    if($row && (int)$row['c'] >= $maxAttempts) {
        fail('Trop de tentatives echouees depuis cette adresse. Reessayez dans '.$blockMinutes.' minutes.', 429);
    }
}
// Second verrou, INDEPENDANT du mot de passe admin partage : un admin qui
// connait ADMIN_PASSWORD peut gerer le reste de l'app mais reste bloque ici
// tant qu'il ne connait pas aussi EARNINGS_PASSWORD (connu du seul
// proprietaire). Echoue explicitement si la variable n'est pas configuree,
// plutot que de laisser passer par defaut.
function check_earnings_password($b) {
    earnings_bruteforce_check();
    if(!EARNINGS_PASSWORD) fail('EARNINGS_PASSWORD non configuree sur Render.',500);
    $pw = (string)($b['earnings_password'] ?? '');
    if(!hash_equals(EARNINGS_PASSWORD, $pw)) {
        admin_log('earnings_login','failed',null,dk('d_wrong_password'));
        fail('Code Gains ROM incorrect',401);
    }
}

// ============================================================
// 2FA ADMIN (TOTP, RFC 6238) — meme principe que Google Authenticator /
// Authy. Implemente ici a la main (pas de librairie externe / Composer,
// coherent avec le reste du projet) : c'est un algorithme standard et
// court (HMAC-SHA1 sur un compteur de temps par pas de 30s).
// Le secret et les codes de recuperation sont stockes via app_settings
// (table cle/valeur deja existante), pas besoin de nouvelle table.
// ============================================================
function totp_base32_encode($bin) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    for($i=0; $i<strlen($bin); $i++) $bits .= str_pad(decbin(ord($bin[$i])), 8, '0', STR_PAD_LEFT);
    $out = '';
    foreach(str_split($bits, 5) as $chunk) {
        $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
        $out .= $alphabet[bindec($chunk)];
    }
    return $out;
}
function totp_base32_decode($b32) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper(preg_replace('/[^A-Z2-7]/','', $b32));
    $bits = '';
    for($i=0; $i<strlen($b32); $i++) $bits .= str_pad(decbin(strpos($alphabet, $b32[$i])), 5, '0', STR_PAD_LEFT);
    $bytes = '';
    foreach(str_split($bits, 8) as $chunk) {
        if(strlen($chunk) < 8) continue;
        $bytes .= chr(bindec($chunk));
    }
    return $bytes;
}
function totp_generate_secret() {
    return totp_base32_encode(random_bytes(20)); // secret 160 bits, standard
}
function totp_code_at($secret, $timeSlice) {
    $key = totp_base32_decode($secret);
    $time = pack('N*', 0) . pack('N*', $timeSlice); // 8 octets big-endian
    $hash = hash_hmac('sha1', $time, $key, true);
    $offset = ord($hash[19]) & 0x0F;
    $part = ((ord($hash[$offset]) & 0x7F) << 24)
          | ((ord($hash[$offset+1]) & 0xFF) << 16)
          | ((ord($hash[$offset+2]) & 0xFF) << 8)
          | (ord($hash[$offset+3]) & 0xFF);
    return str_pad((string)($part % 1000000), 6, '0', STR_PAD_LEFT);
}
// Tolerance : accepte le code actuel + celui d'avant/d'apres (fenetre de
// +/-30s), pour absorber le decalage naturel entre le moment ou l'admin
// lit le code et celui ou il le tape (~60-90s de marge en pratique),
// sans changer le pas standard de 30s (necessaire pour rester compatible
// avec Google Authenticator / Authy, qui l'imposent).
function totp_verify($secret, $code) {
    $code = preg_replace('/\D/', '', (string)$code);
    if(strlen($code) !== 6) return false;
    $slice = (int)floor(time() / 30);
    for($i=-1; $i<=1; $i++) {
        if(hash_equals(totp_code_at($secret, $slice + $i), $code)) return true;
    }
    return false;
}
function totp_generate_recovery_codes($count = 10) {
    $codes = [];
    for($i=0; $i<$count; $i++) {
        $codes[] = strtoupper(bin2hex(random_bytes(4))); // ex: A1B2C3D4
    }
    return $codes;
}

// ============================================================
// REGLAGES DYNAMIQUES — taux de frais et plafonds, modifiables depuis
// l'admin sans redeploiement. Tant qu'un reglage n'a jamais ete modifie,
// la valeur par defaut ci-dessous s'applique (comportement identique a
// avant l'introduction de ce systeme).
// ============================================================
function get_setting($key, $default) {
    static $cache = [];
    if(array_key_exists($key, $cache)) return $cache[$key];
    $row = q("SELECT value FROM app_settings WHERE setting_key=?", [$key])->fetch();
    $cache[$key] = ($row && $row['value']!=='') ? $row['value'] : $default;
    return $cache[$key];
}
function set_setting($key, $value) {
    q("INSERT INTO app_settings (setting_key, value, updated_at) VALUES (?,?,CURRENT_TIMESTAMP)
       ON CONFLICT (setting_key) DO UPDATE SET value=EXCLUDED.value, updated_at=CURRENT_TIMESTAMP",
      [$key, $value]);
}
// Reglages exposes publiquement (utilisateurs connectes, pas seulement
// l'admin) : necessaires pour que l'apercu des frais cote app corresponde
// toujours exactement au montant reellement debite cote serveur.
function get_public_settings() {
    return [
        'fee_rate_national' => (float)get_setting('fee_rate_national', 0.01),
        'fee_free_threshold_national' => (float)get_setting('fee_free_threshold_national', 4000),
        'fee_rate_africa' => (float)get_setting('fee_rate_africa', 0.015),
    ];
}

// ============================================================
// CHIFFREMENT DES PHOTOS KYC — les pieces d'identite (recto/verso) sont
// parmi les donnees les plus sensibles de l'app. Chiffrees avec AES-256-GCM
// (chiffrement authentifie : toute alteration des donnees est detectee, pas
// seulement empechee de se lire) avant d'etre stockees, avec une cle separee
// de JWT_SECRET/ADMIN_PASSWORD (KYC_ENCRYPTION_KEY, variable d'environnement
// Render). Ainsi, meme en cas de fuite de la seule base de donnees, les
// photos restent illisibles sans cette cle.
// Le marqueur "ENC1:" en prefixe permet de reconnaitre les donnees deja
// chiffrees et de rester compatible avec d'eventuelles anciennes demandes
// KYC deja en base avant la mise en place de ce chiffrement (non chiffrees,
// lues telles quelles).
// ============================================================
function kyc_encrypt($plaintext) {
    $key = getenv('KYC_ENCRYPTION_KEY');
    if (!$key) fail('Configuration serveur incomplete : KYC_ENCRYPTION_KEY non definie sur Render.', 500);
    $rawKey = hash('sha256', $key, true);
    $iv = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $rawKey, OPENSSL_RAW_DATA, $iv, $tag);
    return 'ENC1:'.base64_encode($iv.$tag.$ciphertext);
}
function kyc_decrypt($stored) {
    if (!is_string($stored) || strpos($stored, 'ENC1:') !== 0) return $stored; // donnee ancienne non chiffree
    $key = getenv('KYC_ENCRYPTION_KEY');
    if (!$key) return null; // impossible a dechiffrer sans la cle
    $rawKey = hash('sha256', $key, true);
    $raw = base64_decode(substr($stored, 5));
    if (strlen($raw) < 28) return null;
    $iv = substr($raw, 0, 12);
    $tag = substr($raw, 12, 16);
    $ciphertext = substr($raw, 28);
    $plain = openssl_decrypt($ciphertext, 'aes-256-gcm', $rawKey, OPENSSL_RAW_DATA, $iv, $tag);
    return $plain !== false ? $plain : null;
}

function kyc_submit() {
    $pl = auth(); $b = body();
    $recto = trim($b['photo_recto']??'');
    $verso = trim($b['photo_verso']??'');
    $legalPrenom = trim($b['legal_prenom']??'');
    $legalNom = trim($b['legal_nom']??'');
    $legalBirthdate = trim($b['legal_birthdate']??'');
    $ocrPrenom = trim($b['ocr_prenom']??'');
    $ocrNom = trim($b['ocr_nom']??'');
    $ocrBirthdate = trim($b['ocr_birthdate']??'');
    $ocrError = trim($b['ocr_error']??'');
    if(!$recto || !$verso) fail('Recto et verso requis');
    if(!$legalPrenom || !$legalNom) fail('Le prenom et le nom exacts (piece d\'identite) sont requis');
    $legalName = trim($legalPrenom.' '.$legalNom);
    $ocrName = trim($ocrPrenom.' '.$ocrNom);

    $existing = q("SELECT id FROM kyc_requests WHERE user_id=? AND status='pending'",[$pl['sub']])->fetch();
    if($existing) fail('Une demande est deja en attente de verification');

    $u = q("SELECT full_name,phone_number,is_kyc FROM users WHERE id=?",[$pl['sub']])->fetch();
    if($u && (int)($u['is_kyc']??0) === 1) fail('Une piece d\'identite est deja validee sur ce compte - contactez le support pour la remplacer');

    $id = uid();
    q("INSERT INTO kyc_requests (id,user_id,phone_number,full_name,legal_name,legal_prenom,legal_nom,legal_birthdate,ocr_name,ocr_prenom,ocr_nom,ocr_birthdate,ocr_error,photo_recto,photo_verso,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')",
      [$id,$pl['sub'],$u['phone_number'],$u['full_name'],$legalName,$legalPrenom,$legalNom,$legalBirthdate?:null,$ocrName?:null,$ocrPrenom?:null,$ocrNom?:null,$ocrBirthdate?:null,$ocrError?:null,kyc_encrypt($recto),kyc_encrypt($verso)]);
    ok(['id'=>$id],'Demande envoyee, en attente de verification');
}

function kyc_status() {
    $pl = auth();
    $r = q("SELECT status,created_at,reviewed_at FROM kyc_requests WHERE user_id=? ORDER BY created_at DESC LIMIT 1",[$pl['sub']])->fetch();
    ok(['request'=>$r?:null]);
}

// ═══════════════════════════════════════════
// KYC - OCR via Google Cloud Vision (lecture de la CNI)
// ═══════════════════════════════════════════
function google_vision_ocr($imageBase64) {
    $apiKey = getenv('GOOGLE_VISION_API_KEY');
    if(!$apiKey) return ['text'=>null, 'error'=>'GOOGLE_VISION_API_KEY absente des variables d\'environnement'];
    if(strpos($imageBase64, 'base64,') !== false) {
        $imageBase64 = substr($imageBase64, strpos($imageBase64, 'base64,')+7);
    }
    $payload = json_encode([
        'requests' => [[
            'image' => ['content' => $imageBase64],
            'features' => [['type' => 'DOCUMENT_TEXT_DETECTION']],
            'imageContext' => ['languageHints' => ['fr']]
        ]]
    ]);
    $ch = curl_init('https://vision.googleapis.com/v1/images:annotate?key='.$apiKey);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 25);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);
    if($curlErr) return ['text'=>null, 'error'=>'Erreur cURL: '.$curlErr];
    if(!$response) return ['text'=>null, 'error'=>'Reponse vide de Google Vision (HTTP '.$httpCode.')'];
    if($httpCode !== 200) return ['text'=>null, 'error'=>'HTTP '.$httpCode.' - '.substr($response,0,500)];
    $data = json_decode($response, true);
    if(isset($data['responses'][0]['error'])) {
        return ['text'=>null, 'error'=>'Erreur Vision API: '.json_encode($data['responses'][0]['error'])];
    }
    $text = $data['responses'][0]['fullTextAnnotation']['text'] ?? null;
    if(!$text) return ['text'=>null, 'error'=>'Aucun texte detecte. Reponse brute: '.substr($response,0,500)];
    return ['text'=>$text, 'error'=>null];
}

// Fournisseur alternatif a Google Vision : OCR.space, gratuit (25 000
// requetes/mois) SANS carte bancaire ni compte de facturation - juste une
// cle obtenue par email sur ocr.space/ocrapi/freekey. Meme format de retour
// (text/error) que google_vision_ocr(), donc le reste du pipeline (parsing,
// comparaison OCR vs saisie utilisateur, diagnostic visible en admin)
// fonctionne a l'identique quel que soit le fournisseur actif.
function ocrspace_ocr($imageBase64) {
    $apiKey = getenv('OCR_SPACE_API_KEY');
    if(!$apiKey) return ['text'=>null, 'error'=>'OCR_SPACE_API_KEY absente des variables d\'environnement'];
    if(strpos($imageBase64, 'data:image') !== 0) {
        $imageBase64 = 'data:image/jpeg;base64,'.$imageBase64;
    }
    $payload = http_build_query([
        'apikey' => $apiKey,
        'base64Image' => $imageBase64,
        'language' => 'fre',
        'OCREngine' => 2,
        'isOverlayRequired' => 'false',
    ]);
    $ch = curl_init('https://api.ocr.space/parse/image');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 25);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);
    if($curlErr) return ['text'=>null, 'error'=>'Erreur cURL: '.$curlErr];
    if(!$response) return ['text'=>null, 'error'=>'Reponse vide de OCR.space (HTTP '.$httpCode.')'];
    $data = json_decode($response, true);
    if(!$data) return ['text'=>null, 'error'=>'Reponse invalide de OCR.space: '.substr($response,0,300)];
    if(!empty($data['IsErroredOnProcessing'])) {
        $msg = is_array($data['ErrorMessage']??null) ? implode(', ',$data['ErrorMessage']) : ($data['ErrorMessage'] ?? 'Erreur inconnue');
        return ['text'=>null, 'error'=>'Erreur OCR.space: '.$msg];
    }
    $text = $data['ParsedResults'][0]['ParsedText'] ?? null;
    if(!$text || trim($text)==='') return ['text'=>null, 'error'=>'Aucun texte detecte par OCR.space'];
    return ['text'=>$text, 'error'=>null];
}

// --- Logique d'extraction portee depuis la version JS (Tesseract.js),
// affinee sur de vrais textes OCR reels au fil de plusieurs iterations :
// tolerance aux deformations de "Prenom(s)", recherche du "Nom" totalement
// independante (au cas ou le prenom n'ait pas ete localise), nettoyage du
// bruit court colle devant les valeurs, et date de naissance filtree par
// plausibilite pour ne jamais confondre avec la date d'expiration.
function kyc_clean_chunk($s) {
    $s = str_replace("\n", ' ', $s ?? '');
    $s = preg_replace('/[^A-Za-zÀ-ÿ\'\s-]/u', ' ', $s);
    $s = preg_replace('/\s+/', ' ', $s);
    return trim($s ?? '');
}
function kyc_strip_leading_noise($s) {
    $words = array_values(array_filter(explode(' ', $s), fn($w)=>$w!==''));
    while(count($words) > 1 && mb_strlen(preg_replace('/[^A-Za-zÀ-ÿ]/u', '', $words[0])) <= 2) {
        array_shift($words);
    }
    return implode(' ', $words);
}
function kyc_capture_after($t, $fromIdx, $endPattern, $maxLen=25) {
    $windowEnd = min(strlen($t), $fromIdx + $maxLen);
    $rest = substr($t, $fromIdx, max(0,$windowEnd - $fromIdx));
    if(preg_match($endPattern, $rest, $m, PREG_OFFSET_CAPTURE)) {
        return ['value'=>substr($rest,0,$m[0][1]), 'nextIdx'=>$fromIdx+$m[0][1]+strlen($m[0][0]), 'found'=>true];
    }
    $firstNl = strpos($rest, "\n");
    if($firstNl === false) return ['value'=>trim($rest), 'nextIdx'=>$fromIdx+strlen($rest), 'found'=>false];
    $afterFirstLine = substr($rest, $firstNl+1);
    $secondNl = strpos($afterFirstLine, "\n");
    $value = $secondNl !== false ? substr($afterFirstLine,0,$secondNl) : $afterFirstLine;
    $nextIdx = $fromIdx + $firstNl + 1 + ($secondNl !== false ? $secondNl : strlen($afterFirstLine));
    return ['value'=>$value, 'nextIdx'=>$nextIdx, 'found'=>false];
}
function kyc_find_standalone_nom($t) {
    if(preg_match_all('/\bnom\b/iu', $t, $matches, PREG_OFFSET_CAPTURE)) {
        foreach($matches[0] as $m) {
            $idx=$m[1];
            $before=mb_strtolower(substr($t, max(0,$idx-3), min(3,$idx)));
            if(preg_match('/pr[ée]$/u', $before)) continue;
            return ['index'=>$idx, 'length'=>strlen($m[0])];
        }
    }
    return null;
}
function kyc_pad_date($d) {
    if(!$d) return $d;
    $p=explode('/',$d);
    if(count($p)!==3) return $d;
    return str_pad($p[0],2,'0',STR_PAD_LEFT).'/'.str_pad($p[1],2,'0',STR_PAD_LEFT).'/'.$p[2];
}
function kyc_extract_birthdate($t) {
    if(preg_match('/naissance[\s\S]{0,45}?(\d{1,2}\/\d{1,2}\/\d{4})/iu', $t, $m)) return kyc_pad_date($m[1]);
    if(!preg_match_all('/\d{1,2}\/\d{1,2}\/\d{4}/', $t, $matches, PREG_OFFSET_CAPTURE)) return null;
    if(empty($matches[0])) return null;
    $expIdx=null;
    if(preg_match('/expiration/iu', $t, $em, PREG_OFFSET_CAPTURE)) $expIdx=$em[0][1];
    $currentYear=(int)date('Y');
    foreach($matches[0] as $dm){
        $val=$dm[0]; $idx=$dm[1];
        $parts=explode('/',$val);
        $year=(int)$parts[2];
        $tooRecent=$year>=$currentYear-5;
        $afterExpiration=$expIdx!==null && $idx>=$expIdx;
        if(!$tooRecent && !$afterExpiration) return kyc_pad_date($val);
    }
    return null;
}
function kyc_parse_cni_text($text) {
    $norm = preg_replace('/[\\\\_|~]/', ' ', $text);
    $prenom=null; $nom=null;
    if(preg_match('/pr[ée]n[o0]r?m\W*f?s?\)?/iu', $norm, $pm, PREG_OFFSET_CAPTURE)) {
        $pmIdx=$pm[0][1]+strlen($pm[0][0]);
        $res1=kyc_capture_after($norm, $pmIdx, '/\bnom\b/iu', 25);
        $prenom=kyc_strip_leading_noise(mb_strtoupper(kyc_clean_chunk($res1['value'])));
        if($res1['found']){
            $res2=kyc_capture_after($norm, $res1['nextIdx'], '/date\s*de\s*naissance|sexe|nationalit/iu', 25);
            $nom=kyc_strip_leading_noise(mb_strtoupper(kyc_clean_chunk($res2['value'])));
        }
    }
    $sm=kyc_find_standalone_nom($norm);
    if($sm){
        $res3=kyc_capture_after($norm, $sm['index']+$sm['length'], '/date\s*de\s*naissance|sexe|nationalit/iu', 25);
        $standaloneNom=kyc_strip_leading_noise(mb_strtoupper(kyc_clean_chunk($res3['value'])));
        if(strlen($standaloneNom)>($nom?strlen($nom):0)) $nom=$standaloneNom;
    }
    $birthdate=kyc_extract_birthdate($text);
    return ['prenom'=>$prenom?:null, 'nom'=>$nom?:null, 'birthdate'=>$birthdate];
}
function kyc_ocr_extract() {
    auth();
    $b = body();
    $recto = trim($b['photo_recto'] ?? '');
    if(!$recto) fail('Photo recto requise');
    // Priorite a OCR.space (gratuit, sans carte bancaire) si sa cle est
    // configuree ; sinon repli sur Google Vision si SA cle existe. Les deux
    // fonctions renvoient exactement le meme format, donc rien d'autre a
    // adapter selon le fournisseur actif.
    $result = getenv('OCR_SPACE_API_KEY') ? ocrspace_ocr($recto) : google_vision_ocr($recto);
    if(!$result['text']) {
        ok(['prenom'=>null,'nom'=>null,'birthdate'=>null,'raw_text'=>'[DIAGNOSTIC] '.($result['error']?:'Erreur inconnue')], 'OCR indisponible pour le moment, saisie manuelle requise');
        return;
    }
    $parsed = kyc_parse_cni_text($result['text']);
    ok(['prenom'=>$parsed['prenom'],'nom'=>$parsed['nom'],'birthdate'=>$parsed['birthdate'],'raw_text'=>$result['text']]);
}

function kyc_admin_list() {
    $b = body();
    check_admin_password($b);
    list($scopeSql, $scopeParams) = admin_country_scope_clause('u.country');
    $rows = q("SELECT k.id,k.user_id,k.phone_number,k.full_name,k.legal_name,k.legal_prenom,k.legal_nom,k.legal_birthdate,k.ocr_name,k.ocr_prenom,k.ocr_nom,k.ocr_birthdate,k.ocr_error,k.photo_recto,k.photo_verso,k.status,k.created_at
        FROM kyc_requests k LEFT JOIN users u ON u.id=k.user_id WHERE k.status='pending'".$scopeSql." ORDER BY k.created_at ASC", $scopeParams)->fetchAll();
    foreach($rows as &$r){ $r['photo_recto']=kyc_decrypt($r['photo_recto']); $r['photo_verso']=kyc_decrypt($r['photo_verso']); }
    unset($r);
    ok(['requests'=>$rows]);
}

// Route legere dediee au comptage, pour le badge de notification admin -
// evite de retelecharger toutes les photos recto/verso a chaque poll.
function kyc_pending_count() {
    $b = body();
    check_admin_password($b);
    list($scopeSql, $scopeParams) = admin_country_scope_clause('u.country');
    $count = q("SELECT COUNT(*) FROM kyc_requests k LEFT JOIN users u ON u.id=k.user_id WHERE k.status='pending'".$scopeSql, $scopeParams)->fetchColumn();
    ok(['count'=>(int)$count]);
}

function kyc_admin_approve() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['id']??'');
    if(!$id) fail('ID requis');
    $r = q("SELECT k.user_id,k.phone_number,k.legal_prenom,k.legal_nom,k.legal_birthdate,u.country FROM kyc_requests k LEFT JOIN users u ON u.id=k.user_id WHERE k.id=? AND k.status='pending'",[$id])->fetch();
    if(!$r) fail('Demande introuvable ou deja traitee',404);
    admin_check_country_access($r['country']);

    // L'admin peut corriger le prenom/nom/date de naissance juste avant de
    // valider (ex: faute de frappe de l'utilisateur a la soumission, ou
    // lecture OCR erronee qu'il corrige en comparant visuellement a la
    // photo de la piece). Si rien n'est envoye depuis l'admin, on garde
    // simplement ce que l'utilisateur avait soumis - comportement identique
    // a avant ce correctif.
    $prenom = trim($b['legal_prenom'] ?? '') ?: $r['legal_prenom'];
    $nom = trim($b['legal_nom'] ?? '') ?: $r['legal_nom'];
    $birthdate = trim($b['legal_birthdate'] ?? '') ?: $r['legal_birthdate'];
    if(!$prenom || !$nom) fail('Prenom et nom requis');
    $legalName = trim($prenom.' '.$nom);
    $wasCorrected = ($prenom !== $r['legal_prenom']) || ($nom !== $r['legal_nom']) || ($birthdate !== $r['legal_birthdate']);

    q("UPDATE kyc_requests SET status='approved', reviewed_at=NOW(), legal_prenom=?, legal_nom=?, legal_name=?, legal_birthdate=? WHERE id=?",
      [$prenom, $nom, $legalName, $birthdate?:null, $id]);
    q("UPDATE users SET is_kyc=1, verified_name=?, verified_birthdate=? WHERE id=?",[$legalName, $birthdate?:null, $r['user_id']]);
    if($wasCorrected){
        admin_log('kyc_approve_corrected','success',$r['phone_number'],dk('d_kyc_name_corrected'));
    }
    ok(null,'Compte verifie avec succes');
}

function kyc_admin_reject() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['id']??'');
    $reason = trim($b['reason']??'');
    if(!$id) fail('ID requis');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $r = q("SELECT k.id, k.user_id, k.phone_number, u.country FROM kyc_requests k LEFT JOIN users u ON u.id=k.user_id WHERE k.id=? AND k.status='pending'",[$id])->fetch();
    if(!$r) fail('Demande introuvable ou deja traitee',404);
    admin_check_country_access($r['country']);
    // Refuse = aucune trace dans le systeme = suppression automatique et
    // immediate, pas de statut 'rejected' persistant. La raison reste
    // consultable en permanence dans le Journal d'audit (admin_log), pour
    // pouvoir expliquer plus tard pourquoi cette demande a ete refusee.
    q("DELETE FROM kyc_requests WHERE id=?",[$id]);
    admin_log('kyc_reject','success',$r['phone_number'],$reason);
    // Sans notification, la personne n'a plus aucun moyen de savoir que sa
    // demande a ete traitee (la ligne est supprimee) - elle risquerait
    // d'attendre indefiniment en pensant que l'examen est toujours en cours.
    web_push_send_to_user($r['user_id'], 'ROM_MONEY', 'Votre demande de verification d\'identite a ete refusee : '.$reason.' Vous pouvez soumettre une nouvelle demande.');
    ok(null,'Demande refusee');
}

// ============================================================
// EXPORT — historique des transactions en CSV ou PDF
// ============================================================
function route_export($action) {
    match($action) {
        'xlsx' => export_xlsx(),
        'pdf' => export_pdf(),
        default => fail('Action inconnue',404)
    };
}

// Recupere les lignes d'historique (hors frais, qui sont deja inclus dans
// chaque transaction via amount-net_amount) pour l'utilisateur connecte.
function export_get_rows($pl, $period, $from=null, $to=null) {
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();
    $where = "(t.sender_wallet_id=? OR t.receiver_wallet_id=?) AND t.type!='fee'";
    $params = [$wid,$wid];
    if($period==='month'){
        $where .= " AND EXTRACT(MONTH FROM t.created_at)=EXTRACT(MONTH FROM NOW()) AND EXTRACT(YEAR FROM t.created_at)=EXTRACT(YEAR FROM NOW())";
    } elseif($period==='custom' && preg_match('/^\d{4}-\d{2}$/',(string)$from) && preg_match('/^\d{4}-\d{2}$/',(string)$to)){
        $where .= " AND t.created_at >= ?::date AND t.created_at < (date_trunc('month', ?::date) + interval '1 month')";
        $params[] = $from.'-01';
        $params[] = $to.'-01';
    }
    // 'all' (ou periode personnalisee invalide) : aucun filtre de date supplementaire

    $countRow = q("SELECT COUNT(*) cnt FROM transactions t WHERE $where",$params)->fetch();
    $total = (int)($countRow['cnt']??0);

    $LIMIT = 5000; // plafond de securite, quelle que soit la periode choisie
    // Joint aussi merchant_wallets/merchants des deux cotes - sans ca, une
    // ligne ou l'utilisateur a paye/ete paye par un marchand affichait "-"
    // en Contact dans l'export, alors que l'ecran d'historique (qui fait un
    // COALESCE equivalent) montrait bien le nom du commerce.
    $sql = "SELECT t.*,
        CASE WHEN t.sender_wallet_id=? THEN 'debit' ELSE 'credit' END as direction,
        su.full_name sender_name, su.phone_number sender_phone, su.verified_name sender_verified_name,
        ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name,
        sm.business_name sender_merchant_name, rm.business_name receiver_merchant_name
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        WHERE $where ORDER BY t.created_at DESC LIMIT $LIMIT";
    $rows = q($sql, array_merge([$wid],$params))->fetchAll();
    return ['rows'=>$rows, 'total'=>$total, 'truncated'=>$total>$LIMIT, 'limit'=>$LIMIT];
}

// Petit dictionnaire de traduction pour l'export CSV/PDF (fr/en), independant
// du systeme i18n du frontend puisque ces fichiers sont generes cote serveur.
function export_t($key, $lang) {
    $dict = [
        'title'        => ['fr'=>'ROM_MONEY - Releve de transactions', 'en'=>'ROM_MONEY - Transaction Statement'],
        'holder'       => ['fr'=>'Titulaire : ', 'en'=>'Account holder: '],
        'period'       => ['fr'=>'Periode : ', 'en'=>'Period: '],
        'period_month' => ['fr'=>'Ce mois', 'en'=>'This month'],
        'period_all'   => ['fr'=>"Tout l'historique", 'en'=>'Entire history'],
        'period_from'  => ['fr'=>'du ', 'en'=>'from '],
        'period_to'    => ['fr'=>' au ', 'en'=>' to '],
        'generated'    => ['fr'=>'Genere le ', 'en'=>'Generated on '],
        'generated_at' => ['fr'=>' a ', 'en'=>' at '],
        'truncated'    => ['fr'=>'Limite aux {limit} dernieres transactions sur {total} au total. Choisissez une periode plus precise pour tout voir.',
                            'en'=>'Limited to the last {limit} transactions out of {total} total. Choose a more precise period to see everything.'],
        'col_date'     => ['fr'=>'Date', 'en'=>'Date'],
        'col_type'     => ['fr'=>'Type', 'en'=>'Type'],
        'col_contact'  => ['fr'=>'Contact', 'en'=>'Contact'],
        'col_amount'   => ['fr'=>'Montant', 'en'=>'Amount'],
        'col_fee'      => ['fr'=>'Frais', 'en'=>'Fee'],
        'col_ref'      => ['fr'=>'Reference', 'en'=>'Reference'],
        'col_status'   => ['fr'=>'Statut', 'en'=>'Status'],
    ];
    $row = $dict[$key] ?? null;
    if(!$row) return $key;
    return $row[$lang] ?? $row['fr'];
}

function export_type_label($type, $isDebit=false, $lang='fr'){
    if($type==='transfer'){
        if($lang==='en') return $isDebit ? 'Transfer sent' : 'Transfer received';
        return $isDebit ? 'Transfert envoye' : 'Transfert recu';
    }
    $map = $lang==='en'
        ? ['payment'=>'Purchase','bank_deposit'=>'Bank deposit',
           'bank_withdraw'=>'Bank withdrawal','deposit'=>'Deposit','vault_deposit'=>'Vault',
           'referral_bonus'=>'Referral bonus']
        : ['payment'=>'Achat','bank_deposit'=>'Depot banque',
           'bank_withdraw'=>'Retrait banque','deposit'=>'Depot','vault_deposit'=>'Coffre',
           'referral_bonus'=>'Bonus parrainage'];
    return $map[$type] ?? $type;
}

function export_xlsx() {
    $pl = auth();
    $periodRaw = $_GET['period']??'month';
    $period = in_array($periodRaw,['month','all','custom']) ? $periodRaw : 'month';
    $from = $_GET['from']??null;
    $to = $_GET['to']??null;
    $lang = ($_GET['lang']??'fr')==='en' ? 'en' : 'fr';
    $res = export_get_rows($pl, $period, $from, $to);
    $rows = $res['rows'];
    $userCurrency = q("SELECT currency FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn() ?: 'XOF';
    $curSuffix = ($userCurrency==='XOF'||$userCurrency==='XAF') ? 'F' : $userCurrency;

    // Styles : 0=normal, 1=en-tete (gras+fond+bordure), 2=texte borde
    $data = [];
    if($res['truncated']){
        $msg = str_replace(['{limit}','{total}'], [$res['limit'],$res['total']], export_t('truncated',$lang));
        $data[] = [[ $msg, 0, 's' ]];
    }
    $data[] = [
        [ export_t('col_date',$lang), 1, 's' ], [ export_t('col_type',$lang), 1, 's' ], [ export_t('col_contact',$lang), 1, 's' ],
        [ export_t('col_amount',$lang), 1, 's' ], [ export_t('col_fee',$lang), 1, 's' ], [ export_t('col_ref',$lang), 1, 's' ], [ export_t('col_status',$lang), 1, 's' ]
    ];
    foreach($rows as $t){
        $isDebit = $t['direction']==='debit';
        $amount = (float)$t['amount'];
        $net = $t['net_amount']!==null ? (float)$t['net_amount'] : $amount;
        $frais = max(0, $amount - $net);
        $montant = $isDebit ? -$amount : $net;
        $contact = $isDebit ? ($t['receiver_verified_name']?:$t['receiver_name']?:$t['receiver_merchant_name']?:$t['receiver_phone']?:'-') : ($t['sender_verified_name']?:$t['sender_name']?:$t['sender_merchant_name']?:$t['sender_phone']?:'-');
        $data[] = [
            [ date('d/m/Y H:i', strtotime($t['created_at'])), 2, 's' ],
            [ export_type_label($t['type'], $isDebit, $lang), 2, 's' ],
            [ $contact, 2, 's' ],
            [ number_format($montant,0,',',' ').' '.$curSuffix, 2, 's' ],
            [ number_format($frais,0,',',' ').' '.$curSuffix, 2, 's' ],
            [ $t['reference'], 2, 's' ],
            [ $t['status'], 2, 's' ]
        ];
    }

    $sheetXml = xlsx_build_sheet($data);
    $xlsxData = xlsx_build($sheetXml);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment; filename="rom_money_historique.xlsx"');
    header('Access-Control-Expose-Headers: X-Export-Truncated, X-Export-Total, X-Export-Limit');
    header('X-Export-Truncated: '.($res['truncated']?'1':'0'));
    header('X-Export-Total: '.$res['total']);
    header('X-Export-Limit: '.$res['limit']);
    header('Content-Length: '.strlen($xlsxData));
    echo $xlsxData;
    exit;
}

// Remplace utf8_decode() (obsolete/supprimee en PHP recent) : FPDF attend du
// Latin-1 (ISO-8859-1), pas de l'UTF-8, pour ses polices standard.
function pdf_str($s) {
    $out = @iconv('UTF-8', 'ISO-8859-1//TRANSLIT', (string)$s);
    return $out !== false ? $out : (string)$s;
}

function export_pdf() {
    $pl = auth();
    $periodRaw = $_GET['period']??'month';
    $period = in_array($periodRaw,['month','all','custom']) ? $periodRaw : 'month';
    $from = $_GET['from']??null;
    $to = $_GET['to']??null;
    $lang = ($_GET['lang']??'fr')==='en' ? 'en' : 'fr';
    $res = export_get_rows($pl, $period, $from, $to);
    $rows = $res['rows'];
    $u = q("SELECT full_name,phone_number,verified_name FROM users WHERE id=?",[$pl['sub']])->fetch();
    $userCurrency = q("SELECT currency FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn() ?: 'XOF';
    $curSuffix = ($userCurrency==='XOF'||$userCurrency==='XAF') ? 'F' : $userCurrency;

    $periodeLabel = export_t('period_month',$lang);
    if($period==='all') $periodeLabel = export_t('period_all',$lang);
    elseif($period==='custom'){
        $fmtYm = function($ym){ $p=explode('-',(string)$ym); return count($p)===2 ? $p[1].'-'.$p[0] : $ym; };
        $periodeLabel = export_t('period_from',$lang).$fmtYm($from).export_t('period_to',$lang).$fmtYm($to);
    }

    require_once __DIR__.'/fpdf.php';
    $pdf = new FPDF();
    $pdf->AddPage();
    $pdf->SetFont('Arial','B',14);
    $pdf->Cell(0,10,pdf_str(export_t('title',$lang)),0,1);
    $infoTopY = $pdf->GetY();
    $logoPath = __DIR__.'/logo.png';
    if(file_exists($logoPath)){
        $pdf->Image($logoPath, 182, $infoTopY, 18, 18);
    }
    $pdf->SetFont('Arial','',10);
    $pdf->Cell(150,6,pdf_str(export_t('holder',$lang).($u['verified_name']?:$u['full_name']?:'').' ('.$u['phone_number'].')'),0,1);
    $pdf->Cell(150,6,pdf_str(export_t('period',$lang).$periodeLabel),0,1);
    $pdf->Cell(150,6,pdf_str(export_t('generated',$lang).date('d/m/Y').export_t('generated_at',$lang).date('H:i')),0,1);
    if(file_exists($logoPath)){
        $pdf->SetY(max($pdf->GetY(), $infoTopY+18));
    }
    if($res['truncated']){
        $pdf->SetTextColor(200,0,0);
        $msg = str_replace(['{limit}','{total}'], [$res['limit'],$res['total']], export_t('truncated',$lang));
        $pdf->Cell(0,6,pdf_str($msg),0,1);
        $pdf->SetTextColor(0,0,0);
    }
    $pdf->Ln(4);

    $pdf->SetFont('Arial','B',9);
    $pdf->SetFillColor(230,241,251);
    $w = [26,28,42,28,20,32,20];
    $headers = [export_t('col_date',$lang), export_t('col_type',$lang), export_t('col_contact',$lang),
        export_t('col_amount',$lang), export_t('col_fee',$lang), export_t('col_ref',$lang), export_t('col_status',$lang)];
    foreach($headers as $i=>$h){ $pdf->Cell($w[$i],8,pdf_str($h),1,0,'C',true); }
    $pdf->Ln();

    $pdf->SetFont('Arial','',8);
    foreach($rows as $t){
        $isDebit = $t['direction']==='debit';
        $amount = (float)$t['amount'];
        $net = $t['net_amount']!==null ? (float)$t['net_amount'] : $amount;
        $frais = max(0, $amount - $net);
        $montant = $isDebit ? -$amount : $net;
        $contact = $isDebit ? ($t['receiver_verified_name']?:$t['receiver_name']?:$t['receiver_merchant_name']?:$t['receiver_phone']?:'-') : ($t['sender_verified_name']?:$t['sender_name']?:$t['sender_merchant_name']?:$t['sender_phone']?:'-');

        $pdf->Cell($w[0],7,date('d/m/y H:i',strtotime($t['created_at'])),1);
        $pdf->Cell($w[1],7,pdf_str(export_type_label($t['type'],$isDebit,$lang)),1);
        $pdf->Cell($w[2],7,substr(pdf_str($contact),0,22),1);
        $pdf->Cell($w[3],7,number_format($montant,0,',',' ').' '.$curSuffix,1,0,'R');
        $pdf->Cell($w[4],7,number_format($frais,0,',',' ').' '.$curSuffix,1,0,'R');
        $pdf->Cell($w[5],7,pdf_str($t['reference']),1);
        $pdf->Cell($w[6],7,pdf_str($t['status']),1);
        $pdf->Ln();
    }

    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="rom_money_releve.pdf"');
    echo $pdf->Output('S');
    exit;
}

// ============================================================
// ANNONCES — messages pousses par l'admin (mises a jour / promos)
// Les "update" sont toujours renvoyees. Les "promo" ne sont renvoyees
// que si l'utilisateur a active "Offres et promotions" dans ses reglages.
// ============================================================
function route_push($action) {
    switch($action) {
        case 'vapid-key':
            ok(['public_key' => VAPID_PUBLIC_KEY]);
            break;
        case 'subscribe': {
            $pl = auth(); $b = body();
            $endpoint = trim($b['endpoint'] ?? '');
            $p256dh   = trim($b['p256dh'] ?? '');
            $authKey  = trim($b['auth'] ?? '');
            if(!$endpoint || !$p256dh || !$authKey) fail('Abonnement push invalide');
            q("INSERT INTO push_subscriptions (user_id,endpoint,p256dh_key,auth_key)
               VALUES (?,?,?,?)
               ON CONFLICT (user_id, endpoint) DO UPDATE SET p256dh_key=EXCLUDED.p256dh_key, auth_key=EXCLUDED.auth_key",
              [$pl['sub'], $endpoint, $p256dh, $authKey]);
            ok(null, 'Notifications push activees');
            break;
        }
        case 'unsubscribe': {
            $pl = auth(); $b = body();
            $endpoint = trim($b['endpoint'] ?? '');
            if($endpoint){
                q("DELETE FROM push_subscriptions WHERE user_id=? AND endpoint=?", [$pl['sub'], $endpoint]);
            } else {
                q("DELETE FROM push_subscriptions WHERE user_id=?", [$pl['sub']]);
            }
            ok(null, 'Notifications push desactivees');
            break;
        }
        // Abonnement push cote ADMIN : distinct du systeme utilisateur
        // ci-dessus (protege par mot de passe admin, pas par jeton JWT
        // utilisateur, puisque l'admin n'a pas de compte "utilisateur").
        case 'admin-subscribe': {
            $b = body();
            check_admin_password($b);
            $endpoint = trim($b['endpoint'] ?? '');
            $p256dh   = trim($b['p256dh'] ?? '');
            $authKey  = trim($b['auth'] ?? '');
            if(!$endpoint || !$p256dh || !$authKey) fail('Abonnement push invalide');
            q("INSERT INTO admin_push_subscriptions (endpoint,p256dh_key,auth_key)
               VALUES (?,?,?)
               ON CONFLICT (endpoint) DO UPDATE SET p256dh_key=EXCLUDED.p256dh_key, auth_key=EXCLUDED.auth_key",
              [$endpoint, $p256dh, $authKey]);
            ok(null, 'Notifications push admin activees');
            break;
        }
        case 'admin-unsubscribe': {
            $b = body();
            check_admin_password($b);
            $endpoint = trim($b['endpoint'] ?? '');
            if($endpoint){
                q("DELETE FROM admin_push_subscriptions WHERE endpoint=?", [$endpoint]);
            } else {
                q("DELETE FROM admin_push_subscriptions");
            }
            ok(null, 'Notifications push admin desactivees');
            break;
        }
        // Abonnement push cote ROM_BUSINESS : meme principe que ci-dessus mais
        // avec merchant_auth() et sa propre table (identite marchand separee).
        case 'merchant-subscribe': {
            $pl = merchant_auth(); $b = body();
            $endpoint = trim($b['endpoint'] ?? '');
            $p256dh   = trim($b['p256dh'] ?? '');
            $authKey  = trim($b['auth'] ?? '');
            if(!$endpoint || !$p256dh || !$authKey) fail('Abonnement push invalide');
            q("INSERT INTO merchant_push_subscriptions (merchant_id,endpoint,p256dh_key,auth_key)
               VALUES (?,?,?,?)
               ON CONFLICT (merchant_id, endpoint) DO UPDATE SET p256dh_key=EXCLUDED.p256dh_key, auth_key=EXCLUDED.auth_key",
              [$pl['sub'], $endpoint, $p256dh, $authKey]);
            ok(null, 'Notifications push activees');
            break;
        }
        case 'merchant-unsubscribe': {
            $pl = merchant_auth(); $b = body();
            $endpoint = trim($b['endpoint'] ?? '');
            if($endpoint){
                q("DELETE FROM merchant_push_subscriptions WHERE merchant_id=? AND endpoint=?", [$pl['sub'], $endpoint]);
            } else {
                q("DELETE FROM merchant_push_subscriptions WHERE merchant_id=?", [$pl['sub']]);
            }
            ok(null, 'Notifications push desactivees');
            break;
        }
        // Abonnement push cote ROM_GUICHET : meme principe, avec agent_auth()
        // et sa propre table (identite agent separee).
        case 'agent-subscribe': {
            $pl = agent_auth(); $b = body();
            $endpoint = trim($b['endpoint'] ?? '');
            $p256dh   = trim($b['p256dh'] ?? '');
            $authKey  = trim($b['auth'] ?? '');
            if(!$endpoint || !$p256dh || !$authKey) fail('Abonnement push invalide');
            q("INSERT INTO agent_push_subscriptions (agent_id,endpoint,p256dh_key,auth_key)
               VALUES (?,?,?,?)
               ON CONFLICT (agent_id, endpoint) DO UPDATE SET p256dh_key=EXCLUDED.p256dh_key, auth_key=EXCLUDED.auth_key",
              [$pl['sub'], $endpoint, $p256dh, $authKey]);
            ok(null, 'Notifications push activees');
            break;
        }
        case 'agent-unsubscribe': {
            $pl = agent_auth(); $b = body();
            $endpoint = trim($b['endpoint'] ?? '');
            if($endpoint){
                q("DELETE FROM agent_push_subscriptions WHERE agent_id=? AND endpoint=?", [$pl['sub'], $endpoint]);
            } else {
                q("DELETE FROM agent_push_subscriptions WHERE agent_id=?", [$pl['sub']]);
            }
            ok(null, 'Notifications push desactivees');
            break;
        }
        default: fail('Action inconnue', 404);
    }
}

function route_announce($action) {
    match($action) {
        'list'         => announce_list(),
        'admin-create' => announce_admin_create(),
        default        => fail('Action inconnue',404)
    };
}

function announce_list() {
    $pl = auth();
    $lang = ($_GET['lang']??'fr')==='en' ? 'en' : 'fr';
    $u = q("SELECT notif_promo FROM users WHERE id=?",[$pl['sub']])->fetch();
    $allowPromo = (bool)($u['notif_promo'] ?? true);
    if($allowPromo){
        $rows = q("SELECT id,title,message,title_en,message_en,type,created_at FROM announcements
            WHERE created_at >= NOW() - INTERVAL '30 days' ORDER BY created_at ASC")->fetchAll();
    } else {
        $rows = q("SELECT id,title,message,title_en,message_en,type,created_at FROM announcements
            WHERE type='update' AND created_at >= NOW() - INTERVAL '30 days' ORDER BY created_at ASC")->fetchAll();
    }
    // Resout la bonne langue cote serveur : si une traduction EN existe et que le
    // client la demande, on la sert ; sinon on retombe sur le francais (langue
    // de saisie par defaut de l'admin).
    $resolved = array_map(function($r) use ($lang){
        return [
            'id' => $r['id'],
            'title' => ($lang==='en' && !empty($r['title_en'])) ? $r['title_en'] : $r['title'],
            'message' => ($lang==='en' && !empty($r['message_en'])) ? $r['message_en'] : $r['message'],
            'type' => $r['type'],
            'created_at' => $r['created_at']
        ];
    }, $rows);
    ok(['announcements'=>$resolved]);
}

function announce_admin_create() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $title = trim($b['title']??'');
    $message = trim($b['message']??'');
    $titleEn = trim($b['title_en']??'');
    $messageEn = trim($b['message_en']??'');
    $type = ($b['type']??'update')==='promo' ? 'promo' : 'update';
    if(!$title || !$message) fail('Titre et message requis');
    $id = uid();
    q("INSERT INTO announcements (id,title,message,title_en,message_en,type) VALUES (?,?,?,?,?,?)",
        [$id,$title,$message,$titleEn?:null,$messageEn?:null,$type]);
    ok(['id'=>$id],'Annonce envoyee');
}

// ============================================================
// ADMIN — outils reserves (protege par mot de passe, cf check_admin_password)
// Chaque action sensible est journalisee dans audit_logs.
// ============================================================
function route_admin($action) {
    match($action) {
        'login'             => admin_login_check(),
        'reset-pin'         => admin_reset_pin(),
        'search-tx'         => admin_search_tx(),
        'search-phone'      => admin_search_by_phone(),
        'test-credit-wallet' => admin_test_credit_wallet(),
        'merchant-test-credit-wallet' => admin_merchant_test_credit_wallet(),
        'late-cancel'       => admin_late_cancel(),
        'audit-list'        => admin_audit_list(),
        'accounts-list'     => admin_accounts_list(),
        'accounts-create'   => admin_accounts_create(),
        'accounts-set-active' => admin_accounts_set_active(),
        'accounts-reset-password' => admin_accounts_reset_password(),
        'accounts-set-countries' => admin_accounts_set_countries(),
        'dashboard-stats'   => admin_dashboard_stats(),
        'audit-export-xlsx' => admin_audit_export_xlsx(),
        'audit-export-pdf'  => admin_audit_export_pdf(),
        'countries-list'    => admin_countries_list(),
        'country-toggle'    => admin_country_toggle(),
        'account-status'    => admin_account_status(),
        'block-account'     => admin_block_account(),
        'unblock-account'   => admin_unblock_account(),
        'update-country'    => admin_update_country(),
        'delete-kyc'        => admin_delete_kyc(),
        'list-users'        => admin_list_users(),
        'list-alerts'       => admin_list_alerts(),
        'dashboard-export-xlsx' => admin_dashboard_export_xlsx(),
        'get-settings'      => admin_get_settings(),
        'update-settings'   => admin_update_settings(),
        'dashboard-export-pdf' => admin_dashboard_export_pdf(),
        '2fa-status'        => admin_2fa_status(),
        '2fa-setup'         => admin_2fa_setup(),
        '2fa-confirm'       => admin_2fa_confirm(),
        '2fa-disable'       => admin_2fa_disable(),
        '2fa-regenerate-codes' => admin_2fa_regenerate_codes(),
        'kyc-migrate-encrypt'  => admin_kyc_migrate_encrypt(),
        'backfill-verified-names' => admin_backfill_verified_names(),
        'delete-account' => admin_delete_account(),
        'get-exchange-rates' => admin_get_exchange_rates(),
        'refresh-exchange-rates' => admin_refresh_exchange_rates(),
        'freeze-tx'      => admin_freeze_transaction(),
        'unfreeze-tx'    => admin_unfreeze_transaction(),
        'confirm-cancel-frozen' => admin_confirm_cancel_frozen(),
        'list-frozen'    => admin_list_frozen(),
        'list-fraud-alerts'    => admin_list_fraud_alerts(),
        'mark-fraud-reviewed'  => admin_mark_fraud_reviewed(),
        'merchant-search'          => admin_merchant_search(),
        'merchant-update-country'  => admin_merchant_update_country(),
        'merchant-delete-account'  => admin_merchant_delete_account(),
        'merchant-toggle-verified' => admin_merchant_toggle_verified(),
        'merchant-block'           => admin_merchant_block(),
        'merchant-unblock'         => admin_merchant_unblock(),
        'merchant-reset-pin'       => admin_merchant_reset_pin(),
        'merchant-list'            => admin_merchant_list(),
        'agent-search'             => admin_agent_search(),
        'agent-list'               => admin_agent_list(),
        'agent-test-credit-wallet' => admin_agent_test_credit_wallet(),
        'agent-delete-account'     => admin_agent_delete_account(),
        'agent-recharge-list'      => admin_agent_list_recharge_requests(),
        'agent-recharge-approve'   => admin_agent_approve_recharge(),
        'agent-recharge-movements' => admin_agent_recharge_movements(),
        'agent-tiers-list'         => admin_agent_commission_tiers_list(),
        'agent-tiers-update'       => admin_agent_commission_tiers_update(),
        'agent-toggle-distributor' => admin_agent_toggle_distributor(),
        'agent-set-float-cap'      => admin_agent_set_float_cap(),
        'agent-pending-list'       => admin_agent_list_pending(),
        'agent-documents'          => admin_agent_documents(),
        'agent-approve-registration' => admin_agent_approve_registration(),
        'agent-reject-registration'  => admin_agent_reject_registration(),
        'agent-reopen-registration'  => admin_agent_reopen_registration(),
        'agent-delete-document'    => admin_agent_delete_document(),
        'add-note'                 => admin_add_note(),
        'search-tx-advanced'       => admin_search_tx_advanced(),
        'users-export-xlsx'        => admin_users_export_xlsx(),
        'users-export-pdf'         => admin_users_export_pdf(),
        'list-near-limit'          => admin_list_near_limit(),
        'merchant-add-note'        => admin_merchant_add_note(),
        'merchant-search-tx-advanced' => admin_merchant_search_tx_advanced(),
        'merchants-export-xlsx'    => admin_merchants_export_xlsx(),
        'merchants-export-pdf'     => admin_merchants_export_pdf(),
        'merchant-documents'       => admin_merchant_documents(),
        'merchant-delete-document' => admin_merchant_delete_document(),
        'earnings-summary'         => admin_earnings_summary(),
        'earnings-withdraw'        => admin_earnings_withdraw(),
        'earnings-cancel-withdrawal' => admin_earnings_cancel_withdrawal(),
        'earnings-fees-stats' => admin_earnings_fees_stats(),
        default             => fail('Action inconnue',404)
    };
}

// ============================================================
// GAINS ROM — le compte systeme (0160629502, meme table users/wallets
// qu'un compte personnel classique) accumule tous les frais preleves par
// la plateforme (voir credit_merchant_fee() et les blocs de frais dans
// tx_send()). Tant qu'aucun partenaire bancaire/mobile money reel n'est
// integre (voir la suppression du module banque simule), le seul moyen
// de "sortir" cet argent est manuel : l'admin transfere lui-meme l'argent
// reel de son cote (via son propre Mobile Money), puis enregistre ici le
// montant retire pour que le solde du compte systeme reste le reflet
// honnete de ce qui n'a PAS encore ete retire - aucun vrai mouvement
// bancaire n'est declenche par cette fonction.
function admin_earnings_summary() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    check_earnings_password($b);
    $w = q("SELECT w.id,w.balance FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",['0160629502'])->fetch();
    if(!$w) fail('Compte systeme introuvable (0160629502)',404);
    $totalWithdrawn = (float)q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE sender_wallet_id=? AND type='manual_withdrawal' AND status='completed'",[$w['id']])->fetchColumn();
    $withdrawals = q("SELECT id,amount,description,reference,created_at FROM transactions WHERE sender_wallet_id=? AND type='manual_withdrawal' AND status='completed' ORDER BY created_at DESC LIMIT 50",[$w['id']])->fetchAll();
    ok(['balance'=>(float)$w['balance'],'total_withdrawn'=>$totalWithdrawn,'withdrawals'=>$withdrawals]);
}

function admin_earnings_withdraw() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    check_earnings_password($b);
    $amount = (float)($b['amount']??0);
    $recipientType = trim($b['recipient_type']??'');
    $recipient = trim($b['recipient']??'');
    $reason = trim($b['reason']??'');
    $typeLabels = ['mobile_money'=>'Mobile Money','bank'=>'Compte bancaire','other'=>'Autre'];
    if($amount<=0) fail('Montant invalide');
    if(!isset($typeLabels[$recipientType])) fail('Le type de destinataire est obligatoire');
    if(!$recipient) fail('Le destinataire est obligatoire (journalise)');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $w = q("SELECT w.id,w.balance FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",['0160629502'])->fetch();
    if(!$w) fail('Compte systeme introuvable (0160629502)',404);
    if((float)$w['balance'] < $amount) fail('Solde insuffisant sur le compte systeme');
    // Type/destinataire/raison stockes ensemble dans description (seul champ
    // texte libre disponible sur transactions) - le type prefixe le champ
    // libre pour lever toute ambiguite a la lecture de l'historique (un
    // meme champ texte pouvait autrement contenir aussi bien un numero
    // Mobile Money qu'un numero de compte bancaire, sans indication claire
    // de sa nature).
    $description = '['.$typeLabels[$recipientType].'] Vers : '.$recipient.' — '.$reason;
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'manual_withdrawal','completed',?,?)",
          [$txid,$w['id'],$amount,$reference,$description]);
        $rows = q("UPDATE wallets SET balance=balance-? WHERE id=? AND balance>=?",[$amount,$w['id'],$amount])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        db()->commit();
        admin_log('earnings_withdraw','success',null,dk('d_ref_with_reason', ['ref'=>$reference, 'reason'=>$description]));
        $bal = (float)q("SELECT balance FROM wallets WHERE id=?",[$w['id']])->fetchColumn();
        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$amount,'new_balance'=>$bal],'Retrait enregistre');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec de l\'enregistrement', 500); }
}

// Corrige une entree de retrait saisie par erreur (mauvais montant, faux
// destinataire...) : recredite le compte systeme et marque l'entree comme
// annulee. N'est PAS une annulation de mouvement bancaire reel (il n'y en a
// jamais eu) - juste la correction d'une erreur de saisie dans ce journal.
function admin_earnings_cancel_withdrawal() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    check_earnings_password($b);
    $txid = trim($b['transaction_id']??'');
    $reason = trim($b['reason']??'');
    if(!$txid) fail('ID requis');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $tx = q("SELECT t.*,w.id wid FROM transactions t JOIN wallets w ON t.sender_wallet_id=w.id WHERE t.id=? AND t.type='manual_withdrawal'",[$txid])->fetch();
    if(!$tx) fail('Retrait introuvable',404);
    if($tx['status']!=='completed') fail('Ce retrait n\'est pas au statut "completed" (deja annule)');
    db()->beginTransaction();
    try {
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$tx['amount'],$tx['wid']]);
        q("UPDATE transactions SET status='cancelled', cancelled_at=NOW(), cancel_reason=? WHERE id=?",[$reason,$txid]);
        db()->commit();
        admin_log('earnings_withdraw_cancel','success',null,dk('d_ref_with_reason', ['ref'=>$tx['reference'], 'reason'=>$reason]));
        $bal = (float)q("SELECT balance FROM wallets WHERE id=?",[$tx['wid']])->fetchColumn();
        ok(['new_balance'=>$bal],'Retrait annule, solde recredite');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec de l\'annulation', 500); }
}

// Meme resolution de periode que admin_dashboard_get_data() (dupliquee ici
// plutot que partagee, pour ne pas toucher a une fonction du dashboard
// deja en production) mais separe explicitement les frais personnels
// (sender_wallet_id) des frais marchands (sender_merchant_wallet_id) - le
// dashboard commun ne fait actuellement que les additionner.
function admin_earnings_fees_breakdown($period, $dateFrom, $dateTo) {
    $where = "status='completed' AND type='fee'";
    $params = [];
    if ($period==='7d') {
        $where .= " AND created_at >= NOW() - INTERVAL '7 days'";
    } elseif ($period==='month') {
        $where .= " AND created_at >= date_trunc('month', CURRENT_DATE)";
    } elseif ($period==='custom' && $dateFrom!=='' && $dateTo!=='') {
        $where .= " AND created_at >= ? AND created_at <= ?";
        $params[] = $dateFrom.' 00:00:00';
        $params[] = $dateTo.' 23:59:59';
    } elseif ($period==='all') {
        // pas de condition supplementaire
    } else {
        $period = 'today';
        $where .= " AND created_at >= CURRENT_DATE";
    }
    $personalFees = (float)q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE $where AND sender_wallet_id IS NOT NULL", $params)->fetchColumn();
    $merchantFees = (float)q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE $where AND sender_merchant_wallet_id IS NOT NULL", $params)->fetchColumn();
    return ['period'=>$period,'personal_fees'=>$personalFees,'merchant_fees'=>$merchantFees,'total_fees'=>$personalFees+$merchantFees];
}

function admin_earnings_fees_stats() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    check_earnings_password($b);
    $period = trim($b['period'] ?? 'today');
    $dateFrom = trim($b['date_from'] ?? '');
    $dateTo = trim($b['date_to'] ?? '');
    ok(admin_earnings_fees_breakdown($period, $dateFrom, $dateTo));
}

// Capture automatiquement l'IP et l'appareil/navigateur (user-agent) sur
// CHAQUE action journalisee, sans que les ~20 fonctions qui appellent deja
// admin_log() n'aient besoin d'etre modifiees une par une.
// $details accepte deux formats :
// - une chaine de texte brute (ancien comportement, jamais traduite - reste
//   en francais pour toujours, y compris pour tout l'historique deja en
//   base avant ce changement)
// - un tableau ['key'=>'...', 'params'=>[...]] (nouveau, traduisible cote
//   client selon la langue admin choisie) - stocke avec un prefixe "I18N::"
//   reconnaissable, pour ne jamais confondre les deux formats a la lecture.
function admin_log($action, $result, $targetPhone, $details) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;
    $stored = is_array($details) ? ('I18N::'.json_encode($details, JSON_UNESCAPED_UNICODE)) : $details;
    // Renseigne par check_admin_password_str() plus tot dans la meme requete
    // - null pour les tres rares appels sans mot de passe admin prealable
    // (ex: echec de connexion, ou le mot de passe teste ne correspond a
    // personne - voir admin_login pas de nom resolu).
    $adminName = $GLOBALS['_current_admin_name'] ?? null;
    q("INSERT INTO audit_logs (action,result,target_phone,details,ip_address,user_agent,admin_name) VALUES (?,?,?,?,?,?,?)",
      [$action,$result,$targetPhone,$stored,$ip,$ua,$adminName]);
    admin_notify_if_sensitive($action, $result, $targetPhone, $stored, $ip);
}
// Raccourci pour construire une entree traduisible sans repeter la structure
// du tableau a chaque appel : dk('d_login_success') ou avec parametres
// dk('d_ref_with_reason', ['ref'=>$ref, 'reason'=>$reason]).
function dk($key, $params = []) {
    return ['key' => $key, 'params' => $params];
}

// Liste volontairement courte : seulement les actions ou une notification
// immediate a une vraie valeur (savoir tout de suite plutot qu'en consultant
// le journal plus tard). Trop d'alertes = alertes ignorees, donc on reste
// concentre sur l'essentiel : connexion admin (toute connexion reussie,
// meme legitime - c'est justement le principe), et les actions qui bougent
// de l'argent ou changent la protection du compte.
function admin_notify_if_sensitive($action, $result, $targetPhone, $details, $ip) {
    if ($result !== 'success') return;
    $sensitive = ['admin_login','account_block','pin_reset','late_cancel','2fa_disable'];
    if (!in_array($action, $sensitive, true)) return;
    $labels = [
        'admin_login'   => 'Connexion admin reussie',
        'account_block' => 'Compte utilisateur bloque',
        'pin_reset'     => 'PIN utilisateur reinitialise',
        'late_cancel'   => 'Transaction annulee (apres coup)',
        '2fa_disable'   => 'Double authentification admin desactivee',
    ];
    $title = $labels[$action] ?? 'Action admin sensible';
    $body = ($targetPhone ? 'Compte '.$targetPhone.' — ' : '').($ip ? 'IP '.$ip : '');
    web_push_send_to_admin($title, $body ?: 'Voir le journal d\'audit pour le detail');
}

// Anti brute-force : bloque les tentatives de mot de passe admin apres N
// echecs recents (fenetre glissante basee sur audit_logs, pas besoin de
// nouvelle table). Seuil et duree modifiables par l'admin lui-meme dans
// Reglages, sans redeploiement (memes principes que fee_rate_* etc.).
function admin_bruteforce_check() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $maxAttempts = (int)get_setting('admin_bf_max_attempts', 3);
    $blockMinutes = (int)get_setting('admin_bf_block_minutes', 60);
    $row = q("SELECT COUNT(*) c FROM audit_logs
              WHERE action='admin_login' AND result='failed' AND ip_address=?
              AND created_at > NOW() - (?::text || ' minutes')::interval",
              [$ip, $blockMinutes])->fetch();
    if($row && (int)$row['c'] >= $maxAttempts) {
        fail('Trop de tentatives echouees depuis cette adresse. Reessayez dans '.$blockMinutes.' minutes.', 429);
    }
}

function admin_2fa_enabled() { return get_setting('admin_2fa_enabled','0') === '1'; }

function admin_login_check() {
    $b = body();
    check_admin_password_str((string)($b['admin_password'] ?? ''));
    if (admin_2fa_enabled()) {
        $totpCode = trim((string)($b['totp_code'] ?? ''));
        $recoveryCode = trim((string)($b['recovery_code'] ?? ''));
        if ($totpCode === '' && $recoveryCode === '') {
            // Mot de passe correct mais code 2FA pas encore fourni : ce
            // n'est pas un echec (pas de log 'failed', pas de decompte
            // brute-force), juste une etape supplementaire attendue par
            // le frontend.
            http_response_code(200);
            echo json_encode(['success'=>false,'need_2fa'=>true,'message'=>'Code de verification requis'], JSON_UNESCAPED_UNICODE);
            exit;
        }
        $secret = get_setting('admin_2fa_secret', '');
        $verified = false;
        $usedRecovery = false;
        if ($totpCode !== '' && $secret !== '' && totp_verify($secret, $totpCode)) {
            $verified = true;
        } elseif ($recoveryCode !== '') {
            $codes = json_decode(get_setting('admin_2fa_recovery_codes', '[]'), true) ?: [];
            $recoveryCode = strtoupper(preg_replace('/[^A-Z0-9]/','', $recoveryCode));
            foreach ($codes as $idx => $hashed) {
                if (password_verify($recoveryCode, $hashed)) {
                    $verified = true;
                    $usedRecovery = true;
                    unset($codes[$idx]); // code a usage unique
                    set_setting('admin_2fa_recovery_codes', json_encode(array_values($codes)));
                    break;
                }
            }
        }
        if (!$verified) {
            admin_log('admin_login','failed',null,dk('d_2fa_invalid'));
            fail('Code de verification incorrect',401);
        }
        if ($usedRecovery) {
            admin_log('admin_login','success',null,dk('d_login_success_recovery'));
            ok(['recovery_used'=>true,'admin_name'=>$GLOBALS['_current_admin_name']??null,'is_super_admin'=>($GLOBALS['_current_admin_name']??null)==='Admin Principal','countries'=>$GLOBALS['_current_admin_countries']??null],'Connexion reussie');
            return;
        }
    }
    admin_log('admin_login','success',null,dk('d_login_success'));
    ok(['admin_name'=>$GLOBALS['_current_admin_name']??null,'is_super_admin'=>($GLOBALS['_current_admin_name']??null)==='Admin Principal','countries'=>$GLOBALS['_current_admin_countries']??null],'Connexion reussie');
}

function admin_2fa_status() {
    $b = body();
    check_admin_password($b);
    ok(['enabled' => admin_2fa_enabled()]);
}

// Etape 1 : genere un nouveau secret + QR code (URI otpauth://) + codes de
// recuperation. Rien n'est active tant que l'admin n'a pas prouve, via
// 2fa-confirm, qu'il a bien configure son application (Google Authenticator
// etc.) avec ce secret — evite de se retrouver bloque hors de l'admin par
// une mauvaise manipulation.
function admin_2fa_setup() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $secret = totp_generate_secret();
    $recoveryCodesPlain = totp_generate_recovery_codes(10);
    $recoveryCodesHashed = array_map(fn($c) => password_hash($c, PASSWORD_BCRYPT), $recoveryCodesPlain);
    // Stocke en "pending" tant que non confirme (cle separee de la cle active)
    set_setting('admin_2fa_secret_pending', $secret);
    set_setting('admin_2fa_recovery_codes_pending', json_encode($recoveryCodesHashed));
    $otpauth = 'otpauth://totp/ROM-MONEY%20Admin?secret='.$secret.'&issuer=ROM-MONEY&period=30&digits=6';
    admin_log('2fa_setup_started','success',null,dk('d_2fa_secret_generated'));
    ok(['secret'=>$secret, 'otpauth_uri'=>$otpauth, 'recovery_codes'=>$recoveryCodesPlain]);
}

// Etape 2 : l'admin scanne le QR et tape le code affiche par son
// application pour prouver que la configuration fonctionne AVANT que le
// 2FA ne devienne obligatoire a la connexion.
function admin_2fa_confirm() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $code = trim((string)($b['totp_code'] ?? ''));
    $secret = get_setting('admin_2fa_secret_pending', '');
    if ($secret === '') fail('Aucune configuration 2FA en attente. Relancez la generation du QR code.');
    if (!totp_verify($secret, $code)) {
        admin_log('2fa_setup_confirm','failed',null,dk('d_confirm_code_wrong'));
        fail('Code incorrect. Verifiez l\'heure de votre telephone et reessayez.',401);
    }
    set_setting('admin_2fa_secret', $secret);
    set_setting('admin_2fa_recovery_codes', get_setting('admin_2fa_recovery_codes_pending','[]'));
    set_setting('admin_2fa_enabled', '1');
    set_setting('admin_2fa_secret_pending', '');
    set_setting('admin_2fa_recovery_codes_pending', '');
    admin_log('2fa_setup_confirm','success',null,dk('d_2fa_activated'));
    ok(null,'Double authentification activee avec succes');
}

function admin_2fa_disable() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    if (admin_2fa_enabled()) {
        $code = trim((string)($b['totp_code'] ?? ''));
        $secret = get_setting('admin_2fa_secret', '');
        if (!totp_verify($secret, $code)) {
            admin_log('2fa_disable','failed',null,dk('d_confirm_code_wrong'));
            fail('Code incorrect',401);
        }
    }
    set_setting('admin_2fa_enabled', '0');
    set_setting('admin_2fa_secret', '');
    set_setting('admin_2fa_recovery_codes', '[]');
    admin_log('2fa_disable','success',null,dk('d_2fa_deactivated'));
    ok(null,'Double authentification desactivee');
}

// Regenere les 10 codes de recuperation SANS toucher au secret ni
// desactiver le 2FA (donc aucune interruption d'acces). Exige un code TOTP
// valide (pas juste le mot de passe) : ca prouve que l'admin a toujours son
// telephone en main, ce qui est precisement le but recherche puisque ces
// codes servent en cas de perte du telephone. Les anciens codes deviennent
// immediatement invalides (ils sont remplaces, pas ajoutes).
function admin_2fa_regenerate_codes() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    if (!admin_2fa_enabled()) fail('La double authentification n\'est pas activee');
    $code = trim((string)($b['totp_code'] ?? ''));
    $secret = get_setting('admin_2fa_secret', '');
    if (!totp_verify($secret, $code)) {
        admin_log('2fa_regenerate_codes','failed',null,dk('d_confirm_code_wrong'));
        fail('Code incorrect',401);
    }
    $recoveryCodesPlain = totp_generate_recovery_codes(10);
    $recoveryCodesHashed = array_map(fn($c) => password_hash($c, PASSWORD_BCRYPT), $recoveryCodesPlain);
    set_setting('admin_2fa_recovery_codes', json_encode($recoveryCodesHashed));
    admin_log('2fa_regenerate_codes','success',null,dk('d_recovery_codes_regenerated'));
    ok(['recovery_codes'=>$recoveryCodesPlain],'Nouveaux codes generes');
}

// Migration a usage unique : chiffre les photos KYC deja en base AVANT la
// mise en place du chiffrement (donc encore en texte brut). Sans effet sur
// les demandes deja chiffrees (marqueur ENC1: detecte, ignorees). Peut etre
// relance sans risque plusieurs fois - les entrees deja migrees sont
// simplement ignorees a chaque fois.
function admin_kyc_migrate_encrypt() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $rows = q("SELECT id, photo_recto, photo_verso FROM kyc_requests")->fetchAll();
    $migrated = 0;
    foreach ($rows as $r) {
        $needsRecto = $r['photo_recto'] && strpos($r['photo_recto'], 'ENC1:') !== 0;
        $needsVerso = $r['photo_verso'] && strpos($r['photo_verso'], 'ENC1:') !== 0;
        if (!$needsRecto && !$needsVerso) continue;
        $newRecto = $needsRecto ? kyc_encrypt($r['photo_recto']) : $r['photo_recto'];
        $newVerso = $needsVerso ? kyc_encrypt($r['photo_verso']) : $r['photo_verso'];
        q("UPDATE kyc_requests SET photo_recto=?, photo_verso=? WHERE id=?", [$newRecto, $newVerso, $r['id']]);
        $migrated++;
    }
    admin_log('kyc_migrate_encrypt','success',null,dk('d_kyc_migrated', ['count'=>$migrated]));
    ok(['migrated'=>$migrated],'Migration terminee');
}

// Migration a usage unique : corrige les comptes marques "verifie" (is_kyc=1)
// mais dont verified_name est reste vide - typiquement des comptes approuves
// AVANT que cette colonne n'existe dans le schema. Pour chacun, va chercher
// sa demande KYC approuvee la plus recente (source la plus fiable : le nom
// legal qu'il avait soumis) ; a defaut, se rabat sur le nom de profil actuel
// (mieux que rien). Sans effet sur les comptes deja corrects - peut etre
// relance sans risque plusieurs fois.
function admin_backfill_verified_names() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $users = q("SELECT id, full_name FROM users WHERE is_kyc=1 AND (verified_name IS NULL OR verified_name='')")->fetchAll();
    $fixed = 0;
    foreach ($users as $u) {
        $kyc = q("SELECT legal_name, legal_birthdate FROM kyc_requests WHERE user_id=? AND status='approved' ORDER BY reviewed_at DESC NULLS LAST, created_at DESC LIMIT 1", [$u['id']])->fetch();
        $verifiedName = ($kyc && $kyc['legal_name']) ? $kyc['legal_name'] : $u['full_name'];
        $verifiedBirthdate = $kyc ? ($kyc['legal_birthdate'] ?: null) : null;
        q("UPDATE users SET verified_name=?, verified_birthdate=? WHERE id=?", [$verifiedName, $verifiedBirthdate, $u['id']]);
        $fixed++;
    }
    admin_log('backfill_verified_names','success',null,dk('d_accounts_fixed', ['count'=>$fixed]));
    ok(['fixed'=>$fixed],'Migration terminee');
}

function admin_reset_pin() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone']??'');
    $newPin = trim($b['new_pin']??'');
    $reason = trim($b['reason']??'');
    if(!preg_match('/^\d{4}$/',$newPin)) fail('Le nouveau PIN doit contenir exactement 4 chiffres');
    if(is_weak_pin($newPin)) fail('Ce code est trop simple, choisissez une autre combinaison');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    // Le compte systeme (gains de la plateforme) ne doit jamais etre
    // manipulable via les outils generiques (ADMIN_PASSWORD seul) - sinon un
    // admin pourrait lui fixer un PIN connu puis se connecter dessus comme un
    // compte normal et vider tout le solde accumule, sans jamais toucher a
    // l'onglet Gains ROM ni a son mot de passe separe (EARNINGS_PASSWORD).
    if($phone === '0160629502'){
        admin_log('pin_reset','failed',$phone,'Tentative de reinitialisation du PIN du compte systeme via l\'outil generique (bloquee)');
        fail('Ce compte est reserve a l\'onglet Gains ROM.',403);
    }
    $u = q("SELECT id,country FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u){
        admin_log('pin_reset','failed',$phone,dk('d_account_not_found_with_reason', ['reason'=>$reason]));
        fail('Compte introuvable',404);
    }
    admin_check_country_access($u['country']);
    q("UPDATE users SET pin_hash=?, pin_attempts=0, pin_locked_until=NULL WHERE id=?",
      [password_hash($newPin,PASSWORD_BCRYPT), $u['id']]);
    admin_log('pin_reset','success',$phone,$reason);
    ok(null,'PIN reinitialise avec succes (verrou anti-fraude aussi leve)');
}

function admin_search_tx() {
    $b = body();
    check_admin_password($b);
    $ref = trim($b['reference']??'');
    if(!$ref) fail('Reference requise');
    $tx = q("SELECT t.*,
        su.full_name sender_name, su.phone_number sender_phone, su.verified_name sender_verified_name, su.operator sender_operator,
        ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name, ru.operator receiver_operator,
        sm.business_name sender_merchant_name, sm.phone_number sender_merchant_phone,
        rm.business_name receiver_merchant_name, rm.phone_number receiver_merchant_phone
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        WHERE t.reference=? AND t.type!='manual_withdrawal'",[$ref])->fetch();
    if(!$tx) fail('Transaction introuvable',404);
    admin_check_country_access_any(admin_tx_involved_countries($tx));
    ok(['transaction'=>$tx]);
}

// Recherche une transaction sans connaitre sa reference ni le numero du
// compte concerne : par plage de montant, plage de dates et/ou statut.
// Exige au moins un critere reel pour eviter de parcourir tout l'historique
// par accident. Pagine comme admin_list_users()/admin_merchant_list().
function admin_search_tx_advanced() {
    $b = body();
    check_admin_password($b);
    $amountMin = trim($b['amount_min'] ?? '');
    $amountMax = trim($b['amount_max'] ?? '');
    $dateFrom = trim($b['date_from'] ?? '');
    $dateTo = trim($b['date_to'] ?? '');
    $status = trim($b['status'] ?? '');
    $page = max(1, (int)($b['page'] ?? 1));
    $perPage = 25;
    $offset = ($page - 1) * $perPage;

    if($amountMin==='' && $amountMax==='' && !$dateFrom && !$dateTo && !$status){
        fail('Au moins un critère de recherche est requis (montant, date ou statut)');
    }

    $where = "t.type NOT IN ('fee','manual_withdrawal')"; $params = [];
    if($amountMin!==''){ $where .= " AND t.amount >= ?"; $params[] = (float)$amountMin; }
    if($amountMax!==''){ $where .= " AND t.amount <= ?"; $params[] = (float)$amountMax; }
    if($dateFrom){ $where .= " AND t.created_at >= ?"; $params[] = $dateFrom.' 00:00:00'; }
    if($dateTo){ $where .= " AND t.created_at <= ?"; $params[] = $dateTo.' 23:59:59'; }
    if($status){ $where .= " AND t.status = ?"; $params[] = $status; }

    $countWhere = $where; $countParams = $params;
    list($scopeSql, $scopeParams) = admin_country_scope_clause_either('su.country,sm.country', 'ru.country,rm.country');
    $countSql = "SELECT COUNT(*) FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        WHERE $countWhere".$scopeSql;
    $total = (int)q($countSql, array_merge($countParams, $scopeParams))->fetchColumn();
    $rows = q("SELECT t.*,
        su.full_name sender_name, su.phone_number sender_phone, su.verified_name sender_verified_name,
        ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name,
        sm.business_name sender_merchant_name, sm.phone_number sender_merchant_phone,
        rm.business_name receiver_merchant_name, rm.phone_number receiver_merchant_phone
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        WHERE $where".$scopeSql." ORDER BY t.created_at DESC LIMIT $perPage OFFSET $offset", array_merge($params, $scopeParams))->fetchAll();

    ok(['transactions'=>$rows,'total'=>$total,'page'=>$page,'per_page'=>$perPage]);
}

// Equivalent de admin_search_tx_advanced() mais restreint aux transactions
// impliquant un portefeuille marchand (sender_merchant_wallet_id OU
// receiver_merchant_wallet_id non nul) - inclut donc a la fois les
// encaissements/paiements marchand et les virements sortants.
function admin_merchant_search_tx_advanced() {
    $b = body();
    check_admin_password($b);
    $amountMin = trim($b['amount_min'] ?? '');
    $amountMax = trim($b['amount_max'] ?? '');
    $dateFrom = trim($b['date_from'] ?? '');
    $dateTo = trim($b['date_to'] ?? '');
    $status = trim($b['status'] ?? '');
    $page = max(1, (int)($b['page'] ?? 1));
    $perPage = 25;
    $offset = ($page - 1) * $perPage;

    if($amountMin==='' && $amountMax==='' && !$dateFrom && !$dateTo && !$status){
        fail('Au moins un critère de recherche est requis (montant, date ou statut)');
    }

    $where = "t.type!='fee' AND (t.sender_merchant_wallet_id IS NOT NULL OR t.receiver_merchant_wallet_id IS NOT NULL)";
    $params = [];
    if($amountMin!==''){ $where .= " AND t.amount >= ?"; $params[] = (float)$amountMin; }
    if($amountMax!==''){ $where .= " AND t.amount <= ?"; $params[] = (float)$amountMax; }
    if($dateFrom){ $where .= " AND t.created_at >= ?"; $params[] = $dateFrom.' 00:00:00'; }
    if($dateTo){ $where .= " AND t.created_at <= ?"; $params[] = $dateTo.' 23:59:59'; }
    if($status){ $where .= " AND t.status = ?"; $params[] = $status; }

    list($scopeSql, $scopeParams) = admin_country_scope_clause_either('su.country,sm.country', 'ru.country,rm.country');
    $countSql = "SELECT COUNT(*) FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        WHERE $where".$scopeSql;
    $total = (int)q($countSql, array_merge($params, $scopeParams))->fetchColumn();
    $rows = q("SELECT t.*,
        su.full_name sender_name, su.phone_number sender_phone, su.verified_name sender_verified_name,
        ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name,
        sm.business_name sender_merchant_name, sm.phone_number sender_merchant_phone,
        rm.business_name receiver_merchant_name, rm.phone_number receiver_merchant_phone
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        WHERE $where".$scopeSql." ORDER BY t.created_at DESC LIMIT $perPage OFFSET $offset", array_merge($params, $scopeParams))->fetchAll();

    ok(['transactions'=>$rows,'total'=>$total,'page'=>$page,'per_page'=>$perPage]);
}

// Liste les dernieres transactions d'un compte (par numero de telephone),
// avec nom+numero du contact de chaque cote - permet de verifier que ce que
// le client decrit au telephone correspond bien a une vraie transaction,
// avant de chercher/annuler par reference.
function admin_search_by_phone() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone']??'');
    if(!$phone) fail('Numero requis');
    // Le compte systeme (gains de la plateforme) ne doit etre consultable
    // que depuis l'onglet Gains ROM (protege par EARNINGS_PASSWORD) - sans
    // ce blocage, chercher ce numero via cet outil de support generique
    // (accessible avec le seul mot de passe admin partage) revelait son
    // solde et ses retraits, contournant completement ce verrou.
    if($phone === '0160629502'){
        admin_log('search_phone','failed',$phone,'Tentative de consultation du compte systeme via la recherche generique (bloquee)');
        fail('Ce compte est reserve a l\'onglet Gains ROM.',403);
    }
    $u = q("SELECT id,full_name,verified_name,verified_birthdate,phone_number,email,operator,status,is_kyc,country,created_at,referral_code
            FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u) fail('Compte introuvable',404);
    admin_check_country_access($u['country']);

    $w = q("SELECT id,balance,vault_balance,vault_locked,vault_lock_date,currency FROM wallets WHERE user_id=?",[$u['id']])->fetch();
    $wid = $w['id'] ?? null;

    // Joint aussi merchant_wallets/merchants des deux cotes - un utilisateur
    // personnel peut avoir paye ou ete paye par un marchand ; sans cette
    // jointure ce cas affichait "-" au lieu du nom/numero du commerce.
    // Exclut aussi 'manual_withdrawal' (retraits Gains ROM) en plus de
    // 'fee', pour la meme raison que le blocage ci-dessus.
    $rows = q("SELECT t.*,
        CASE WHEN t.sender_wallet_id=? THEN 'debit' ELSE 'credit' END as direction,
        su.full_name sender_name, su.phone_number sender_phone, su.verified_name sender_verified_name,
        ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name,
        sm.business_name sender_merchant_name, sm.phone_number sender_merchant_phone,
        rm.business_name receiver_merchant_name, rm.phone_number receiver_merchant_phone
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        WHERE (t.sender_wallet_id=? OR t.receiver_wallet_id=?) AND t.type NOT IN ('fee','manual_withdrawal')
        ORDER BY t.created_at DESC LIMIT 30",[$wid,$wid,$wid])->fetchAll();

    // Historique complet des demandes KYC (pas seulement la plus recente), pour
    // pouvoir revoir les photos recto/verso meme longtemps apres validation.
    $kycHistory = q("SELECT id,legal_name,legal_birthdate,photo_recto,photo_verso,status,created_at,reviewed_at
        FROM kyc_requests WHERE user_id=? ORDER BY created_at DESC",[$u['id']])->fetchAll();
    foreach($kycHistory as &$kh){ $kh['photo_recto']=kyc_decrypt($kh['photo_recto']); $kh['photo_verso']=kyc_decrypt($kh['photo_verso']); }
    unset($kh);

    $devices = q("SELECT device_id,user_agent,first_seen,last_seen FROM known_devices WHERE user_id=? ORDER BY last_seen DESC",[$u['id']])->fetchAll();

    $banks = q("SELECT bank_name,account_last4,is_default,linked_at FROM linked_banks WHERE user_id=? ORDER BY linked_at DESC",[$u['id']])->fetchAll();

    $referredCount = (int)(q("SELECT COUNT(*) c FROM users WHERE referred_by=?",[$u['id']])->fetch()['c']??0);
    $referralEarned = (float)(q("SELECT COALESCE(SUM(bonus_amount),0) t FROM referral_bonuses WHERE referrer_id=?",[$u['id']])->fetch()['t']??0);

    // Protege par try/catch : ne doit jamais casser toute la fiche compte si
    // la table admin_notes n'est pas encore creee sur cette base (migration
    // pas encore executee).
    try {
        $notes = q("SELECT id,note,created_at FROM admin_notes WHERE user_id=? ORDER BY created_at DESC",[$u['id']])->fetchAll();
    } catch(Exception $e) {
        $notes = [];
    }

    ok([
        'account_name'=>$u['verified_name']?:$u['full_name'],
        'account_verified'=>!empty($u['verified_name']),
        'account_operator'=>$u['operator'],
        'profile'=>[
            'full_name'=>$u['full_name'],'verified_name'=>$u['verified_name'],'verified_birthdate'=>$u['verified_birthdate'],
            'phone'=>$u['phone_number'],'email'=>$u['email'],'operator'=>$u['operator'],'status'=>$u['status'],
            'is_kyc'=>(bool)$u['is_kyc'],'country'=>$u['country'],'created_at'=>$u['created_at'],'referral_code'=>$u['referral_code']
        ],
        'wallet'=>[
            'balance'=>(float)($w['balance']??0),'vault_balance'=>(float)($w['vault_balance']??0),
            'vault_locked'=>(bool)($w['vault_locked']??false),'vault_lock_date'=>$w['vault_lock_date']??null,
            'currency'=>$w['currency']??'XOF'
        ],
        'kyc_history'=>$kycHistory,
        'known_devices'=>$devices,
        'linked_banks'=>$banks,
        'referral'=>['referred_count'=>$referredCount,'total_earned'=>$referralEarned],
        'notes'=>$notes,
        'transactions'=>$rows
    ]);
}

// Credite un compte personnel a des fins de TEST uniquement (aucun vrai
// depot bancaire n'existe dans l'app, voir la suppression du module banque
// simule). Reserve a l'admin - jamais expose aux utilisateurs. Raison
// obligatoire journalisee, transaction clairement etiquetee "ROM" dans
// l'historique pour ne jamais etre confondue avec un vrai mouvement d'argent.
function admin_test_credit_wallet() {
    $b = body();
    check_admin_password($b);
    // Creer de l'argent a partir de rien (meme plafonne, meme journalise) est
    // un pouvoir trop sensible pour rester accessible a n'importe quel admin
    // ne connaissant que le mot de passe partage - un admin malveillant
    // pourrait se crediter lui-meme ou crediter un compte complice. Reserve
    // donc a l'Admin Principal, comme Gains ROM.
    check_earnings_password($b);
    $phone = trim($b['phone']??'');
    $amount = (float)($b['amount']??0);
    $reason = trim($b['reason']??'');
    if(!$phone) fail('Numero requis');
    if($amount<=0) fail('Montant invalide');
    // Plafond fixe (outil de TEST uniquement) : sans limite, un admin ayant
    // seulement ADMIN_PASSWORD pourrait crediter des montants arbitraires.
    if($amount>1000000) fail('Montant trop eleve pour un credit de test (max 1 000 000)');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    // Empeche d'utiliser cet outil pour gonfler artificiellement le compte
    // systeme (Gains ROM) - ce credit doit toujours refleter de vrais frais
    // collectes, jamais un credit de test.
    if($phone === '0160629502') fail('Le compte systeme ne peut pas etre credite via cet outil.',403);
    $u = q("SELECT id,country FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u) fail('Compte introuvable',404);
    admin_check_country_access($u['country']);
    $w = q("SELECT id FROM wallets WHERE user_id=?",[$u['id']])->fetch();
    if(!$w) fail('Portefeuille introuvable',404);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'admin_test_credit','completed',?,?)",
          [$txid,$w['id'],$amount,$reference,'ROM '.$reason]);
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$amount,$w['id']]);
        db()->commit();
        admin_log('test_credit','success',$phone,dk('d_ref_with_reason', ['ref'=>$reference, 'reason'=>$reason]));
        $bal = (float)q("SELECT balance FROM wallets WHERE id=?",[$w['id']])->fetchColumn();
        ok(['new_balance'=>$bal],'Credit de test effectue');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec du credit', 500); }
}

// Equivalent de admin_test_credit_wallet() mais pour un portefeuille marchand
// - meme restriction a l'Admin Principal (check_earnings_password), meme
// plafond de test, meme journalisation.
function admin_merchant_test_credit_wallet() {
    $b = body();
    check_admin_password($b);
    check_earnings_password($b);
    $phone = trim($b['phone']??'');
    $amount = (float)($b['amount']??0);
    $reason = trim($b['reason']??'');
    if(!$phone) fail('Numero requis');
    if($amount<=0) fail('Montant invalide');
    if($amount>1000000) fail('Montant trop eleve pour un credit de test (max 1 000 000)');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $m = q("SELECT id,country FROM merchants WHERE phone_number=?",[$phone])->fetch();
    if(!$m) fail('Compte marchand introuvable',404);
    admin_check_country_access($m['country']);
    $mw = q("SELECT id FROM merchant_wallets WHERE merchant_id=?",[$m['id']])->fetch();
    if(!$mw) fail('Portefeuille marchand introuvable',404);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,receiver_merchant_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'admin_test_credit','completed',?,?)",
          [$txid,$mw['id'],$amount,$reference,'ROM '.$reason]);
        q("UPDATE merchant_wallets SET balance=balance+? WHERE id=?",[$amount,$mw['id']]);
        db()->commit();
        admin_log('merchant_test_credit','success',$phone,dk('d_ref_with_reason', ['ref'=>$reference, 'reason'=>$reason]));
        $bal = (float)q("SELECT balance FROM merchant_wallets WHERE id=?",[$mw['id']])->fetchColumn();
        ok(['new_balance'=>$bal],'Credit de test effectue');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec du credit', 500); }
}

// Ajoute une note admin en texte libre sur un compte (contexte humain, pas
// une action structuree - reste distinct de audit_logs). Append-only : pas
// d'edition/suppression, comme le journal d'audit.
function admin_add_note() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone'] ?? '');
    $note = trim($b['note'] ?? '');
    if(!$phone) fail('Numero requis');
    if(!$note) fail('Note vide');
    $u = q("SELECT id,country FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u) fail('Compte introuvable',404);
    admin_check_country_access($u['country']);
    try {
        q("INSERT INTO admin_notes (user_id,note) VALUES (?,?)",[$u['id'],$note]);
    } catch(Exception $e) {
        log_and_fail($e, 'Table des notes non initialisee (migration a executer).', 503);
    }
    admin_log('account_note_added','success',$phone,mb_substr($note,0,120));
    ok(null,'Note ajoutee');
}

// Recherche un compte marchand ROM_BUSINESS par numero (independant de la
// recherche de compte personnel ci-dessus : un numero peut avoir les deux,
// ou un marchand seul sans compte ROM_MONEY personnel).
function admin_merchant_search() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone']??'');
    if(!$phone) fail('Numero requis');
    try {
        $m = q("SELECT * FROM merchants WHERE phone_number=?",[$phone])->fetch();
    } catch(Exception $e) {
        log_and_fail($e, 'Service marchand indisponible (base non initialisee).', 503);
    }
    if(!$m) fail('Aucun compte marchand pour ce numero',404);
    admin_check_country_access($m['country']);
    $w = q("SELECT id,balance,vault_balance,currency FROM merchant_wallets WHERE merchant_id=?",[$m['id']])->fetch();
    try {
        $notes = q("SELECT id,note,created_at FROM merchant_notes WHERE merchant_id=? ORDER BY created_at DESC",[$m['id']])->fetchAll();
    } catch(Exception $e) {
        $notes = [];
    }
    // Historique des appareils connectes - equivalent marchand de
    // known_devices deja affiche cote personnel (admin_search_by_phone()),
    // manquait ici jusqu'a present.
    try {
        $devices = q("SELECT device_id,user_agent,first_seen,last_seen FROM merchant_known_devices WHERE merchant_id=? ORDER BY last_seen DESC",[$m['id']])->fetchAll();
    } catch(Exception $e) {
        $devices = [];
    }
    // Transactions recentes de ce marchand (encaissements et virements) :
    // direction calculee par rapport au merchant_wallet de ce marchand.
    // Joint aussi merchant_wallets/merchants des deux cotes (en plus des
    // tables client) - depuis l'ajout du paiement marchand-a-marchand par QR
    // (merchant_pay_merchant()), la contrepartie n'est plus forcement un
    // compte personnel ; sans cette jointure le nom/telephone apparaissait a
    // tort comme "-" quand un autre marchand payait ou etait paye.
    $mwid = $w['id'] ?? null;
    $txs = [];
    if($mwid){
        $txs = q("SELECT t.*,
            CASE WHEN t.sender_merchant_wallet_id=? THEN 'debit' ELSE 'credit' END as direction,
            su.full_name sender_name, su.phone_number sender_phone, su.verified_name sender_verified_name,
            ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name,
            sm.business_name sender_merchant_name, sm.phone_number sender_merchant_phone,
            rm.business_name receiver_merchant_name, rm.phone_number receiver_merchant_phone
            FROM transactions t
            LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
            LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
            LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
            LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
            WHERE (t.sender_merchant_wallet_id=? OR t.receiver_merchant_wallet_id=?) AND t.type!='fee'
            ORDER BY t.created_at DESC LIMIT 30",[$mwid,$mwid,$mwid])->fetchAll();
    }
    ok(['id'=>$m['id'],'business_name'=>$m['business_name'],'phone_number'=>$m['phone_number'],
        'location_type'=>$m['location_type'],'address'=>$m['address'],'status'=>$m['status'],
        'verified'=>(bool)($m['verified']??false),'created_at'=>$m['created_at'],
        'country'=>$m['country']??null,'currency'=>$w['currency']??'XOF',
        'balance'=>(float)($w['balance']??0),'vault_balance'=>(float)($w['vault_balance']??0),
        'notes'=>$notes,'transactions'=>$txs,'known_devices'=>$devices]);
}

// Ajoute une note admin en texte libre sur un compte marchand - equivalent
// de admin_add_note() cote personnel, table separee (merchant_notes).
function admin_merchant_add_note() {
    $b = body();
    check_admin_password($b);
    $merchantId = trim($b['merchant_id'] ?? '');
    $note = trim($b['note'] ?? '');
    if(!$merchantId) fail('Marchand requis');
    if(!$note) fail('Note vide');
    $m = q("SELECT id,phone_number,country FROM merchants WHERE id=?",[$merchantId])->fetch();
    if(!$m) fail('Marchand introuvable',404);
    admin_check_country_access($m['country']);
    try {
        q("INSERT INTO merchant_notes (merchant_id,note) VALUES (?,?)",[$m['id'],$note]);
    } catch(Exception $e) {
        log_and_fail($e, 'Table des notes non initialisee (migration a executer).', 503);
    }
    admin_log('merchant_note_added','success',$m['phone_number'],mb_substr($note,0,120));
    ok(null,'Note ajoutee');
}

// Documents "entreprise" (KYB) envoyes par le marchand - preuves a l'appui
// avant d'accorder le badge "commerce verifie" (voir admin_merchant_toggle_verified).
// Dechiffre a la volee, uniquement quand un admin les consulte explicitement
// (pas inclus dans admin_merchant_search() pour ne pas alourdir chaque
// recherche avec des photos potentiellement lourdes).
function admin_merchant_documents() {
    $b = body();
    check_admin_password($b);
    $merchantId = trim($b['merchant_id'] ?? '');
    if(!$merchantId) fail('Marchand requis');
    $mc = q("SELECT country FROM merchants WHERE id=?",[$merchantId])->fetch();
    if(!$mc) fail('Marchand introuvable',404);
    admin_check_country_access($mc['country']);
    try {
        $rows = q("SELECT id, doc_type, status, photo, uploaded_at FROM merchant_documents WHERE merchant_id=? ORDER BY uploaded_at DESC",[$merchantId])->fetchAll();
    } catch(Exception $e) {
        $rows = [];
    }
    // Meme raisonnement que admin_agent_documents() : ordre logique (celui
    // utilise cote marchand a l'envoi), pas l'ordre alphabetique du type.
    usort($rows, function($a, $b2) {
        $ia = array_search($a['doc_type'], MERCHANT_DOC_TYPES); $ia = $ia===false ? 999 : $ia;
        $ib = array_search($b2['doc_type'], MERCHANT_DOC_TYPES); $ib = $ib===false ? 999 : $ib;
        if($ia !== $ib) return $ia <=> $ib;
        return strcmp($b2['uploaded_at'], $a['uploaded_at']);
    });
    foreach($rows as &$r){ $r['photo'] = kyc_decrypt($r['photo']); }
    unset($r);
    ok(['documents'=>$rows]);
}

// Supprime un document marchand - raison obligatoire et journalisee.
// Meme mecanique pour les deux usages : refuser une piece de mauvaise
// qualite (refuse = supprime automatiquement, aucune trace conservee) ou
// retirer volontairement une piece deja approuvee pour permettre son
// remplacement. Ne touche jamais merchants.status : un marchand continue
// d'operer normalement quel que soit l'etat de ses documents.
function admin_merchant_delete_document() {
    $b = body();
    check_admin_password($b);
    $id = (int)($b['id'] ?? 0);
    $reason = trim($b['reason']??'');
    if(!$id) fail('Document requis');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $d = q("SELECT md.doc_type, md.merchant_id, m.phone_number, m.country FROM merchant_documents md JOIN merchants m ON m.id=md.merchant_id WHERE md.id=?",[$id])->fetch();
    if(!$d) fail('Document introuvable',404);
    admin_check_country_access($d['country']);
    q("DELETE FROM merchant_documents WHERE id=?",[$id]);
    admin_log('merchant_delete_document','success',$d['phone_number'],$reason.' ('.$d['doc_type'].')');
    web_push_send_to_merchant($d['merchant_id'], 'ROM_BUSINESS', 'Votre document ('.$d['doc_type'].') a ete retire : '.$reason.' Cela ne bloque pas votre compte, vous pouvez en renvoyer un nouveau a tout moment.');
    ok(null,'Document supprime');
}

// Bascule le badge "commerce verifie" - purement declaratif cote admin (pas
// de KYC marchand pour le moment), affiche ensuite chez le marchand et sur
// l'ecran de paiement du client qui scanne son QR.
function admin_merchant_toggle_verified() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['merchant_id']??'');
    if(!$id) fail('Marchand requis');
    $m = q("SELECT id,business_name,verified,country FROM merchants WHERE id=?",[$id])->fetch();
    if(!$m) fail('Marchand introuvable',404);
    admin_check_country_access($m['country']);
    $newVal = $m['verified'] ? 0 : 1;
    q("UPDATE merchants SET verified=? WHERE id=?",[$newVal,$id]);
    admin_log('merchant_toggle_verified','success',null,'Marchand '.$m['business_name'].' -> '.($newVal?'verifie':'non verifie'));
    ok(['verified'=>(bool)$newVal],$newVal?'Marchand verifie':'Verification retiree');
}

// Bloque/debloque un compte marchand - meme principe que admin_block_account()/
// admin_unblock_account() cote personnel (raison obligatoire, journalisee).
// Un marchand bloque ne peut plus se connecter (merchant_login() verifie deja
// status==='active') ni utiliser un jeton existant (merchant_auth() aussi).
function admin_merchant_block() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['merchant_id'] ?? '');
    $reason = trim($b['reason'] ?? '');
    if(!$id || !$reason) fail('Marchand et raison requis');
    $m = q("SELECT id,business_name,phone_number,status,country FROM merchants WHERE id=?",[$id])->fetch();
    if(!$m){ admin_log('merchant_block','failed',null,dk('d_account_not_found')); fail('Marchand introuvable',404); }
    admin_check_country_access($m['country']);
    if($m['status']==='blocked'){ admin_log('merchant_block','failed',$m['phone_number'],'Marchand '.$m['business_name'].' deja bloque'); fail('Ce marchand est deja bloque'); }
    q("UPDATE merchants SET status='blocked' WHERE id=?",[$id]);
    admin_log('merchant_block','success',$m['phone_number'],'Marchand '.$m['business_name'].' bloque : '.$reason);
    ok(null,'Marchand bloque avec succes');
}
function admin_merchant_unblock() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['merchant_id'] ?? '');
    $reason = trim($b['reason'] ?? '');
    if(!$id || !$reason) fail('Marchand et raison requis');
    $m = q("SELECT id,business_name,phone_number,status,country FROM merchants WHERE id=?",[$id])->fetch();
    if(!$m){ admin_log('merchant_unblock','failed',null,dk('d_account_not_found')); fail('Marchand introuvable',404); }
    admin_check_country_access($m['country']);
    if($m['status']==='active'){ admin_log('merchant_unblock','failed',$m['phone_number'],'Marchand '.$m['business_name'].' deja actif'); fail('Ce marchand est deja actif'); }
    q("UPDATE merchants SET status='active' WHERE id=?",[$id]);
    admin_log('merchant_unblock','success',$m['phone_number'],'Marchand '.$m['business_name'].' debloque : '.$reason);
    ok(null,'Marchand debloque avec succes');
}

// Reinitialise le PIN d'un marchand - meme principe que admin_reset_pin()
// cote personnel : leve aussi le verrou anti-fraude (pin_attempts/pin_locked_until).
function admin_merchant_reset_pin() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['merchant_id'] ?? '');
    $newPin = trim($b['new_pin'] ?? '');
    $reason = trim($b['reason'] ?? '');
    if(!preg_match('/^\d{4}$/',$newPin)) fail('Le nouveau PIN doit contenir exactement 4 chiffres');
    if(is_weak_pin($newPin)) fail('Ce code est trop simple, choisissez une autre combinaison');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $m = q("SELECT id,business_name,phone_number,country FROM merchants WHERE id=?",[$id])->fetch();
    if(!$m){
        admin_log('merchant_pin_reset','failed',null,dk('d_account_not_found_with_reason', ['reason'=>$reason]));
        fail('Marchand introuvable',404);
    }
    admin_check_country_access($m['country']);
    q("UPDATE merchants SET pin_hash=?, pin_attempts=0, pin_locked_until=NULL WHERE id=?",
      [password_hash($newPin,PASSWORD_BCRYPT), $m['id']]);
    admin_log('merchant_pin_reset','success',$m['phone_number'],'Marchand '.$m['business_name'].' : '.$reason);
    ok(null,'PIN marchand reinitialise avec succes (verrou anti-fraude aussi leve)');
}

// Liste paginee des marchands - meme mecanique que admin_list_users() cote
// comptes personnels.
// Construit la clause WHERE + params partagee par admin_merchant_list() et
// les deux exports (xlsx/pdf), meme principe que admin_users_build_where().
function admin_merchants_build_where($f) {
    $search = trim($f['search'] ?? '');
    $verifiedFilter = trim($f['verified'] ?? '');
    $statusFilter = trim($f['status'] ?? '');

    $where = "1=1"; $params = [];
    if($search){
        $where .= " AND (business_name ILIKE ? OR phone_number ILIKE ?)";
        $like = '%'.$search.'%';
        $params[] = $like; $params[] = $like;
    }
    if($verifiedFilter==='verified'){ $where .= " AND verified=1"; }
    elseif($verifiedFilter==='unverified'){ $where .= " AND (verified=0 OR verified IS NULL)"; }
    if($statusFilter==='active'){ $where .= " AND status='active'"; }
    elseif($statusFilter==='blocked'){ $where .= " AND status='blocked'"; }
    list($scopeSql, $scopeParams) = admin_country_scope_clause('country');
    $where .= $scopeSql; $params = array_merge($params, $scopeParams);
    return [$where, $params];
}

function admin_merchant_list() {
    $b = body();
    check_admin_password($b);
    $page = max(1, (int)($b['page'] ?? 1));
    $perPage = 25;
    $offset = ($page - 1) * $perPage;

    list($where, $params) = admin_merchants_build_where($b);

    try {
        $total = (int)q("SELECT COUNT(*) FROM merchants WHERE $where", $params)->fetchColumn();
        $rows = q("SELECT id,business_name,phone_number,location_type,status,verified,created_at
                   FROM merchants WHERE $where ORDER BY created_at DESC LIMIT $perPage OFFSET $offset", $params)->fetchAll();
    } catch(Exception $e) {
        log_and_fail($e, 'Service marchand indisponible (base non initialisee).', 503);
    }
    ok(['merchants'=>$rows,'total'=>$total,'page'=>$page,'per_page'=>$perPage]);
}

// Export de la liste de marchands filtree (memes criteres que
// admin_merchant_list()), meme mecanique que admin_users_export_xlsx/pdf().
function admin_merchants_export_xlsx() {
    check_admin_password_str((string)bg('admin_password',''));
    $filters = ['search'=>(string)bg('search',''), 'verified'=>(string)bg('verified',''), 'status'=>(string)bg('status','')];
    list($where, $params) = admin_merchants_build_where($filters);
    $LIMIT = 5000;
    try {
        $total = (int)q("SELECT COUNT(*) FROM merchants WHERE $where", $params)->fetchColumn();
        $rows = q("SELECT business_name,phone_number,location_type,address,status,verified,created_at
                   FROM merchants WHERE $where ORDER BY created_at DESC LIMIT $LIMIT", $params)->fetchAll();
    } catch(Exception $e) {
        log_and_fail($e, 'Service marchand indisponible (base non initialisee).', 503);
    }

    $sheetRows = [];
    $sheetRows[] = [[ 'ROM_BUSINESS - Liste des marchands', 4, 's' ]];
    $sheetRows[] = [[ 'Genere le '.date('d/m/Y').' a '.date('H:i').' - '.$total.' marchand(s)'.($total>$LIMIT?' (limite aux '.$LIMIT.' premiers)':''), 0, 's' ]];
    $sheetRows[] = [];
    $sheetRows[] = [[ 'Boutique',1,'s' ],[ 'Telephone',1,'s' ],[ 'Type',1,'s' ],[ 'Adresse',1,'s' ],[ 'Statut',1,'s' ],[ 'Verifie',1,'s' ],[ 'Inscrit le',1,'s' ]];
    foreach($rows as $m){
        $sheetRows[] = [
            [ $m['business_name'], 2, 's' ],
            [ $m['phone_number'], 2, 's' ],
            [ $m['location_type']==='physical'?'Local commercial':'En ligne', 2, 's' ],
            [ $m['address']?:'-', 2, 's' ],
            [ $m['status']==='blocked'?'Bloque':'Actif', 2, 's' ],
            [ $m['verified']?'Oui':'Non', 2, 's' ],
            [ date('d/m/Y',strtotime($m['created_at'])), 2, 's' ]
        ];
    }
    $sheetXml = xlsx_build_sheet($sheetRows);
    $xlsxData = xlsx_build($sheetXml);
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment; filename="rom_business_marchands.xlsx"');
    header('Content-Length: '.strlen($xlsxData));
    echo $xlsxData;
    exit;
}
function admin_merchants_export_pdf() {
    check_admin_password_str((string)bg('admin_password',''));
    $filters = ['search'=>(string)bg('search',''), 'verified'=>(string)bg('verified',''), 'status'=>(string)bg('status','')];
    list($where, $params) = admin_merchants_build_where($filters);
    $LIMIT = 3000;
    try {
        $total = (int)q("SELECT COUNT(*) FROM merchants WHERE $where", $params)->fetchColumn();
        $rows = q("SELECT business_name,phone_number,location_type,status,verified,created_at
                   FROM merchants WHERE $where ORDER BY created_at DESC LIMIT $LIMIT", $params)->fetchAll();
    } catch(Exception $e) {
        log_and_fail($e, 'Service marchand indisponible (base non initialisee).', 503);
    }

    require_once __DIR__.'/fpdf.php';
    $pdf = new FPDF();
    $pdf->AddPage();
    $pdf->SetFont('Arial','B',14);
    $pdf->Cell(0,10,pdf_str('ROM_BUSINESS - Liste des marchands'),0,1);
    $pdf->SetFont('Arial','',10);
    $pdf->Cell(0,6,pdf_str('Genere le '.date('d/m/Y').' a '.date('H:i').' - '.$total.' marchand(s)'.($total>$LIMIT?' (limite aux '.$LIMIT.' premiers)':'')),0,1);
    $pdf->Ln(4);

    $pdf->SetFont('Arial','B',8);
    $pdf->SetFillColor(230,241,251);
    $w = [45,30,30,25,25,35];
    $headers = ['Boutique','Telephone','Type','Statut','Verifie','Inscrit le'];
    foreach($headers as $i=>$h){ $pdf->Cell($w[$i],8,pdf_str($h),1,0,'C',true); }
    $pdf->Ln();
    $pdf->SetFont('Arial','',8);
    foreach($rows as $m){
        $pdf->Cell($w[0],7,pdf_str(substr($m['business_name'],0,28)),1);
        $pdf->Cell($w[1],7,$m['phone_number'],1);
        $pdf->Cell($w[2],7,$m['location_type']==='physical'?'Local commercial':'En ligne',1);
        $pdf->Cell($w[3],7,$m['status']==='blocked'?'Bloque':'Actif',1);
        $pdf->Cell($w[4],7,$m['verified']?'Oui':'Non',1);
        $pdf->Cell($w[5],7,date('d/m/y',strtotime($m['created_at'])),1);
        $pdf->Ln();
    }

    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="rom_business_marchands.pdf"');
    echo $pdf->Output('S');
    exit;
}

// Annulation tardive - reserve admin, distincte de l'annulation utilisateur
// (5 minutes, deja existante ailleurs). Limite stricte a 2 jours, meme pour
// l'admin, et verifie que le destinataire a toujours le solde necessaire.
function admin_late_cancel() {
    $b = body();
    check_admin_password($b);
    $ref = trim($b['reference']??'');
    $reason = trim($b['reason']??'');
    if(!$ref) fail('Reference requise');
    if(!$reason) fail('La raison est obligatoire (journalisee)');

    $tx = q("SELECT * FROM transactions WHERE reference=?",[$ref])->fetch();
    if(!$tx){
        admin_log('late_cancel','failed',null,dk('d_ref_not_found', ['ref'=>$ref, 'reason'=>$reason]));
        fail('Transaction introuvable',404);
    }
    admin_check_country_access_any(admin_tx_involved_countries($tx));
    $senderPhone = null;
    if($tx['sender_wallet_id']){
        $senderPhone = q("SELECT u.phone_number FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.id=?",[$tx['sender_wallet_id']])->fetchColumn() ?: null;
    } elseif($tx['sender_merchant_wallet_id']){
        $senderPhone = q("SELECT m.phone_number FROM merchant_wallets mw JOIN merchants m ON mw.merchant_id=m.id WHERE mw.id=?",[$tx['sender_merchant_wallet_id']])->fetchColumn() ?: null;
    }
    if($tx['status']!=='completed'){
        admin_log('late_cancel','failed',$senderPhone,dk('d_ref_wrong_status', ['ref'=>$ref, 'status'=>$tx['status'], 'reason'=>$reason]));
        fail('Cette transaction n\'est pas au statut "completed" (deja annulee ou en attente)');
    }
    if($tx['type']==='fee'){
        fail('Impossible d\'annuler directement une ligne de frais');
    }
    if((time() - strtotime($tx['created_at'])) > 2*24*3600){
        admin_log('late_cancel','failed',$senderPhone,dk('d_ref_deadline_passed', ['ref'=>$ref, 'reason'=>$reason]));
        fail('Delai de 2 jours depasse : annulation tardive impossible, meme pour un admin');
    }
    // Resout chaque cote sur le bon portefeuille (personnel OU marchand) :
    // couvre desormais aussi bien un paiement marchand (receiver=merchant)
    // qu'un virement sortant marchand (sender=merchant), en plus du
    // transfert classique personnel<->personnel.
    $senderIsMerchant = !empty($tx['sender_merchant_wallet_id']);
    $receiverIsMerchant = !empty($tx['receiver_merchant_wallet_id']);
    $sw = $senderIsMerchant ? $tx['sender_merchant_wallet_id'] : $tx['sender_wallet_id'];
    $rw = $receiverIsMerchant ? $tx['receiver_merchant_wallet_id'] : $tx['receiver_wallet_id'];
    if(!$sw || !$rw){
        fail('Transaction sans les deux portefeuilles (depot/retrait banque) : annulation manuelle requise, pas via cet outil');
    }
    $senderTable = $senderIsMerchant ? 'merchant_wallets' : 'wallets';
    $receiverTable = $receiverIsMerchant ? 'merchant_wallets' : 'wallets';
    $receiverBal = q("SELECT balance FROM $receiverTable WHERE id=?",[$rw])->fetch();
    if(!$receiverBal || (float)$receiverBal['balance'] < (float)$tx['amount']){
        admin_log('late_cancel','failed',$senderPhone,dk('d_ref_insufficient_balance', ['ref'=>$ref, 'reason'=>$reason]));
        fail('Le destinataire n\'a plus assez de solde pour annuler automatiquement cette transaction');
    }

    db()->beginTransaction();
    try {
        q("UPDATE $receiverTable SET balance=balance-? WHERE id=?",[$tx['amount'],$rw]);
        q("UPDATE $senderTable SET balance=balance+? WHERE id=?",[$tx['amount'],$sw]);
        q("UPDATE transactions SET status='cancelled', cancelled_at=NOW(), cancel_reason='admin_late_cancel' WHERE id=?",[$tx['id']]);
        admin_log('late_cancel','success',$senderPhone,dk('d_ref_with_reason', ['ref'=>$ref, 'reason'=>$reason]));
        db()->commit();
        // Notifie les deux parties : sans ca, seul le client s'en rend compte
        // (son solde/historique change des qu'il consulte l'app), tandis que
        // le marchand ne voit la baisse de son solde qu'au prochain rafraichissement
        // manuel, sans jamais etre averti qu'un paiement a ete annule par l'admin.
        if($senderIsMerchant){
            $sid = q("SELECT merchant_id FROM merchant_wallets WHERE id=?",[$sw])->fetchColumn();
            if($sid) web_push_send_to_merchant($sid,'ROM_BUSINESS','Votre transaction ('.number_format($tx['amount'],0,',',' ').' F) a ete annulee par l\'administration. Le montant a ete recredite.');
        } else {
            $suid = q("SELECT user_id FROM wallets WHERE id=?",[$sw])->fetchColumn();
            if($suid) web_push_send_to_user($suid,'ROM_MONEY','Votre transaction ('.number_format($tx['amount'],0,',',' ').' F) a ete annulee par l\'administration. Le montant a ete recredite.');
        }
        if($receiverIsMerchant){
            $rid = q("SELECT merchant_id FROM merchant_wallets WHERE id=?",[$rw])->fetchColumn();
            if($rid) web_push_send_to_merchant($rid,'ROM_BUSINESS','Une transaction recue ('.number_format($tx['amount'],0,',',' ').' F) a ete annulee par l\'administration. Le montant a ete debite.');
        } else {
            $ruid = q("SELECT user_id FROM wallets WHERE id=?",[$rw])->fetchColumn();
            if($ruid) web_push_send_to_user($ruid,'ROM_MONEY','Une transaction recue ('.number_format($tx['amount'],0,',',' ').' F) a ete annulee par l\'administration. Le montant a ete debite.');
        }
        ok(null,'Transaction annulee avec succes');
    } catch(Exception $e) {
        db()->rollBack();
        log_and_fail($e, 'Echec de l\'annulation', 500);
    }
}

// ============================================================
// GEL DE TRANSACTION — alternative a l'annulation directe : donne le temps
// de verifier (ex: suite a une alerte de fraude) avant de trancher. Reutilise
// exactement le meme mouvement de fonds que l'annulation (argent repris au
// destinataire, redonne a l'expediteur), mais avec un statut 'frozen'
// distinct de 'cancelled' - reversible via admin_unfreeze_transaction(),
// ou rendu definitif via admin_confirm_cancel_frozen(). Memes protections
// contre le solde negatif que l'annulation.
// ============================================================
function admin_freeze_transaction() {
    $b = body();
    check_admin_password($b);
    $ref = trim($b['reference']??'');
    $reason = trim($b['reason']??'');
    if(!$ref) fail('Reference requise');
    if(!$reason) fail('La raison est obligatoire (journalisee)');

    $tx = q("SELECT * FROM transactions WHERE reference=?",[$ref])->fetch();
    if(!$tx){
        admin_log('tx_freeze','failed',null,dk('d_ref_not_found', ['ref'=>$ref, 'reason'=>$reason]));
        fail('Transaction introuvable',404);
    }
    admin_check_country_access_any(admin_tx_involved_countries($tx));
    $senderPhone = null;
    if($tx['sender_wallet_id']){
        $senderPhone = q("SELECT u.phone_number FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.id=?",[$tx['sender_wallet_id']])->fetchColumn();
    } elseif($tx['sender_merchant_wallet_id']){
        $senderPhone = q("SELECT m.phone_number FROM merchant_wallets mw JOIN merchants m ON mw.merchant_id=m.id WHERE mw.id=?",[$tx['sender_merchant_wallet_id']])->fetchColumn();
    }
    if($tx['status']!=='completed'){
        admin_log('tx_freeze','failed',$senderPhone,dk('d_ref_wrong_status', ['ref'=>$ref, 'status'=>$tx['status'], 'reason'=>$reason]));
        fail('Seule une transaction "completed" peut etre gelee (statut actuel : '.$tx['status'].')');
    }
    if($tx['type']==='fee'){
        fail('Impossible de geler directement une ligne de frais');
    }
    // Meme resolution personnel/marchand que admin_late_cancel().
    $senderIsMerchant = !empty($tx['sender_merchant_wallet_id']);
    $receiverIsMerchant = !empty($tx['receiver_merchant_wallet_id']);
    $sw = $senderIsMerchant ? $tx['sender_merchant_wallet_id'] : $tx['sender_wallet_id'];
    $rw = $receiverIsMerchant ? $tx['receiver_merchant_wallet_id'] : $tx['receiver_wallet_id'];
    if(!$sw || !$rw){
        fail('Transaction sans les deux portefeuilles (depot/retrait banque) : gel manuel requis, pas via cet outil');
    }
    $senderTable = $senderIsMerchant ? 'merchant_wallets' : 'wallets';
    $receiverTable = $receiverIsMerchant ? 'merchant_wallets' : 'wallets';
    $receiverBal = q("SELECT balance FROM $receiverTable WHERE id=?",[$rw])->fetch();
    if(!$receiverBal || (float)$receiverBal['balance'] < (float)$tx['amount']){
        admin_log('tx_freeze','failed',$senderPhone,dk('d_ref_insufficient_balance', ['ref'=>$ref, 'reason'=>$reason]));
        fail('Le destinataire n\'a plus assez de solde pour geler cette transaction');
    }

    db()->beginTransaction();
    try {
        q("UPDATE $receiverTable SET balance=balance-? WHERE id=?",[$tx['amount'],$rw]);
        q("UPDATE $senderTable SET balance=balance+? WHERE id=?",[$tx['amount'],$sw]);
        q("UPDATE transactions SET status='frozen', frozen_at=NOW(), frozen_reason=? WHERE id=?",[$reason,$tx['id']]);
        admin_log('tx_freeze','success',$senderPhone,dk('d_ref_with_reason', ['ref'=>$ref, 'reason'=>$reason]));
        db()->commit();
        if($senderIsMerchant){
            $sid = q("SELECT merchant_id FROM merchant_wallets WHERE id=?",[$sw])->fetchColumn();
            if($sid) web_push_send_to_merchant($sid,'ROM_BUSINESS','Une de vos transactions ('.number_format($tx['amount'],0,',',' ').' F) est temporairement en cours de verification.');
        } else {
            $suid = q("SELECT user_id FROM wallets WHERE id=?",[$sw])->fetchColumn();
            if($suid) web_push_send_to_user($suid,'ROM_MONEY','Une de vos transactions ('.number_format($tx['amount'],0,',',' ').' F) est temporairement en cours de verification.');
        }
        if($receiverIsMerchant){
            $rid = q("SELECT merchant_id FROM merchant_wallets WHERE id=?",[$rw])->fetchColumn();
            if($rid) web_push_send_to_merchant($rid,'ROM_BUSINESS','Une transaction recue ('.number_format($tx['amount'],0,',',' ').' F) est temporairement en cours de verification.');
        } else {
            $ruid = q("SELECT user_id FROM wallets WHERE id=?",[$rw])->fetchColumn();
            if($ruid) web_push_send_to_user($ruid,'ROM_MONEY','Une transaction recue ('.number_format($tx['amount'],0,',',' ').' F) est temporairement en cours de verification.');
        }
        ok(null,'Transaction gelee avec succes');
    } catch(Exception $e) {
        db()->rollBack();
        log_and_fail($e, 'Echec du gel', 500);
    }
}

// Debloque une transaction gelee : remet tout exactement comme avant le gel
// (statut 'completed' restaure). Meme protection dans l'autre sens : si
// l'expediteur a entre-temps depense l'argent temporairement recredite, on
// refuse plutot que de le mettre en negatif.
function admin_unfreeze_transaction() {
    $b = body();
    check_admin_password($b);
    $ref = trim($b['reference']??'');
    if(!$ref) fail('Reference requise');
    $tx = q("SELECT * FROM transactions WHERE reference=?",[$ref])->fetch();
    if(!$tx) fail('Transaction introuvable',404);
    admin_check_country_access_any(admin_tx_involved_countries($tx));
    if($tx['status']!=='frozen') fail('Cette transaction n\'est pas geleee (statut actuel : '.$tx['status'].')');
    $senderIsMerchant = !empty($tx['sender_merchant_wallet_id']);
    $receiverIsMerchant = !empty($tx['receiver_merchant_wallet_id']);
    $sw = $senderIsMerchant ? $tx['sender_merchant_wallet_id'] : $tx['sender_wallet_id'];
    $rw = $receiverIsMerchant ? $tx['receiver_merchant_wallet_id'] : $tx['receiver_wallet_id'];
    $senderTable = $senderIsMerchant ? 'merchant_wallets' : 'wallets';
    $receiverTable = $receiverIsMerchant ? 'merchant_wallets' : 'wallets';
    $senderPhone = null;
    if($sw){
        $senderPhone = $senderIsMerchant
            ? q("SELECT m.phone_number FROM merchant_wallets mw JOIN merchants m ON mw.merchant_id=m.id WHERE mw.id=?",[$sw])->fetchColumn()
            : q("SELECT u.phone_number FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.id=?",[$sw])->fetchColumn();
    }
    $senderBal = q("SELECT balance FROM $senderTable WHERE id=?",[$sw])->fetch();
    if(!$senderBal || (float)$senderBal['balance'] < (float)$tx['amount']){
        admin_log('tx_unfreeze','failed',$senderPhone,dk('d_ref_unfreeze_insufficient', ['ref'=>$ref]));
        fail('L\'expediteur n\'a plus assez de solde pour debloquer cette transaction (il a peut-etre depense l\'argent temporairement recredite)');
    }
    db()->beginTransaction();
    try {
        q("UPDATE $senderTable SET balance=balance-? WHERE id=?",[$tx['amount'],$sw]);
        q("UPDATE $receiverTable SET balance=balance+? WHERE id=?",[$tx['amount'],$rw]);
        q("UPDATE transactions SET status='completed', frozen_at=NULL, frozen_reason=NULL WHERE id=?",[$tx['id']]);
        admin_log('tx_unfreeze','success',$senderPhone,dk('d_ref_unfrozen', ['ref'=>$ref]));
        db()->commit();
        if($senderIsMerchant){
            $sid = q("SELECT merchant_id FROM merchant_wallets WHERE id=?",[$sw])->fetchColumn();
            if($sid) web_push_send_to_merchant($sid,'ROM_BUSINESS','La verification est terminee : votre transaction ('.number_format($tx['amount'],0,',',' ').' F) est confirmee.');
        } else {
            $suid = q("SELECT user_id FROM wallets WHERE id=?",[$sw])->fetchColumn();
            if($suid) web_push_send_to_user($suid,'ROM_MONEY','La verification est terminee : votre transaction ('.number_format($tx['amount'],0,',',' ').' F) est confirmee.');
        }
        if($receiverIsMerchant){
            $rid = q("SELECT merchant_id FROM merchant_wallets WHERE id=?",[$rw])->fetchColumn();
            if($rid) web_push_send_to_merchant($rid,'ROM_BUSINESS','La verification est terminee : la transaction recue ('.number_format($tx['amount'],0,',',' ').' F) est confirmee.');
        } else {
            $ruid = q("SELECT user_id FROM wallets WHERE id=?",[$rw])->fetchColumn();
            if($ruid) web_push_send_to_user($ruid,'ROM_MONEY','La verification est terminee : la transaction recue ('.number_format($tx['amount'],0,',',' ').' F) est confirmee.');
        }
        ok(null,'Transaction debloquee avec succes');
    } catch(Exception $e) {
        db()->rollBack();
        log_and_fail($e, 'Echec du deblocage', 500);
    }
}

// Rend l'annulation definitive pour une transaction gelee. Aucun mouvement
// de fonds necessaire ici : le gel a deja effectue le mouvement (argent
// repris au destinataire, rendu a l'expediteur) - il ne reste qu'a changer
// le statut de 'frozen' a 'cancelled' pour finaliser.
function admin_confirm_cancel_frozen() {
    $b = body();
    check_admin_password($b);
    $ref = trim($b['reference']??'');
    $reason = trim($b['reason']??'');
    if(!$ref) fail('Reference requise');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $tx = q("SELECT * FROM transactions WHERE reference=?",[$ref])->fetch();
    if(!$tx) fail('Transaction introuvable',404);
    admin_check_country_access_any(admin_tx_involved_countries($tx));
    if($tx['status']!=='frozen') fail('Cette transaction n\'est pas gelee (statut actuel : '.$tx['status'].')');
    $senderIsMerchant = !empty($tx['sender_merchant_wallet_id']);
    $receiverIsMerchant = !empty($tx['receiver_merchant_wallet_id']);
    $sw = $senderIsMerchant ? $tx['sender_merchant_wallet_id'] : $tx['sender_wallet_id'];
    $rw = $receiverIsMerchant ? $tx['receiver_merchant_wallet_id'] : $tx['receiver_wallet_id'];
    $senderPhone = null;
    if($sw){
        $senderPhone = $senderIsMerchant
            ? q("SELECT m.phone_number FROM merchant_wallets mw JOIN merchants m ON mw.merchant_id=m.id WHERE mw.id=?",[$sw])->fetchColumn()
            : q("SELECT u.phone_number FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.id=?",[$sw])->fetchColumn();
    }
    q("UPDATE transactions SET status='cancelled', cancelled_at=NOW(), cancel_reason=? WHERE id=?",[$reason,$tx['id']]);
    admin_log('tx_freeze_confirm_cancel','success',$senderPhone,dk('d_ref_with_reason', ['ref'=>$ref, 'reason'=>$reason]));
    if($senderIsMerchant){
        $sid = $sw ? q("SELECT merchant_id FROM merchant_wallets WHERE id=?",[$sw])->fetchColumn() : null;
        if($sid) web_push_send_to_merchant($sid,'ROM_BUSINESS','Votre transaction ('.number_format($tx['amount'],0,',',' ').' F) a ete definitivement annulee suite a verification.');
    } else {
        $suid = $sw ? q("SELECT user_id FROM wallets WHERE id=?",[$sw])->fetchColumn() : null;
        if($suid) web_push_send_to_user($suid,'ROM_MONEY','Votre transaction ('.number_format($tx['amount'],0,',',' ').' F) a ete definitivement annulee suite a verification.');
    }
    if($receiverIsMerchant){
        $rid = $rw ? q("SELECT merchant_id FROM merchant_wallets WHERE id=?",[$rw])->fetchColumn() : null;
        if($rid) web_push_send_to_merchant($rid,'ROM_BUSINESS','La transaction ('.number_format($tx['amount'],0,',',' ').' F) a ete definitivement annulee suite a verification.');
    } else {
        $ruid = $rw ? q("SELECT user_id FROM wallets WHERE id=?",[$rw])->fetchColumn() : null;
        if($ruid) web_push_send_to_user($ruid,'ROM_MONEY','La transaction ('.number_format($tx['amount'],0,',',' ').' F) a ete definitivement annulee suite a verification.');
    }
    ok(null,'Annulation confirmee');
}

// Liste des transactions actuellement gelees, en attente d'une decision -
// pour ne pas en perdre une de vue.
function admin_list_frozen() {
    $b = body();
    check_admin_password($b);
    list($scopeSql, $scopeParams) = admin_country_scope_clause_either('su.country,sm.country', 'ru.country,rm.country');
    $rows = q("SELECT t.*,
        COALESCE(su.phone_number, sm.phone_number) sender_phone,
        COALESCE(su.full_name, sm.business_name) sender_name,
        su.verified_name sender_verified_name,
        COALESCE(ru.phone_number, rm.phone_number) receiver_phone,
        COALESCE(ru.full_name, rm.business_name) receiver_name,
        ru.verified_name receiver_verified_name
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        LEFT JOIN merchant_wallets smw ON t.sender_merchant_wallet_id=smw.id LEFT JOIN merchants sm ON smw.merchant_id=sm.id
        LEFT JOIN merchant_wallets rmw ON t.receiver_merchant_wallet_id=rmw.id LEFT JOIN merchants rm ON rmw.merchant_id=rm.id
        WHERE t.status='frozen'".$scopeSql." ORDER BY t.frozen_at ASC", $scopeParams)->fetchAll();
    ok(['frozen'=>$rows]);
}

// ── COMPTES ADMIN NOMMES ── identification uniquement (voir
// resolve_admin_name()) : tous les comptes ont les memes acces complets que
// le mot de passe partage ADMIN_PASSWORD, qui reste toujours valable en
// parallele. Createur/gestionnaire = n'importe qui connait deja un mot de
// passe admin valide (aucune hierarchie entre comptes).
function admin_accounts_list() {
    $b = body();
    check_admin_password($b);
    $rows = q("SELECT id,name,active,countries,created_at FROM admin_accounts ORDER BY created_at ASC")->fetchAll();
    foreach($rows as &$r){ $r['countries'] = $r['countries'] ? (json_decode($r['countries'], true) ?: []) : []; }
    unset($r);
    ok(['accounts'=>$rows]);
}
function admin_accounts_create() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $name = trim($b['name'] ?? '');
    // trim() ici pour rester coherent avec check_admin_password_str() /
    // le champ de connexion frontend qui trim deja - sinon un espace de
    // trop tape sans le voir a la creation rendait le compte injoignable
    // des la connexion (le hash stocke ne correspondait plus jamais).
    $pw = trim((string)($b['password'] ?? ''));
    if(!$name) fail('Le nom est requis');
    if(mb_strlen($pw) < 6) fail('Le mot de passe doit contenir au moins 6 caracteres');
    if($name === 'Admin Principal') fail('Ce nom est reserve');
    $exists = q("SELECT id FROM admin_accounts WHERE name=?",[$name])->fetch();
    if($exists) fail('Un compte avec ce nom existe deja');
    // Tableau de noms de pays (peut etre vide - un compte fraichement cree
    // sans pays assigne ne peut alors rien consulter, voir
    // admin_check_country_access()).
    $countries = is_array($b['countries'] ?? null) ? array_values(array_filter(array_map('trim', $b['countries']))) : [];
    q("INSERT INTO admin_accounts (name,password_hash,countries) VALUES (?,?,?)",[$name,password_hash($pw,PASSWORD_BCRYPT),json_encode($countries,JSON_UNESCAPED_UNICODE)]);
    admin_log('admin_account_create','success',null,dk('d_ref_with_reason',['ref'=>$name,'reason'=>'Nouveau compte admin']));
    ok(null,'Compte cree');
}
// Desactivation plutot que suppression : garde l'historique du journal
// d'audit coherent (les entrees passees restent attribuees a ce nom), et
// reste reversible en cas d'erreur - meme principe deja etabli partout
// ailleurs dans ce projet (blocage plutot que suppression definitive).
function admin_accounts_set_active() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $id = (int)($b['id'] ?? 0);
    $active = !empty($b['active']) ? 1 : 0;
    if(!$id) fail('Compte requis');
    $acc = q("SELECT name FROM admin_accounts WHERE id=?",[$id])->fetch();
    if(!$acc) fail('Compte introuvable',404);
    q("UPDATE admin_accounts SET active=? WHERE id=?",[$active,$id]);
    admin_log($active ? 'admin_account_reactivate' : 'admin_account_deactivate','success',null,dk('d_ref_with_reason',['ref'=>$acc['name'],'reason'=>$active?'Reactive':'Desactive']));
    ok(null,'Compte mis a jour');
}
// Sans ceci, un mot de passe mal saisi/oublie a la creation obligeait a
// abandonner le nom choisi (unique en base) pour en recreer un autre - ici
// on garde le meme compte (et donc son historique d'audit), juste un
// nouveau mot de passe.
function admin_accounts_reset_password() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $id = (int)($b['id'] ?? 0);
    $pw = trim((string)($b['password'] ?? ''));
    if(!$id) fail('Compte requis');
    if(mb_strlen($pw) < 6) fail('Le mot de passe doit contenir au moins 6 caracteres');
    $acc = q("SELECT name FROM admin_accounts WHERE id=?",[$id])->fetch();
    if(!$acc) fail('Compte introuvable',404);
    q("UPDATE admin_accounts SET password_hash=? WHERE id=?",[password_hash($pw,PASSWORD_BCRYPT),$id]);
    admin_log('admin_account_reset_password','success',null,dk('d_ref_with_reason',['ref'=>$acc['name'],'reason'=>'Mot de passe reinitialise']));
    ok(null,'Mot de passe mis a jour');
}
// Change les pays assignes SANS toucher au mot de passe - separe de la
// creation pour pouvoir corriger/etendre le perimetre d'un compte deja en
// service (ex: Kofi couvrait juste la Cote d'Ivoire, on lui ajoute le
// Ghana) sans devoir le recreer.
function admin_accounts_set_countries() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $id = (int)($b['id'] ?? 0);
    if(!$id) fail('Compte requis');
    $acc = q("SELECT name FROM admin_accounts WHERE id=?",[$id])->fetch();
    if(!$acc) fail('Compte introuvable',404);
    $countries = is_array($b['countries'] ?? null) ? array_values(array_filter(array_map('trim', $b['countries']))) : [];
    q("UPDATE admin_accounts SET countries=? WHERE id=?",[json_encode($countries,JSON_UNESCAPED_UNICODE),$id]);
    admin_log('admin_account_set_countries','success',null,dk('d_ref_with_reason',['ref'=>$acc['name'],'reason'=>'Pays assignes : '.($countries?implode(', ',$countries):'aucun')]));
    ok(null,'Pays mis a jour');
}

function admin_audit_list() {
    $b = body();
    check_admin_password($b);
    $actionFilter = trim($b['action_filter'] ?? '');
    $phoneFilter  = trim($b['phone_filter'] ?? '');
    $dateFrom     = trim($b['date_from'] ?? '');
    $dateTo       = trim($b['date_to'] ?? '');

    // Exclut les actions Gains ROM : ce journal general est accessible avec
    // le seul mot de passe admin partage, alors que ces actions doivent
    // rester derriere le second code (EARNINGS_PASSWORD) - sans cette
    // exclusion, n'importe quel admin pouvait lire le detail des retraits
    // (destinataire, raison) via ce journal, contournant completement le
    // verrou de l'onglet Gains ROM.
    list($joinSql, $scopeSql, $scopeParams) = admin_audit_scope_sql();
    $sql = "SELECT audit_logs.* FROM audit_logs".$joinSql." WHERE audit_logs.action NOT IN ('earnings_login','earnings_withdraw','earnings_withdraw_cancel')";
    $params = [];
    if ($actionFilter !== '') { $sql .= " AND audit_logs.action = ?"; $params[] = $actionFilter; }
    if ($phoneFilter !== '')  { $sql .= " AND audit_logs.target_phone LIKE ?"; $params[] = '%'.$phoneFilter.'%'; }
    if ($dateFrom !== '')     { $sql .= " AND audit_logs.created_at >= ?"; $params[] = $dateFrom.' 00:00:00'; }
    if ($dateTo !== '')       { $sql .= " AND audit_logs.created_at <= ?"; $params[] = $dateTo.' 23:59:59'; }
    $sql .= $scopeSql;
    $sql .= " ORDER BY audit_logs.created_at DESC LIMIT 100";

    $rows = q($sql, array_merge($params, $scopeParams))->fetchAll();
    ok(['logs'=>$rows]);
}

function admin_audit_get_rows() {
    check_admin_password_str((string)bg('admin_password',''));
    $actionFilter = trim((string)bg('action_filter',''));
    $phoneFilter  = trim((string)bg('phone_filter',''));
    $dateFrom     = trim((string)bg('date_from',''));
    $dateTo       = trim((string)bg('date_to',''));

    list($joinSql, $scopeSql, $scopeParams) = admin_audit_scope_sql();
    $sql = "SELECT audit_logs.* FROM audit_logs".$joinSql." WHERE audit_logs.action NOT IN ('earnings_login','earnings_withdraw','earnings_withdraw_cancel')";
    $params = [];
    if ($actionFilter !== '') { $sql .= " AND audit_logs.action = ?"; $params[] = $actionFilter; }
    if ($phoneFilter !== '')  { $sql .= " AND audit_logs.target_phone LIKE ?"; $params[] = '%'.$phoneFilter.'%'; }
    if ($dateFrom !== '')     { $sql .= " AND audit_logs.created_at >= ?"; $params[] = $dateFrom.' 00:00:00'; }
    if ($dateTo !== '')       { $sql .= " AND audit_logs.created_at <= ?"; $params[] = $dateTo.' 23:59:59'; }
    $sql .= $scopeSql;
    $sql .= " ORDER BY audit_logs.created_at DESC LIMIT 100";
    return q($sql, array_merge($params, $scopeParams))->fetchAll();
}

function admin_audit_action_label($a) {
    $labels = ['pin_reset'=>'Reinitialisation PIN','late_cancel'=>'Annulation tardive','admin_login'=>'Connexion admin','country_toggle'=>'Pays actif/inactif','account_block'=>'Blocage de compte','account_unblock'=>'Deblocage de compte','update_country'=>'Modification du pays'];
    return $labels[$a] ?? $a;
}
function admin_audit_result_label($r) {
    $labels = ['success'=>'Succes','failed'=>'Echec'];
    return $labels[$r] ?? $r;
}

function admin_audit_export_xlsx() {
    $rows = admin_audit_get_rows();

    $data = [];
    $data[] = [[ 'Date',1,'s' ], [ 'Action',1,'s' ], [ 'Resultat',1,'s' ], [ 'Admin',1,'s' ], [ 'Compte',1,'s' ], [ 'Details',1,'s' ]];
    foreach($rows as $l){
        $data[] = [
            [ date('d/m/Y H:i', strtotime($l['created_at'])), 2, 's' ],
            [ admin_audit_action_label($l['action']), 2, 's' ],
            [ admin_audit_result_label($l['result']), 2, 's' ],
            [ $l['admin_name'] ?: 'Inconnu', 2, 's' ],
            [ $l['target_phone'] ?: '-', 2, 's' ],
            [ $l['details'] ?: '', 2, 's' ]
        ];
    }

    $sheetXml = xlsx_build_sheet($data);
    $xlsxData = xlsx_build($sheetXml);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment; filename="rom_money_journal_audit.xlsx"');
    header('Content-Length: '.strlen($xlsxData));
    echo $xlsxData;
    exit;
}

function admin_audit_export_pdf() {
    $rows = admin_audit_get_rows();

    require_once __DIR__.'/fpdf.php';
    $pdf = new FPDF();
    $pdf->AddPage();
    $pdf->SetFont('Arial','B',14);
    $pdf->Cell(0,10,pdf_str('ROM_MONEY - Journal d\'audit admin'),0,1);
    $infoTopY = $pdf->GetY();
    $logoPath = __DIR__.'/logo.png';
    if(file_exists($logoPath)){
        $pdf->Image($logoPath, 182, $infoTopY, 18, 18);
    }
    $pdf->SetFont('Arial','',10);
    $pdf->Cell(150,6,pdf_str('Genere le '.date('d/m/Y').' a '.date('H:i')),0,1);
    $pdf->Cell(150,6,pdf_str($rows ? count($rows).' action(s) journalisee(s)' : 'Aucune action'),0,1);
    if(file_exists($logoPath)){
        $pdf->SetY(max($pdf->GetY(), $infoTopY+18));
    }
    $pdf->Ln(4);

    $pdf->SetFont('Arial','B',9);
    $pdf->SetFillColor(230,241,251);
    $w = [24,34,20,26,26,60];
    $headers = ['Date','Action','Resultat','Admin','Compte','Details'];
    foreach($headers as $i=>$h){ $pdf->Cell($w[$i],8,pdf_str($h),1,0,'C',true); }
    $pdf->Ln();

    $pdf->SetFont('Arial','',8);
    foreach($rows as $l){
        $pdf->Cell($w[0],7,date('d/m/y H:i',strtotime($l['created_at'])),1);
        $pdf->Cell($w[1],7,pdf_str(admin_audit_action_label($l['action'])),1);
        $pdf->Cell($w[2],7,pdf_str(admin_audit_result_label($l['result'])),1);
        $pdf->Cell($w[3],7,pdf_str($l['admin_name'] ?: 'Inconnu'),1);
        $pdf->Cell($w[4],7,pdf_str($l['target_phone'] ?: '-'),1);
        $pdf->Cell($w[5],7,substr(pdf_str($l['details'] ?: ''),0,46),1);
        $pdf->Ln();
    }

    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="rom_money_journal_audit.pdf"');
    echo $pdf->Output('S');
    exit;
}

// admin_dash_xof_sum()/admin_dash_count() (voir plus haut, pres de
// admin_dash_country_join_sql()) font desormais la conversion XOF ET
// l'execution en un seul appel - remplace l'ancien admin_dash_xof_sum_sql()
// qui ne renvoyait que le texte SQL. Sans conversion, un virement de 100 GHS
// et un de 100 XOF comptaient tous deux pour "100" alors qu'ils ne
// representent pas la meme valeur (100 GHS vaut environ 12x plus).

function admin_dashboard_get_data($period, $dateFrom, $dateTo, $countryFilter = null) {
    // Rafraichit les taux si besoin AVANT les JOIN sur exchange_rates
    // ci-dessous (sinon une base fraichement installee, sans jamais avoir
    // affiche l'ecran "Taux de change" de Reglages, n'aurait aucun taux et
    // tous les COALESCE(...,1) ci-dessous traiteraient tout comme du XOF).
    refresh_exchange_rates_if_stale();

    // Liste des pays que cet admin peut choisir dans le selecteur "Pays" du
    // tableau de bord - calculee AVANT tout retrecissement eventuel, pour
    // servir a la fois a peupler ce selecteur cote frontend et a valider
    // qu'un filtre demande est legitime (jamais un pays hors du perimetre
    // de l'admin, ni un pays inconnu pour Admin Principal).
    $adminCountries = $GLOBALS['_current_admin_countries'] ?? null; // null = Admin Principal
    $availableCountries = $adminCountries !== null
        ? $adminCountries
        : array_column(q("SELECT name FROM active_countries WHERE is_active=1 ORDER BY name ASC")->fetchAll(), 'name');
    if ($countryFilter !== null && $countryFilter !== '' && !in_array($countryFilter, $availableCountries, true)) {
        fail("Vous n'etes pas autorise a filtrer sur ce pays.", 403);
    }
    // Retrecit temporairement le perimetre pays lu par admin_dash_xof_sum()/
    // admin_dash_count()/admin_country_scope_clause()/admin_dash_country_scope_where()
    // (qui lisent toutes $GLOBALS['_current_admin_countries']) a un seul pays
    // si un filtre est demande, sinon perimetre normal inchange. Remis en
    // l'etat original en toute fin de fonction - chaque requete HTTP a son
    // propre processus PHP donc aucune fuite possible entre deux requetes,
    // mais plus rigoureux de restaurer plutot que de compter dessus.
    $savedGlobalCountries = $GLOBALS['_current_admin_countries'] ?? null;
    if ($countryFilter) {
        $GLOBALS['_current_admin_countries'] = [$countryFilter];
    }

    // Bloc "Aujourd'hui" - toujours fixe, independant du filtre de periode
    $todayCount  = admin_dash_count("transactions.status='completed' AND transactions.type NOT IN ('fee','manual_withdrawal') AND transactions.created_at >= CURRENT_DATE");
    // Converti en XOF (voir admin_dash_xof_sum()) : additionner des
    // montants dans des devises differentes brutes ne donne jamais un total
    // qui veut dire quelque chose.
    $todayVolume = admin_dash_xof_sum("transactions.status='completed' AND transactions.type NOT IN ('fee','manual_withdrawal') AND transactions.created_at >= CURRENT_DATE");
    $todayFees   = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE status='completed' AND type='fee' AND created_at >= CURRENT_DATE")->fetchColumn();
    list($kycScopeSql, $kycScopeParams) = admin_country_scope_clause('u.country');
    $kycPending  = q("SELECT COUNT(*) FROM kyc_requests k LEFT JOIN users u ON u.id=k.user_id WHERE k.status='pending'".$kycScopeSql, $kycScopeParams)->fetchColumn();

    // Bloc "Periode selectionnee"
    // Prefixe avec "transactions." (valide meme sans alias explicite dans le
    // FROM, puisque c'est le nom de la table elle-meme) : reutilise aussi
    // bien dans des requetes simples (FROM transactions seul) que dans
    // admin_dash_xof_sum() (qui joint wallets/merchant_wallets, toutes deux
    // avec leur PROPRE colonne created_at - une reference non prefixee y est
    // ambigue pour PostgreSQL, provoquant une erreur SQL silencieuse
    // remontee comme "Erreur de chargement").
    $where = "transactions.status='completed'";
    $params = [];
    if ($period==='7d') {
        $where .= " AND transactions.created_at >= NOW() - INTERVAL '7 days'";
    } elseif ($period==='month') {
        $where .= " AND transactions.created_at >= date_trunc('month', CURRENT_DATE)";
    } elseif ($period==='custom' && $dateFrom!=='' && $dateTo!=='') {
        $where .= " AND transactions.created_at >= ? AND transactions.created_at <= ?";
        $params[] = $dateFrom.' 00:00:00';
        $params[] = $dateTo.' 23:59:59';
    } elseif ($period==='all') {
        // pas de condition supplementaire
    } else {
        $period = 'today';
        $where .= " AND transactions.created_at >= CURRENT_DATE";
    }

    $periodVolume = admin_dash_xof_sum("$where AND transactions.type NOT IN ('fee','manual_withdrawal')", $params);
    $periodFees   = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE $where AND type='fee'", $params)->fetchColumn();

    // Repartition par pays sur la periode selectionnee - utile des qu'un
    // compte admin nomme a plusieurs pays assignes (sinon un seul total
    // combine en XOF ne permet pas de distinguer ce qui vient de chaque
    // pays), ou pour Admin Principal qui veut comparer les pays entre eux.
    // Liste TOUJOURS un pays par pays pertinent, meme sans la moindre
    // transaction (volume/count a 0) - jamais juste les pays qui ont deja
    // des donnees, sinon un pays assigne mais encore inactif disparaitrait
    // silencieusement de l'ecran au lieu de confirmer "rien a signaler ici".
    // Aucun interet quand un filtre pays precis est deja actif (le reste du
    // tableau de bord EST deja ce pays) - reste vide dans ce cas, plutot que
    // de recalculer sur le perimetre retreci ci-dessus (qui ne contiendrait
    // de toute facon que ce seul pays).
    $cbCountriesToShow = $countryFilter ? [] : $availableCountries;
    $countryBreakdown = [];
    if (!empty($cbCountriesToShow)) {
        list($cbScopeSql, $cbScopeParams) = admin_dash_country_scope_where();
        // Attribue chaque transaction au pays de l'UNE des deux parties qui
        // figure dans la liste a afficher - jamais juste "celui du
        // destinataire" sans condition, sinon une transaction comptee dans
        // period_volume parce que SEUL l'expediteur est dans le perimetre
        // (le destinataire etant dans un pays non affiche) disparaissait
        // silencieusement de cette repartition tout en restant dans le
        // total ci-dessus - deux chiffres incoherents entre eux.
        $cbPh = implode(',', array_fill(0, count($cbCountriesToShow), '?'));
        $cbAttribution = "CASE
            WHEN dru.country IN ($cbPh) THEN dru.country
            WHEN drm.country IN ($cbPh) THEN drm.country
            WHEN dsu.country IN ($cbPh) THEN dsu.country
            WHEN dsm.country IN ($cbPh) THEN dsm.country
            ELSE COALESCE(dru.country, drm.country, dsu.country, dsm.country)
        END";
        $cbAttrParams = array_merge($cbCountriesToShow, $cbCountriesToShow, $cbCountriesToShow, $cbCountriesToShow);
        $cbRows = q("SELECT $cbAttribution AS country,
                COUNT(*) AS count,
                COALESCE(SUM(
                    COALESCE(transactions.receiver_amount,transactions.net_amount,transactions.amount)
                    * COALESCE(NULLIF(erxof.rate_to_usd,0),1)
                    / COALESCE(NULLIF(errate.rate_to_usd,0), NULLIF(erxof.rate_to_usd,0), 1)
                ),0) AS volume
            FROM transactions
            LEFT JOIN wallets erw ON transactions.receiver_wallet_id = erw.id
            LEFT JOIN merchant_wallets ermw ON transactions.receiver_merchant_wallet_id = ermw.id
            LEFT JOIN exchange_rates errate ON errate.currency_code = UPPER(COALESCE(erw.currency, ermw.currency, 'XOF'))
            LEFT JOIN exchange_rates erxof ON erxof.currency_code = 'XOF'"
            .admin_dash_country_join_sql()."
            WHERE $where AND transactions.type NOT IN ('fee','manual_withdrawal')".$cbScopeSql."
            GROUP BY $cbAttribution", array_merge($cbAttrParams, $params, $cbScopeParams, $cbAttrParams))->fetchAll();
        $cbByCountry = [];
        foreach ($cbRows as $r) { if ($r['country']) $cbByCountry[$r['country']] = $r; }
        foreach ($cbCountriesToShow as $c) {
            $row = $cbByCountry[$c] ?? null;
            $countryBreakdown[] = ['country'=>$c, 'count'=>(int)($row['count']??0), 'volume'=>(float)($row['volume']??0)];
        }
        usort($countryBreakdown, function($a,$b){ return $b['volume'] <=> $a['volume']; });
    }

    $totalVolume = admin_dash_xof_sum("transactions.status='completed' AND transactions.type NOT IN ('fee','manual_withdrawal')");
    // Meme exclusion que admin_audit_list() : ce widget est visible sur le
    // dashboard partage (mot de passe admin seul), les actions Gains ROM ne
    // doivent y laisser aucune trace, meme juste le nom de l'action. Meme
    // perimetre pays que le vrai journal d'audit (admin_audit_scope_sql()).
    list($alJoinSql, $alScopeSql, $alScopeParams) = admin_audit_scope_sql();
    $recentLogs  = q("SELECT audit_logs.* FROM audit_logs".$alJoinSql." WHERE audit_logs.action NOT IN ('earnings_login','earnings_withdraw','earnings_withdraw_cancel')".$alScopeSql." ORDER BY audit_logs.created_at DESC LIMIT 5", $alScopeParams)->fetchAll();
    list($opScopeSql, $opScopeParams) = admin_country_scope_clause('country');
    $operatorBreakdown = q("SELECT COALESCE(NULLIF(operator,''),'Non renseigné') AS operator, COUNT(*) AS total
        FROM users WHERE 1=1".$opScopeSql." GROUP BY operator
        ORDER BY CASE COALESCE(NULLIF(operator,''),'Non renseigné')
            WHEN 'Orange CI' THEN 1
            WHEN 'MTN CI' THEN 2
            WHEN 'Moov Africa CI' THEN 3
            ELSE 4
        END", $opScopeParams)->fetchAll();

    // Evolution quotidienne (14 derniers jours), independante du filtre de
    // periode ci-dessus : sert a visualiser une tendance recente, pas a
    // cumuler sur une longue duree.
    list($dailyScopeSql, $dailyScopeParams) = admin_dash_country_scope_where();
    $dailyRows = q("SELECT DATE(transactions.created_at) AS day, COUNT(*) AS count,
            COALESCE(SUM(
                COALESCE(transactions.receiver_amount,transactions.net_amount,transactions.amount)
                * COALESCE(NULLIF(erxof.rate_to_usd,0),1)
                / COALESCE(NULLIF(errate.rate_to_usd,0), NULLIF(erxof.rate_to_usd,0), 1)
            ),0) AS volume
        FROM transactions
        LEFT JOIN wallets erw ON transactions.receiver_wallet_id = erw.id
        LEFT JOIN merchant_wallets ermw ON transactions.receiver_merchant_wallet_id = ermw.id
        LEFT JOIN exchange_rates errate ON errate.currency_code = UPPER(COALESCE(erw.currency, ermw.currency, 'XOF'))
        LEFT JOIN exchange_rates erxof ON erxof.currency_code = 'XOF'"
        .admin_dash_country_join_sql()."
        WHERE transactions.status='completed' AND transactions.type NOT IN ('fee','manual_withdrawal') AND transactions.created_at >= NOW() - INTERVAL '14 days'".$dailyScopeSql."
        GROUP BY DATE(transactions.created_at) ORDER BY day", $dailyScopeParams)->fetchAll();
    // Comble les jours sans transaction (absents du GROUP BY) avec des zeros,
    // pour un graphique continu sur 14 jours consecutifs.
    $dailyByDate = [];
    foreach($dailyRows as $r){ $dailyByDate[$r['day']] = $r; }
    $dailyVolume = [];
    for($i=13; $i>=0; $i--){
        $day = date('Y-m-d', strtotime("-$i days"));
        $row = $dailyByDate[$day] ?? null;
        $dailyVolume[] = ['day'=>$day, 'count'=>(int)($row['count']??0), 'volume'=>(float)($row['volume']??0)];
    }

    // Classement des utilisateurs les plus actifs (somme des montants ou ils
    // sont emetteur OU destinataire, tous statuts de transaction confondus
    // hors frais), pour reperer les comptes les plus utilises.
    // w represente TOUJOURS le portefeuille de cet utilisateur (qu'il soit
    // emetteur ou destinataire sur la ligne), donc w.currency est deja la
    // bonne devise dans les deux cas - un seul JOIN de taux suffit ici,
    // contrairement aux agregats globaux ci-dessus qui melangent plusieurs
    // portefeuilles differents.
    list($tuScopeSql, $tuScopeParams) = admin_country_scope_clause('u.country');
    $topUsers = q("SELECT u.id, COALESCE(NULLIF(u.verified_name,''), u.full_name) AS name, u.phone_number,
            SUM(
                (CASE WHEN t.sender_wallet_id = w.id THEN t.amount ELSE COALESCE(t.receiver_amount,t.net_amount,t.amount) END)
                * COALESCE(NULLIF(erxof.rate_to_usd,0),1)
                / COALESCE(NULLIF(errate.rate_to_usd,0), NULLIF(erxof.rate_to_usd,0), 1)
            ) AS total_volume, COUNT(*) AS tx_count
        FROM users u
        JOIN wallets w ON w.user_id = u.id
        JOIN transactions t ON (t.sender_wallet_id = w.id OR t.receiver_wallet_id = w.id)
        LEFT JOIN exchange_rates errate ON errate.currency_code = UPPER(w.currency)
        LEFT JOIN exchange_rates erxof ON erxof.currency_code = 'XOF'
        WHERE t.status='completed' AND t.type NOT IN ('fee','manual_withdrawal')".$tuScopeSql."
        GROUP BY u.id, name, u.phone_number
        ORDER BY total_volume DESC
        LIMIT 10", $tuScopeParams)->fetchAll();

    // Bloc marchands ROM_BUSINESS - protege par try/catch au cas ou les
    // tables merchants/merchant_wallets ne seraient pas encore creees sur
    // cette base (meme precaution que merchant_register()/merchant_login()).
    try {
        list($mScopeSql, $mScopeParams) = admin_country_scope_clause('country');
        $merchantsTotal    = (int)q("SELECT COUNT(*) FROM merchants WHERE 1=1".$mScopeSql, $mScopeParams)->fetchColumn();
        $merchantsVerified = (int)q("SELECT COUNT(*) FROM merchants WHERE verified=1".$mScopeSql, $mScopeParams)->fetchColumn();
        // "Aujourd'hui" - toujours fixe, meme principe que todayVolume/todayFees.
        // Converti en XOF (voir admin_dash_xof_sum()) : un paiement de
        // 100 GHS et un de 100 XOF ne representent pas la meme valeur.
        $merchantVolumeToday = admin_dash_xof_sum("transactions.status='completed' AND transactions.type='merchant_payment' AND transactions.created_at >= CURRENT_DATE");
        $merchantCountToday  = admin_dash_count("transactions.status='completed' AND transactions.type='merchant_payment' AND transactions.created_at >= CURRENT_DATE");
        // Part recue d'un AUTRE MARCHAND (et non d'un client) - reconnaissable
        // a sender_merchant_wallet_id non nul sur une transaction de type
        // 'merchant_payment'. Affichee separement du volume total ci-dessus
        // pour qu'un admin puisse reperer un marchand dont l'essentiel du
        // volume vient d'autres marchands plutot que de vraies ventes clients
        // (signal a surveiller, pas bloque automatiquement).
        $merchantVolumeTodayFromMerchants = admin_dash_xof_sum("transactions.status='completed' AND transactions.type='merchant_payment' AND transactions.sender_merchant_wallet_id IS NOT NULL AND transactions.created_at >= CURRENT_DATE");
        $merchantCountTodayFromMerchants  = admin_dash_count("transactions.status='completed' AND transactions.type='merchant_payment' AND transactions.sender_merchant_wallet_id IS NOT NULL AND transactions.created_at >= CURRENT_DATE");
        // Periode selectionnee (meme $where/$params que le bloc personnel juste au-dessus).
        $merchantVolumePeriod = admin_dash_xof_sum("$where AND transactions.type='merchant_payment'", $params);
        $merchantCountPeriod  = admin_dash_count("$where AND transactions.type='merchant_payment'", $params);
        $merchantVolumePeriodFromMerchants = admin_dash_xof_sum("$where AND transactions.type='merchant_payment' AND transactions.sender_merchant_wallet_id IS NOT NULL", $params);
        $merchantCountPeriodFromMerchants  = admin_dash_count("$where AND transactions.type='merchant_payment' AND transactions.sender_merchant_wallet_id IS NOT NULL", $params);
        // Cumule (depuis toujours), independant du filtre de periode.
        $merchantVolume    = admin_dash_xof_sum("transactions.status='completed' AND transactions.type='merchant_payment'");
        $merchantVolumeFromMerchants = admin_dash_xof_sum("transactions.status='completed' AND transactions.type='merchant_payment' AND transactions.sender_merchant_wallet_id IS NOT NULL");
        // Classement des marchands recevant le plus d'un AUTRE marchand
        // (et non de clients) - meme logique que topMerchants ci-dessous mais
        // filtree sur les paiements inter-marchands uniquement. mw.currency
        // est directement la devise de t.receiver_amount (mw EST le
        // portefeuille receveur des que la ligne transaction existe).
        $topMerchantsFromMerchants = q("SELECT m.id, m.business_name, m.phone_number, m.verified,
                COALESCE(SUM(
                    COALESCE(t.receiver_amount,t.net_amount,t.amount)
                    * COALESCE(NULLIF(erxof.rate_to_usd,0),1)
                    / COALESCE(NULLIF(errate.rate_to_usd,0), NULLIF(erxof.rate_to_usd,0), 1)
                ),0) AS total_volume, COUNT(t.id) AS tx_count
            FROM merchants m
            JOIN merchant_wallets mw ON mw.merchant_id = m.id
            JOIN transactions t ON t.receiver_merchant_wallet_id = mw.id AND t.status='completed' AND t.type='merchant_payment' AND t.sender_merchant_wallet_id IS NOT NULL
            LEFT JOIN exchange_rates errate ON errate.currency_code = UPPER(mw.currency)
            LEFT JOIN exchange_rates erxof ON erxof.currency_code = 'XOF'
            WHERE 1=1".$mScopeSql."
            GROUP BY m.id, m.business_name, m.phone_number, m.verified
            HAVING COALESCE(SUM(
                    COALESCE(t.receiver_amount,t.net_amount,t.amount)
                    * COALESCE(NULLIF(erxof.rate_to_usd,0),1)
                    / COALESCE(NULLIF(errate.rate_to_usd,0), NULLIF(erxof.rate_to_usd,0), 1)
                ),0) > 0
            ORDER BY total_volume DESC
            LIMIT 10", $mScopeParams)->fetchAll();
        $topMerchants = q("SELECT m.id, m.business_name, m.phone_number, m.verified,
                COALESCE(SUM(
                    COALESCE(t.receiver_amount,t.net_amount,t.amount)
                    * COALESCE(NULLIF(erxof.rate_to_usd,0),1)
                    / COALESCE(NULLIF(errate.rate_to_usd,0), NULLIF(erxof.rate_to_usd,0), 1)
                ),0) AS total_volume, COUNT(t.id) AS tx_count
            FROM merchants m
            JOIN merchant_wallets mw ON mw.merchant_id = m.id
            LEFT JOIN transactions t ON t.receiver_merchant_wallet_id = mw.id AND t.status='completed' AND t.type='merchant_payment'
            LEFT JOIN exchange_rates errate ON errate.currency_code = UPPER(mw.currency)
            LEFT JOIN exchange_rates erxof ON erxof.currency_code = 'XOF'
            WHERE 1=1".$mScopeSql."
            GROUP BY m.id, m.business_name, m.phone_number, m.verified
            ORDER BY total_volume DESC
            LIMIT 10", $mScopeParams)->fetchAll();
    } catch(Exception $e) {
        $merchantsTotal = 0; $merchantsVerified = 0; $merchantVolume = 0; $topMerchants = [];
        $merchantVolumeToday = 0; $merchantCountToday = 0;
        $merchantVolumePeriod = 0; $merchantCountPeriod = 0;
        $merchantVolumeTodayFromMerchants = 0; $merchantCountTodayFromMerchants = 0;
        $merchantVolumePeriodFromMerchants = 0; $merchantCountPeriodFromMerchants = 0;
        $merchantVolumeFromMerchants = 0; $topMerchantsFromMerchants = [];
    }

    // Retabli avant de retourner : voir la note plus haut sur pourquoi ce
    // retrecissement temporaire n'est en pratique jamais partage entre deux
    // requetes, mais rigueur avant tout.
    $GLOBALS['_current_admin_countries'] = $savedGlobalCountries;

    return [
        'today_count'    => (int)$todayCount,
        'today_volume'   => (float)$todayVolume,
        'kyc_pending'    => (int)$kycPending,
        'period'         => $period,
        'period_volume'  => (float)$periodVolume,
        'operator_breakdown' => $operatorBreakdown,
        'country_breakdown' => $countryBreakdown,
        'country_filter' => $countryFilter,
        'available_countries' => $availableCountries,
        'total_volume'   => (float)$totalVolume,
        'recent_logs'    => $recentLogs,
        'daily_volume'   => $dailyVolume,
        'top_users'      => $topUsers,
        'merchants'      => [
            'total'    => $merchantsTotal,
            'verified' => $merchantsVerified,
            'volume'   => $merchantVolume,
            'today_volume' => $merchantVolumeToday,
            'today_count'  => $merchantCountToday,
            'today_volume_from_merchants' => $merchantVolumeTodayFromMerchants,
            'today_count_from_merchants'  => $merchantCountTodayFromMerchants,
            'period_volume' => $merchantVolumePeriod,
            'period_count'  => $merchantCountPeriod,
            'period_volume_from_merchants' => $merchantVolumePeriodFromMerchants,
            'period_count_from_merchants'  => $merchantCountPeriodFromMerchants,
            'volume_from_merchants' => $merchantVolumeFromMerchants,
            'top'      => $topMerchants,
            'top_from_merchants' => $topMerchantsFromMerchants
        ]
    ];
}

function admin_dashboard_stats() {
    $b = body();
    check_admin_password($b);
    $period   = trim($b['period'] ?? 'today');
    $dateFrom = trim($b['date_from'] ?? '');
    $dateTo   = trim($b['date_to'] ?? '');
    $country  = trim($b['country'] ?? '');
    ok(admin_dashboard_get_data($period, $dateFrom, $dateTo, $country ?: null));
}

// ============================================================
// GENERATEUR XLSX MINIMAL — construit un vrai fichier Excel (.xlsx) en PHP
// pur, sans dependance a l'extension `zip` ni a aucune librairie externe
// (coherent avec le reste du projet : FPDF est deja utilise de la meme
// facon pour les PDF). Un .xlsx est en realite une archive ZIP contenant
// plusieurs fichiers XML (format Office Open XML) : on construit le ZIP a
// la main avec des entrees non compressees ("stored"), format valide et
// verifie avec succes (unzip + openpyxl) avant integration.
// ============================================================

// Construit une archive ZIP brute (methode "stored", sans compression) a
// partir d'un tableau [chemin => contenu]. N'utilise que des fonctions du
// coeur PHP (pack, crc32) : fonctionne sur n'importe quel serveur PHP,
// meme sans extension zip/zlib.
function zip_create($files) {
    $localParts = [];
    $centralParts = [];
    $offset = 0;
    foreach ($files as $name => $content) {
        $crc = crc32($content);
        $len = strlen($content);
        $nameLen = strlen($name);
        $localHeader = pack('VvvvvvVVVvv', 0x04034b50, 20, 0, 0, 0, 0, $crc, $len, $len, $nameLen, 0) . $name;
        $localParts[] = $localHeader . $content;
        $centralHeader = pack('VvvvvvvVVVvvvvvVV', 0x02014b50, 20, 20, 0, 0, 0, 0, $crc, $len, $len, $nameLen, 0, 0, 0, 0, 0, $offset) . $name;
        $centralParts[] = $centralHeader;
        $offset += strlen($localHeader) + $len;
    }
    $localData = implode('', $localParts);
    $centralData = implode('', $centralParts);
    $endRecord = pack('VvvvvVVv', 0x06054b50, 0, 0, count($files), count($files), strlen($centralData), strlen($localData), 0);
    return $localData . $centralData . $endRecord;
}

function xlsx_col_letter($idx) {
    $letter = ''; $idx++;
    while ($idx > 0) {
        $mod = ($idx - 1) % 26;
        $letter = chr(65 + $mod) . $letter;
        $idx = intval(($idx - $mod) / 26);
    }
    return $letter;
}
function xlsx_esc($s) { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_XML1, 'UTF-8'); }

// $rows = [ [ [valeur, styleIdx, type] | null, ... ], ... ]  type: 'n' (nombre) ou 's' (texte inline)
// Une cellule null est simplement omise (case vide).
function xlsx_build_sheet($rows) {
    $xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        . '<cols><col min="1" max="1" width="6"/><col min="2" max="2" width="26"/><col min="3" max="3" width="18"/><col min="4" max="4" width="16"/><col min="5" max="5" width="16"/></cols>'
        . '<sheetData>';
    foreach ($rows as $r => $cells) {
        $rowNum = $r + 1;
        $xml .= '<row r="'.$rowNum.'">';
        foreach ($cells as $c => $cell) {
            if ($cell === null) continue;
            list($value, $style, $type) = $cell;
            $ref = xlsx_col_letter($c).$rowNum;
            if ($type === 's') {
                $xml .= '<c r="'.$ref.'" s="'.$style.'" t="inlineStr"><is><t xml:space="preserve">'.xlsx_esc($value).'</t></is></c>';
            } else {
                $xml .= '<c r="'.$ref.'" s="'.$style.'"><v>'.xlsx_esc($value).'</v></c>';
            }
        }
        $xml .= '</row>';
    }
    $xml .= '</sheetData></worksheet>';
    return $xml;
}

function xlsx_styles_xml() {
    return '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    . '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    . '<numFmts count="1"><numFmt numFmtId="164" formatCode="#,##0"/></numFmts>'
    . '<fonts count="4">'
    . '<font><sz val="11"/><name val="Calibri"/></font>'
    . '<font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font>'
    . '<font><b/><sz val="14"/><name val="Calibri"/></font>'
    . '<font><b/><sz val="12"/><color rgb="FF085041"/><name val="Calibri"/></font>'
    . '</fonts>'
    . '<fills count="3">'
    . '<fill><patternFill patternType="none"/></fill>'
    . '<fill><patternFill patternType="gray125"/></fill>'
    . '<fill><patternFill patternType="solid"><fgColor rgb="FF085041"/><bgColor indexed="64"/></patternFill></fill>'
    . '</fills>'
    . '<borders count="2">'
    . '<border><left/><right/><top/><bottom/><diagonal/></border>'
    . '<border><left style="thin"><color indexed="64"/></left><right style="thin"><color indexed="64"/></right><top style="thin"><color indexed="64"/></top><bottom style="thin"><color indexed="64"/></bottom><diagonal/></border>'
    . '</borders>'
    . '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    . '<cellXfs count="6">'
    . '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    . '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>'
    . '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1"/>'
    . '<xf numFmtId="164" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"/>'
    . '<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
    . '<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
    . '</cellXfs>'
    . '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
    . '</styleSheet>';
}

function xlsx_build($sheetXml) {
    $contentTypes = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        . '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        . '<Default Extension="xml" ContentType="application/xml"/>'
        . '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        . '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        . '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        . '</Types>';
    $rootRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        . '</Relationships>';
    $workbook = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        . '<sheets><sheet name="Dashboard" sheetId="1" r:id="rId1"/></sheets>'
        . '</workbook>';
    $workbookRels = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        . '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        . '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        . '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        . '</Relationships>';
    $files = [
        '[Content_Types].xml' => $contentTypes,
        '_rels/.rels' => $rootRels,
        'xl/workbook.xml' => $workbook,
        'xl/_rels/workbook.xml.rels' => $workbookRels,
        'xl/styles.xml' => xlsx_styles_xml(),
        'xl/worksheets/sheet1.xml' => $sheetXml,
    ];
    return zip_create($files);
}

function admin_dashboard_export_xlsx() {
    check_admin_password_str((string)bg('admin_password',''));
    $period   = trim((string)bg('period','today'));
    $dateFrom = trim((string)bg('date_from',''));
    $dateTo   = trim((string)bg('date_to',''));
    $country  = trim((string)bg('country',''));
    $d = admin_dashboard_get_data($period, $dateFrom, $dateTo, $country ?: null);

    // Styles : 0=normal, 1=en-tete (gras+fond+bordure), 2=texte borde,
    // 3=nombre borde (separateur de milliers), 4=titre, 5=sous-titre section
    $rows = [];
    $rows[] = [[ 'ROM_MONEY - Tableau de bord', 4, 's' ]];
    $rows[] = [[ 'Genere le '.date('d/m/Y').' a '.date('H:i'), 0, 's' ]];
    $rows[] = [];

    $rows[] = [[ 'Resume', 5, 's' ]];
    $rows[] = [[ 'Transactions aujourd\'hui', 2, 's' ], [ $d['today_count'], 3, 'n' ]];
    $rows[] = [[ 'Volume aujourd\'hui', 2, 's' ], [ $d['today_volume'], 3, 'n' ]];
    $rows[] = [[ 'KYC en attente', 2, 's' ], [ $d['kyc_pending'], 3, 'n' ]];
    $rows[] = [[ 'Volume periode ('.$d['period'].')', 2, 's' ], [ $d['period_volume'], 3, 'n' ]];
    $rows[] = [[ 'Volume total cumule', 2, 's' ], [ $d['total_volume'], 3, 'n' ]];
    $rows[] = [];

    $rows[] = [[ 'Evolution quotidienne (14 jours)', 5, 's' ]];
    $rows[] = [[ 'Date',1,'s' ], [ 'Transactions',1,'s' ], [ 'Volume',1,'s' ]];
    foreach($d['daily_volume'] as $row){
        $rows[] = [[ date('d/m/Y',strtotime($row['day'])), 2, 's' ], [ $row['count'], 3, 'n' ], [ $row['volume'], 3, 'n' ]];
    }
    $rows[] = [];

    $rows[] = [[ 'Top 10 utilisateurs', 5, 's' ]];
    $rows[] = [[ 'Rang',1,'s' ], [ 'Nom',1,'s' ], [ 'Telephone',1,'s' ], [ 'Volume total',1,'s' ], [ 'Transactions',1,'s' ]];
    foreach($d['top_users'] as $i=>$u){
        $rows[] = [[ $i+1, 3, 'n' ], [ $u['name'], 2, 's' ], [ $u['phone_number'], 2, 's' ], [ $u['total_volume'], 3, 'n' ], [ $u['tx_count'], 3, 'n' ]];
    }
    $rows[] = [];

    $rows[] = [[ 'Repartition par operateur', 5, 's' ]];
    $rows[] = [[ 'Operateur',1,'s' ], [ 'Nombre de comptes',1,'s' ]];
    foreach($d['operator_breakdown'] as $o){
        $rows[] = [[ $o['operator'], 2, 's' ], [ $o['total'], 3, 'n' ]];
    }

    // Vue comparative entre pays - le remplacement voulu pour l'ancienne
    // liste toujours affichee en direct sur l'ecran (invivable a 50 pays) :
    // reservee a l'export, jamais a l'ecran. N'apparait que si aucun filtre
    // pays precis n'etait deja actif (sinon ce tableau ne contiendrait
    // qu'une seule ligne, deja couverte par le Resume ci-dessus).
    if(!$d['country_filter'] && !empty($d['country_breakdown'])){
        $rows[] = [];
        $rows[] = [[ 'Repartition par pays ('.$d['period'].')', 5, 's' ]];
        $rows[] = [[ 'Pays',1,'s' ], [ 'Volume',1,'s' ], [ 'Transactions',1,'s' ]];
        foreach($d['country_breakdown'] as $c){
            $rows[] = [[ $c['country'] ?: '-', 2, 's' ], [ $c['volume'], 3, 'n' ], [ $c['count'], 3, 'n' ]];
        }
    }

    $sheetXml = xlsx_build_sheet($rows);
    $xlsxData = xlsx_build($sheetXml);

    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment; filename="rom_money_dashboard.xlsx"');
    header('Content-Length: '.strlen($xlsxData));
    echo $xlsxData;
    exit;
}

// Cle => [valeur par defaut, libelle pour le journal d'audit]. Fonction
// plutot que const : les fonctions sont hissees par PHP quel que soit leur
// emplacement dans le fichier, contrairement a `const` au niveau racine qui
// doit avoir ete atteinte dans l'ordre sequentiel du script pour exister -
// une const declaree ici serait indisponible pour le code de routage place
// plus haut dans le fichier, provoquant une erreur fatale.
function app_settings_defs() {
    return [
        'fee_rate_national'           => [0.01, 'Taux de frais national'],
        'fee_free_threshold_national' => [4000, 'Seuil de gratuite national'],
        'fee_rate_africa'             => [0.015, 'Taux de frais Transfert Afrique'],
        'fee_rate_merchant'           => [0.01, 'Taux de frais encaissement marchand'],
        'fee_free_threshold_merchant_daily' => [25000, 'Seuil de gratuite marchand (cumul quotidien)'],
        'limit_unverified'            => [2000000, 'Plafond mensuel non verifie'],
        'limit_verified'              => [100000000, 'Plafond mensuel verifie'],
        'admin_bf_max_attempts'       => [3, 'Tentatives admin avant blocage'],
        'admin_bf_block_minutes'      => [60, 'Duree du blocage admin (minutes)'],
        'fraud_velocity_count'        => [5, 'Nb transactions suspect (velocite)'],
        'fraud_velocity_minutes'      => [10, 'Fenetre de velocite (minutes)'],
        'fraud_unusual_multiplier'    => [5, 'Multiplicateur montant inhabituel'],
        'fraud_unusual_min_amount'    => [20000, 'Montant plancher (inhabituel)'],
        'fraud_new_recipient_min_amount' => [50000, 'Montant plancher (nouveau destinataire)'],
        'fx_margin_rate'              => [0.01, 'Marge de change (0 = aucune)'],
    ];
}

function admin_get_settings() {
    $b = body();
    check_admin_password($b);
    $out = [];
    foreach(app_settings_defs() as $key => $def){
        $out[$key] = (float)get_setting($key, $def[0]);
    }
    ok($out);
}

function admin_update_settings() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $changes = [];
    foreach(app_settings_defs() as $key => $def){
        if(!isset($b[$key])) continue;
        $val = (float)$b[$key];
        if($val < 0) fail('Valeur invalide pour '.$def[1]);
        // Les taux (fee_rate_*) sont des proportions : rejette toute valeur
        // absurde (> 1 = plus de 100%), garde-fou simple contre une erreur
        // de saisie (ex: 15 au lieu de 0.15).
        if(strpos($key,'fee_rate_')===0 && $val > 1) fail($def[1].' doit etre une proportion entre 0 et 1 (ex: 0.01 pour 1%)');
        if($key==='fx_margin_rate' && ($val < 0 || $val > 1)) fail('La marge de change doit etre une proportion entre 0 et 1 (ex: 0.01 pour 1%, 0 pour aucune marge)');
        if($key==='admin_bf_max_attempts' && $val < 1) fail('Le nombre de tentatives avant blocage doit etre au moins 1');
        if($key==='admin_bf_block_minutes' && $val < 1) fail('La duree de blocage doit etre d\'au moins 1 minute');
        if($key==='fraud_velocity_count' && $val < 2) fail('Le seuil de velocite doit etre d\'au moins 2 transactions');
        if($key==='fraud_velocity_minutes' && $val < 1) fail('La fenetre de velocite doit etre d\'au moins 1 minute');
        if($key==='fraud_unusual_multiplier' && $val < 2) fail('Le multiplicateur doit etre d\'au moins 2');
        set_setting($key, (string)$val);
        $changes[] = ['key'=>$key, 'value'=>$val];
    }
    admin_log('update_settings','success',null, empty($changes) ? dk('d_no_change') : dk('d_settings_changed', ['items'=>json_encode($changes)]));
    ok(null,'Reglages mis a jour');
}

function admin_dashboard_export_pdf() {
    check_admin_password_str((string)bg('admin_password',''));
    $period   = trim((string)bg('period','today'));
    $dateFrom = trim((string)bg('date_from',''));
    $dateTo   = trim((string)bg('date_to',''));
    $country  = trim((string)bg('country',''));
    $d = admin_dashboard_get_data($period, $dateFrom, $dateTo, $country ?: null);

    require_once __DIR__.'/fpdf.php';
    $pdf = new FPDF();
    $pdf->AddPage();
    $pdf->SetFont('Arial','B',14);
    $pdf->Cell(0,10,pdf_str('ROM_MONEY - Tableau de bord'),0,1);
    $infoTopY = $pdf->GetY();
    $logoPath = __DIR__.'/logo.png';
    if(file_exists($logoPath)){
        $pdf->Image($logoPath, 182, $infoTopY, 18, 18);
    }
    $pdf->SetFont('Arial','',10);
    $pdf->Cell(150,6,pdf_str('Genere le '.date('d/m/Y').' a '.date('H:i')),0,1);
    if(file_exists($logoPath)){
        $pdf->SetY(max($pdf->GetY(), $infoTopY+18));
    }
    $pdf->Ln(4);

    $pdf->SetFont('Arial','B',11);
    $pdf->Cell(0,8,pdf_str('Resume'),0,1);
    $pdf->SetFont('Arial','',9);
    $pdf->Cell(0,6,pdf_str('Transactions aujourd\'hui : '.$d['today_count'].'  -  Volume : '.number_format($d['today_volume'],0,',',' ').' F'),0,1);
    $pdf->Cell(0,6,pdf_str('Periode ('.$d['period'].') : Volume '.number_format($d['period_volume'],0,',',' ').' F'),0,1);
    $pdf->Cell(0,6,pdf_str('Volume total cumule : '.number_format($d['total_volume'],0,',',' ').' F  -  KYC en attente : '.$d['kyc_pending']),0,1);
    $pdf->Ln(4);

    $pdf->SetFont('Arial','B',11);
    $pdf->Cell(0,8,pdf_str('Evolution quotidienne (14 jours)'),0,1);
    $pdf->SetFont('Arial','B',9);
    $pdf->SetFillColor(230,241,251);
    $pdf->Cell(50,7,pdf_str('Date'),1,0,'C',true);
    $pdf->Cell(50,7,pdf_str('Transactions'),1,0,'C',true);
    $pdf->Cell(50,7,pdf_str('Volume'),1,1,'C',true);
    $pdf->SetFont('Arial','',9);
    foreach($d['daily_volume'] as $row){
        $pdf->Cell(50,6,date('d/m/Y',strtotime($row['day'])),1);
        $pdf->Cell(50,6,(string)$row['count'],1);
        $pdf->Cell(50,6,number_format($row['volume'],0,',',' ').' F',1,1);
    }
    $pdf->Ln(4);

    $pdf->SetFont('Arial','B',11);
    $pdf->Cell(0,8,pdf_str('Top 10 utilisateurs'),0,1);
    $pdf->SetFont('Arial','B',9);
    $pdf->SetFillColor(230,241,251);
    $pdf->Cell(10,7,pdf_str('#'),1,0,'C',true);
    $pdf->Cell(60,7,pdf_str('Nom'),1,0,'C',true);
    $pdf->Cell(45,7,pdf_str('Telephone'),1,0,'C',true);
    $pdf->Cell(40,7,pdf_str('Volume'),1,0,'C',true);
    $pdf->Cell(35,7,pdf_str('Transactions'),1,1,'C',true);
    $pdf->SetFont('Arial','',9);
    foreach($d['top_users'] as $i=>$u){
        $pdf->Cell(10,6,(string)($i+1),1);
        $pdf->Cell(60,6,pdf_str(substr($u['name'],0,32)),1);
        $pdf->Cell(45,6,$u['phone_number'],1);
        $pdf->Cell(40,6,number_format($u['total_volume'],0,',',' ').' F',1);
        $pdf->Cell(35,6,(string)$u['tx_count'],1,1);
    }
    $pdf->Ln(4);

    $pdf->SetFont('Arial','B',11);
    $pdf->Cell(0,8,pdf_str('Repartition par operateur'),0,1);
    $pdf->SetFont('Arial','B',9);
    $pdf->SetFillColor(230,241,251);
    $pdf->Cell(90,7,pdf_str('Operateur'),1,0,'C',true);
    $pdf->Cell(90,7,pdf_str('Nombre de comptes'),1,1,'C',true);
    $pdf->SetFont('Arial','',9);
    foreach($d['operator_breakdown'] as $o){
        $pdf->Cell(90,6,pdf_str($o['operator']),1);
        $pdf->Cell(90,6,(string)$o['total'],1,1);
    }

    // Vue comparative entre pays - reservee a l'export (voir meme note que
    // dans admin_dashboard_export_xlsx()), absente si un filtre pays precis
    // etait deja actif.
    if(!$d['country_filter'] && !empty($d['country_breakdown'])){
        $pdf->Ln(4);
        $pdf->SetFont('Arial','B',11);
        $pdf->Cell(0,8,pdf_str('Repartition par pays ('.$d['period'].')'),0,1);
        $pdf->SetFont('Arial','B',9);
        $pdf->SetFillColor(230,241,251);
        $pdf->Cell(90,7,pdf_str('Pays'),1,0,'C',true);
        $pdf->Cell(50,7,pdf_str('Volume'),1,0,'C',true);
        $pdf->Cell(40,7,pdf_str('Transactions'),1,1,'C',true);
        $pdf->SetFont('Arial','',9);
        foreach($d['country_breakdown'] as $c){
            $pdf->Cell(90,6,pdf_str($c['country'] ?: '-'),1);
            $pdf->Cell(50,6,number_format($c['volume'],0,',',' ').' F',1);
            $pdf->Cell(40,6,(string)$c['count'],1,1);
        }
    }

    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="rom_money_dashboard.pdf"');
    echo $pdf->Output('S');
    exit;
}

function admin_countries_list() {
    $b = body();
    check_admin_password($b);
    $rows = q("SELECT name,is_active FROM active_countries ORDER BY is_active DESC, name ASC")->fetchAll();
    ok(['countries'=>$rows]);
}

function admin_country_toggle() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $name = trim($b['name'] ?? '');
    if(!$name) fail('Pays requis');
    $row = q("SELECT is_active FROM active_countries WHERE name=?",[$name])->fetch();
    if(!$row) fail('Pays introuvable',404);
    $newStatus = $row['is_active'] ? 0 : 1;
    q("UPDATE active_countries SET is_active=?, updated_at=NOW() WHERE name=?",[$newStatus,$name]);
    admin_log('country_toggle','success',null,dk($newStatus?'d_country_toggle_on':'d_country_toggle_off', ['country'=>$name]));
    ok(['name'=>$name,'is_active'=>(bool)$newStatus],'Statut du pays mis a jour');
}

function admin_account_status() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone'] ?? '');
    if(!$phone) fail('Telephone requis');
    $u = q("SELECT status,country FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u) fail('Compte introuvable',404);
    admin_check_country_access($u['country']);
    ok(['phone'=>$phone,'status'=>$u['status']]);
}

function admin_block_account() {
    $b = body();
    check_admin_password($b);
    $phone  = trim($b['phone'] ?? '');
    $reason = trim($b['reason'] ?? '');
    if(!$phone || !$reason) fail('Telephone et raison requis');
    if($phone === '0160629502'){
        admin_log('account_block','failed',$phone,'Tentative de blocage du compte systeme via l\'outil generique (bloquee)');
        fail('Ce compte est reserve a l\'onglet Gains ROM.',403);
    }
    $u = q("SELECT id,status,country FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u){
        admin_log('account_block','failed',$phone,dk('d_account_not_found'));
        fail('Compte introuvable',404);
    }
    admin_check_country_access($u['country']);
    if($u['status']==='blocked'){
        admin_log('account_block','failed',$phone,dk('d_already_blocked', ['reason'=>$reason]));
        fail('Ce compte est deja bloque');
    }
    q("UPDATE users SET status='blocked' WHERE id=?",[$u['id']]);
    admin_log('account_block','success',$phone,$reason);
    ok(null,'Compte bloque avec succes');
}

function admin_unblock_account() {
    $b = body();
    check_admin_password($b);
    $phone  = trim($b['phone'] ?? '');
    $reason = trim($b['reason'] ?? '');
    if(!$phone || !$reason) fail('Telephone et raison requis');
    if($phone === '0160629502'){
        admin_log('account_unblock','failed',$phone,'Tentative de deblocage du compte systeme via l\'outil generique (bloquee)');
        fail('Ce compte est reserve a l\'onglet Gains ROM.',403);
    }
    $u = q("SELECT id,status,country FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u){
        admin_log('account_unblock','failed',$phone,dk('d_account_not_found'));
        fail('Compte introuvable',404);
    }
    admin_check_country_access($u['country']);
    if($u['status']==='active'){
        admin_log('account_unblock','failed',$phone,dk('d_already_active', ['reason'=>$reason]));
        fail('Ce compte est deja actif');
    }
    q("UPDATE users SET status='active' WHERE id=?",[$u['id']]);
    admin_log('account_unblock','success',$phone,$reason);
    ok(null,'Compte debloque avec succes');
}

// ============================================================
// SUPPRESSION COMPLETE D'UN COMPTE — irreversible. Reserve aux comptes de
// test/erreurs d'inscription : supprime TOUT ce qui identifie ce compte
// (utilisateur, portefeuille, historique KYC, appareils connus, banques
// liees, notifications, abonnements push) de sorte que le numero de
// telephone redevient totalement libre, comme s'il n'avait jamais existe.
// Les transactions DEJA EFFECTUEES ne sont PAS supprimees : les toucher
// fausserait l'historique comptable de l'autre partie impliquee (quelqu'un
// a reellement recu ou envoye cet argent). Seul le compte disparait ; ces
// transactions resteront visibles cote destinataire/expediteur, juste sans
// nom associe pour ce compte supprime.
// ============================================================
function admin_delete_account() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone'] ?? '');
    $confirmPhone = trim($b['confirm_phone'] ?? '');
    $reason = trim($b['reason'] ?? '');
    if(!$phone || !$reason) fail('Telephone et raison requis');
    if($phone !== $confirmPhone) fail('La confirmation ne correspond pas au numero saisi');
    if($phone === '0160629502'){
        admin_log('account_delete','failed',$phone,'Tentative de suppression du compte systeme via l\'outil generique (bloquee)');
        fail('Ce compte est reserve a l\'onglet Gains ROM.',403);
    }

    $u = q("SELECT id,full_name,country FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u){
        admin_log('account_delete','failed',$phone,dk('d_account_not_found'));
        fail('Compte introuvable',404);
    }
    admin_check_country_access($u['country']);
    $uid = $u['id'];

    q("DELETE FROM kyc_requests WHERE user_id=?",[$uid]);
    q("DELETE FROM known_devices WHERE user_id=?",[$uid]);
    q("DELETE FROM push_subscriptions WHERE user_id=?",[$uid]);
    q("DELETE FROM linked_banks WHERE user_id=?",[$uid]);
    q("DELETE FROM notifications WHERE user_id=?",[$uid]);
    q("DELETE FROM referral_bonuses WHERE referrer_id=? OR referee_id=?",[$uid,$uid]);
    // Debarrasse les autres comptes de la reference a ce parrain supprime,
    // sans les toucher autrement (ils gardent leur propre historique intact).
    q("UPDATE users SET referred_by=NULL WHERE referred_by=?",[$uid]);
    q("DELETE FROM wallets WHERE user_id=?",[$uid]);
    q("DELETE FROM users WHERE id=?",[$uid]);

    admin_log('account_delete','success',$phone,dk('d_account_deleted', ['name'=>($u['full_name']?:'?'), 'reason'=>$reason]));
    ok(null,'Compte supprime definitivement');
}

// Equivalent de admin_delete_account() mais pour un compte marchand
// ROM_BUSINESS. Supprime aussi sub_vaults (sous-coffres) rattaches au
// portefeuille marchand - sans FK CASCADE sur cette table, un oubli laisserait
// des lignes orphelines invisibles apres suppression du portefeuille.
function admin_merchant_delete_account() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone'] ?? '');
    $confirmPhone = trim($b['confirm_phone'] ?? '');
    $reason = trim($b['reason'] ?? '');
    if(!$phone || !$reason) fail('Telephone et raison requis');
    if($phone !== $confirmPhone) fail('La confirmation ne correspond pas au numero saisi');

    $m = q("SELECT id,business_name,country FROM merchants WHERE phone_number=?",[$phone])->fetch();
    if(!$m){
        admin_log('merchant_delete','failed',$phone,'Compte marchand introuvable');
        fail('Compte marchand introuvable',404);
    }
    admin_check_country_access($m['country']);
    $mid = $m['id'];
    $mw = q("SELECT id FROM merchant_wallets WHERE merchant_id=?",[$mid])->fetch();

    q("DELETE FROM merchant_documents WHERE merchant_id=?",[$mid]);
    q("DELETE FROM merchant_notes WHERE merchant_id=?",[$mid]);
    q("DELETE FROM merchant_known_devices WHERE merchant_id=?",[$mid]);
    q("DELETE FROM merchant_push_subscriptions WHERE merchant_id=?",[$mid]);
    q("DELETE FROM merchant_payment_links WHERE merchant_id=?",[$mid]);
    if($mw){
        q("DELETE FROM sub_vaults WHERE wallet_id=?",[$mw['id']]);
    }
    q("DELETE FROM merchant_wallets WHERE merchant_id=?",[$mid]);
    q("DELETE FROM merchants WHERE id=?",[$mid]);

    admin_log('merchant_delete','success',$phone,'Compte marchand "'.($m['business_name']?:'?').'" supprime definitivement ('.$reason.')');
    ok(null,'Compte marchand supprime definitivement');
}

// ============================================================
// ROM_GUICHET — Outillage admin pour les agents de depot/retrait.
// Meme conception que l'outillage marchand ci-dessus.
// ============================================================
function admin_agent_search() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone']??'');
    if(!$phone) fail('Numero requis');
    try {
        $a = q("SELECT * FROM agents WHERE phone_number=?",[$phone])->fetch();
    } catch(Exception $e) {
        log_and_fail($e, 'Service agent indisponible (base non initialisee).', 503);
    }
    if(!$a) fail('Aucun compte agent pour ce numero',404);
    admin_check_country_access($a['country']);
    $w = q("SELECT id,balance,currency FROM agent_wallets WHERE agent_id=?",[$a['id']])->fetch();
    try {
        $devices = q("SELECT device_id,user_agent,first_seen,last_seen FROM agent_known_devices WHERE agent_id=? ORDER BY last_seen DESC",[$a['id']])->fetchAll();
    } catch(Exception $e) {
        $devices = [];
    }
    $recharges = q("SELECT id,amount,note,status,created_at,reviewed_at,reject_reason FROM agent_recharge_requests WHERE agent_id=? ORDER BY created_at DESC LIMIT 20",[$a['id']])->fetchAll();
    $awid = $w['id'] ?? null;
    $txs = [];
    if($awid){
        $txs = q("SELECT t.*,
            CASE WHEN t.sender_agent_wallet_id=? THEN 'debit' ELSE 'credit' END as direction,
            cu.full_name customer_name, cu.phone_number customer_phone
            FROM transactions t
            LEFT JOIN wallets cw ON cw.id = COALESCE(t.sender_wallet_id, t.receiver_wallet_id)
            LEFT JOIN users cu ON cu.id = cw.user_id
            WHERE t.sender_agent_wallet_id=? OR t.receiver_agent_wallet_id=?
            ORDER BY t.created_at DESC LIMIT 30",[$awid,$awid,$awid])->fetchAll();
    }
    ok(['id'=>$a['id'],'full_name'=>$a['full_name'],'phone_number'=>$a['phone_number'],
        'address'=>$a['address'],'status'=>$a['status'],'rejection_reason'=>$a['rejection_reason']??null,
        'verified'=>(bool)($a['verified']??false),
        'is_distributor'=>(bool)($a['is_distributor']??false),'max_float_cap'=>$a['max_float_cap']!==null?(float)$a['max_float_cap']:null,
        'created_at'=>$a['created_at'],'country'=>$a['country']??null,'currency'=>$w['currency']??'XOF',
        'balance'=>(float)($w['balance']??0),'transactions'=>$txs,'known_devices'=>$devices,
        'recharge_requests'=>$recharges]);
}

// Liste des agents avec statistiques agregees (commission totale, volume
// total, derniere activite) - permet de suivre/comparer les agents et
// distributeurs d'un coup d'oeil, sans devoir ouvrir chaque fiche un par un.
function admin_agent_list() {
    $b = body();
    check_admin_password($b);
    $page = max(1, (int)($b['page'] ?? 1));
    $perPage = 25;
    $offset = ($page - 1) * $perPage;
    list($scopeSql, $scopeParams) = admin_country_scope_clause('a.country');
    try {
        $total = (int)q("SELECT COUNT(*) FROM agents a WHERE 1=1".$scopeSql, $scopeParams)->fetchColumn();
        $rows = q("SELECT a.id,a.full_name,a.phone_number,a.status,a.verified,a.is_distributor,a.max_float_cap,a.created_at,
                MAX(w.balance) AS balance, MAX(w.currency) AS currency,
                COALESCE(SUM(CASE WHEN t.type='agent_commission' THEN t.amount ELSE 0 END),0) AS total_commission,
                COALESCE(SUM(CASE WHEN t.type IN ('agent_cash_in','agent_cash_out') THEN t.amount ELSE 0 END),0) AS total_volume,
                MAX(CASE WHEN t.type IN ('agent_cash_in','agent_cash_out') THEN t.created_at END) AS last_activity
            FROM agents a
            LEFT JOIN agent_wallets w ON w.agent_id = a.id
            LEFT JOIN transactions t ON (t.sender_agent_wallet_id = w.id OR t.receiver_agent_wallet_id = w.id) AND t.status='completed'
            WHERE 1=1".$scopeSql."
            GROUP BY a.id
            ORDER BY a.created_at DESC LIMIT $perPage OFFSET $offset", $scopeParams)->fetchAll();
    } catch(Exception $e) {
        log_and_fail($e, 'Service agent indisponible (base non initialisee).', 503);
    }
    ok(['agents'=>$rows,'total'=>$total,'page'=>$page,'per_page'=>$perPage]);
}

function admin_agent_test_credit_wallet() {
    $b = body();
    check_admin_password($b);
    check_earnings_password($b);
    $phone = trim($b['phone']??'');
    $amount = (float)($b['amount']??0);
    $reason = trim($b['reason']??'');
    if(!$phone) fail('Numero requis');
    if($amount<=0) fail('Montant invalide');
    if($amount>1000000) fail('Montant trop eleve pour un credit de test (max 1 000 000)');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $a = q("SELECT id,country FROM agents WHERE phone_number=?",[$phone])->fetch();
    if(!$a) fail('Compte agent introuvable',404);
    admin_check_country_access($a['country']);
    $aw = q("SELECT id FROM agent_wallets WHERE agent_id=?",[$a['id']])->fetch();
    if(!$aw) fail('Portefeuille agent introuvable',404);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,receiver_agent_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'admin_test_credit','completed',?,?)",
          [$txid,$aw['id'],$amount,$reference,'ROM '.$reason]);
        q("UPDATE agent_wallets SET balance=balance+? WHERE id=?",[$amount,$aw['id']]);
        db()->commit();
        admin_log('agent_test_credit','success',$phone,dk('d_ref_with_reason', ['ref'=>$reference, 'reason'=>$reason]));
        $bal = (float)q("SELECT balance FROM agent_wallets WHERE id=?",[$aw['id']])->fetchColumn();
        ok(['new_balance'=>$bal],'Credit de test effectue');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec du credit', 500); }
}

function admin_agent_delete_account() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone'] ?? '');
    $confirmPhone = trim($b['confirm_phone'] ?? '');
    $reason = trim($b['reason'] ?? '');
    if(!$phone || !$reason) fail('Telephone et raison requis');
    if($phone !== $confirmPhone) fail('La confirmation ne correspond pas au numero saisi');

    $a = q("SELECT id,full_name,country FROM agents WHERE phone_number=?",[$phone])->fetch();
    if(!$a){
        admin_log('agent_delete','failed',$phone,'Compte agent introuvable');
        fail('Compte agent introuvable',404);
    }
    admin_check_country_access($a['country']);
    $aid = $a['id'];

    q("DELETE FROM agent_known_devices WHERE agent_id=?",[$aid]);
    q("DELETE FROM agent_recharge_requests WHERE agent_id=?",[$aid]);
    q("DELETE FROM agent_wallets WHERE agent_id=?",[$aid]);
    q("DELETE FROM agents WHERE id=?",[$aid]);

    admin_log('agent_delete','success',$phone,'Compte agent "'.($a['full_name']?:'?').'" supprime definitivement ('.$reason.')');
    ok(null,'Compte agent supprime definitivement');
}

// Demandes de recharge de float en attente (+ historique complet si
// status='' est passe) - meme principe que admin_delete_kyc()'s file d'attente.
function admin_agent_list_recharge_requests() {
    $b = body();
    check_admin_password($b);
    $status = trim($b['status'] ?? 'pending');
    agent_expire_stale_recharge_requests();
    // dist_name/dist_phone n'est renseigne qu'une fois la demande traitee
    // (approuvee/rejetee) - qui l'a servie, jamais un ciblage a l'avance
    // (file d'attente partagee entre tous les distributeurs + admin, voir
    // agent_approve_recharge_request()). Colonnes listees explicitement
    // (jamais r.*) : confirmation_code ne doit
    // JAMAIS transiter par cette liste, seul le demandeur doit pouvoir le
    // retrouver (voir agent_recharge_history()), sinon le code ne prouve
    // plus un contact reel entre les deux parties.
    $cols = "r.id,r.agent_id,r.amount,r.note,r.status,r.created_at,r.reviewed_at,r.reject_reason,r.distributor_id";
    list($scopeSql, $scopeParams) = admin_country_scope_clause('a.country');
    if($status !== ''){
        $rows = q("SELECT $cols, a.full_name, a.phone_number, d.full_name dist_name, d.phone_number dist_phone FROM agent_recharge_requests r
            JOIN agents a ON a.id=r.agent_id LEFT JOIN agents d ON d.id=r.distributor_id
            WHERE r.status=?".$scopeSql." ORDER BY r.created_at ASC", array_merge([$status], $scopeParams))->fetchAll();
    } else {
        $rows = q("SELECT $cols, a.full_name, a.phone_number, d.full_name dist_name, d.phone_number dist_phone FROM agent_recharge_requests r
            JOIN agents a ON a.id=r.agent_id LEFT JOIN agents d ON d.id=r.distributor_id
            WHERE 1=1".$scopeSql." ORDER BY r.created_at DESC LIMIT 100", $scopeParams)->fetchAll();
    }
    ok(['requests'=>$rows]);
}

function admin_agent_approve_recharge() {
    $b = body();
    check_admin_password($b);
    check_earnings_password($b);
    $id = trim($b['id'] ?? '');
    $code = trim($b['code'] ?? '');
    if(!$id) fail('Demande requise');
    if(!$code) fail('Code de confirmation requis');
    agent_expire_stale_recharge_requests();
    $r = q("SELECT * FROM agent_recharge_requests WHERE id=?",[$id])->fetch();
    if(!$r) fail('Demande introuvable',404);
    $rAgent = q("SELECT country FROM agents WHERE id=?",[$r['agent_id']])->fetch();
    admin_check_country_access($rAgent['country'] ?? null);
    if($r['status'] === 'expired') fail('Cette demande a expire (plus de 3h sans traitement), le demandeur doit en refaire une', 410);
    if($r['status'] !== 'pending') fail('Cette demande a deja ete traitee');
    if(!hash_equals((string)$r['confirmation_code'], $code)) fail('Code de confirmation incorrect', 401);
    $aw = q("SELECT id,balance FROM agent_wallets WHERE agent_id=?",[$r['agent_id']])->fetch();
    if(!$aw) fail('Portefeuille agent introuvable',404);
    // Plafond de float (distributeurs uniquement) : protection contre le
    // risque qu'une trop grosse somme lui soit confiee d'un coup - voir
    // DISTRIBUTOR_DEFAULT_FLOAT_CAP / admin_agent_set_float_cap().
    $targetAgent = q("SELECT is_distributor,max_float_cap FROM agents WHERE id=?",[$r['agent_id']])->fetch();
    if($targetAgent && $targetAgent['is_distributor'] && $targetAgent['max_float_cap'] !== null){
        $futureBalance = (float)$aw['balance'] + (float)$r['amount'];
        if($futureBalance > (float)$targetAgent['max_float_cap']){
            fail('Ce montant depasserait le plafond de float autorise pour ce distributeur ('.$targetAgent['max_float_cap'].' XOF). Augmentez son plafond avant d\'approuver, si besoin.', 422);
        }
    }
    // Genere AVANT le claim pour pouvoir l'enregistrer sur la demande elle-
    // meme (visible ensuite dans l'historique agent pour preuve/comptabilite).
    $txid = uid(); $reference = ref();
    db()->beginTransaction();
    // Meme "claim" atomique que agent_approve_recharge_request() : la file
    // est desormais partagee entre l'admin ET tous les distributeurs, un
    // distributeur pourrait approuver au meme instant.
    $claimed = q("UPDATE agent_recharge_requests SET status='approved', reference=?, reviewed_at=NOW() WHERE id=? AND status='pending'",[$reference,$id])->rowCount();
    if(!$claimed){ db()->rollBack(); fail('Cette demande vient d\'etre traitee par quelqu\'un d\'autre', 409); }
    try {
        q("INSERT INTO transactions (id,receiver_agent_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'agent_recharge','completed',?,?)",
          [$txid,$aw['id'],$r['amount'],$reference,'Recharge de float approuvee']);
        q("UPDATE agent_wallets SET balance=balance+? WHERE id=?",[$r['amount'],$aw['id']]);
        db()->commit();
        admin_log('agent_recharge_approve','success',null,dk('d_ref_with_reason', ['ref'=>$reference, 'reason'=>'Recharge de '.$r['amount']]));
        $bal = (float)q("SELECT balance FROM agent_wallets WHERE id=?",[$aw['id']])->fetchColumn();
        web_push_send_to_agent($r['agent_id'], 'ROM_GUICHET', 'Votre demande de recharge de '.number_format($r['amount'],0,',',' ').' a ete approuvee.');
        ok(['new_balance'=>$bal],'Recharge approuvee et creditee');
    } catch(Exception $e) { db()->rollBack(); log_and_fail($e, 'Echec de la recharge', 500); }
}

// Registre complet de tous les mouvements de recharge de float agent
// (admin_agent_approve_recharge() ET agent_approve_recharge_request(),
// desormais dans une file partagee - voir plus haut), avec tous les filtres
// utiles. Construit depuis `transactions` (source de verite du mouvement
// d'argent reel), pas depuis agent_recharge_requests (etat de workflow) :
// sender_agent_wallet_id NULL = credit direct par l'Admin Principal (Gains
// ROM) ; renseigne = redirige depuis le float d'un distributeur.
function admin_agent_recharge_movements() {
    $b = body();
    check_admin_password($b);
    $dateFrom = trim($b['date_from'] ?? '');
    $dateTo = trim($b['date_to'] ?? '');
    $agentPhone = trim($b['agent_phone'] ?? '');
    $distPhone = trim($b['distributor_phone'] ?? '');
    $minAmount = isset($b['min_amount']) && $b['min_amount']!=='' ? (float)$b['min_amount'] : null;
    $maxAmount = isset($b['max_amount']) && $b['max_amount']!=='' ? (float)$b['max_amount'] : null;
    $source = trim($b['source'] ?? ''); // '' = tous, 'admin' = credit direct, 'distributor' = via distributeur

    $where = ["t.type='agent_recharge'", "t.status='completed'"];
    $params = [];
    if($dateFrom){ $where[] = "t.created_at >= ?"; $params[] = $dateFrom.' 00:00:00'; }
    if($dateTo){ $where[] = "t.created_at <= ?"; $params[] = $dateTo.' 23:59:59'; }
    if($agentPhone){ $where[] = "ra.phone_number = ?"; $params[] = $agentPhone; }
    if($distPhone){ $where[] = "rd.phone_number = ?"; $params[] = $distPhone; }
    if($minAmount !== null){ $where[] = "t.amount >= ?"; $params[] = $minAmount; }
    if($maxAmount !== null){ $where[] = "t.amount <= ?"; $params[] = $maxAmount; }
    if($source === 'admin'){ $where[] = "t.sender_agent_wallet_id IS NULL"; }
    if($source === 'distributor'){ $where[] = "t.sender_agent_wallet_id IS NOT NULL"; }

    list($scopeSql, $scopeParams) = admin_country_scope_clause('ra.country');
    $sql = "SELECT t.id,t.amount,t.reference,t.description,t.created_at,
        ra.full_name receiver_name, ra.phone_number receiver_phone,
        rd.full_name sender_name, rd.phone_number sender_phone
        FROM transactions t
        JOIN agent_wallets raw ON raw.id = t.receiver_agent_wallet_id
        JOIN agents ra ON ra.id = raw.agent_id
        LEFT JOIN agent_wallets rdw ON rdw.id = t.sender_agent_wallet_id
        LEFT JOIN agents rd ON rd.id = rdw.agent_id
        WHERE ".implode(' AND ', $where).$scopeSql."
        ORDER BY t.created_at DESC LIMIT 300";
    $rows = q($sql, array_merge($params, $scopeParams))->fetchAll();
    ok(['movements'=>$rows]);
}

// Bascule le statut "distributeur" - mirror exact de
// admin_merchant_toggle_verified(). Mot de passe admin standard suffit :
// ca ne cree pas d'argent, ca ne fait que deleguer la capacite de rediriger
// du float deja approuve vers d'autres agents.
function admin_agent_toggle_distributor() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['agent_id']??'');
    if(!$id) fail('Agent requis');
    $a = q("SELECT id,full_name,is_distributor,max_float_cap,country FROM agents WHERE id=?",[$id])->fetch();
    if(!$a) fail('Agent introuvable',404);
    admin_check_country_access($a['country']);
    $newVal = $a['is_distributor'] ? 0 : 1;
    // A la toute premiere promotion (pas de plafond deja fixe), demarre bas -
    // montee en confiance progressive, jamais un gros plafond d'entree de jeu.
    // Le retrait du statut ne touche pas au plafond (garde l'historique si le
    // statut est redonne plus tard).
    if($newVal && $a['max_float_cap']===null){
        q("UPDATE agents SET is_distributor=1, max_float_cap=? WHERE id=?",[DISTRIBUTOR_DEFAULT_FLOAT_CAP,$id]);
    } else {
        q("UPDATE agents SET is_distributor=? WHERE id=?",[$newVal,$id]);
    }
    admin_log('agent_toggle_distributor','success',null,'Agent '.$a['full_name'].' -> '.($newVal?'distributeur':'agent standard'));
    ok(['is_distributor'=>(bool)$newVal],$newVal?'Statut distributeur accorde':'Statut distributeur retire');
}

// Ajustement manuel du plafond de float d'un distributeur - permet a
// l'admin de l'augmenter au fil de la confiance etablie (ou de le baisser
// si besoin). $cap=null retire toute limite (a utiliser avec prudence).
function admin_agent_set_float_cap() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['agent_id']??'');
    if(!$id) fail('Agent requis');
    $capRaw = $b['max_float_cap'] ?? null;
    $cap = ($capRaw===null || $capRaw==='') ? null : (float)$capRaw;
    if($cap !== null && $cap < 0) fail('Plafond invalide');
    $a = q("SELECT id,full_name,is_distributor,country FROM agents WHERE id=?",[$id])->fetch();
    if(!$a) fail('Agent introuvable',404);
    admin_check_country_access($a['country']);
    if(!$a['is_distributor']) fail('Ce plafond ne concerne que les distributeurs');
    q("UPDATE agents SET max_float_cap=? WHERE id=?",[$cap,$id]);
    admin_log('agent_set_float_cap','success',null,'Plafond de '.$a['full_name'].' -> '.($cap===null?'illimite':$cap));
    ok(['max_float_cap'=>$cap],'Plafond mis a jour');
}

// ── Agrement agent (documents + activation) ──
// Pas de check_earnings_password() ici : approuver/rejeter une inscription
// n'autorise ni ne deplace d'argent, seulement l'acces a l'application -
// meme logique que admin_agent_toggle_distributor() ci-dessus.
function admin_agent_list_pending() {
    $b = body();
    check_admin_password($b);
    list($scopeSql, $scopeParams) = admin_country_scope_clause('country');
    $rows = q("SELECT id,full_name,phone_number,country,created_at FROM agents WHERE status='pending_approval'".$scopeSql." ORDER BY created_at ASC", $scopeParams)->fetchAll();
    ok(['agents'=>$rows]);
}

function admin_agent_documents() {
    $b = body();
    check_admin_password($b);
    $agentId = trim($b['agent_id'] ?? '');
    if(!$agentId) fail('Agent requis');
    $ac = q("SELECT country FROM agents WHERE id=?",[$agentId])->fetch();
    if(!$ac) fail('Agent introuvable',404);
    admin_check_country_access($ac['country']);
    try {
        $rows = q("SELECT id, doc_type, photo, uploaded_at FROM agent_documents WHERE agent_id=? ORDER BY uploaded_at DESC",[$agentId])->fetchAll();
    } catch(Exception $e) {
        $rows = [];
    }
    // Trie selon l'ordre logique agent (requis puis optionnels, meme ordre
    // que cote agent au moment de l'envoi) plutot que l'ordre alphabetique
    // du type - sinon l'admin voit une disposition incoherente avec ce que
    // l'agent avait sous les yeux en envoyant ses documents.
    $order = array_merge(AGENT_DOC_TYPES, AGENT_OPTIONAL_DOC_TYPES);
    usort($rows, function($a, $b2) use ($order) {
        $ia = array_search($a['doc_type'], $order); $ia = $ia===false ? 999 : $ia;
        $ib = array_search($b2['doc_type'], $order); $ib = $ib===false ? 999 : $ib;
        if($ia !== $ib) return $ia <=> $ib;
        return strcmp($b2['uploaded_at'], $a['uploaded_at']);
    });
    foreach($rows as &$r){ $r['photo'] = kyc_decrypt($r['photo']); }
    unset($r);
    ok(['documents'=>$rows]);
}

// Libere un creneau (agent+doc_type) occupe par un document deja fourni -
// raison obligatoire et journalisee. Sert aussi bien a rejeter une piece
// de mauvaise qualite qu'a retirer volontairement un document deja valide
// pour permettre son remplacement (meme mecanique SQL dans les deux cas).
function admin_agent_delete_document() {
    $b = body();
    check_admin_password($b);
    $id = (int)($b['id'] ?? 0);
    $reason = trim($b['reason']??'');
    if(!$id) fail('Document requis');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $d = q("SELECT ad.agent_id, ad.doc_type, a.phone_number, a.country FROM agent_documents ad JOIN agents a ON a.id=ad.agent_id WHERE ad.id=?",[$id])->fetch();
    if(!$d) fail('Document introuvable',404);
    admin_check_country_access($d['country']);
    q("DELETE FROM agent_documents WHERE id=?",[$id]);
    // Contrairement au refus de toute la demande (qui a deja sa propre
    // rejection_reason globale), retirer UN SEUL document pour en demander un
    // meilleur n'a aujourd'hui aucune trace visible cote agent - il voit juste
    // le creneau redevenu vide, sans savoir pourquoi. On garde une note legere
    // (jamais la photo elle-meme) jusqu'a ce qu'il renvoie ce type de document.
    q("INSERT INTO agent_document_notices (agent_id,doc_type,reason) VALUES (?,?,?)",[$d['agent_id'],$d['doc_type'],$reason]);
    admin_log('agent_delete_document','success',$d['phone_number'],$reason.' ('.$d['doc_type'].')');
    ok(null,'Document supprime');
}

function admin_agent_approve_registration() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['agent_id']??'');
    if(!$id) fail('Agent requis');
    $a = q("SELECT id,full_name,phone_number,status,country FROM agents WHERE id=?",[$id])->fetch();
    if(!$a) fail('Agent introuvable',404);
    admin_check_country_access($a['country']);
    if($a['status'] !== 'pending_approval') fail('Cette demande a deja ete traitee');
    q("UPDATE agents SET status='active', rejection_reason=NULL WHERE id=?",[$id]);
    admin_log('agent_approve_registration','success',$a['phone_number'],'Agent '.$a['full_name'].' agree et active');
    ok(null,'Agent agree et active');
}

function admin_agent_reject_registration() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['agent_id']??'');
    $reason = trim($b['reason']??'');
    if(!$id) fail('Agent requis');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $a = q("SELECT id,full_name,phone_number,status,country FROM agents WHERE id=?",[$id])->fetch();
    if(!$a) fail('Agent introuvable',404);
    admin_check_country_access($a['country']);
    if($a['status'] !== 'pending_approval') fail('Cette demande a deja ete traitee');
    q("UPDATE agents SET status='rejected', rejection_reason=? WHERE id=?",[$reason,$id]);
    // Refuse = aucune trace dans le systeme = suppression automatique et
    // immediate des documents fournis, sans etape manuelle separee.
    q("DELETE FROM agent_documents WHERE agent_id=?",[$id]);
    // Les notes individuelles eventuelles n'ont plus de sens : la raison
    // globale (rejection_reason ci-dessus) prend le relais a l'affichage.
    q("DELETE FROM agent_document_notices WHERE agent_id=?",[$id]);
    admin_log('agent_reject_registration','success',$a['phone_number'],$reason);
    ok(null,'Demande d\'agrement refusee');
}

// Rouvre une demande rejetee par erreur (ou apres reconsideration) - remet
// en file d'attente sans obliger l'agent a renvoyer ses documents ni a
// recreer un compte (le numero reste bloque pour une nouvelle inscription
// tant que ce compte existe).
function admin_agent_reopen_registration() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['agent_id']??'');
    if(!$id) fail('Agent requis');
    $a = q("SELECT id,full_name,phone_number,status,country FROM agents WHERE id=?",[$id])->fetch();
    if(!$a) fail('Agent introuvable',404);
    admin_check_country_access($a['country']);
    if($a['status'] !== 'rejected') fail('Seule une demande refusee peut etre rouverte');
    q("UPDATE agents SET status='pending_approval', rejection_reason=NULL WHERE id=?",[$id]);
    admin_log('agent_reopen_registration','success',$a['phone_number'],'Demande rouverte pour '.$a['full_name']);
    ok(null,'Demande rouverte, remise en attente');
}

// CRUD des 26 paliers de commission - meme pattern que
// admin_countries_list()/admin_country_toggle() (une vraie table, pas un
// reglage app_settings scalaire : aucun precedent de tableau dans
// app_settings dans ce projet).
function admin_agent_commission_tiers_list() {
    $b = body();
    check_admin_password($b);
    $rows = q("SELECT id,band_min_xof,band_max_xof,commission_xof FROM agent_commission_tiers ORDER BY band_min_xof ASC")->fetchAll();
    ok(['tiers'=>$rows]);
}

function admin_agent_commission_tiers_update() {
    $b = body();
    check_admin_password($b);
    check_super_admin_only();
    $id = (int)($b['id'] ?? 0);
    $commission = (float)($b['commission_xof'] ?? -1);
    if(!$id) fail('Palier requis');
    if($commission < 0) fail('Commission invalide');
    $row = q("SELECT id FROM agent_commission_tiers WHERE id=?",[$id])->fetch();
    if(!$row) fail('Palier introuvable',404);
    q("UPDATE agent_commission_tiers SET commission_xof=?, updated_at=NOW() WHERE id=?",[$commission,$id]);
    admin_log('agent_tier_update','success',null,'Palier #'.$id.' -> '.$commission.' XOF');
    ok(null,'Palier mis a jour');
}

// Consultation des taux actuellement en cache - permet de verifier que la
// recuperation automatique fonctionne, et de voir "l'age" des taux affiches.
function admin_get_exchange_rates() {
    $b = body();
    check_admin_password($b);
    $rows = q("SELECT currency_code, rate_to_usd, updated_at FROM exchange_rates ORDER BY currency_code ASC")->fetchAll();
    ok(['rates' => $rows]);
}

// Force un rafraichissement immediat (ignore le cache de 12h), pour tester
// tout de suite apres deploiement sans attendre le prochain cycle naturel.
function admin_refresh_exchange_rates() {
    $b = body();
    check_admin_password($b);
    $rates = fetch_rates_from_api();
    if (!$rates) fail('Impossible de contacter la source de taux de change (les deux URLs ont echoue). Reessayez dans quelques instants.');
    $count = 0;
    foreach ($rates as $code => $rate) {
        if (!is_numeric($rate) || $rate <= 0) continue;
        q("INSERT INTO exchange_rates (currency_code, rate_to_usd) VALUES (?,?)
           ON CONFLICT (currency_code) DO UPDATE SET rate_to_usd=EXCLUDED.rate_to_usd, updated_at=NOW()",
          [strtoupper($code), $rate]);
        $count++;
    }
    admin_log('exchange_rates_refresh','success',null,dk('d_currencies_updated', ['count'=>$count]));
    ok(['updated' => $count], 'Taux de change actualises');
}

function admin_update_country() {
    $b = body();
    check_admin_password($b);
    $phone   = trim($b['phone'] ?? '');
    $country = trim($b['country'] ?? '');
    $reason  = trim($b['reason'] ?? '');
    if(!$phone || !$country || !$reason) fail('Telephone, pays et raison requis');
    if($phone === '0160629502'){
        admin_log('update_country','failed',$phone,'Tentative de changement de pays du compte systeme via l\'outil generique (bloquee)');
        fail('Ce compte est reserve a l\'onglet Gains ROM.',403);
    }
    $u = q("SELECT id,country FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u){
        admin_log('update_country','failed',$phone,dk('d_account_not_found'));
        fail('Compte introuvable',404);
    }
    admin_check_country_access($u['country']);
    $countryRow = q("SELECT is_active FROM active_countries WHERE name=?",[$country])->fetch();
    if(!$countryRow || !$countryRow['is_active']){
        admin_log('update_country','failed',$phone,dk('d_country_not_active', ['country'=>$country, 'reason'=>$reason]));
        fail('Ce pays n\'est pas actif sur ROM_MONEY');
    }
    $oldCountry = $u['country'];
    $newCurrency = country_to_currency($country);
    $w = q("SELECT id,currency,balance,vault_balance FROM wallets WHERE user_id=?",[$u['id']])->fetch();
    $oldCurrency = $w ? strtoupper($w['currency'] ?: 'XOF') : 'XOF';
    if($oldCurrency==='FCFA') $oldCurrency='XOF'; // voir convert_currency() : ancienne valeur par defaut, pas un vrai code ISO

    db()->beginTransaction();
    try {
        q("UPDATE users SET country=? WHERE id=?",[$country,$u['id']]);
        if($w && $oldCurrency !== $newCurrency){
            // Convertit solde principal, coffre et sous-coffres au VRAI taux de
            // change pour preserver la valeur reelle de l'argent - un simple
            // changement d'etiquette de devise ferait passer par ex. 10000 XOF
            // (~17 USD) pour 10000 MAD (~1000 USD), un gain fictif enorme.
            $newBalance = convert_currency((float)$w['balance'], $oldCurrency, $newCurrency);
            $newVault = convert_currency((float)$w['vault_balance'], $oldCurrency, $newCurrency);
            if($newBalance===null || $newVault===null) throw new Exception('Conversion de devise momentanement indisponible');
            q("UPDATE wallets SET currency=?,balance=?,vault_balance=? WHERE id=?",
              [$newCurrency, round($newBalance,2), round($newVault,2), $w['id']]);
            $subVaults = q("SELECT id,balance,goal_amount FROM sub_vaults WHERE wallet_id=?",[$w['id']])->fetchAll();
            foreach($subVaults as $sv){
                $svBal = convert_currency((float)$sv['balance'], $oldCurrency, $newCurrency);
                if($svBal===null) throw new Exception('Conversion de devise momentanement indisponible');
                $svGoal = null;
                if($sv['goal_amount']!==null){
                    $svGoal = convert_currency((float)$sv['goal_amount'], $oldCurrency, $newCurrency);
                    if($svGoal===null) throw new Exception('Conversion de devise momentanement indisponible');
                }
                q("UPDATE sub_vaults SET balance=?,goal_amount=? WHERE id=?",
                  [round($svBal,2), $svGoal!==null?round($svGoal,2):null, $sv['id']]);
            }
        } elseif($w) {
            q("UPDATE wallets SET currency=? WHERE id=?",[$newCurrency,$w['id']]);
        }
        db()->commit();
    } catch(Exception $e) {
        db()->rollBack();
        admin_log('update_country','failed',$phone,'Echec conversion devise lors du changement de pays vers '.$country.' ('.$reason.')');
        log_and_fail($e, 'Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
    }
    admin_log('update_country','success',$phone,dk('d_country_changed', ['old'=>($oldCountry?:'-'), 'new'=>$country, 'reason'=>$reason]));
    ok(null,'Pays mis a jour avec succes');
}

// Equivalent de admin_update_country() mais pour un compte marchand
// ROM_BUSINESS (table merchants/merchant_wallets, identifie par telephone
// marchand plutot que numero personnel). Meme logique de conversion reelle
// (jamais un simple relabel) sur balance/vault_balance et les sous-coffres
// du marchand (sub_vaults partage le meme moteur que ROM_MONEY, cle sur
// merchant_wallets.id).
function admin_merchant_update_country() {
    $b = body();
    check_admin_password($b);
    $phone   = trim($b['phone'] ?? '');
    $country = trim($b['country'] ?? '');
    $reason  = trim($b['reason'] ?? '');
    if(!$phone || !$country || !$reason) fail('Telephone, pays et raison requis');
    $m = q("SELECT id,country FROM merchants WHERE phone_number=?",[$phone])->fetch();
    if(!$m){
        admin_log('merchant_update_country','failed',$phone,'Compte marchand introuvable');
        fail('Compte marchand introuvable',404);
    }
    admin_check_country_access($m['country']);
    $countryRow = q("SELECT is_active FROM active_countries WHERE name=?",[$country])->fetch();
    if(!$countryRow || !$countryRow['is_active']){
        admin_log('merchant_update_country','failed',$phone,'Pays non actif : '.$country.' ('.$reason.')');
        fail('Ce pays n\'est pas actif sur ROM_BUSINESS');
    }
    $oldCountry = $m['country'];
    $newCurrency = country_to_currency($country);
    $w = q("SELECT id,currency,balance,vault_balance FROM merchant_wallets WHERE merchant_id=?",[$m['id']])->fetch();
    $oldCurrency = $w ? strtoupper($w['currency'] ?: 'XOF') : 'XOF';
    if($oldCurrency==='FCFA') $oldCurrency='XOF';

    db()->beginTransaction();
    try {
        q("UPDATE merchants SET country=? WHERE id=?",[$country,$m['id']]);
        if($w && $oldCurrency !== $newCurrency){
            $newBalance = convert_currency((float)$w['balance'], $oldCurrency, $newCurrency);
            $newVault = convert_currency((float)$w['vault_balance'], $oldCurrency, $newCurrency);
            if($newBalance===null || $newVault===null) throw new Exception('Conversion de devise momentanement indisponible');
            q("UPDATE merchant_wallets SET currency=?,balance=?,vault_balance=? WHERE id=?",
              [$newCurrency, round($newBalance,2), round($newVault,2), $w['id']]);
            $subVaults = q("SELECT id,balance,goal_amount FROM sub_vaults WHERE wallet_id=?",[$w['id']])->fetchAll();
            foreach($subVaults as $sv){
                $svBal = convert_currency((float)$sv['balance'], $oldCurrency, $newCurrency);
                if($svBal===null) throw new Exception('Conversion de devise momentanement indisponible');
                $svGoal = null;
                if($sv['goal_amount']!==null){
                    $svGoal = convert_currency((float)$sv['goal_amount'], $oldCurrency, $newCurrency);
                    if($svGoal===null) throw new Exception('Conversion de devise momentanement indisponible');
                }
                q("UPDATE sub_vaults SET balance=?,goal_amount=? WHERE id=?",
                  [round($svBal,2), $svGoal!==null?round($svGoal,2):null, $sv['id']]);
            }
        } elseif($w) {
            q("UPDATE merchant_wallets SET currency=? WHERE id=?",[$newCurrency,$w['id']]);
        }
        db()->commit();
    } catch(Exception $e) {
        db()->rollBack();
        admin_log('merchant_update_country','failed',$phone,'Echec conversion devise lors du changement de pays vers '.$country.' ('.$reason.')');
        log_and_fail($e, 'Conversion de devise momentanement indisponible. Reessayez dans quelques instants.', 503);
    }
    admin_log('merchant_update_country','success',$phone,'Pays marchand : '.($oldCountry?:'-').' -> '.$country.' ('.$reason.')');
    ok(null,'Pays mis a jour avec succes');
}

// Nettoyage manuel d'une demande KYC redondante/obsolete (ex: doublons issus
// de vieux tests). Reservee au nettoyage de donnees, jamais utilisee pour
// annuler une verification legitime deja approuvee.
// Utilise ctid (identifiant physique de ligne PostgreSQL, TOUJOURS unique)
// plutot que id seul : d'anciennes lignes de test peuvent partager le meme
// id si la contrainte d'unicite n'a jamais ete appliquee retroactivement a
// la table existante (CREATE TABLE IF NOT EXISTS ne modifie jamais une
// table deja presente). Sans cette precaution, supprimer "par id" risquerait
// de supprimer plusieurs lignes en meme temps au lieu d'une seule.
function admin_delete_kyc() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['id'] ?? '');
    $createdAt = trim($b['created_at'] ?? '');
    $reason = trim($b['reason'] ?? '');
    if(!$id) fail('Identifiant de la demande requis');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $where = "k.id=?"; $params = [$id];
    if($createdAt){ $where .= " AND k.created_at=?"; $params[] = $createdAt; }
    $k = q("SELECT k.ctid, k.phone_number, k.user_id, k.status, u.country FROM kyc_requests k LEFT JOIN users u ON u.id=k.user_id WHERE $where LIMIT 1", $params)->fetch();
    if(!$k){
        admin_log('delete_kyc','failed',null,dk('d_request_not_found', ['id'=>$id]));
        fail('Demande introuvable',404);
    }
    admin_check_country_access($k['country']);
    q("DELETE FROM kyc_requests WHERE ctid = ?::tid", [$k['ctid']]);
    // Si la demande supprimee etait approuvee, le compte doit redevenir
    // non-verifie pour liberer reellement le creneau (sinon users.is_kyc
    // reste a 1 avec un nom/date verifies dont la preuve n'existe plus).
    if($k['status'] === 'approved' && $k['user_id']){
        q("UPDATE users SET is_kyc=0, verified_name=NULL, verified_birthdate=NULL WHERE id=?",[$k['user_id']]);
    }
    // La raison reste consultable en permanence dans le Journal d'audit,
    // pour pouvoir expliquer plus tard pourquoi ce document a ete retire.
    admin_log('delete_kyc','success',$k['phone_number'],$reason);
    if($k['user_id']){
        web_push_send_to_user($k['user_id'], 'ROM_MONEY', 'Votre document d\'identite a ete retire : '.$reason.' Vous pouvez en soumettre un nouveau.');
    }
    ok(null,'Demande KYC supprimee');
}

// Liste/recherche globale des comptes, avec filtres combinables (texte,
// statut KYC, statut du compte, plage de dates d'inscription) et pagination.
// Construit la clause WHERE + params partagee par admin_list_users() et les
// deux exports (xlsx/pdf), pour ne pas dupliquer 3 fois la meme logique de
// filtre.
function admin_users_build_where($f) {
    $search = trim($f['search'] ?? '');
    $kycFilter = trim($f['kyc'] ?? '');
    $statusFilter = trim($f['status'] ?? '');
    $dateFrom = trim($f['date_from'] ?? '');
    $dateTo = trim($f['date_to'] ?? '');

    $where = "1=1"; $params = [];
    if($search){
        $where .= " AND (full_name ILIKE ? OR phone_number ILIKE ? OR COALESCE(verified_name,'') ILIKE ?)";
        $like = '%'.$search.'%';
        $params[] = $like; $params[] = $like; $params[] = $like;
    }
    if($kycFilter==='verified'){ $where .= " AND is_kyc=1"; }
    elseif($kycFilter==='unverified'){ $where .= " AND is_kyc=0"; }
    if($statusFilter==='active'){ $where .= " AND status='active'"; }
    elseif($statusFilter==='blocked'){ $where .= " AND status='blocked'"; }
    if($dateFrom){ $where .= " AND created_at >= ?"; $params[] = $dateFrom.' 00:00:00'; }
    if($dateTo){ $where .= " AND created_at <= ?"; $params[] = $dateTo.' 23:59:59'; }
    list($scopeSql, $scopeParams) = admin_country_scope_clause('country');
    $where .= $scopeSql; $params = array_merge($params, $scopeParams);
    return [$where, $params];
}

function admin_list_users() {
    $b = body();
    check_admin_password($b);
    $page = max(1, (int)($b['page'] ?? 1));
    $perPage = 25;
    $offset = ($page - 1) * $perPage;

    list($where, $params) = admin_users_build_where($b);

    $total = (int)q("SELECT COUNT(*) FROM users WHERE $where", $params)->fetchColumn();
    $rows = q("SELECT id,full_name,verified_name,phone_number,operator,status,is_kyc,created_at
               FROM users WHERE $where ORDER BY created_at DESC LIMIT $perPage OFFSET $offset", $params)->fetchAll();

    ok(['users'=>$rows,'total'=>$total,'page'=>$page,'per_page'=>$perPage]);
}

// Export de la liste filtree (memes criteres que admin_list_users(), sans
// pagination - plafonnee a un nombre raisonnable de lignes par securite).
function admin_users_export_xlsx() {
    check_admin_password_str((string)bg('admin_password',''));
    $filters = ['search'=>(string)bg('search',''), 'kyc'=>(string)bg('kyc',''), 'status'=>(string)bg('status',''),
        'date_from'=>(string)bg('date_from',''), 'date_to'=>(string)bg('date_to','')];
    list($where, $params) = admin_users_build_where($filters);
    $LIMIT = 5000;
    $total = (int)q("SELECT COUNT(*) FROM users WHERE $where", $params)->fetchColumn();
    $rows = q("SELECT full_name,verified_name,phone_number,operator,country,status,is_kyc,created_at
               FROM users WHERE $where ORDER BY created_at DESC LIMIT $LIMIT", $params)->fetchAll();

    $sheetRows = [];
    $sheetRows[] = [[ 'ROM_MONEY - Liste des utilisateurs', 4, 's' ]];
    $sheetRows[] = [[ 'Genere le '.date('d/m/Y').' a '.date('H:i').' - '.$total.' compte(s)'.($total>$LIMIT?' (limite aux '.$LIMIT.' premiers)':''), 0, 's' ]];
    $sheetRows[] = [];
    $sheetRows[] = [[ 'Nom',1,'s' ],[ 'Telephone',1,'s' ],[ 'Operateur',1,'s' ],[ 'Pays',1,'s' ],[ 'Statut',1,'s' ],[ 'KYC',1,'s' ],[ 'Inscrit le',1,'s' ]];
    foreach($rows as $u){
        $sheetRows[] = [
            [ $u['verified_name']?:$u['full_name'], 2, 's' ],
            [ $u['phone_number'], 2, 's' ],
            [ $u['operator']?:'-', 2, 's' ],
            [ $u['country']?:'-', 2, 's' ],
            [ $u['status']==='blocked'?'Bloque':'Actif', 2, 's' ],
            [ $u['is_kyc']?'Verifie':'Non verifie', 2, 's' ],
            [ date('d/m/Y',strtotime($u['created_at'])), 2, 's' ]
        ];
    }
    $sheetXml = xlsx_build_sheet($sheetRows);
    $xlsxData = xlsx_build($sheetXml);
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment; filename="rom_money_utilisateurs.xlsx"');
    header('Content-Length: '.strlen($xlsxData));
    echo $xlsxData;
    exit;
}
function admin_users_export_pdf() {
    check_admin_password_str((string)bg('admin_password',''));
    $filters = ['search'=>(string)bg('search',''), 'kyc'=>(string)bg('kyc',''), 'status'=>(string)bg('status',''),
        'date_from'=>(string)bg('date_from',''), 'date_to'=>(string)bg('date_to','')];
    list($where, $params) = admin_users_build_where($filters);
    $LIMIT = 3000; // FPDF genererait un fichier trop volumineux au-dela
    $total = (int)q("SELECT COUNT(*) FROM users WHERE $where", $params)->fetchColumn();
    $rows = q("SELECT full_name,verified_name,phone_number,operator,status,is_kyc,created_at
               FROM users WHERE $where ORDER BY created_at DESC LIMIT $LIMIT", $params)->fetchAll();

    require_once __DIR__.'/fpdf.php';
    $pdf = new FPDF();
    $pdf->AddPage();
    $pdf->SetFont('Arial','B',14);
    $pdf->Cell(0,10,pdf_str('ROM_MONEY - Liste des utilisateurs'),0,1);
    $pdf->SetFont('Arial','',10);
    $pdf->Cell(0,6,pdf_str('Genere le '.date('d/m/Y').' a '.date('H:i').' - '.$total.' compte(s)'.($total>$LIMIT?' (limite aux '.$LIMIT.' premiers)':'')),0,1);
    $pdf->Ln(4);

    $pdf->SetFont('Arial','B',8);
    $pdf->SetFillColor(230,241,251);
    $w = [45,30,35,25,25,30];
    $headers = ['Nom','Telephone','Operateur','Statut','KYC','Inscrit le'];
    foreach($headers as $i=>$h){ $pdf->Cell($w[$i],8,pdf_str($h),1,0,'C',true); }
    $pdf->Ln();
    $pdf->SetFont('Arial','',8);
    foreach($rows as $u){
        $pdf->Cell($w[0],7,pdf_str(substr($u['verified_name']?:$u['full_name'],0,28)),1);
        $pdf->Cell($w[1],7,$u['phone_number'],1);
        $pdf->Cell($w[2],7,pdf_str(substr($u['operator']?:'-',0,20)),1);
        $pdf->Cell($w[3],7,$u['status']==='blocked'?'Bloque':'Actif',1);
        $pdf->Cell($w[4],7,$u['is_kyc']?'Verifie':'Non verifie',1);
        $pdf->Cell($w[5],7,date('d/m/y',strtotime($u['created_at'])),1);
        $pdf->Ln();
    }

    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="rom_money_utilisateurs.pdf"');
    echo $pdf->Output('S');
    exit;
}

// Flux centralise des connexions "nouvel appareil" recentes, tous comptes
// confondus. Exclut volontairement le tout premier appareil de chaque
// compte (celui de l'inscription, qui n'a rien de suspect) : ne montre que
// les appareils ajoutes APRES le premier, exactement le meme critere que
// celui qui declenche deja la notification push d'alerte au moment de la
// connexion. Fenetre fixe de 30 jours, plafonnee a 50 entrees.
// Comptes non-verifies (KYC) approchant leur plafond mensuel de reception -
// permet d'anticiper (ex: leur suggerer le KYC) plutot que de decouvrir le
// blocage seulement quand le client appelle. Meme calcul que
// check_receive_limit() (conversion de devise incluse), mais en lecture
// seule et sur l'ensemble des comptes actifs non-verifies.
function admin_list_near_limit() {
    $b = body();
    check_admin_password($b);
    $threshold = (float)($b['threshold'] ?? 70) / 100;
    $limitUnverified = (float)get_setting('limit_unverified', 2000000);

    list($scopeSql, $scopeParams) = admin_country_scope_clause('u.country');
    $rows = q("SELECT u.id, COALESCE(NULLIF(u.verified_name,''), u.full_name) AS name, u.phone_number,
            w.currency,
            COALESCE(SUM(COALESCE(t.receiver_amount, t.net_amount, t.amount)),0) AS received_this_month
        FROM users u
        JOIN wallets w ON w.user_id = u.id
        LEFT JOIN transactions t ON t.receiver_wallet_id = w.id AND t.status='completed' AND t.type!='fee'
            AND EXTRACT(MONTH FROM t.created_at)=EXTRACT(MONTH FROM NOW())
            AND EXTRACT(YEAR FROM t.created_at)=EXTRACT(YEAR FROM NOW())
        WHERE u.is_kyc=0 AND u.status='active'".$scopeSql."
        GROUP BY u.id, name, u.phone_number, w.currency", $scopeParams)->fetchAll();

    $result = [];
    foreach($rows as $r){
        $currency = $r['currency'] ?: 'XOF';
        $limit = $limitUnverified;
        if($currency !== 'XOF'){
            $converted = convert_currency($limitUnverified, 'XOF', $currency);
            if($converted !== null) $limit = $converted;
        }
        if($limit <= 0) continue;
        $received = (float)$r['received_this_month'];
        $pct = $received / $limit;
        if($pct >= $threshold){
            $result[] = [
                'name'=>$r['name'], 'phone_number'=>$r['phone_number'],
                'received'=>$received, 'limit'=>$limit, 'currency'=>$currency,
                'percent'=>round($pct*100,1)
            ];
        }
    }
    usort($result, function($a,$b){ return $b['percent'] <=> $a['percent']; });
    ok(['accounts'=>array_slice($result,0,50), 'threshold'=>$threshold*100]);
}

function admin_list_alerts() {
    $b = body();
    check_admin_password($b);
    list($scopeSql, $scopeParams) = admin_country_scope_clause('u.country');
    $rows = q("SELECT kd.device_id, kd.user_agent, kd.first_seen,
                      u.id AS user_id, u.full_name, u.verified_name, u.phone_number
               FROM known_devices kd
               JOIN users u ON u.id = kd.user_id
               WHERE kd.first_seen >= NOW() - INTERVAL '30 days'
                 AND kd.first_seen > (
                     SELECT MIN(kd2.first_seen) FROM known_devices kd2 WHERE kd2.user_id = kd.user_id
                 )".$scopeSql."
               ORDER BY kd.first_seen DESC
               LIMIT 50", $scopeParams)->fetchAll();
    ok(['alerts'=>$rows]);
}

// Transactions signalees par fraud_check_transaction() (velocite, montant
// inhabituel, nouveau destinataire + montant eleve). Non-reviewees d'abord,
// puis les plus recentes. Plafonne a 100 entrees.
// fraud_alerts n'a pas de colonne pays propre (sender_phone/receiver_phone
// seulement) - jointure par numero vers users ET merchants (une transaction
// signalee peut impliquer l'un ou l'autre de chaque cote), meme logique
// "au moins une des deux parties dans le perimetre" que pour les transactions.
function admin_fraud_alerts_join_sql() {
    return " LEFT JOIN users su ON su.phone_number = fa.sender_phone
        LEFT JOIN merchants sm ON sm.phone_number = fa.sender_phone
        LEFT JOIN users ru ON ru.phone_number = fa.receiver_phone
        LEFT JOIN merchants rm ON rm.phone_number = fa.receiver_phone";
}
function admin_list_fraud_alerts() {
    $b = body();
    check_admin_password($b);
    list($scopeSql, $scopeParams) = admin_country_scope_clause_either('su.country,sm.country', 'ru.country,rm.country');
    $joinSql = admin_fraud_alerts_join_sql();
    $rows = q("SELECT fa.* FROM fraud_alerts fa".$joinSql." WHERE 1=1".$scopeSql." ORDER BY fa.reviewed ASC, fa.created_at DESC LIMIT 100", $scopeParams)->fetchAll();
    $unreviewed = (int)q("SELECT COUNT(*) FROM fraud_alerts fa".$joinSql." WHERE fa.reviewed=false".$scopeSql, $scopeParams)->fetchColumn();
    ok(['alerts'=>$rows, 'unreviewed_count'=>$unreviewed]);
}

function admin_mark_fraud_reviewed() {
    $b = body();
    check_admin_password($b);
    $id = (int)($b['id'] ?? 0);
    if(!$id) fail('Alerte introuvable');
    $joinSql = admin_fraud_alerts_join_sql();
    $fa = q("SELECT su.country su_country, sm.country sm_country, ru.country ru_country, rm.country rm_country
        FROM fraud_alerts fa".$joinSql." WHERE fa.id=?",[$id])->fetch();
    if(!$fa) fail('Alerte introuvable',404);
    admin_check_country_access_any([$fa['su_country'], $fa['sm_country'], $fa['ru_country'], $fa['rm_country']]);
    q("UPDATE fraud_alerts SET reviewed=true WHERE id=?",[$id]);
    ok(null,'Alerte marquee comme verifiee');
}

// INSTALL
function route_install() {
    $key = $_GET['key']??'';
    if(APP_ENV!=='development' && $key!==JWT_SECRET) fail('Non autorise',403);

    $sqls = [
    "CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        full_name VARCHAR(100) NOT NULL,
        phone_number VARCHAR(20) NOT NULL UNIQUE,
        email VARCHAR(150),
        operator VARCHAR(50),
        password_hash VARCHAR(255) NOT NULL,
        pin_hash VARCHAR(255) NOT NULL,
        bio_enabled SMALLINT DEFAULT 0,
        status VARCHAR(20) DEFAULT 'active',
        is_kyc SMALLINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE TABLE IF NOT EXISTS wallets (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL UNIQUE,
        balance DECIMAL(15,2) DEFAULT 0.00,
        vault_balance DECIMAL(15,2) DEFAULT 0.00,
        vault_locked SMALLINT DEFAULT 0,
        vault_lock_date DATE,
        currency VARCHAR(10) DEFAULT 'XOF',
        qr_seed VARCHAR(50) NOT NULL,
        qr_renewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE TABLE IF NOT EXISTS sub_vaults (
        id VARCHAR(36) PRIMARY KEY,
        wallet_id VARCHAR(36) NOT NULL,
        name VARCHAR(100) NOT NULL,
        balance DECIMAL(15,2) DEFAULT 0.00,
        goal_amount DECIMAL(15,2),
        locked SMALLINT DEFAULT 0,
        lock_date DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_subvaults_wallet ON sub_vaults(wallet_id)",
    // ============================================================
    // ROM_BUSINESS — comptes marchands, INTENTIONNELLEMENT dans des tables
    // separees de users/wallets (pas une simple etiquette sur un compte
    // personnel) : ca permet au MEME numero de telephone d'avoir a la fois
    // un compte ROM_MONEY personnel et un compte ROM_BUSINESS marchand,
    // ce qui serait impossible si les deux partageaient la contrainte
    // d'unicite sur users.phone_number. Le moteur d'argent (transactions,
    // sub_vaults) reste partage : seule l'identite/le profil est distinct.
    // ============================================================
    "CREATE TABLE IF NOT EXISTS merchants (
        id VARCHAR(36) PRIMARY KEY,
        phone_number VARCHAR(20) NOT NULL UNIQUE,
        pin_hash VARCHAR(255) NOT NULL,
        business_name VARCHAR(150) NOT NULL,
        location_type VARCHAR(20) NOT NULL DEFAULT 'online',
        address VARCHAR(255),
        status VARCHAR(20) DEFAULT 'active',
        pin_attempts SMALLINT DEFAULT 0,
        pin_locked_until TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "ALTER TABLE merchants ADD COLUMN IF NOT EXISTS verified SMALLINT DEFAULT 0",
    "ALTER TABLE merchants ADD COLUMN IF NOT EXISTS country VARCHAR(100)",
    // Notes admin en texte libre sur un compte personnel - contexte humain
    // (appel client, litige en cours...) distinct du journal d'actions
    // automatique (audit_logs), qui ne trace que les actions structurees.
    "CREATE TABLE IF NOT EXISTS admin_notes (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        note TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_admin_notes_user ON admin_notes(user_id)",
    // Equivalent de admin_notes mais pour un compte marchand ROM_BUSINESS -
    // table separee (comme merchant_known_devices vs known_devices) plutot
    // que reutiliser admin_notes.user_id pour un ID marchand.
    "CREATE TABLE IF NOT EXISTS merchant_notes (
        id SERIAL PRIMARY KEY,
        merchant_id VARCHAR(36) NOT NULL,
        note TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_merchant_notes_merchant ON merchant_notes(merchant_id)",
    // Documents "entreprise" (KYB) : piece d'identite, RCCM, DFE, patente,
    // photo du magasin, photo du gerant. Un seul enregistrement par
    // (marchand, type de document) - renvoyer le meme type remplace l'ancien.
    // Plus de UNIQUE(merchant_id, doc_type) : un nouvel envoi ne doit JAMAIS
    // ecraser le precedent - chaque version reste consultable indefiniment
    // (peut servir de preuve des annees plus tard). ALTER ci-dessous retire
    // la contrainte sur une base deja installee avant ce changement (nom de
    // contrainte auto-genere par Postgres, sans risque si elle n'existe deja plus).
    "CREATE TABLE IF NOT EXISTS merchant_documents (
        id SERIAL PRIMARY KEY,
        merchant_id VARCHAR(36) NOT NULL,
        doc_type VARCHAR(30) NOT NULL,
        photo TEXT NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "ALTER TABLE merchant_documents DROP CONSTRAINT IF EXISTS merchant_documents_merchant_id_doc_type_key",
    // Defaut 'approved' (pas 'pending') : le marchand n'a aucun gate
    // d'inscription, ses documents n'ont jamais besoin d'une revue admin
    // pour etre utilisables - le statut ne sert qu'a enregistrer une
    // action explicite de l'admin.
    "ALTER TABLE merchant_documents ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'approved'",
    "CREATE INDEX IF NOT EXISTS idx_merchant_documents_merchant ON merchant_documents(merchant_id)",
    // Lien de paiement a distance : le marchand indique un montant/motif,
    // partage le lien (id sert de jeton, deja imprevisible via uid()) par
    // n'importe quel moyen hors-app (SMS, WhatsApp...), le client l'ouvre
    // et paie depuis ROM_MONEY. 'status' evite qu'un lien deja paye (ou
    // annule) soit repaye.
    "CREATE TABLE IF NOT EXISTS merchant_payment_links (
        id VARCHAR(36) PRIMARY KEY,
        merchant_id VARCHAR(36) NOT NULL,
        amount DECIMAL(15,2) NOT NULL,
        description TEXT,
        status VARCHAR(20) DEFAULT 'pending',
        transaction_id VARCHAR(36),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        paid_at TIMESTAMP,
        expires_at TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_merchant_payment_links_merchant ON merchant_payment_links(merchant_id)",
    "CREATE TABLE IF NOT EXISTS merchant_known_devices (
        id SERIAL PRIMARY KEY,
        merchant_id VARCHAR(36) NOT NULL,
        device_id VARCHAR(64) NOT NULL,
        user_agent TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        revoked SMALLINT DEFAULT 0,
        UNIQUE(merchant_id, device_id)
    )",
    "CREATE TABLE IF NOT EXISTS merchant_wallets (
        id VARCHAR(36) PRIMARY KEY,
        merchant_id VARCHAR(36) NOT NULL UNIQUE,
        balance DECIMAL(15,2) DEFAULT 0.00,
        vault_balance DECIMAL(15,2) DEFAULT 0.00,
        vault_locked SMALLINT DEFAULT 0,
        vault_lock_date DATE,
        currency VARCHAR(10) DEFAULT 'XOF',
        qr_seed VARCHAR(50) NOT NULL,
        qr_renewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_merchant_wallets_merchant ON merchant_wallets(merchant_id)",
    "CREATE TABLE IF NOT EXISTS transactions (
        id VARCHAR(36) PRIMARY KEY,
        sender_wallet_id VARCHAR(36),
        receiver_wallet_id VARCHAR(36),
        amount DECIMAL(15,2) NOT NULL,
        net_amount DECIMAL(15,2),
        fee DECIMAL(15,2) DEFAULT 0,
        currency VARCHAR(10) DEFAULT 'XOF',
        type VARCHAR(30) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        reference VARCHAR(50) NOT NULL UNIQUE,
        description VARCHAR(255),
        cancel_reason VARCHAR(255),
        cancelled_at TIMESTAMP,
        cancel_deadline TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS net_amount DECIMAL(15,2)",
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS frozen_at TIMESTAMP",
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS frozen_reason VARCHAR(255)",
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS channel VARCHAR(20) DEFAULT 'national'",
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS sender_currency VARCHAR(10)",
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS receiver_currency VARCHAR(10)",
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS fx_rate_applied DECIMAL(20,8)",
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS receiver_amount DECIMAL(15,2)",
    // Une transaction impliquant un marchand remplit UNE de ces deux colonnes
    // a la place de sender_wallet_id/receiver_wallet_id (jamais les deux a
    // la fois pour le meme cote) : evite toute ambiguite sur quelle table
    // (wallets ou merchant_wallets) interroger pour afficher l'historique.
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS sender_merchant_wallet_id VARCHAR(36)",
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS receiver_merchant_wallet_id VARCHAR(36)",
    // Meme principe pour les agents de depot/retrait (ROM_GUICHET) : une
    // transaction impliquant un agent remplit UNE de ces deux colonnes a la
    // place de sender_wallet_id/receiver_wallet_id.
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS sender_agent_wallet_id VARCHAR(36)",
    "ALTER TABLE transactions ADD COLUMN IF NOT EXISTS receiver_agent_wallet_id VARCHAR(36)",
    // ============================================================
    // ROM_GUICHET — Agents de depot/retrait (cash-in/cash-out)
    // Meme conception que les marchands (tables separees des comptes
    // personnels, phone_number unique par table, pas globalement) : un
    // meme numero peut donc avoir un compte personnel, marchand ET agent.
    // ============================================================
    "CREATE TABLE IF NOT EXISTS agents (
        id VARCHAR(36) PRIMARY KEY,
        phone_number VARCHAR(20) NOT NULL UNIQUE,
        pin_hash VARCHAR(255) NOT NULL,
        full_name VARCHAR(150) NOT NULL,
        address VARCHAR(255),
        country VARCHAR(100),
        status VARCHAR(20) DEFAULT 'active',
        pin_attempts SMALLINT DEFAULT 0,
        pin_locked_until TIMESTAMP,
        verified SMALLINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    // Un distributeur est un agent qui peut recharger le float d'autres
    // agents avec SON PROPRE float deja approuve (hierarchie a la Orange
    // Money : Admin Principal -> distributeur -> agent -> client). Bascule
    // par un admin standard (pas earnings - ne cree pas d'argent, ne fait
    // que deleguer la capacite de rediriger du float deja existant).
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS is_distributor SMALLINT DEFAULT 0",
    // Raison du refus d'agrement (obligatoire, journalisee) - meme principe
    // que reject_reason sur agent_recharge_requests.
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS rejection_reason VARCHAR(255)",
    // Plafond de float qu'un DISTRIBUTEUR peut detenir - protection contre le
    // risque qu'une trop grosse somme lui soit confiee d'un coup (voir
    // discussion : un distributeur qui disparait avec son float ne peut
    // jamais partir avec plus que ce plafond). NULL = pas de plafond (agents
    // normaux, non concernes). Demarre bas a la premiere promotion
    // distributeur, augmente manuellement par l'admin au fil de la confiance
    // etablie (voir admin_agent_toggle_distributor()/admin_agent_set_float_cap()).
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS max_float_cap DECIMAL(15,2)",
    // Position fixe (jamais un suivi en direct) pour la fonctionnalite
    // "Trouver un distributeur" cote agent : ville/commune/quartier en texte
    // + coordonnees GPS optionnelles posees une fois. NULL tant que non
    // renseigne (agent_set_location() cote agent).
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS city VARCHAR(150)",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS commune VARCHAR(150)",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS quartier VARCHAR(150)",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS latitude DECIMAL(10,7)",
    "ALTER TABLE agents ADD COLUMN IF NOT EXISTS longitude DECIMAL(10,7)",
    "CREATE INDEX IF NOT EXISTS idx_agents_city ON agents(city)",
    "CREATE INDEX IF NOT EXISTS idx_agents_commune ON agents(commune)",
    // Documents d'agrement (piece d'identite + photo du local) - mirror exact
    // de merchant_documents : un seul enregistrement par (agent, type de
    // document), renvoyer le meme type remplace l'ancien.
    // Meme raisonnement que merchant_documents ci-dessus : plus de UNIQUE,
    // chaque envoi cree une nouvelle ligne, rien n'est jamais ecrase.
    "CREATE TABLE IF NOT EXISTS agent_documents (
        id SERIAL PRIMARY KEY,
        agent_id VARCHAR(36) NOT NULL,
        doc_type VARCHAR(30) NOT NULL,
        photo TEXT NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "ALTER TABLE agent_documents DROP CONSTRAINT IF EXISTS agent_documents_agent_id_doc_type_key",
    "CREATE INDEX IF NOT EXISTS idx_agent_documents_agent ON agent_documents(agent_id)",
    // Note legere laissee quand un admin retire UN document precis (pas toute
    // la demande) pour en demander un meilleur - jamais la photo elle-meme,
    // juste la raison, effacee automatiquement des que l'agent renvoie ce type.
    "CREATE TABLE IF NOT EXISTS agent_document_notices (
        id SERIAL PRIMARY KEY,
        agent_id VARCHAR(36) NOT NULL,
        doc_type VARCHAR(30) NOT NULL,
        reason VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_agent_doc_notices_agent ON agent_document_notices(agent_id)",
    "CREATE TABLE IF NOT EXISTS agent_wallets (
        id VARCHAR(36) PRIMARY KEY,
        agent_id VARCHAR(36) NOT NULL UNIQUE,
        balance DECIMAL(15,2) DEFAULT 0.00,
        currency VARCHAR(10) DEFAULT 'XOF',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_agent_wallets_agent ON agent_wallets(agent_id)",
    "CREATE TABLE IF NOT EXISTS agent_known_devices (
        id SERIAL PRIMARY KEY,
        agent_id VARCHAR(36) NOT NULL,
        device_id VARCHAR(64) NOT NULL,
        user_agent TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        revoked SMALLINT DEFAULT 0,
        UNIQUE(agent_id, device_id)
    )",
    // Paliers de commission journaliere, toujours exprimes en XOF (meme
    // principe que fee_free_threshold_merchant_daily) : le volume reel d'un
    // agent, peu importe sa devise, est converti en XOF-equivalent avant
    // d'etre compare a cette table, pour que la meme activite reelle paie
    // la meme commission reelle partout. band_max_xof NULL = dernier
    // palier (illimite).
    "CREATE TABLE IF NOT EXISTS agent_commission_tiers (
        id SERIAL PRIMARY KEY,
        band_min_xof DECIMAL(15,2) NOT NULL,
        band_max_xof DECIMAL(15,2),
        commission_xof DECIMAL(15,2) NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_agent_tiers_band ON agent_commission_tiers(band_min_xof)",
    // Demande de recharge du float de l'agent, validee par l'admin (pas de
    // credit direct) : meme mecanique pending/approved/rejected que
    // kyc_requests.
    "CREATE TABLE IF NOT EXISTS agent_recharge_requests (
        id VARCHAR(36) PRIMARY KEY,
        agent_id VARCHAR(36) NOT NULL,
        amount DECIMAL(15,2) NOT NULL,
        note VARCHAR(255),
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TIMESTAMP,
        reject_reason VARCHAR(255)
    )",
    "CREATE INDEX IF NOT EXISTS idx_agent_recharge_agent ON agent_recharge_requests(agent_id)",
    // NULL = va a la file d'attente Admin Principal (comportement d'origine,
    // inchange) ; renseigne = va au distributeur cible, qui approuve lui-meme
    // depuis son propre appareil sans mot de passe admin.
    "ALTER TABLE agent_recharge_requests ADD COLUMN IF NOT EXISTS distributor_id VARCHAR(36)",
    // Code de confirmation a 6 chiffres, genere a la demande, partage
    // verbalement/en personne par l'agent a celui qui approuve (distributeur
    // ou admin). Jamais renvoye dans les listes (file d'attente distributeur
    // ou admin) - seul le demandeur le voit, sinon ca ne prouve plus rien.
    // Impossible a reutiliser : une fois la demande approuvee/rejetee, son
    // statut n'est plus 'pending' et le code ne peut plus rien valider.
    "ALTER TABLE agent_recharge_requests ADD COLUMN IF NOT EXISTS confirmation_code VARCHAR(10)",
    // Reference de la transaction reelle, renseignee UNIQUEMENT une fois la
    // demande approuvee (jamais pour 'pending'/'rejected', aucune transaction
    // n'existe encore) - contrairement au code de confirmation, reste utile
    // apres traitement : c'est la piece justificative pour la comptabilite
    // de l'agent/du distributeur, visible dans leurs historiques respectifs.
    "ALTER TABLE agent_recharge_requests ADD COLUMN IF NOT EXISTS reference VARCHAR(30)",
    // Demandes de code de confirmation pour un retrait (cash-out) identifie
    // par numero de telephone plutot que par QR scanne - voir
    // agent_request_cash_out_code()/agent_confirm_cash_out(). Le code n'est
    // JAMAIS renvoye a l'agent, uniquement envoye par SMS au client.
    "CREATE TABLE IF NOT EXISTS agent_cashout_requests (
        id VARCHAR(36) PRIMARY KEY,
        agent_id VARCHAR(36) NOT NULL,
        customer_user_id VARCHAR(36) NOT NULL,
        customer_phone VARCHAR(20) NOT NULL,
        amount DECIMAL(15,2) NOT NULL,
        code VARCHAR(6) NOT NULL,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_agent_cashout_requests_agent ON agent_cashout_requests(agent_id)",
    // Reutilise pour "Envoyer a un tiers" (meme mecanique code/expiration/SMS,
    // juste une destination differente) plutot qu'une nouvelle table :
    // request_type distingue 'cashout' (defaut, retrait existant) de
    // 'transfer' (nouveau), recipient_phone n'est renseigne que pour ce
    // dernier.
    "ALTER TABLE agent_cashout_requests ADD COLUMN IF NOT EXISTS request_type VARCHAR(20) DEFAULT 'cashout'",
    "ALTER TABLE agent_cashout_requests ADD COLUMN IF NOT EXISTS recipient_phone VARCHAR(20)",
    "CREATE TABLE IF NOT EXISTS exchange_rates (
        id SERIAL PRIMARY KEY,
        currency_code VARCHAR(10) NOT NULL UNIQUE,
        rate_to_usd DECIMAL(20,8) NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_tx_sender ON transactions(sender_wallet_id)",
    "CREATE INDEX IF NOT EXISTS idx_tx_receiver ON transactions(receiver_wallet_id)",
    "CREATE INDEX IF NOT EXISTS idx_tx_created_at ON transactions(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_tx_status ON transactions(status)",
    "CREATE INDEX IF NOT EXISTS idx_tx_type ON transactions(type)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_attempts SMALLINT DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_locked_until TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS photo_url TEXT",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS notif_tx BOOLEAN DEFAULT true",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS notif_promo BOOLEAN DEFAULT true",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(20)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by VARCHAR(36)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS verified_name VARCHAR(150)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS verified_birthdate VARCHAR(20)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS country VARCHAR(100) DEFAULT 'Côte d''Ivoire'",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)",
    "CREATE TABLE IF NOT EXISTS referral_bonuses (
        id VARCHAR(36) PRIMARY KEY,
        referrer_id VARCHAR(36) NOT NULL,
        referee_id VARCHAR(36) NOT NULL,
        transaction_id VARCHAR(36),
        bonus_amount DECIMAL(15,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_refbonus_referrer ON referral_bonuses(referrer_id)",
    "CREATE INDEX IF NOT EXISTS idx_refbonus_referee ON referral_bonuses(referee_id)",
    "CREATE TABLE IF NOT EXISTS kyc_requests (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        phone_number VARCHAR(20),
        full_name VARCHAR(150),
        legal_name VARCHAR(150),
        photo_recto TEXT,
        photo_verso TEXT,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TIMESTAMP
    )",
    "ALTER TABLE kyc_requests ADD COLUMN IF NOT EXISTS legal_name VARCHAR(150)",
    "ALTER TABLE kyc_requests ADD COLUMN IF NOT EXISTS legal_prenom VARCHAR(100)",
    "ALTER TABLE kyc_requests ADD COLUMN IF NOT EXISTS legal_nom VARCHAR(100)",
    "ALTER TABLE kyc_requests ADD COLUMN IF NOT EXISTS legal_birthdate VARCHAR(20)",
    "ALTER TABLE kyc_requests ADD COLUMN IF NOT EXISTS ocr_name VARCHAR(150)",
    "ALTER TABLE kyc_requests ADD COLUMN IF NOT EXISTS ocr_prenom VARCHAR(100)",
    "ALTER TABLE kyc_requests ADD COLUMN IF NOT EXISTS ocr_nom VARCHAR(100)",
    "ALTER TABLE kyc_requests ADD COLUMN IF NOT EXISTS ocr_birthdate VARCHAR(20)",
    "ALTER TABLE kyc_requests ADD COLUMN IF NOT EXISTS ocr_error TEXT",
    "CREATE TABLE IF NOT EXISTS linked_banks (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        bank_name VARCHAR(100) NOT NULL,
        account_last4 VARCHAR(4),
        mock_token VARCHAR(100),
        is_default BOOLEAN DEFAULT false,
        linked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_kyc_user ON kyc_requests(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_kyc_status ON kyc_requests(status)",
    "CREATE INDEX IF NOT EXISTS idx_banks_user ON linked_banks(user_id)",
    "CREATE TABLE IF NOT EXISTS announcements (
        id VARCHAR(36) PRIMARY KEY,
        title VARCHAR(150) NOT NULL,
        message TEXT NOT NULL,
        type VARCHAR(20) DEFAULT 'update',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "ALTER TABLE announcements ADD COLUMN IF NOT EXISTS title_en VARCHAR(150)",
    "ALTER TABLE announcements ADD COLUMN IF NOT EXISTS message_en TEXT",
    "CREATE INDEX IF NOT EXISTS idx_announce_created ON announcements(created_at)",
    "CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        title VARCHAR(150) NOT NULL,
        body TEXT NOT NULL,
        is_read SMALLINT DEFAULT 0,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    // 'category' distingue les notifications deja affichees par l'app via un
    // autre mecanisme (credit = argent recu, reconstruit par polling des
    // transactions) de celles qui ne le sont pas (general = alertes securite,
    // gel/degel...) : evite d'afficher "argent recu" deux fois une fois que
    // le frontend recupere aussi cette table.
    "ALTER TABLE notifications ADD COLUMN IF NOT EXISTS category VARCHAR(30) DEFAULT 'general'",
    "CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(36),
        action VARCHAR(100) NOT NULL,
        ip_address VARCHAR(45),
        result VARCHAR(20) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS details TEXT",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS target_phone VARCHAR(20)",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_agent TEXT",
    // Qui a fait quoi : nom resolu depuis le mot de passe utilise (voir
    // resolve_admin_name()) - "Admin Principal" (ADMIN_PASSWORD partage) ou
    // le nom d'un compte admin_accounts. NULL pour les entrees anterieures
    // a cette fonctionnalite (aucun moyen de savoir qui, a l'epoque il n'y
    // avait qu'un seul mot de passe partage sans identite associee).
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS admin_name VARCHAR(100)",
    // Comptes admin nommes : IDENTIFICATION uniquement, pas de restriction
    // d'acces (decision explicite - tous les comptes ont les memes acces
    // complets que le mot de passe partage ADMIN_PASSWORD, qui reste
    // toujours valable en parallele comme filet de securite). Objectif
    // unique : savoir qui a fait quoi dans le journal d'audit.
    "CREATE TABLE IF NOT EXISTS admin_accounts (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        active SMALLINT DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    // Tableau JSON de noms de pays (ex: ["Ghana"]) - NULL ou vide = aucun
    // pays assigne, donc aucun acces aux donnees d'un utilisateur/agent/
    // marchand precis tant qu'un pays n'a pas ete assigne explicitement
    // (voir admin_check_country_access()). Sans lien avec Admin Principal
    // (ADMIN_PASSWORD), qui reste toujours sans restriction de pays.
    "ALTER TABLE admin_accounts ADD COLUMN IF NOT EXISTS countries TEXT",
    "CREATE TABLE IF NOT EXISTS waitlist (
        id SERIAL PRIMARY KEY,
        phone VARCHAR(20) NOT NULL,
        pays VARCHAR(100) NOT NULL,
        email VARCHAR(150),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE TABLE IF NOT EXISTS active_countries (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL UNIQUE,
        is_active SMALLINT DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    // Filet de securite : sur certaines bases restaurees (ex: migration
    // interrompue vers Neon), la contrainte UNIQUE peut manquer meme si la
    // colonne existe, ce qui a permis des doublons de s'accumuler lors des
    // tentatives d'installation precedentes. On nettoie ces doublons (en
    // gardant la version active s'il y en a une) avant de recreer la
    // contrainte, sans jamais planter.
    "DELETE FROM active_countries
     WHERE id NOT IN (
         SELECT DISTINCT ON (name) id
         FROM active_countries
         ORDER BY name, is_active DESC, id ASC
     )",
    "DO $$ BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'active_countries_name_unique'
        ) THEN
            ALTER TABLE active_countries ADD CONSTRAINT active_countries_name_unique UNIQUE (name);
        END IF;
    END $$;",
    "CREATE TABLE IF NOT EXISTS push_subscriptions (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        endpoint TEXT NOT NULL,
        p256dh_key TEXT NOT NULL,
        auth_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, endpoint)
    )",
    "CREATE TABLE IF NOT EXISTS admin_push_subscriptions (
        id SERIAL PRIMARY KEY,
        endpoint TEXT NOT NULL UNIQUE,
        p256dh_key TEXT NOT NULL,
        auth_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE TABLE IF NOT EXISTS merchant_push_subscriptions (
        id SERIAL PRIMARY KEY,
        merchant_id VARCHAR(36) NOT NULL,
        endpoint TEXT NOT NULL,
        p256dh_key TEXT NOT NULL,
        auth_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(merchant_id, endpoint)
    )",
    // Meme principe que merchant_push_subscriptions (identite agent separee
    // des utilisateurs personnels) - le service worker ROM_GUICHET a deja
    // son ecouteur 'push' pret, restait dormant faute de cette table.
    "CREATE TABLE IF NOT EXISTS agent_push_subscriptions (
        id SERIAL PRIMARY KEY,
        agent_id VARCHAR(36) NOT NULL,
        endpoint TEXT NOT NULL,
        p256dh_key TEXT NOT NULL,
        auth_key TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(agent_id, endpoint)
    )",
    "CREATE TABLE IF NOT EXISTS known_devices (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        device_id VARCHAR(64) NOT NULL,
        user_agent TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, device_id)
    )",
    // 'revoked' permet a l'utilisateur de couper a distance la session d'un
    // appareil precis (ex: telephone vole) sans attendre l'expiration
    // naturelle du jeton (12h) : verifie a chaque appel authentifie (auth()).
    "ALTER TABLE known_devices ADD COLUMN IF NOT EXISTS revoked SMALLINT DEFAULT 0",
    "CREATE TABLE IF NOT EXISTS fraud_alerts (
        id SERIAL PRIMARY KEY,
        transaction_id VARCHAR(36),
        reference VARCHAR(50),
        sender_phone VARCHAR(20),
        receiver_phone VARCHAR(20),
        amount DECIMAL(15,2),
        reasons TEXT,
        reviewed BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_fraud_alerts_created ON fraud_alerts(created_at)",
    "CREATE INDEX IF NOT EXISTS idx_fraud_alerts_reviewed ON fraud_alerts(reviewed)",
    "ALTER TABLE fraud_alerts ADD COLUMN IF NOT EXISTS currency VARCHAR(10) DEFAULT 'XOF'",
    // Corrige les comptes crees avant l'ajout de country_to_currency() : la
    // colonne wallets.currency avait alors 'FCFA' comme valeur par defaut -
    // pas un vrai code ISO, donc absent de exchange_rates, ce qui faisait
    // echouer silencieusement toute conversion Transfert Afrique impliquant
    // un de ces comptes ("Conversion de devise momentanement indisponible").
    // 'FCFA' designe toujours le franc CFA ouest-africain (XOF) dans cette
    // app (voir fmt() et les autres endroits qui l'affichent comme tel).
    "UPDATE wallets SET currency='XOF' WHERE currency='FCFA'",
    "UPDATE transactions SET currency='XOF' WHERE currency='FCFA'",
    "CREATE TABLE IF NOT EXISTS rate_limit_hits (
        id SERIAL PRIMARY KEY,
        bucket VARCHAR(50) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE INDEX IF NOT EXISTS idx_rate_limit_lookup ON rate_limit_hits(bucket, ip_address, created_at)",
    "CREATE TABLE IF NOT EXISTS app_settings (
        setting_key VARCHAR(50) PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )"
    ];

    $created = [];
    foreach($sqls as $sql) {
        try {
            db()->exec($sql);
            preg_match('/TABLE IF NOT EXISTS (\w+)/', $sql, $m);
            $created[] = $m[1]??'table';
        } catch(Exception $e) {
            fail('Erreur SQL: '.$e->getMessage(), 500);
        }
    }

    // Peuple la liste des pays (seule la Cote d'Ivoire active au depart).
    // Idempotent grace a ON CONFLICT DO NOTHING : ne touche pas aux pays
    // deja actives manuellement par l'admin lors des installs suivants.
    $allCountries = [
        "Côte d'Ivoire",'Sénégal','Mali','Burkina Faso','Niger','Togo','Bénin',
        'Guinée-Bissau','Cameroun','Congo-Brazzaville','Gabon','Centrafrique','Tchad',
        'Guinée Équatoriale','Comores','Algérie','Angola','Burundi','Botswana',
        'Congo-Kinshasa','Djibouti','Égypte','Érythrée','Éthiopie','Ghana',
        'Guinée Conakry','Kenya','Lesotho','Liberia','Libye','Madagascar','Malawi',
        'Mauritanie','Maurice','Maroc','Mozambique','Namibie','Nigeria','Rwanda',
        'São Tomé','Seychelles','Sierra Leone','Somalie','Afrique du Sud',
        'Soudan du Sud','Soudan','Eswatini','Tanzanie','Tunisie','Ouganda','Zambie',
        'Zimbabwe'
    ];
    foreach($allCountries as $c){
        $isActive = ($c === "Côte d'Ivoire") ? 1 : 0;
        q("INSERT INTO active_countries (name,is_active) VALUES (?,?) ON CONFLICT (name) DO NOTHING",[$c,$isActive]);
    }

    // Filet de securite : les comptes existants sans pays renseigne (avant
    // l'ajout de ce champ) sont rattaches a la Cote d'Ivoire par defaut.
    q("UPDATE users SET country='Côte d''Ivoire' WHERE country IS NULL");

    // Nettoyage des anciennes valeurs "sales" du champ operateur (ex: "mtn",
    // "orange" en minuscules, saisies avant que ce champ soit verrouille a
    // un menu deroulant a choix fixes) - on les fait correspondre aux 4
    // valeurs officielles actuelles.
    q("UPDATE users SET operator='MTN CI' WHERE LOWER(TRIM(operator)) IN ('mtn','mtn ci')");
    q("UPDATE users SET operator='Orange CI' WHERE LOWER(TRIM(operator)) IN ('orange','orange ci')");
    q("UPDATE users SET operator='Moov Africa CI' WHERE LOWER(TRIM(operator)) IN ('moov','moov africa','moov africa ci','moov ci')");
    q("UPDATE users SET operator='Wave' WHERE LOWER(TRIM(operator)) IN ('wave','wave ci')");

    // Seed unique des 26 paliers de commission agent (toujours en XOF) - ne
    // s'execute que si la table est vide, pour ne jamais ecraser des
    // ajustements faits depuis le panneau admin lors d'un /install ulterieur.
    $tierCount = (int)q("SELECT COUNT(*) c FROM agent_commission_tiers")->fetch()['c'];
    if ($tierCount === 0) {
        $tiers = [
            [1, 9999, 50], [10000, 99999, 250], [100000, 174999, 550],
            [175000, 249999, 850], [250000, 599999, 1300], [600000, 999999, 1925],
            [1000000, 1499999, 2675], [1500000, 1999999, 3200], [2000000, 2499999, 3725],
            [2500000, 2999999, 4225], [3000000, 3499999, 4750], [3500000, 3999999, 5350],
            [4000000, 4499999, 6000], [4500000, 4999999, 6750], [5000000, 5999999, 7500],
            [6000000, 6999999, 8650], [7000000, 7999999, 9800], [8000000, 8999999, 11050],
            [9000000, 9999999, 12300], [10000000, 12499999, 16050], [12500000, 14999999, 19800],
            [15000000, 17499999, 23550], [17500000, 19999999, 27300], [20000000, 24999999, 32300],
            [25000000, 29999999, 42300], [30000000, null, 52000],
        ];
        foreach ($tiers as $t) {
            q("INSERT INTO agent_commission_tiers (band_min_xof,band_max_xof,commission_xof) VALUES (?,?,?)",
              [$t[0], $t[1], $t[2]]);
        }
    }

    ok(['tables_created'=>$created],'Installation terminee ! Toutes les tables ont ete creees.');
}
