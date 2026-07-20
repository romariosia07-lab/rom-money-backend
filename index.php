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
function body() {
    $d = json_decode(file_get_contents('php://input'), true);
    return is_array($d) ? $d : [];
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
    if(!$pl) fail('Token invalide ou expire',401);
    // Verifie le statut du compte a CHAQUE appel authentifie, pas seulement
    // au login, pour qu'un blocage admin coupe l'acces immediatement meme
    // si l'utilisateur a deja un token valide en cours de session.
    $status = q("SELECT status FROM users WHERE id=?",[$pl['sub']])->fetchColumn();
    if($status !== false && $status !== 'active') fail('Compte suspendu ou bloque', 403);
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
function web_push_send_to_user($userId, $title, $body, $extra = []) {
    try {
        $subs = q("SELECT * FROM push_subscriptions WHERE user_id=?", [$userId])->fetchAll();
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
const REFERRAL_BONUS_PCT = 0.30;

// Verse au parrain 30% des frais generes par la PREMIERE transaction a frais
// (>= 4000 F) de son filleul. Ne se declenche qu'une seule fois par filleul
// (verifie via referral_bonuses). Le lien de parrainage etant fixe a
// l'inscription (users.referred_by, jamais modifiable ensuite), un compte
// deja existant ne peut jamais devenir "parraine" retroactivement.
function apply_referral_bonus($senderId, $fee) {
    if($fee <= 0) return;
    $u = q("SELECT referred_by FROM users WHERE id=?",[$senderId])->fetch();
    if(!$u || !$u['referred_by']) return;
    $referrerId = $u['referred_by'];

    $already = q("SELECT id FROM referral_bonuses WHERE referee_id=?",[$senderId])->fetch();
    if($already) return;

    $bonus = round($fee * REFERRAL_BONUS_PCT);
    if($bonus <= 0) return;

    $referrerWid = q("SELECT id FROM wallets WHERE user_id=?",[$referrerId])->fetchColumn();
    if(!$referrerWid) return;

    $bonusId = uid(); $txid = uid(); $ref = ref();
    q("INSERT INTO referral_bonuses (id,referrer_id,referee_id,transaction_id,bonus_amount) VALUES (?,?,?,?,?)",
      [$bonusId,$referrerId,$senderId,$txid,$bonus]);
    q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'referral_bonus','completed',?,'Bonus de parrainage')",
      [$txid,null,$referrerWid,$bonus,$ref]);
    q("UPDATE wallets SET balance=balance+? WHERE id=?",[$bonus,$referrerWid]);
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
    case 'transactions':route_tx($action); break;
    case 'profile':     route_profile($action); break;
    case 'bank':        route_bank($action); break;
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

// PIN faibles interdits : chiffres identiques (000000, 111111...) et
// suites logiques evidentes (croissantes ou decroissantes). Reste un code
// a 6 chiffres classique pour l'utilisateur, sans nouvelle contrainte de
// lecture - juste quelques combinaisons trop simples ecartees.
function is_weak_pin($pin) {
    if (preg_match('/^(\d)\1{5}$/', $pin)) return true; // 000000, 111111, ...
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
    if(!$name) fail('Nom requis');
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $phone))) fail('Telephone invalide');
    if(!preg_match('/^\d{6}$/', $pin)) fail('PIN doit avoir 6 chiffres');
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
        $token = jwt_make(['sub'=>$uid,'phone'=>$phone]);
        db()->commit();
        ok(['token'=>$token,'user_id'=>$uid,'name'=>$name,'phone'=>$phone,'qr_seed'=>$qrseed,'referral_code'=>$myReferralCode],'Compte cree', 201);
    } catch(Exception $e) {
        db()->rollBack();
        fail(APP_DEBUG ? $e->getMessage() : 'Erreur creation compte', 500);
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
               ON CONFLICT (user_id, device_id) DO UPDATE SET last_seen=CURRENT_TIMESTAMP",
              [$user['id'], $deviceId, $ua]);
        } else {
            q("UPDATE known_devices SET last_seen=CURRENT_TIMESTAMP WHERE user_id=? AND device_id=?", [$user['id'], $deviceId]);
        }
    }

    $token = jwt_make(['sub'=>$user['id'],'phone'=>$phone]);
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
    if(!preg_match('/^\d{6}$/',$cur)) fail('PIN actuel invalide');
    if(!preg_match('/^\d{6}$/',$new)) fail('Nouveau PIN invalide');
    if(is_weak_pin($new)) fail('Ce code est trop simple, choisissez une autre combinaison');
    $user = q("SELECT pin_hash FROM users WHERE id=?", [$pl['sub']])->fetch();
    if(!password_verify($cur, $user['pin_hash'])) fail('PIN actuel incorrect', 401);
    q("UPDATE users SET pin_hash=? WHERE id=?", [password_hash($new,PASSWORD_BCRYPT), $pl['sub']]);
    ok(null,'PIN mis a jour');
}

// WALLET
function route_wallet($action) {
    match($action) {
        'balance'        => wallet_balance(),
        'topup'          => wallet_topup(),
        'vault-deposit'  => vault_deposit(),
        'vault-withdraw' => vault_withdraw(),
        'vault-lock'     => vault_lock(),
        'renew-qr'       => wallet_renew_qr(),
        'resolve-qr'     => wallet_resolve_qr(),
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
    auth();
    ok(get_public_settings());
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

function wallet_topup() {
    $pl = auth(); $b = body();
    $amt = (float)($b['amount']??0);
    if($amt<=0) fail('Montant invalide');
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();
    db()->beginTransaction();
    try {
        $reference = ref();
        q("INSERT INTO transactions (id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'deposit','completed',?,'Recharge')",[uid(),$wid,$amt,$reference]);
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$amt,$wid]);
        db()->commit();
        $bal = (float)q("SELECT balance FROM wallets WHERE id=?",[$wid])->fetchColumn();
        ok(['reference'=>$reference,'amount'=>$amt,'new_balance'=>$bal],'Recharge effectuee');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur recharge',500); }
}

function vault_deposit() {
    $pl = auth(); $b = body();
    $amt = (float)($b['amount']??0);
    if($amt<=0) fail('Montant invalide');
    $w = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    if((float)$w['balance']<$amt) fail('Solde insuffisant');
    db()->beginTransaction();
    try {
        q("UPDATE wallets SET balance=balance-?,vault_balance=vault_balance+? WHERE id=?",[$amt,$amt,$w['id']]);
        q("INSERT INTO transactions (id,sender_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'vault_deposit','completed',?,'Depot coffre')",[uid(),$w['id'],$amt,ref()]);
        db()->commit();
        ok(['amount'=>$amt,'new_balance'=>(float)$w['balance']-$amt,'vault_balance'=>(float)$w['vault_balance']+$amt],'Depose dans le coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur depot',500); }
}

function vault_withdraw() {
    $pl = auth(); $b = body();
    $amt = (float)($b['amount']??0); $pin = trim($b['pin']??'');
    if($amt<=0) fail('Montant invalide');
    if(!preg_match('/^\d{6}$/',$pin)) fail('PIN invalide');
    $user = q("SELECT pin_hash FROM users WHERE id=?",[$pl['sub']])->fetch();
    if(!password_verify($pin,$user['pin_hash'])) fail('PIN incorrect',401);
    $w = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    if($w['vault_locked'] && strtotime($w['vault_lock_date']??'0')>time())
        fail("Coffre verrouille jusqu'au ".date('d/m/Y',strtotime($w['vault_lock_date'])));
    if((float)$w['vault_balance']<$amt) fail('Solde coffre insuffisant');
    db()->beginTransaction();
    try {
        q("UPDATE wallets SET vault_balance=vault_balance-?,balance=balance+?,vault_locked=0 WHERE id=?",[$amt,$amt,$w['id']]);
        q("INSERT INTO transactions (id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,'vault_withdrawal','completed',?,'Retrait coffre')",[uid(),$w['id'],$amt,ref()]);
        db()->commit();
        ok(['amount'=>$amt,'new_balance'=>(float)$w['balance']+$amt,'vault_balance'=>(float)$w['vault_balance']-$amt],'Retire du coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur retrait',500); }
}

function vault_lock() {
    $pl = auth(); $b = body();
    $date = trim($b['lock_date']??'');
    if(!$date || strtotime($date)<=time()) fail('Date invalide');
    q("UPDATE wallets SET vault_locked=1,vault_lock_date=? WHERE user_id=?",[$date,$pl['sub']]);
    ok(['lock_date'=>$date],'Coffre verrouille');
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
        SUM(CASE WHEN receiver_wallet_id=? AND status='completed' THEN amount ELSE 0 END) as total_in,
        SUM(CASE WHEN sender_wallet_id=? AND status='completed' THEN amount ELSE 0 END) as total_out,
        COUNT(CASE WHEN (sender_wallet_id=? OR receiver_wallet_id=?) AND status='completed' THEN 1 END) as tx_count,
        COUNT(CASE WHEN sender_wallet_id=? AND status='cancelled' THEN 1 END) as cancelled
        FROM transactions WHERE EXTRACT(MONTH FROM created_at)=EXTRACT(MONTH FROM NOW())
        AND (sender_wallet_id=? OR receiver_wallet_id=?)",
        [$wid,$wid,$wid,$wid,$wid,$wid,$wid])->fetch();
    ok($stats);
}

// TRANSACTIONS
function route_tx($action) {
    match($action) {
        'send'    => tx_send(),
        'collect' => tx_collect(),
        'pay'     => tx_pay(),
        'cancel'  => tx_cancel(),
        'history' => tx_history(),
        'detail'  => tx_detail(),
        'resolve' => tx_resolve(),
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
            q("INSERT INTO fraud_alerts (transaction_id,reference,sender_phone,receiver_phone,amount,reasons) VALUES (?,?,?,?,?,?)",
              [$txid, $reference, $senderPhone, $receiverPhone, $amount, implode(' | ', $reasons)]);
        }
    } catch (Exception $e) { /* la detection ne doit jamais casser un transfert deja reussi */ }
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
    if(!preg_match('/^\d{6}$/',$pin)) fail('PIN invalide');
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
        if($mode==='brut'){
            $brut = $amount;
            $fee  = ($brut >= $freeThreshold) ? round($brut * $rateNational) : 0;
            $net  = $brut - $fee;
        } else {
            $net  = $amount;
            $fee  = ($net >= $freeThreshold) ? round($net * $rateNational) : 0;
            $brut = $net + $fee; // Total amount debited from sender
        }
    }
    if($net<=0) fail('Montant invalide');

    $sw = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
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
        if($fee > 0){
            $fee_recv = q("SELECT u.id,w.id wid FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$fee_phone])->fetch();
            if($fee_recv && $fee_recv['id'] !== $pl['sub']){
                $fee_txid = uid(); $fee_ref = ref();
                $feeLabel = $channel==='africa' ? 'Frais ROM_MONEY 1.5% (Transfert Afrique)' : 'Frais ROM_MONEY 1%';
                q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'fee','completed',?,?)",
                  [$fee_txid,$sw['id'],$fee_recv['wid'],$fee,$fee_ref,$feeLabel]);
                q("UPDATE wallets SET balance=balance+? WHERE id=?",[$fee,$fee_recv['wid']]);
            }
        }
        apply_referral_bonus($pl['sub'], $fee);

        db()->commit();

        fraud_check_transaction($sw['id'], $to, $brut, $txid, $reference);

        web_push_send_to_user($recv['id'], 'ROM_MONEY',
            'Vous avez recu '.number_format($receiverAmount,0,',',' ').' '.($receiverCurrency==='XOF'||$receiverCurrency==='XAF'?'F':$receiverCurrency).' de '.($user['full_name']?:'un utilisateur'));

        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$brut,'net_amount'=>$net,'fee'=>$fee,
            'receiver_name'=>$recv['verified_name']?:$recv['full_name'],'cancel_before'=>$deadline,
            'new_balance'=>(float)$sw['balance']-$brut,
            'receiver_amount'=>$receiverAmount,'receiver_currency'=>$receiverCurrency,
            'sender_currency'=>$senderCurrency,'fx_rate_applied'=>$fxRateApplied],'Transfert effectue');
    } catch(Exception $e) { db()->rollBack(); fail(APP_DEBUG?$e->getMessage():'Echec transfert',500); }
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
    if(!preg_match('/^\d{6}$/',$pin)) fail('PIN invalide');

    $payer = q("SELECT u.id,u.full_name,u.verified_name,u.pin_hash,w.id wid,w.balance FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$payerPhone])->fetch();
    if(!$payer) fail('Payeur introuvable');
    if($payer['id']===$pl['sub']) fail('Encaissement de soi-meme impossible');

    // PIN is verified against the PAYER's own account (not the merchant's), with
    // anti-bruteforce lockout since this account is identified by phone, not by token.
    pin_check($payer['id'], $pin, $payer['pin_hash']);

    $rateNational = (float)get_setting('fee_rate_national', 0.01);
    $freeThreshold = (float)get_setting('fee_free_threshold_national', 4000);
    if($mode==='brut'){
        $brut = $amount;
        $fee  = ($brut >= $freeThreshold) ? round($brut * $rateNational) : 0;
        $net  = $brut - $fee;
    } else {
        $net  = $amount;
        $fee  = ($net >= $freeThreshold) ? round($net * $rateNational) : 0;
        $brut = $net + $fee;
    }
    if($net<=0) fail('Montant invalide');
    if((float)$payer['balance'] < $brut) fail('Solde du payeur insuffisant');
    check_receive_limit($pl['sub'], $net);

    $mw = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    if(!$mw) fail('Wallet marchand introuvable');

    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,net_amount,type,status,reference,description,cancel_deadline) VALUES (?,?,?,?,?,'transfer','pending',?,?,?)",
          [$txid,$payer['wid'],$mw['id'],$brut,$net,$reference,$desc?:null,$deadline]);
        $rows = q("UPDATE wallets SET balance=balance-? WHERE id=? AND balance>=?",[$brut,$payer['wid'],$brut])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$net,$mw['id']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);

        $fee_phone = '0160629502';
        if($fee > 0){
            $fee_recv = q("SELECT u.id,w.id wid FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$fee_phone])->fetch();
            if($fee_recv && $fee_recv['id'] !== $payer['id']){
                $fee_txid = uid(); $fee_ref = ref();
                q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'fee','completed',?,'Frais ROM_MONEY 1%')",
                  [$fee_txid,$payer['wid'],$fee_recv['wid'],$fee,$fee_ref]);
                q("UPDATE wallets SET balance=balance+? WHERE id=?",[$fee,$fee_recv['wid']]);
            }
        }
        apply_referral_bonus($payer['id'], $fee);

        db()->commit();

        $merchantPhone = q("SELECT phone_number FROM users WHERE id=?",[$pl['sub']])->fetchColumn();
        fraud_check_transaction($payer['wid'], $merchantPhone, $brut, $txid, $reference);

        web_push_send_to_user($pl['sub'], 'ROM_MONEY',
            'Vous avez recu '.number_format($net,0,',',' ').' F de '.($payer['full_name']?:'un client'));

        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$brut,'net_amount'=>$net,'fee'=>$fee,
            'payer_name'=>$payer['verified_name']?:$payer['full_name'],'cancel_before'=>$deadline],'Encaissement effectue');
    } catch(Exception $e) { db()->rollBack(); fail(APP_DEBUG?$e->getMessage():'Echec encaissement',500); }
}

function tx_pay() {
    $pl = auth(); $b = body();
    $code = trim($b['merchant_code']??'');
    $amt  = (float)($b['amount']??0);
    $pin  = trim($b['pin']??'');
    if(!$code) fail('Code marchand requis');
    if($amt<=0) fail('Montant invalide');
    if(!preg_match('/^\d{6}$/',$pin)) fail('PIN invalide');
    $user = q("SELECT pin_hash FROM users WHERE id=?",[$pl['sub']])->fetch();
    if(!password_verify($pin,$user['pin_hash'])) fail('PIN incorrect',401);
    $w = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    if((float)$w['balance']<$amt) fail('Solde insuffisant');
    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_wallet_id,amount,type,status,reference,description,cancel_deadline) VALUES (?,?,?,'payment','pending',?,?,?)",
          [$txid,$w['id'],$amt,$reference,"Paiement: $code",$deadline]);
        q("UPDATE wallets SET balance=balance-? WHERE id=?",[$amt,$w['id']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);
        db()->commit();
        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$amt,
            'merchant'=>$code,'cancel_before'=>$deadline,'new_balance'=>(float)$w['balance']-$amt],'Paiement effectue');
    } catch(Exception $e) { db()->rollBack(); fail('Echec paiement',500); }
}

function tx_cancel() {
    $pl = auth(); $b = body();
    $txid = trim($b['transaction_id']??'');
    $pin  = trim($b['pin']??'');
    if(!$txid) fail('ID requis');
    if(!preg_match('/^\d{6}$/',$pin)) fail('PIN invalide');
    $user = q("SELECT pin_hash FROM users WHERE id=?",[$pl['sub']])->fetch();
    pin_check($pl['sub'], $pin, $user['pin_hash']);
    $tx = q("SELECT t.*,w.user_id sender_uid FROM transactions t JOIN wallets w ON t.sender_wallet_id=w.id WHERE t.id=?",[$txid])->fetch();
    if(!$tx) fail('Transaction introuvable',404);
    if($tx['sender_uid']!==$pl['sub']) fail('Non autorise',403);
    if($tx['status']!=='completed') fail('Transaction non annulable');
    if($tx['cancelled_at']) fail('Deja annulee');
    if(strtotime($tx['cancel_deadline']??'0')<time()) fail('Delai annulation depasse');
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
        CASE WHEN t.sender_wallet_id='$wid' THEN 'debit' ELSE 'credit' END direction,
        su.full_name sender_name, su.phone_number sender_phone, su.verified_name sender_verified_name,
        ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        $where ORDER BY t.created_at DESC LIMIT $lim OFFSET $off");
    $txs->execute($params);
    ok(['transactions'=>$txs->fetchAll(),'page'=>$page,'limit'=>$lim]);
}

function tx_detail() {
    $pl = auth();
    $id = $_GET['id']??'';
    if(!$id) fail('ID requis');
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();
    $tx = q("SELECT t.*,
        CASE WHEN t.sender_wallet_id='$wid' THEN 'debit' ELSE 'credit' END direction,
        su.full_name sender_name, su.verified_name sender_verified_name, su.country sender_country,
        ru.full_name receiver_name, ru.verified_name receiver_verified_name, ru.country receiver_country
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        WHERE t.id=? AND (t.sender_wallet_id='$wid' OR t.receiver_wallet_id='$wid')",[$id])->fetch();
    if(!$tx) fail('Transaction introuvable',404);
    $tx['can_cancel'] = $tx['status']==='completed' && $tx['direction']==='debit'
        && !$tx['cancelled_at'] && strtotime($tx['cancel_deadline']??'0')>time();
    ok($tx);
}

function tx_resolve() {
    $pl = auth();
    $phone = $_GET['phone']??'';
    if(!preg_match('/^\+?[0-9]{8,15}$/',preg_replace('/[\s\-]/','', $phone))) fail('Numero invalide');
    $u = q("SELECT full_name,phone_number,is_kyc,verified_name FROM users WHERE phone_number=? AND id!=?",[$phone,$pl['sub']])->fetch();
    if(!$u) fail('Aucun compte trouve',404);
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
    ], 'Compte trouve');
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
        default          => fail('Action inconnue',404)
    };
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
        fail(APP_DEBUG?$e->getMessage():'Echec de la sauvegarde du profil',500);
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
// BANK MODULE — SIMULATION ONLY (no real partner integration yet)
// Every function here is a MOCK. No money actually moves between
// a real bank and ROM_MONEY. This exists to let the full user
// flow (link bank, deposit, withdraw, multi-bank switch) be
// tested end-to-end before any partner agreement is signed.
// When a real aggregator (CinetPay, PayDunya, HUB2...) is
// integrated, only bank_link()/bank_deposit()/bank_withdraw()
// need to be rewritten to call the real API; the table schema
// and the other routes (list/set_default/unlink) stay the same.
// ============================================================
function route_bank($action) {
    match($action) {
        'partners'    => bank_partners(),
        'link'        => bank_link(),
        'list'        => bank_list(),
        'set_default' => bank_set_default(),
        'unlink'      => bank_unlink(),
        'deposit'     => bank_deposit(),
        'withdraw'    => bank_withdraw(),
        default       => fail('Action inconnue',404)
    };
}

// Static placeholder list. Replace with real partner catalogue once
// an aggregator agreement exists — names must not be real banks
// until then (no authorization to use their branding).
function bank_partners() {
    auth();
    ok(['partners'=>[
        ['id'=>'ab','name'=>'Banque AB','type'=>'bank'],
        ['id'=>'cd','name'=>'Banque CD','type'=>'bank'],
        ['id'=>'ef','name'=>'Banque EF','type'=>'bank'],
        ['id'=>'gh','name'=>'Mobile Money GH','type'=>'mobile_money'],
        ['id'=>'ij','name'=>'Mobile Money IJ','type'=>'mobile_money'],
    ]]);
}

function bank_link() {
    $pl = auth(); $b = body();
    $bankName = trim($b['bank_name']??'');
    $accountNumber = trim($b['account_number']??'');
    if(!$bankName) fail('Banque requise');
    if(!preg_match('/^\d{4,20}$/',$accountNumber)) fail('Numero de compte invalide');
    $last4 = substr($accountNumber,-4);
    $id = uid();
    $existing = q("SELECT COUNT(*) c FROM linked_banks WHERE user_id=?",[$pl['sub']])->fetch();
    $isDefault = ((int)$existing['c'] === 0); // first linked bank becomes default automatically
    q("INSERT INTO linked_banks (id,user_id,bank_name,account_last4,mock_token,is_default) VALUES (?,?,?,?,?,?)",
      [$id,$pl['sub'],$bankName,$last4,'mock_'.uid(),$isDefault?'t':'f']);
    ok(['id'=>$id,'bank_name'=>$bankName,'account_last4'=>$last4,'is_default'=>$isDefault],'Banque liee (simulation)');
}

function bank_list() {
    $pl = auth();
    $rows = q("SELECT id,bank_name,account_last4,is_default,linked_at FROM linked_banks WHERE user_id=? ORDER BY linked_at DESC",[$pl['sub']])->fetchAll();
    ok(['banks'=>$rows]);
}

function bank_set_default() {
    $pl = auth(); $b = body();
    $id = trim($b['id']??'');
    if(!$id) fail('ID requis');
    $bank = q("SELECT id FROM linked_banks WHERE id=? AND user_id=?",[$id,$pl['sub']])->fetch();
    if(!$bank) fail('Banque introuvable',404);
    q("UPDATE linked_banks SET is_default=false WHERE user_id=?",[$pl['sub']]);
    q("UPDATE linked_banks SET is_default=true WHERE id=?",[$id]);
    ok(null,'Banque active mise a jour');
}

function bank_unlink() {
    $pl = auth(); $b = body();
    $id = trim($b['id']??'');
    if(!$id) fail('ID requis');
    $bank = q("SELECT id,is_default FROM linked_banks WHERE id=? AND user_id=?",[$id,$pl['sub']])->fetch();
    if(!$bank) fail('Banque introuvable',404);
    q("DELETE FROM linked_banks WHERE id=?",[$id]);
    if($bank['is_default']){
        $next = q("SELECT id FROM linked_banks WHERE user_id=? ORDER BY linked_at ASC LIMIT 1",[$pl['sub']])->fetch();
        if($next) q("UPDATE linked_banks SET is_default=true WHERE id=?",[$next['id']]);
    }
    ok(null,'Banque retiree');
}

// MOCK: simulates money arriving from the linked bank into the wallet.
// No real bank is contacted; the wallet is credited directly.
function bank_deposit() {
    $pl = auth(); $b = body();
    $amount = (float)($b['amount']??0);
    if($amount<=0) fail('Montant invalide');
    $default = q("SELECT id,bank_name FROM linked_banks WHERE user_id=? AND is_default=true",[$pl['sub']])->fetch();
    if(!$default) fail('Aucune banque liee');
    $sw = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    if(!$sw) fail('Wallet introuvable');
    check_receive_limit($pl['sub'], $amount);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'bank_deposit','completed',?,?)",
          [$txid,null,$sw['id'],$amount,$reference,'[SIMULATION] Depot depuis '.$default['bank_name']]);
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$amount,$sw['id']]);
        db()->commit();
        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$amount,'bank_name'=>$default['bank_name']],'Depot simule effectue');
    } catch(Exception $e) { db()->rollBack(); fail(APP_DEBUG?$e->getMessage():'Echec depot',500); }
}

// MOCK: simulates money leaving the wallet toward the linked bank.
// No real bank is contacted; the wallet is debited directly.
function bank_withdraw() {
    $pl = auth(); $b = body();
    $amount = (float)($b['amount']??0);
    if($amount<=0) fail('Montant invalide');
    $default = q("SELECT id,bank_name FROM linked_banks WHERE user_id=? AND is_default=true",[$pl['sub']])->fetch();
    if(!$default) fail('Aucune banque liee');
    $sw = q("SELECT id,balance FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    if(!$sw) fail('Wallet introuvable');
    if((float)$sw['balance'] < $amount) fail('Solde insuffisant');
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'bank_withdraw','completed',?,?)",
          [$txid,$sw['id'],null,$amount,$reference,'[SIMULATION] Retrait vers '.$default['bank_name']]);
        $rows = q("UPDATE wallets SET balance=balance-? WHERE id=? AND balance>=?",[$amount,$sw['id'],$amount])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        db()->commit();
        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$amount,'bank_name'=>$default['bank_name']],'Retrait simule effectue');
    } catch(Exception $e) { db()->rollBack(); fail(APP_DEBUG?$e->getMessage():'Echec retrait',500); }
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
    if(!isset($b['admin_password']) || !hash_equals(ADMIN_PASSWORD, (string)$b['admin_password'])) {
        fail('Mot de passe admin incorrect',401);
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

    $u = q("SELECT full_name,phone_number FROM users WHERE id=?",[$pl['sub']])->fetch();

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
    $rows = q("SELECT id,user_id,phone_number,full_name,legal_name,legal_prenom,legal_nom,legal_birthdate,ocr_name,ocr_prenom,ocr_nom,ocr_birthdate,ocr_error,photo_recto,photo_verso,status,created_at
        FROM kyc_requests WHERE status='pending' ORDER BY created_at ASC")->fetchAll();
    foreach($rows as &$r){ $r['photo_recto']=kyc_decrypt($r['photo_recto']); $r['photo_verso']=kyc_decrypt($r['photo_verso']); }
    unset($r);
    ok(['requests'=>$rows]);
}

// Route legere dediee au comptage, pour le badge de notification admin -
// evite de retelecharger toutes les photos recto/verso a chaque poll.
function kyc_pending_count() {
    $b = body();
    check_admin_password($b);
    $count = q("SELECT COUNT(*) FROM kyc_requests WHERE status='pending'")->fetchColumn();
    ok(['count'=>(int)$count]);
}

function kyc_admin_approve() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['id']??'');
    if(!$id) fail('ID requis');
    $r = q("SELECT user_id,phone_number,legal_prenom,legal_nom,legal_birthdate FROM kyc_requests WHERE id=? AND status='pending'",[$id])->fetch();
    if(!$r) fail('Demande introuvable ou deja traitee',404);

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
        admin_log('kyc_approve_corrected','success',$r['phone_number'],'Nom/date corrige(s) par l\'admin avant validation KYC');
    }
    ok(null,'Compte verifie avec succes');
}

function kyc_admin_reject() {
    $b = body();
    check_admin_password($b);
    $id = trim($b['id']??'');
    if(!$id) fail('ID requis');
    $r = q("SELECT id FROM kyc_requests WHERE id=? AND status='pending'",[$id])->fetch();
    if(!$r) fail('Demande introuvable ou deja traitee',404);
    q("UPDATE kyc_requests SET status='rejected', reviewed_at=NOW() WHERE id=?",[$id]);
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
    $sql = "SELECT t.*,
        CASE WHEN t.sender_wallet_id=? THEN 'debit' ELSE 'credit' END as direction,
        su.full_name sender_name, su.phone_number sender_phone, su.verified_name sender_verified_name,
        ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
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
        $contact = $isDebit ? ($t['receiver_verified_name']?:$t['receiver_name']?:$t['receiver_phone']?:'-') : ($t['sender_verified_name']?:$t['sender_name']?:$t['sender_phone']?:'-');
        $data[] = [
            [ date('d/m/Y H:i', strtotime($t['created_at'])), 2, 's' ],
            [ export_type_label($t['type'], $isDebit, $lang), 2, 's' ],
            [ $contact, 2, 's' ],
            [ number_format($montant,0,',',' ').' F', 2, 's' ],
            [ number_format($frais,0,',',' ').' F', 2, 's' ],
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
        $contact = $isDebit ? ($t['receiver_verified_name']?:$t['receiver_name']?:$t['receiver_phone']?:'-') : ($t['sender_verified_name']?:$t['sender_name']?:$t['sender_phone']?:'-');

        $pdf->Cell($w[0],7,date('d/m/y H:i',strtotime($t['created_at'])),1);
        $pdf->Cell($w[1],7,pdf_str(export_type_label($t['type'],$isDebit,$lang)),1);
        $pdf->Cell($w[2],7,substr(pdf_str($contact),0,22),1);
        $pdf->Cell($w[3],7,number_format($montant,0,',',' ').' F',1,0,'R');
        $pdf->Cell($w[4],7,number_format($frais,0,',',' ').' F',1,0,'R');
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
        'late-cancel'       => admin_late_cancel(),
        'audit-list'        => admin_audit_list(),
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
        default             => fail('Action inconnue',404)
    };
}

// Capture automatiquement l'IP et l'appareil/navigateur (user-agent) sur
// CHAQUE action journalisee, sans que les ~20 fonctions qui appellent deja
// admin_log() n'aient besoin d'etre modifiees une par une.
function admin_log($action, $result, $targetPhone, $details) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;
    q("INSERT INTO audit_logs (action,result,target_phone,details,ip_address,user_agent) VALUES (?,?,?,?,?,?)",
      [$action,$result,$targetPhone,$details,$ip,$ua]);
    admin_notify_if_sensitive($action, $result, $targetPhone, $details, $ip);
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
    $pw = (string)($b['admin_password'] ?? '');
    admin_bruteforce_check();
    if (!hash_equals(ADMIN_PASSWORD, $pw)) {
        admin_log('admin_login','failed',null,'Mot de passe incorrect');
        fail('Mot de passe admin incorrect',401);
    }
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
            admin_log('admin_login','failed',null,'Code 2FA invalide');
            fail('Code de verification incorrect',401);
        }
        if ($usedRecovery) {
            admin_log('admin_login','success',null,'Connexion reussie (code de recuperation utilise - il ne pourra plus resservir)');
            ok(['recovery_used'=>true],'Connexion reussie');
            return;
        }
    }
    admin_log('admin_login','success',null,'Connexion reussie');
    ok(null,'Connexion reussie');
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
    $secret = totp_generate_secret();
    $recoveryCodesPlain = totp_generate_recovery_codes(10);
    $recoveryCodesHashed = array_map(fn($c) => password_hash($c, PASSWORD_BCRYPT), $recoveryCodesPlain);
    // Stocke en "pending" tant que non confirme (cle separee de la cle active)
    set_setting('admin_2fa_secret_pending', $secret);
    set_setting('admin_2fa_recovery_codes_pending', json_encode($recoveryCodesHashed));
    $otpauth = 'otpauth://totp/ROM-MONEY%20Admin?secret='.$secret.'&issuer=ROM-MONEY&period=30&digits=6';
    admin_log('2fa_setup_started','success',null,'Generation d\'un nouveau secret 2FA (non encore active)');
    ok(['secret'=>$secret, 'otpauth_uri'=>$otpauth, 'recovery_codes'=>$recoveryCodesPlain]);
}

// Etape 2 : l'admin scanne le QR et tape le code affiche par son
// application pour prouver que la configuration fonctionne AVANT que le
// 2FA ne devienne obligatoire a la connexion.
function admin_2fa_confirm() {
    $b = body();
    check_admin_password($b);
    $code = trim((string)($b['totp_code'] ?? ''));
    $secret = get_setting('admin_2fa_secret_pending', '');
    if ($secret === '') fail('Aucune configuration 2FA en attente. Relancez la generation du QR code.');
    if (!totp_verify($secret, $code)) {
        admin_log('2fa_setup_confirm','failed',null,'Code de confirmation incorrect');
        fail('Code incorrect. Verifiez l\'heure de votre telephone et reessayez.',401);
    }
    set_setting('admin_2fa_secret', $secret);
    set_setting('admin_2fa_recovery_codes', get_setting('admin_2fa_recovery_codes_pending','[]'));
    set_setting('admin_2fa_enabled', '1');
    set_setting('admin_2fa_secret_pending', '');
    set_setting('admin_2fa_recovery_codes_pending', '');
    admin_log('2fa_setup_confirm','success',null,'Double authentification activee');
    ok(null,'Double authentification activee avec succes');
}

function admin_2fa_disable() {
    $b = body();
    check_admin_password($b);
    if (admin_2fa_enabled()) {
        $code = trim((string)($b['totp_code'] ?? ''));
        $secret = get_setting('admin_2fa_secret', '');
        if (!totp_verify($secret, $code)) {
            admin_log('2fa_disable','failed',null,'Code de confirmation incorrect');
            fail('Code incorrect',401);
        }
    }
    set_setting('admin_2fa_enabled', '0');
    set_setting('admin_2fa_secret', '');
    set_setting('admin_2fa_recovery_codes', '[]');
    admin_log('2fa_disable','success',null,'Double authentification desactivee');
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
    if (!admin_2fa_enabled()) fail('La double authentification n\'est pas activee');
    $code = trim((string)($b['totp_code'] ?? ''));
    $secret = get_setting('admin_2fa_secret', '');
    if (!totp_verify($secret, $code)) {
        admin_log('2fa_regenerate_codes','failed',null,'Code de confirmation incorrect');
        fail('Code incorrect',401);
    }
    $recoveryCodesPlain = totp_generate_recovery_codes(10);
    $recoveryCodesHashed = array_map(fn($c) => password_hash($c, PASSWORD_BCRYPT), $recoveryCodesPlain);
    set_setting('admin_2fa_recovery_codes', json_encode($recoveryCodesHashed));
    admin_log('2fa_regenerate_codes','success',null,'Nouveaux codes de recuperation generes (les anciens sont invalides)');
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
    admin_log('kyc_migrate_encrypt','success',null,$migrated.' demande(s) KYC migree(s) vers le chiffrement');
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
    $users = q("SELECT id, full_name FROM users WHERE is_kyc=1 AND (verified_name IS NULL OR verified_name='')")->fetchAll();
    $fixed = 0;
    foreach ($users as $u) {
        $kyc = q("SELECT legal_name, legal_birthdate FROM kyc_requests WHERE user_id=? AND status='approved' ORDER BY reviewed_at DESC NULLS LAST, created_at DESC LIMIT 1", [$u['id']])->fetch();
        $verifiedName = ($kyc && $kyc['legal_name']) ? $kyc['legal_name'] : $u['full_name'];
        $verifiedBirthdate = $kyc ? ($kyc['legal_birthdate'] ?: null) : null;
        q("UPDATE users SET verified_name=?, verified_birthdate=? WHERE id=?", [$verifiedName, $verifiedBirthdate, $u['id']]);
        $fixed++;
    }
    admin_log('backfill_verified_names','success',null,$fixed.' compte(s) deja verifie(s) corrige(s)');
    ok(['fixed'=>$fixed],'Migration terminee');
}

function admin_reset_pin() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone']??'');
    $newPin = trim($b['new_pin']??'');
    $reason = trim($b['reason']??'');
    if(!preg_match('/^\d{6}$/',$newPin)) fail('Le nouveau PIN doit contenir exactement 6 chiffres');
    if(is_weak_pin($newPin)) fail('Ce code est trop simple, choisissez une autre combinaison');
    if(!$reason) fail('La raison est obligatoire (journalisee)');
    $u = q("SELECT id FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u){
        admin_log('pin_reset','failed',$phone,'Compte introuvable - '.$reason);
        fail('Compte introuvable',404);
    }
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
        ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name, ru.operator receiver_operator
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        WHERE t.reference=?",[$ref])->fetch();
    if(!$tx) fail('Transaction introuvable',404);
    ok(['transaction'=>$tx]);
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
    $u = q("SELECT id,full_name,verified_name,verified_birthdate,phone_number,email,operator,status,is_kyc,country,created_at,referral_code
            FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u) fail('Compte introuvable',404);

    $w = q("SELECT id,balance,vault_balance,vault_locked,vault_lock_date FROM wallets WHERE user_id=?",[$u['id']])->fetch();
    $wid = $w['id'] ?? null;

    $rows = q("SELECT t.*,
        CASE WHEN t.sender_wallet_id=? THEN 'debit' ELSE 'credit' END as direction,
        su.full_name sender_name, su.phone_number sender_phone, su.verified_name sender_verified_name,
        ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        WHERE (t.sender_wallet_id=? OR t.receiver_wallet_id=?) AND t.type!='fee'
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
            'vault_locked'=>(bool)($w['vault_locked']??false),'vault_lock_date'=>$w['vault_lock_date']??null
        ],
        'kyc_history'=>$kycHistory,
        'known_devices'=>$devices,
        'linked_banks'=>$banks,
        'referral'=>['referred_count'=>$referredCount,'total_earned'=>$referralEarned],
        'transactions'=>$rows
    ]);
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
        admin_log('late_cancel','failed',null,'Ref introuvable: '.$ref.' - '.$reason);
        fail('Transaction introuvable',404);
    }
    $senderPhone = null;
    if($tx['sender_wallet_id']){
        $senderPhone = q("SELECT u.phone_number FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.id=?",[$tx['sender_wallet_id']])->fetchColumn() ?: null;
    }
    if($tx['status']!=='completed'){
        admin_log('late_cancel','failed',$senderPhone,'Ref '.$ref.' statut='.$tx['status'].' - '.$reason);
        fail('Cette transaction n\'est pas au statut "completed" (deja annulee ou en attente)');
    }
    if($tx['type']==='fee'){
        fail('Impossible d\'annuler directement une ligne de frais');
    }
    if((time() - strtotime($tx['created_at'])) > 2*24*3600){
        admin_log('late_cancel','failed',$senderPhone,'Ref '.$ref.' - delai 2j depasse - '.$reason);
        fail('Delai de 2 jours depasse : annulation tardive impossible, meme pour un admin');
    }
    $sw = $tx['sender_wallet_id']; $rw = $tx['receiver_wallet_id'];
    if(!$sw || !$rw){
        fail('Transaction sans les deux portefeuilles (depot/retrait banque) : annulation manuelle requise, pas via cet outil');
    }
    $receiverWallet = q("SELECT balance FROM wallets WHERE id=?",[$rw])->fetch();
    if(!$receiverWallet || (float)$receiverWallet['balance'] < (float)$tx['amount']){
        admin_log('late_cancel','failed',$senderPhone,'Ref '.$ref.' - solde destinataire insuffisant - '.$reason);
        fail('Le destinataire n\'a plus assez de solde pour annuler automatiquement cette transaction');
    }

    db()->beginTransaction();
    try {
        q("UPDATE wallets SET balance=balance-? WHERE id=?",[$tx['amount'],$rw]);
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$tx['amount'],$sw]);
        q("UPDATE transactions SET status='cancelled', cancelled_at=NOW(), cancel_reason='admin_late_cancel' WHERE id=?",[$tx['id']]);
        admin_log('late_cancel','success',$senderPhone,'Ref '.$ref.' - '.$reason);
        db()->commit();
        ok(null,'Transaction annulee avec succes');
    } catch(Exception $e) {
        db()->rollBack();
        fail(APP_DEBUG?$e->getMessage():'Echec de l\'annulation',500);
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
        admin_log('tx_freeze','failed',null,'Ref introuvable: '.$ref.' - '.$reason);
        fail('Transaction introuvable',404);
    }
    $senderPhone = $tx['sender_wallet_id'] ? q("SELECT u.phone_number FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.id=?",[$tx['sender_wallet_id']])->fetchColumn() : null;
    if($tx['status']!=='completed'){
        admin_log('tx_freeze','failed',$senderPhone,'Ref '.$ref.' statut='.$tx['status'].' - '.$reason);
        fail('Seule une transaction "completed" peut etre gelee (statut actuel : '.$tx['status'].')');
    }
    if($tx['type']==='fee'){
        fail('Impossible de geler directement une ligne de frais');
    }
    $sw = $tx['sender_wallet_id']; $rw = $tx['receiver_wallet_id'];
    if(!$sw || !$rw){
        fail('Transaction sans les deux portefeuilles (depot/retrait banque) : gel manuel requis, pas via cet outil');
    }
    $receiverWallet = q("SELECT balance FROM wallets WHERE id=?",[$rw])->fetch();
    if(!$receiverWallet || (float)$receiverWallet['balance'] < (float)$tx['amount']){
        admin_log('tx_freeze','failed',$senderPhone,'Ref '.$ref.' - solde destinataire insuffisant - '.$reason);
        fail('Le destinataire n\'a plus assez de solde pour geler cette transaction');
    }

    db()->beginTransaction();
    try {
        q("UPDATE wallets SET balance=balance-? WHERE id=?",[$tx['amount'],$rw]);
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$tx['amount'],$sw]);
        q("UPDATE transactions SET status='frozen', frozen_at=NOW(), frozen_reason=? WHERE id=?",[$reason,$tx['id']]);
        admin_log('tx_freeze','success',$senderPhone,'Ref '.$ref.' - '.$reason);
        db()->commit();
        $senderUid = q("SELECT user_id FROM wallets WHERE id=?",[$sw])->fetchColumn();
        $receiverUid = q("SELECT user_id FROM wallets WHERE id=?",[$rw])->fetchColumn();
        if($senderUid) web_push_send_to_user($senderUid,'ROM_MONEY','Une de vos transactions ('.number_format($tx['amount'],0,',',' ').' F) est temporairement en cours de verification.');
        if($receiverUid) web_push_send_to_user($receiverUid,'ROM_MONEY','Une transaction recue ('.number_format($tx['amount'],0,',',' ').' F) est temporairement en cours de verification.');
        ok(null,'Transaction gelee avec succes');
    } catch(Exception $e) {
        db()->rollBack();
        fail(APP_DEBUG?$e->getMessage():'Echec du gel',500);
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
    if($tx['status']!=='frozen') fail('Cette transaction n\'est pas geleee (statut actuel : '.$tx['status'].')');
    $sw = $tx['sender_wallet_id']; $rw = $tx['receiver_wallet_id'];
    $senderPhone = $sw ? q("SELECT u.phone_number FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.id=?",[$sw])->fetchColumn() : null;
    $senderWallet = q("SELECT balance FROM wallets WHERE id=?",[$sw])->fetch();
    if(!$senderWallet || (float)$senderWallet['balance'] < (float)$tx['amount']){
        admin_log('tx_unfreeze','failed',$senderPhone,'Ref '.$ref.' - solde expediteur insuffisant pour debloquer');
        fail('L\'expediteur n\'a plus assez de solde pour debloquer cette transaction (il a peut-etre depense l\'argent temporairement recredite)');
    }
    db()->beginTransaction();
    try {
        q("UPDATE wallets SET balance=balance-? WHERE id=?",[$tx['amount'],$sw]);
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$tx['amount'],$rw]);
        q("UPDATE transactions SET status='completed', frozen_at=NULL, frozen_reason=NULL WHERE id=?",[$tx['id']]);
        admin_log('tx_unfreeze','success',$senderPhone,'Ref '.$ref.' debloquee');
        db()->commit();
        $senderUid = q("SELECT user_id FROM wallets WHERE id=?",[$sw])->fetchColumn();
        $receiverUid = q("SELECT user_id FROM wallets WHERE id=?",[$rw])->fetchColumn();
        if($senderUid) web_push_send_to_user($senderUid,'ROM_MONEY','La verification est terminee : votre transaction ('.number_format($tx['amount'],0,',',' ').' F) est confirmee.');
        if($receiverUid) web_push_send_to_user($receiverUid,'ROM_MONEY','La verification est terminee : la transaction recue ('.number_format($tx['amount'],0,',',' ').' F) est confirmee.');
        ok(null,'Transaction debloquee avec succes');
    } catch(Exception $e) {
        db()->rollBack();
        fail(APP_DEBUG?$e->getMessage():'Echec du deblocage',500);
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
    if($tx['status']!=='frozen') fail('Cette transaction n\'est pas gelee (statut actuel : '.$tx['status'].')');
    $senderPhone = $tx['sender_wallet_id'] ? q("SELECT u.phone_number FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.id=?",[$tx['sender_wallet_id']])->fetchColumn() : null;
    q("UPDATE transactions SET status='cancelled', cancelled_at=NOW(), cancel_reason=? WHERE id=?",[$reason,$tx['id']]);
    admin_log('tx_freeze_confirm_cancel','success',$senderPhone,'Ref '.$ref.' - '.$reason);
    $sw = $tx['sender_wallet_id']; $rw = $tx['receiver_wallet_id'];
    $senderUid = $sw ? q("SELECT user_id FROM wallets WHERE id=?",[$sw])->fetchColumn() : null;
    $receiverUid = $rw ? q("SELECT user_id FROM wallets WHERE id=?",[$rw])->fetchColumn() : null;
    if($senderUid) web_push_send_to_user($senderUid,'ROM_MONEY','Votre transaction ('.number_format($tx['amount'],0,',',' ').' F) a ete definitivement annulee suite a verification.');
    if($receiverUid) web_push_send_to_user($receiverUid,'ROM_MONEY','La transaction ('.number_format($tx['amount'],0,',',' ').' F) a ete definitivement annulee suite a verification.');
    ok(null,'Annulation confirmee');
}

// Liste des transactions actuellement gelees, en attente d'une decision -
// pour ne pas en perdre une de vue.
function admin_list_frozen() {
    $b = body();
    check_admin_password($b);
    $rows = q("SELECT t.*,
        su.phone_number sender_phone, su.full_name sender_name, su.verified_name sender_verified_name,
        ru.phone_number receiver_phone, ru.full_name receiver_name, ru.verified_name receiver_verified_name
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        WHERE t.status='frozen' ORDER BY t.frozen_at ASC")->fetchAll();
    ok(['frozen'=>$rows]);
}

function admin_audit_list() {
    $b = body();
    check_admin_password($b);
    $actionFilter = trim($b['action_filter'] ?? '');
    $phoneFilter  = trim($b['phone_filter'] ?? '');
    $dateFrom     = trim($b['date_from'] ?? '');
    $dateTo       = trim($b['date_to'] ?? '');

    $sql = "SELECT * FROM audit_logs WHERE 1=1";
    $params = [];
    if ($actionFilter !== '') { $sql .= " AND action = ?"; $params[] = $actionFilter; }
    if ($phoneFilter !== '')  { $sql .= " AND target_phone LIKE ?"; $params[] = '%'.$phoneFilter.'%'; }
    if ($dateFrom !== '')     { $sql .= " AND created_at >= ?"; $params[] = $dateFrom.' 00:00:00'; }
    if ($dateTo !== '')       { $sql .= " AND created_at <= ?"; $params[] = $dateTo.' 23:59:59'; }
    $sql .= " ORDER BY created_at DESC LIMIT 100";

    $rows = q($sql, $params)->fetchAll();
    ok(['logs'=>$rows]);
}

function admin_audit_get_rows() {
    if(!isset($_GET['admin_password']) || !hash_equals(ADMIN_PASSWORD, (string)$_GET['admin_password'])) {
        fail('Mot de passe admin incorrect',401);
    }
    $actionFilter = trim($_GET['action_filter'] ?? '');
    $phoneFilter  = trim($_GET['phone_filter'] ?? '');
    $dateFrom     = trim($_GET['date_from'] ?? '');
    $dateTo       = trim($_GET['date_to'] ?? '');

    $sql = "SELECT * FROM audit_logs WHERE 1=1";
    $params = [];
    if ($actionFilter !== '') { $sql .= " AND action = ?"; $params[] = $actionFilter; }
    if ($phoneFilter !== '')  { $sql .= " AND target_phone LIKE ?"; $params[] = '%'.$phoneFilter.'%'; }
    if ($dateFrom !== '')     { $sql .= " AND created_at >= ?"; $params[] = $dateFrom.' 00:00:00'; }
    if ($dateTo !== '')       { $sql .= " AND created_at <= ?"; $params[] = $dateTo.' 23:59:59'; }
    $sql .= " ORDER BY created_at DESC LIMIT 100";
    return q($sql, $params)->fetchAll();
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
    $data[] = [[ 'Date',1,'s' ], [ 'Action',1,'s' ], [ 'Resultat',1,'s' ], [ 'Compte',1,'s' ], [ 'Details',1,'s' ]];
    foreach($rows as $l){
        $data[] = [
            [ date('d/m/Y H:i', strtotime($l['created_at'])), 2, 's' ],
            [ admin_audit_action_label($l['action']), 2, 's' ],
            [ admin_audit_result_label($l['result']), 2, 's' ],
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
    $w = [26,38,22,30,74];
    $headers = ['Date','Action','Resultat','Compte','Details'];
    foreach($headers as $i=>$h){ $pdf->Cell($w[$i],8,pdf_str($h),1,0,'C',true); }
    $pdf->Ln();

    $pdf->SetFont('Arial','',8);
    foreach($rows as $l){
        $pdf->Cell($w[0],7,date('d/m/y H:i',strtotime($l['created_at'])),1);
        $pdf->Cell($w[1],7,pdf_str(admin_audit_action_label($l['action'])),1);
        $pdf->Cell($w[2],7,pdf_str(admin_audit_result_label($l['result'])),1);
        $pdf->Cell($w[3],7,pdf_str($l['target_phone'] ?: '-'),1);
        $pdf->Cell($w[4],7,substr(pdf_str($l['details'] ?: ''),0,58),1);
        $pdf->Ln();
    }

    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="rom_money_journal_audit.pdf"');
    echo $pdf->Output('S');
    exit;
}

function admin_dashboard_get_data($period, $dateFrom, $dateTo) {
    // Bloc "Aujourd'hui" - toujours fixe, independant du filtre de periode
    $todayCount  = q("SELECT COUNT(*) FROM transactions WHERE status='completed' AND type!='fee' AND created_at >= CURRENT_DATE")->fetchColumn();
    $todayVolume = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE status='completed' AND type!='fee' AND created_at >= CURRENT_DATE")->fetchColumn();
    $todayFees   = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE status='completed' AND type='fee' AND created_at >= CURRENT_DATE")->fetchColumn();
    $kycPending  = q("SELECT COUNT(*) FROM kyc_requests WHERE status='pending'")->fetchColumn();

    // Bloc "Periode selectionnee"
    $where = "status='completed'";
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

    $periodVolume = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE $where AND type!='fee'", $params)->fetchColumn();
    $periodFees   = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE $where AND type='fee'", $params)->fetchColumn();

    $totalVolume = q("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE status='completed' AND type!='fee'")->fetchColumn();
    $recentLogs  = q("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 5")->fetchAll();
    $operatorBreakdown = q("SELECT COALESCE(NULLIF(operator,''),'Non renseigné') AS operator, COUNT(*) AS total
        FROM users GROUP BY operator
        ORDER BY CASE COALESCE(NULLIF(operator,''),'Non renseigné')
            WHEN 'Orange CI' THEN 1
            WHEN 'MTN CI' THEN 2
            WHEN 'Moov Africa CI' THEN 3
            ELSE 4
        END")->fetchAll();

    // Evolution quotidienne (14 derniers jours), independante du filtre de
    // periode ci-dessus : sert a visualiser une tendance recente, pas a
    // cumuler sur une longue duree.
    $dailyRows = q("SELECT DATE(created_at) AS day, COUNT(*) AS count, COALESCE(SUM(amount),0) AS volume
        FROM transactions
        WHERE status='completed' AND type!='fee' AND created_at >= NOW() - INTERVAL '14 days'
        GROUP BY DATE(created_at) ORDER BY day")->fetchAll();
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
    $topUsers = q("SELECT u.id, COALESCE(NULLIF(u.verified_name,''), u.full_name) AS name, u.phone_number,
            SUM(t.amount) AS total_volume, COUNT(*) AS tx_count
        FROM users u
        JOIN wallets w ON w.user_id = u.id
        JOIN transactions t ON (t.sender_wallet_id = w.id OR t.receiver_wallet_id = w.id)
        WHERE t.status='completed' AND t.type != 'fee'
        GROUP BY u.id, name, u.phone_number
        ORDER BY total_volume DESC
        LIMIT 10")->fetchAll();

    return [
        'today_count'    => (int)$todayCount,
        'today_volume'   => (float)$todayVolume,
        'today_fees'     => (float)$todayFees,
        'kyc_pending'    => (int)$kycPending,
        'period'         => $period,
        'period_volume'  => (float)$periodVolume,
        'period_fees'    => (float)$periodFees,
        'operator_breakdown' => $operatorBreakdown,
        'total_volume'   => (float)$totalVolume,
        'recent_logs'    => $recentLogs,
        'daily_volume'   => $dailyVolume,
        'top_users'      => $topUsers
    ];
}

function admin_dashboard_stats() {
    $b = body();
    check_admin_password($b);
    $period   = trim($b['period'] ?? 'today');
    $dateFrom = trim($b['date_from'] ?? '');
    $dateTo   = trim($b['date_to'] ?? '');
    ok(admin_dashboard_get_data($period, $dateFrom, $dateTo));
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
    if(!isset($_GET['admin_password']) || !hash_equals(ADMIN_PASSWORD, (string)$_GET['admin_password'])) {
        fail('Mot de passe admin incorrect',401);
    }
    $period   = trim($_GET['period'] ?? 'today');
    $dateFrom = trim($_GET['date_from'] ?? '');
    $dateTo   = trim($_GET['date_to'] ?? '');
    $d = admin_dashboard_get_data($period, $dateFrom, $dateTo);

    // Styles : 0=normal, 1=en-tete (gras+fond+bordure), 2=texte borde,
    // 3=nombre borde (separateur de milliers), 4=titre, 5=sous-titre section
    $rows = [];
    $rows[] = [[ 'ROM_MONEY - Tableau de bord', 4, 's' ]];
    $rows[] = [[ 'Genere le '.date('d/m/Y').' a '.date('H:i'), 0, 's' ]];
    $rows[] = [];

    $rows[] = [[ 'Resume', 5, 's' ]];
    $rows[] = [[ 'Transactions aujourd\'hui', 2, 's' ], [ $d['today_count'], 3, 'n' ]];
    $rows[] = [[ 'Volume aujourd\'hui', 2, 's' ], [ $d['today_volume'], 3, 'n' ]];
    $rows[] = [[ 'Gains aujourd\'hui', 2, 's' ], [ $d['today_fees'], 3, 'n' ]];
    $rows[] = [[ 'KYC en attente', 2, 's' ], [ $d['kyc_pending'], 3, 'n' ]];
    $rows[] = [[ 'Volume periode ('.$d['period'].')', 2, 's' ], [ $d['period_volume'], 3, 'n' ]];
    $rows[] = [[ 'Gains periode', 2, 's' ], [ $d['period_fees'], 3, 'n' ]];
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
        $changes[] = $def[1].' = '.$val;
    }
    admin_log('update_settings','success',null, implode(', ', $changes) ?: 'Aucun changement');
    ok(null,'Reglages mis a jour');
}

function admin_dashboard_export_pdf() {
    if(!isset($_GET['admin_password']) || !hash_equals(ADMIN_PASSWORD, (string)$_GET['admin_password'])) {
        fail('Mot de passe admin incorrect',401);
    }
    $period   = trim($_GET['period'] ?? 'today');
    $dateFrom = trim($_GET['date_from'] ?? '');
    $dateTo   = trim($_GET['date_to'] ?? '');
    $d = admin_dashboard_get_data($period, $dateFrom, $dateTo);

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
    $pdf->Cell(0,6,pdf_str('Transactions aujourd\'hui : '.$d['today_count'].'  -  Volume : '.number_format($d['today_volume'],0,',',' ').' F  -  Gains : '.number_format($d['today_fees'],0,',',' ').' F'),0,1);
    $pdf->Cell(0,6,pdf_str('Periode ('.$d['period'].') : Volume '.number_format($d['period_volume'],0,',',' ').' F  -  Gains '.number_format($d['period_fees'],0,',',' ').' F'),0,1);
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
    $name = trim($b['name'] ?? '');
    if(!$name) fail('Pays requis');
    $row = q("SELECT is_active FROM active_countries WHERE name=?",[$name])->fetch();
    if(!$row) fail('Pays introuvable',404);
    $newStatus = $row['is_active'] ? 0 : 1;
    q("UPDATE active_countries SET is_active=?, updated_at=NOW() WHERE name=?",[$newStatus,$name]);
    admin_log('country_toggle','success',null,($newStatus?'Activation':'Désactivation').' pays : '.$name);
    ok(['name'=>$name,'is_active'=>(bool)$newStatus],'Statut du pays mis a jour');
}

function admin_account_status() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone'] ?? '');
    if(!$phone) fail('Telephone requis');
    $u = q("SELECT status FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u) fail('Compte introuvable',404);
    ok(['phone'=>$phone,'status'=>$u['status']]);
}

function admin_block_account() {
    $b = body();
    check_admin_password($b);
    $phone  = trim($b['phone'] ?? '');
    $reason = trim($b['reason'] ?? '');
    if(!$phone || !$reason) fail('Telephone et raison requis');
    $u = q("SELECT id,status FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u){
        admin_log('account_block','failed',$phone,'Compte introuvable');
        fail('Compte introuvable',404);
    }
    if($u['status']==='blocked'){
        admin_log('account_block','failed',$phone,'Deja bloque - '.$reason);
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
    $u = q("SELECT id,status FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u){
        admin_log('account_unblock','failed',$phone,'Compte introuvable');
        fail('Compte introuvable',404);
    }
    if($u['status']==='active'){
        admin_log('account_unblock','failed',$phone,'Deja actif - '.$reason);
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

    $u = q("SELECT id,full_name FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u){
        admin_log('account_delete','failed',$phone,'Compte introuvable');
        fail('Compte introuvable',404);
    }
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

    admin_log('account_delete','success',$phone,'Compte "'.($u['full_name']?:'?').'" supprime definitivement - '.$reason);
    ok(null,'Compte supprime definitivement');
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
    admin_log('exchange_rates_refresh','success',null,$count.' devise(s) mise(s) a jour manuellement');
    ok(['updated' => $count], 'Taux de change actualises');
}

function admin_update_country() {
    $b = body();
    check_admin_password($b);
    $phone   = trim($b['phone'] ?? '');
    $country = trim($b['country'] ?? '');
    $reason  = trim($b['reason'] ?? '');
    if(!$phone || !$country || !$reason) fail('Telephone, pays et raison requis');
    $u = q("SELECT id,country FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u){
        admin_log('update_country','failed',$phone,'Compte introuvable');
        fail('Compte introuvable',404);
    }
    $countryRow = q("SELECT is_active FROM active_countries WHERE name=?",[$country])->fetch();
    if(!$countryRow || !$countryRow['is_active']){
        admin_log('update_country','failed',$phone,'Pays non actif: '.$country.' - '.$reason);
        fail('Ce pays n\'est pas actif sur ROM_MONEY');
    }
    $oldCountry = $u['country'];
    q("UPDATE users SET country=? WHERE id=?",[$country,$u['id']]);
    admin_log('update_country','success',$phone,'De "'.($oldCountry?:'-').'" vers "'.$country.'" - '.$reason);
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
    if(!$id) fail('Identifiant de la demande requis');
    $where = "id=?"; $params = [$id];
    if($createdAt){ $where .= " AND created_at=?"; $params[] = $createdAt; }
    $k = q("SELECT ctid, phone_number FROM kyc_requests WHERE $where LIMIT 1", $params)->fetch();
    if(!$k){
        admin_log('delete_kyc','failed',null,'Demande introuvable: '.$id);
        fail('Demande introuvable',404);
    }
    q("DELETE FROM kyc_requests WHERE ctid = ?::tid", [$k['ctid']]);
    admin_log('delete_kyc','success',$k['phone_number'],'Demande KYC '.$id.' supprimee (ligne unique)');
    ok(null,'Demande KYC supprimee');
}

// Liste/recherche globale des comptes, avec filtres combinables (texte,
// statut KYC, statut du compte, plage de dates d'inscription) et pagination.
function admin_list_users() {
    $b = body();
    check_admin_password($b);
    $search = trim($b['search'] ?? '');
    $kycFilter = trim($b['kyc'] ?? '');
    $statusFilter = trim($b['status'] ?? '');
    $dateFrom = trim($b['date_from'] ?? '');
    $dateTo = trim($b['date_to'] ?? '');
    $page = max(1, (int)($b['page'] ?? 1));
    $perPage = 25;
    $offset = ($page - 1) * $perPage;

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

    $total = (int)q("SELECT COUNT(*) FROM users WHERE $where", $params)->fetchColumn();
    $rows = q("SELECT id,full_name,verified_name,phone_number,operator,status,is_kyc,created_at
               FROM users WHERE $where ORDER BY created_at DESC LIMIT $perPage OFFSET $offset", $params)->fetchAll();

    ok(['users'=>$rows,'total'=>$total,'page'=>$page,'per_page'=>$perPage]);
}

// Flux centralise des connexions "nouvel appareil" recentes, tous comptes
// confondus. Exclut volontairement le tout premier appareil de chaque
// compte (celui de l'inscription, qui n'a rien de suspect) : ne montre que
// les appareils ajoutes APRES le premier, exactement le meme critere que
// celui qui declenche deja la notification push d'alerte au moment de la
// connexion. Fenetre fixe de 30 jours, plafonnee a 50 entrees.
function admin_list_alerts() {
    $b = body();
    check_admin_password($b);
    $rows = q("SELECT kd.device_id, kd.user_agent, kd.first_seen,
                      u.id AS user_id, u.full_name, u.verified_name, u.phone_number
               FROM known_devices kd
               JOIN users u ON u.id = kd.user_id
               WHERE kd.first_seen >= NOW() - INTERVAL '30 days'
                 AND kd.first_seen > (
                     SELECT MIN(kd2.first_seen) FROM known_devices kd2 WHERE kd2.user_id = kd.user_id
                 )
               ORDER BY kd.first_seen DESC
               LIMIT 50")->fetchAll();
    ok(['alerts'=>$rows]);
}

// Transactions signalees par fraud_check_transaction() (velocite, montant
// inhabituel, nouveau destinataire + montant eleve). Non-reviewees d'abord,
// puis les plus recentes. Plafonne a 100 entrees.
function admin_list_fraud_alerts() {
    $b = body();
    check_admin_password($b);
    $rows = q("SELECT * FROM fraud_alerts ORDER BY reviewed ASC, created_at DESC LIMIT 100")->fetchAll();
    $unreviewed = (int)q("SELECT COUNT(*) FROM fraud_alerts WHERE reviewed=false")->fetchColumn();
    ok(['alerts'=>$rows, 'unreviewed_count'=>$unreviewed]);
}

function admin_mark_fraud_reviewed() {
    $b = body();
    check_admin_password($b);
    $id = (int)($b['id'] ?? 0);
    if(!$id) fail('Alerte introuvable');
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
        currency VARCHAR(10) DEFAULT 'FCFA',
        qr_seed VARCHAR(50) NOT NULL,
        qr_renewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE TABLE IF NOT EXISTS transactions (
        id VARCHAR(36) PRIMARY KEY,
        sender_wallet_id VARCHAR(36),
        receiver_wallet_id VARCHAR(36),
        amount DECIMAL(15,2) NOT NULL,
        net_amount DECIMAL(15,2),
        fee DECIMAL(15,2) DEFAULT 0,
        currency VARCHAR(10) DEFAULT 'FCFA',
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
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS details TEXT",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS target_phone VARCHAR(20)",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_agent TEXT",
    "CREATE TABLE IF NOT EXISTS notifications (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        title VARCHAR(150) NOT NULL,
        body TEXT NOT NULL,
        is_read SMALLINT DEFAULT 0,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
    "CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(36),
        action VARCHAR(100) NOT NULL,
        ip_address VARCHAR(45),
        result VARCHAR(20) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
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
    "CREATE TABLE IF NOT EXISTS known_devices (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        device_id VARCHAR(64) NOT NULL,
        user_agent TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, device_id)
    )",
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

    ok(['tables_created'=>$created],'Installation terminee ! Toutes les tables ont ete creees.');
}
