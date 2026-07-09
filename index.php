<?php
// ============================================================
// Rom_money - Backend complet PostgreSQL
// ============================================================

define('DB_HOST',    getenv('DB_HOST')    ?: 'localhost');
define('DB_NAME',    getenv('DB_NAME')    ?: 'rom_money_db');
define('DB_USER',    getenv('DB_USER')    ?: 'root');
define('DB_PASS',    getenv('DB_PASS')    ?: '');
define('DB_PORT',    getenv('DB_PORT')    ?: '5432');
define('JWT_SECRET', getenv('JWT_SECRET') ?: 'RomMoney2024SecretKey!@#$%');
define('ADMIN_PASSWORD', getenv('ADMIN_PASSWORD') ?: 'JRB-Rom@rios07');
define('JWT_EXPIRY', 86400);
define('APP_ENV',    getenv('APP_ENV')    ?: 'development');
define('APP_DEBUG',  APP_ENV === 'development');
define('CANCEL_MINS', 5);

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json; charset=utf-8");
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

const RECEIVE_LIMIT_UNVERIFIED = 2000000;
const RECEIVE_LIMIT_VERIFIED   = 100000000;

// Verifie que creditier $userId de $incomingNet ne depasse pas son plafond
// mensuel de reception (remis a zero chaque mois calendaire, comme les stats).
// Bloque avec fail() si le plafond serait depasse. $selfFacing indique si la
// personne qui appelle l'API est elle-meme le destinataire (Encaisser, Depot
// bancaire) ou une autre personne (Envoyer -> le message s'adresse a l'emetteur).
function check_receive_limit($userId, $incomingNet, $selfFacing=true) {
    $u = q("SELECT is_kyc FROM users WHERE id=?",[$userId])->fetch();
    $limit = ($u && $u['is_kyc']) ? RECEIVE_LIMIT_VERIFIED : RECEIVE_LIMIT_UNVERIFIED;
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$userId])->fetchColumn();
    $row = q("SELECT COALESCE(SUM(COALESCE(net_amount,amount)),0) total FROM transactions
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
                [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES=>false]
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

$uri    = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/');
$parts  = explode('/', $uri);
$module = $parts[1] ?? ($parts[0] ?? '');
$action = $_GET['action'] ?? '';

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
    case 'health':
        ok(['status'=>'ok','app'=>'Rom_money','version'=>'1.0','time'=>date('Y-m-d H:i:s')]);
    case 'install':     route_install(); break;
    default:
        ok(['app'=>'Rom_money API','version'=>'1.0','routes'=>['/auth','/wallet','/transactions','/profile','/bank','/kyc','/health','/install']]);
}

// AUTH
function route_auth($action) {
    match($action) {
        'register'   => auth_register(),
        'login'      => auth_login(),
        'logout'     => auth_logout(),
        'change-pin' => auth_change_pin(),
        default      => fail('Action inconnue',404)
    };
}

function generate_referral_code() {
    do {
        $code = 'ROM'.strtoupper(substr(bin2hex(random_bytes(3)),0,6));
        $exists = q("SELECT id FROM users WHERE referral_code=?",[$code])->fetch();
    } while($exists);
    return $code;
}

function auth_register() {
    $b = body();
    $name  = trim($b['full_name'] ?? '');
    $phone = trim($b['phone']     ?? '');
    $pin   = trim($b['pin']       ?? '');
    $email = trim($b['email']     ?? '');
    $op    = trim($b['operator']  ?? '');
    $refCodeInput = trim($b['referral_code'] ?? '');
    if(!$name) fail('Nom requis');
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $phone))) fail('Telephone invalide');
    if(!preg_match('/^\d{6}$/', $pin)) fail('PIN doit avoir 6 chiffres');
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
        q("INSERT INTO users (id,full_name,phone_number,email,operator,password_hash,pin_hash,referral_code,referred_by) VALUES (?,?,?,?,?,?,?,?,?)",
          [$uid,$name,$phone,$email?:null,$op?:null,$passh,$pinh,$myReferralCode,$referredBy]);
        q("INSERT INTO wallets (id,user_id,balance,vault_balance,currency,qr_seed) VALUES (?,?,0,0,'FCFA',?)",
          [$wid,$uid,$qrseed]);
        $token = jwt_make(['sub'=>$uid,'phone'=>$phone]);
        db()->commit();
        ok(['token'=>$token,'user_id'=>$uid,'name'=>$name,'phone'=>$phone,'qr_seed'=>$qrseed,'referral_code'=>$myReferralCode],'Compte cree', 201);
    } catch(Exception $e) {
        db()->rollBack();
        fail(APP_DEBUG ? $e->getMessage() : 'Erreur creation compte', 500);
    }
}

function auth_login() {
    $b = body();
    $phone = trim($b['phone'] ?? '');
    $pin   = trim($b['pin']   ?? '');
    if(!$phone || !$pin) fail('Telephone et PIN requis');
    $user = q("SELECT u.*,w.id wid,w.balance,w.vault_balance,w.vault_locked,w.vault_lock_date,w.qr_seed FROM users u LEFT JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?", [$phone])->fetch();
    if(!$user || !password_verify($pin, $user['pin_hash'])) fail('Numero ou PIN incorrect', 401);
    if($user['status'] !== 'active') fail('Compte suspendu', 403);
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
        default          => fail('Action inconnue',404)
    };
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
    $limit = $isKyc ? RECEIVE_LIMIT_VERIFIED : RECEIVE_LIMIT_UNVERIFIED;
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$pl['sub']])->fetchColumn();
    $row = q("SELECT COALESCE(SUM(COALESCE(net_amount,amount)),0) total FROM transactions
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
        SUM(CASE WHEN receiver_wallet_id=? AND status='completed' THEN COALESCE(net_amount,amount) ELSE 0 END) total_in,
        SUM(CASE WHEN sender_wallet_id=? AND status='completed' THEN amount ELSE 0 END) total_out
        FROM transactions
        WHERE (sender_wallet_id=? OR receiver_wallet_id=?) AND type!='fee'
        AND EXTRACT(YEAR FROM created_at)=EXTRACT(YEAR FROM NOW())
        GROUP BY ym",[$wid,$wid,$wid,$wid])->fetchAll();

    $byMonth = [];
    foreach($rows as $r){ $byMonth[$r['ym']] = $r; }

    $labels = ['Jan','Fev','Mar','Avr','Mai','Jun','Jul','Aou','Sep','Oct','Nov','Dec'];
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
        SUM(CASE WHEN receiver_wallet_id=? AND status='completed' THEN COALESCE(net_amount,amount) ELSE 0 END) total_in,
        SUM(CASE WHEN sender_wallet_id=? AND status='completed' THEN amount ELSE 0 END) total_out,
        COUNT(CASE WHEN (sender_wallet_id=? OR receiver_wallet_id=?) AND status='completed' THEN 1 END) tx_count,
        COUNT(CASE WHEN sender_wallet_id=? AND status='cancelled' THEN 1 END) cancelled
        FROM transactions WHERE type!='fee' AND (sender_wallet_id=? OR receiver_wallet_id=?)
        AND EXTRACT(MONTH FROM created_at)=EXTRACT(MONTH FROM NOW())
        AND EXTRACT(YEAR FROM created_at)=EXTRACT(YEAR FROM NOW())",
        [$wid,$wid,$wid,$wid,$wid,$wid,$wid])->fetch();

    // Cartes du haut - "Recap total" : cumul sur l'annee calendaire affichee dans le graphique.
    $cumulative = q("SELECT
        SUM(CASE WHEN receiver_wallet_id=? AND status='completed' THEN COALESCE(net_amount,amount) ELSE 0 END) total_in,
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
        default   => fail('Action inconnue',404)
    };
}

function tx_send() {
    $pl = auth(); $b = body();
    $to     = trim($b['receiver_phone']??'');
    $amount = (float)($b['amount']??0);
    $mode   = ($b['mode']??'net')==='brut' ? 'brut' : 'net'; // default 'net' for backward compatibility
    $pin = trim($b['pin']??'');
    $desc= trim($b['description']??'');
    if(!preg_match('/^\+?[0-9]{8,15}$/',preg_replace('/[\s\-]/','', $to))) fail('Numero invalide');
    if($amount<=0) fail('Montant invalide');
    if(!preg_match('/^\d{6}$/',$pin)) fail('PIN invalide');
    $user = q("SELECT pin_hash FROM users WHERE id=?",[$pl['sub']])->fetch();
    pin_check($pl['sub'], $pin, $user['pin_hash']);
    // Calculate fee (1% over 4000 F, single calculation matching frontend - direction
    // depends on which field (brut or net) the user actually filled in)
    if($mode==='brut'){
        $brut = $amount;
        $fee  = ($brut >= 4000) ? round($brut * 0.01) : 0;
        $net  = $brut - $fee;
    } else {
        $net  = $amount;
        $fee  = ($net >= 4000) ? round($net * 0.01) : 0;
        $brut = $net + $fee; // Total amount debited from sender
    }
    if($net<=0) fail('Montant invalide');

    $sw = q("SELECT * FROM wallets WHERE user_id=?",[$pl['sub']])->fetch();
    if((float)$sw['balance']<$brut) fail('Solde insuffisant');
    $recv = q("SELECT u.id,u.full_name,w.id wid FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$to])->fetch();
    if(!$recv) fail('Destinataire introuvable');
    if($recv['id']===$pl['sub']) fail('Envoi a soi-meme impossible');
    check_receive_limit($recv['id'], $net, false);
    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        // Record the BRUT amount as the transaction amount (this is what sender sees deducted)
        q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,net_amount,type,status,reference,description,cancel_deadline) VALUES (?,?,?,?,?,'transfer','pending',?,?,?)",
          [$txid,$sw['id'],$recv['wid'],$brut,$net,$reference,$desc?:null,$deadline]);
        $rows = q("UPDATE wallets SET balance=balance-? WHERE id=? AND balance>=?",[$brut,$sw["id"],$brut])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        // Recipient gets NET amount
        q("UPDATE wallets SET balance=balance+? WHERE id=?",[$net,$recv['wid']]);
        q("UPDATE transactions SET status='completed' WHERE id=?",[$txid]);

        // ── Transfer fees to ROM_MONEY system account
        $fee_phone = '0160629502'; // ROM_MONEY system account
        if($fee > 0){
            $fee_recv = q("SELECT u.id,w.id wid FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$fee_phone])->fetch();
            if($fee_recv && $fee_recv['id'] !== $pl['sub']){
                $fee_txid = uid(); $fee_ref = ref();
                q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description) VALUES (?,?,?,?,'fee','completed',?,'Frais ROM_MONEY 1%')",
                  [$fee_txid,$sw['id'],$fee_recv['wid'],$fee,$fee_ref]);
                q("UPDATE wallets SET balance=balance+? WHERE id=?",[$fee,$fee_recv['wid']]);
            }
        }
        apply_referral_bonus($pl['sub'], $fee);

        db()->commit();
        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$brut,'net_amount'=>$net,'fee'=>$fee,
            'receiver_name'=>$recv['full_name'],'cancel_before'=>$deadline,
            'new_balance'=>(float)$sw['balance']-$brut],'Transfert effectue');
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

    $payer = q("SELECT u.id,u.full_name,u.pin_hash,w.id wid,w.balance FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=?",[$payerPhone])->fetch();
    if(!$payer) fail('Payeur introuvable');
    if($payer['id']===$pl['sub']) fail('Encaissement de soi-meme impossible');

    // PIN is verified against the PAYER's own account (not the merchant's), with
    // anti-bruteforce lockout since this account is identified by phone, not by token.
    pin_check($payer['id'], $pin, $payer['pin_hash']);

    if($mode==='brut'){
        $brut = $amount;
        $fee  = ($brut >= 4000) ? round($brut * 0.01) : 0;
        $net  = $brut - $fee;
    } else {
        $net  = $amount;
        $fee  = ($net >= 4000) ? round($net * 0.01) : 0;
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
        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$brut,'net_amount'=>$net,'fee'=>$fee,
            'payer_name'=>$payer['full_name'],'cancel_before'=>$deadline],'Encaissement effectue');
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
        su.full_name sender_name, ru.full_name receiver_name
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
    $u = q("SELECT full_name,phone_number,is_kyc FROM users WHERE phone_number=? AND id!=?",[$phone,$pl['sub']])->fetch();
    if(!$u) fail('Aucun compte trouve',404);
    ok($u,'Compte trouve');
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
    $u = q("SELECT u.id,u.full_name,u.phone_number,u.email,u.operator,u.bio_enabled,u.is_kyc,u.status,u.created_at,u.photo_url,u.notif_tx,u.notif_promo,u.verified_name,w.id wid FROM users u LEFT JOIN wallets w ON w.user_id=u.id WHERE u.id=?",[$pl['sub']])->fetch();
    if(!$u) fail('Introuvable',404);
    ok(['id'=>$u['id'],'name'=>$u['full_name'],'phone'=>$u['phone_number'],'email'=>$u['email'],
        'operator'=>$u['operator'],'bio_enabled'=>(bool)$u['bio_enabled'],'is_kyc'=>(bool)$u['is_kyc'],
        'status'=>$u['status'],'member_since'=>$u['created_at'],'wallet_id'=>$u['wid'],'photo_url'=>$u['photo_url'],
        'notif_tx'=>(bool)($u['notif_tx']??true),'notif_promo'=>(bool)($u['notif_promo']??true),
        'legal_name'=>$u['verified_name']]);
}

function profile_update() {
    $pl = auth(); $b = body();
    $sets=[]; $vals=[];
    if(!empty($b['full_name'])){$sets[]="full_name=?";$vals[]=$b['full_name'];}
    if(!empty($b['email'])){$sets[]="email=?";$vals[]=$b['email'];}
    if(!empty($b['operator'])){$sets[]="operator=?";$vals[]=$b['operator'];}
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
    if(!$recto || !$verso) fail('Recto et verso requis');
    if(!$legalPrenom || !$legalNom) fail('Le prenom et le nom exacts (piece d\'identite) sont requis');
    $legalName = trim($legalPrenom.' '.$legalNom);
    $ocrName = trim($ocrPrenom.' '.$ocrNom);

    $existing = q("SELECT id FROM kyc_requests WHERE user_id=? AND status='pending'",[$pl['sub']])->fetch();
    if($existing) fail('Une demande est deja en attente de verification');

    $u = q("SELECT full_name,phone_number FROM users WHERE id=?",[$pl['sub']])->fetch();

    $id = uid();
    q("INSERT INTO kyc_requests (id,user_id,phone_number,full_name,legal_name,legal_prenom,legal_nom,legal_birthdate,ocr_name,ocr_prenom,ocr_nom,ocr_birthdate,photo_recto,photo_verso,status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,'pending')",
      [$id,$pl['sub'],$u['phone_number'],$u['full_name'],$legalName,$legalPrenom,$legalNom,$legalBirthdate?:null,$ocrName?:null,$ocrPrenom?:null,$ocrNom?:null,$ocrBirthdate?:null,$recto,$verso]);
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
    $result = google_vision_ocr($recto);
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
    $rows = q("SELECT id,user_id,phone_number,full_name,legal_name,legal_prenom,legal_nom,legal_birthdate,ocr_name,ocr_prenom,ocr_nom,ocr_birthdate,photo_recto,photo_verso,status,created_at
        FROM kyc_requests WHERE status='pending' ORDER BY created_at ASC")->fetchAll();
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
    $r = q("SELECT user_id,legal_name,legal_birthdate FROM kyc_requests WHERE id=? AND status='pending'",[$id])->fetch();
    if(!$r) fail('Demande introuvable ou deja traitee',404);
    q("UPDATE kyc_requests SET status='approved', reviewed_at=NOW() WHERE id=?",[$id]);
    q("UPDATE users SET is_kyc=1, verified_name=?, verified_birthdate=? WHERE id=?",[$r['legal_name'],$r['legal_birthdate'],$r['user_id']]);
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
        'csv' => export_csv(),
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

function export_type_label($type, $isDebit=false){
    if($type==='transfer') return $isDebit ? 'Transfert envoye' : 'Transfert recu';
    $map=['payment'=>'Achat','bank_deposit'=>'Depot banque',
          'bank_withdraw'=>'Retrait banque','deposit'=>'Depot','vault_deposit'=>'Coffre',
          'referral_bonus'=>'Bonus parrainage'];
    return $map[$type] ?? $type;
}

function export_csv() {
    $pl = auth();
    $periodRaw = $_GET['period']??'month';
    $period = in_array($periodRaw,['month','all','custom']) ? $periodRaw : 'month';
    $from = $_GET['from']??null;
    $to = $_GET['to']??null;
    $res = export_get_rows($pl, $period, $from, $to);
    $rows = $res['rows'];

    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="rom_money_historique.csv"');
    header('Access-Control-Expose-Headers: X-Export-Truncated, X-Export-Total, X-Export-Limit');
    header('X-Export-Truncated: '.($res['truncated']?'1':'0'));
    header('X-Export-Total: '.$res['total']);
    header('X-Export-Limit: '.$res['limit']);
    echo "\xEF\xBB\xBF"; // BOM UTF-8, pour un affichage correct des accents dans Excel
    $out = fopen('php://output','w');
    if($res['truncated']){
        fputcsv($out, ['Limite aux '.$res['limit'].' dernieres transactions sur '.$res['total'].' au total. Choisissez une periode plus precise pour tout voir.'], ';');
    }
    fputcsv($out, ['Date','Type','Contact','Montant','Frais','Reference','Statut'], ';');
    foreach($rows as $t){
        $isDebit = $t['direction']==='debit';
        $amount = (float)$t['amount'];
        $net = $t['net_amount']!==null ? (float)$t['net_amount'] : $amount;
        $frais = max(0, $amount - $net);
        $montant = $isDebit ? -$amount : $net;
        $contact = $isDebit ? ($t['receiver_verified_name']?:$t['receiver_name']?:$t['receiver_phone']?:'-') : ($t['sender_verified_name']?:$t['sender_name']?:$t['sender_phone']?:'-');
        fputcsv($out, [
            date('d/m/Y H:i', strtotime($t['created_at'])),
            export_type_label($t['type'], $isDebit),
            $contact,
            number_format($montant,0,',',' ').' F',
            number_format($frais,0,',',' ').' F',
            $t['reference'],
            $t['status']
        ], ';');
    }
    fclose($out);
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
    $res = export_get_rows($pl, $period, $from, $to);
    $rows = $res['rows'];
    $u = q("SELECT full_name,phone_number,verified_name FROM users WHERE id=?",[$pl['sub']])->fetch();

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
    $pdf->Cell(0,10,pdf_str('ROM_MONEY - Releve de transactions'),0,1);
    $infoTopY = $pdf->GetY();
    $logoPath = __DIR__.'/logo.png';
    if(file_exists($logoPath)){
        $pdf->Image($logoPath, 182, $infoTopY, 18, 18);
    }
    $pdf->SetFont('Arial','',10);
    $pdf->Cell(150,6,pdf_str('Titulaire : '.($u['verified_name']?:$u['full_name']?:'').' ('.$u['phone_number'].')'),0,1);
    $pdf->Cell(150,6,pdf_str('Periode : '.$periodeLabel),0,1);
    $pdf->Cell(150,6,pdf_str('Genere le '.date('d/m/Y').' a '.date('H:i')),0,1);
    if(file_exists($logoPath)){
        $pdf->SetY(max($pdf->GetY(), $infoTopY+18));
    }
    if($res['truncated']){
        $pdf->SetTextColor(200,0,0);
        $pdf->Cell(0,6,pdf_str('Limite aux '.$res['limit'].' dernieres transactions sur '.$res['total'].' au total. Choisissez une periode plus precise pour tout voir.'),0,1);
        $pdf->SetTextColor(0,0,0);
    }
    $pdf->Ln(4);

    $pdf->SetFont('Arial','B',9);
    $pdf->SetFillColor(230,241,251);
    $w = [26,28,42,28,20,32,20];
    $headers = ['Date','Type','Contact','Montant','Frais','Reference','Statut'];
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
        $pdf->Cell($w[1],7,pdf_str(export_type_label($t['type'],$isDebit)),1);
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
function route_announce($action) {
    match($action) {
        'list'         => announce_list(),
        'admin-create' => announce_admin_create(),
        default        => fail('Action inconnue',404)
    };
}

function announce_list() {
    $pl = auth();
    $u = q("SELECT notif_promo FROM users WHERE id=?",[$pl['sub']])->fetch();
    $allowPromo = (bool)($u['notif_promo'] ?? true);
    if($allowPromo){
        $rows = q("SELECT id,title,message,type,created_at FROM announcements
            WHERE created_at >= NOW() - INTERVAL '30 days' ORDER BY created_at ASC")->fetchAll();
    } else {
        $rows = q("SELECT id,title,message,type,created_at FROM announcements
            WHERE type='update' AND created_at >= NOW() - INTERVAL '30 days' ORDER BY created_at ASC")->fetchAll();
    }
    ok(['announcements'=>$rows]);
}

function announce_admin_create() {
    $b = body();
    check_admin_password($b);
    $title = trim($b['title']??'');
    $message = trim($b['message']??'');
    $type = ($b['type']??'update')==='promo' ? 'promo' : 'update';
    if(!$title || !$message) fail('Titre et message requis');
    $id = uid();
    q("INSERT INTO announcements (id,title,message,type) VALUES (?,?,?,?)",[$id,$title,$message,$type]);
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
        'audit-export-csv'  => admin_audit_export_csv(),
        'audit-export-pdf'  => admin_audit_export_pdf(),
        'countries-list'    => admin_countries_list(),
        'country-toggle'    => admin_country_toggle(),
        'account-status'    => admin_account_status(),
        'block-account'     => admin_block_account(),
        'unblock-account'   => admin_unblock_account(),
        default             => fail('Action inconnue',404)
    };
}

function admin_log($action, $result, $targetPhone, $details) {
    q("INSERT INTO audit_logs (action,result,target_phone,details) VALUES (?,?,?,?)",
      [$action,$result,$targetPhone,$details]);
}

function admin_login_check() {
    $b = body();
    $pw = (string)($b['admin_password'] ?? '');
    $ip = $_SERVER['REMOTE_ADDR'] ?? null;
    if (!hash_equals(ADMIN_PASSWORD, $pw)) {
        admin_log('admin_login','failed',null,'Tentative de connexion echouee'.($ip?' - IP: '.$ip:''));
        fail('Mot de passe admin incorrect',401);
    }
    admin_log('admin_login','success',null,'Connexion reussie'.($ip?' - IP: '.$ip:''));
    ok(null,'Connexion reussie');
}

function admin_reset_pin() {
    $b = body();
    check_admin_password($b);
    $phone = trim($b['phone']??'');
    $newPin = trim($b['new_pin']??'');
    $reason = trim($b['reason']??'');
    if(!preg_match('/^\d{6}$/',$newPin)) fail('Le nouveau PIN doit contenir exactement 6 chiffres');
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
        su.full_name sender_name, su.phone_number sender_phone, su.verified_name sender_verified_name,
        ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name
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
    $u = q("SELECT id,full_name,verified_name FROM users WHERE phone_number=?",[$phone])->fetch();
    if(!$u) fail('Compte introuvable',404);
    $wid = q("SELECT id FROM wallets WHERE user_id=?",[$u['id']])->fetchColumn();
    $rows = q("SELECT t.*,
        CASE WHEN t.sender_wallet_id=? THEN 'debit' ELSE 'credit' END as direction,
        su.full_name sender_name, su.phone_number sender_phone, su.verified_name sender_verified_name,
        ru.full_name receiver_name, ru.phone_number receiver_phone, ru.verified_name receiver_verified_name
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        WHERE (t.sender_wallet_id=? OR t.receiver_wallet_id=?) AND t.type!='fee'
        ORDER BY t.created_at DESC LIMIT 30",[$wid,$wid,$wid])->fetchAll();
    ok(['account_name'=>$u['verified_name']?:$u['full_name'],'account_verified'=>!empty($u['verified_name']),'transactions'=>$rows]);
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
    $labels = ['pin_reset'=>'Reinitialisation PIN','late_cancel'=>'Annulation tardive','admin_login'=>'Connexion admin','country_toggle'=>'Pays actif/inactif','account_block'=>'Blocage de compte','account_unblock'=>'Deblocage de compte'];
    return $labels[$a] ?? $a;
}
function admin_audit_result_label($r) {
    $labels = ['success'=>'Succes','failed'=>'Echec'];
    return $labels[$r] ?? $r;
}

function admin_audit_export_csv() {
    $rows = admin_audit_get_rows();

    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="rom_money_journal_audit.csv"');
    echo "\xEF\xBB\xBF";
    $out = fopen('php://output','w');
    fputcsv($out, ['Date','Action','Resultat','Compte','Details'], ';');
    foreach($rows as $l){
        fputcsv($out, [
            date('d/m/Y H:i', strtotime($l['created_at'])),
            admin_audit_action_label($l['action']),
            admin_audit_result_label($l['result']),
            $l['target_phone'] ?: '-',
            $l['details'] ?: ''
        ], ';');
    }
    fclose($out);
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

function admin_dashboard_stats() {
    $b = body();
    check_admin_password($b);

    $period   = trim($b['period'] ?? 'today');
    $dateFrom = trim($b['date_from'] ?? '');
    $dateTo   = trim($b['date_to'] ?? '');

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

    ok([
        'today_count'    => (int)$todayCount,
        'today_volume'   => (float)$todayVolume,
        'today_fees'     => (float)$todayFees,
        'kyc_pending'    => (int)$kycPending,
        'period'         => $period,
        'period_volume'  => (float)$periodVolume,
        'period_fees'    => (float)$periodFees,
        'total_volume'   => (float)$totalVolume,
        'recent_logs'    => $recentLogs
    ]);
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
    "CREATE INDEX IF NOT EXISTS idx_announce_created ON announcements(created_at)",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS details TEXT",
    "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS target_phone VARCHAR(20)",
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

    ok(['tables_created'=>$created],'Installation terminee ! Toutes les tables ont ete creees.');
}
