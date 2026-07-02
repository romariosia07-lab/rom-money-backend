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
    return $pl;
}
function ref() { return 'REF-'.strtoupper(date('Ymd')).'-'.strtoupper(substr(uniqid(),-6)); }
function uid() { return bin2hex(random_bytes(8)); }

const PIN_MAX_ATTEMPTS = 5;
const PIN_LOCK_MINUTES = 60;

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
    case 'health':
        ok(['status'=>'ok','app'=>'Rom_money','version'=>'1.0','time'=>date('Y-m-d H:i:s')]);
    case 'install':     route_install(); break;
    default:
        ok(['app'=>'Rom_money API','version'=>'1.0','routes'=>['/auth','/wallet','/transactions','/profile','/bank','/health','/install']]);
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

function auth_register() {
    $b = body();
    $name  = trim($b['full_name'] ?? '');
    $phone = trim($b['phone']     ?? '');
    $pin   = trim($b['pin']       ?? '');
    $email = trim($b['email']     ?? '');
    $op    = trim($b['operator']  ?? '');
    if(!$name) fail('Nom requis');
    if(!preg_match('/^\+?[0-9]{8,15}$/', preg_replace('/[\s\-]/','', $phone))) fail('Telephone invalide');
    if(!preg_match('/^\d{6}$/', $pin)) fail('PIN doit avoir 6 chiffres');
    $exist = q("SELECT id FROM users WHERE phone_number=?", [$phone])->fetch();
    if($exist) fail('Ce numero est deja enregistre');
    db()->beginTransaction();
    try {
        $uid    = uid();
        $wid    = uid();
        $qrseed = strtoupper(bin2hex(random_bytes(5)));
        $pinh   = password_hash($pin, PASSWORD_BCRYPT);
        $passh  = password_hash(bin2hex(random_bytes(12)), PASSWORD_BCRYPT);
        q("INSERT INTO users (id,full_name,phone_number,email,operator,password_hash,pin_hash) VALUES (?,?,?,?,?,?,?)",
          [$uid,$name,$phone,$email?:null,$op?:null,$passh,$pinh]);
        q("INSERT INTO wallets (id,user_id,balance,vault_balance,currency,qr_seed) VALUES (?,?,0,0,'FCFA',?)",
          [$wid,$uid,$qrseed]);
        $token = jwt_make(['sub'=>$uid,'phone'=>$phone]);
        db()->commit();
        ok(['token'=>$token,'user_id'=>$uid,'name'=>$name,'phone'=>$phone,'qr_seed'=>$qrseed],'Compte cree', 201);
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
        su.full_name sender_name, su.phone_number sender_phone,
        ru.full_name receiver_name, ru.phone_number receiver_phone
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
        default          => fail('Action inconnue',404)
    };
}

function profile_get() {
    $pl = auth();
    $u = q("SELECT u.id,u.full_name,u.phone_number,u.email,u.operator,u.bio_enabled,u.is_kyc,u.status,u.created_at,w.id wid FROM users u LEFT JOIN wallets w ON w.user_id=u.id WHERE u.id=?",[$pl['sub']])->fetch();
    if(!$u) fail('Introuvable',404);
    ok(['id'=>$u['id'],'name'=>$u['full_name'],'phone'=>$u['phone_number'],'email'=>$u['email'],
        'operator'=>$u['operator'],'bio_enabled'=>(bool)$u['bio_enabled'],'is_kyc'=>(bool)$u['is_kyc'],
        'status'=>$u['status'],'member_since'=>$u['created_at'],'wallet_id'=>$u['wid']]);
}

function profile_update() {
    $pl = auth(); $b = body();
    $sets=[]; $vals=[]; $i=1;
    if(!empty($b['full_name'])){$sets[]="full_name=\$$i";$vals[]=$b['full_name'];$i++;}
    if(!empty($b['email'])){$sets[]="email=\$$i";$vals[]=$b['email'];$i++;}
    if(!empty($b['operator'])){$sets[]="operator=\$$i";$vals[]=$b['operator'];$i++;}
    if(!$sets) fail('Rien a mettre a jour');
    $vals[]=$pl['sub'];
    q("UPDATE users SET ".implode(',',$sets)." WHERE id=\$$i",$vals);
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
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_attempts SMALLINT DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_locked_until TIMESTAMP",
    "CREATE TABLE IF NOT EXISTS linked_banks (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        bank_name VARCHAR(100) NOT NULL,
        account_last4 VARCHAR(4),
        mock_token VARCHAR(100),
        is_default BOOLEAN DEFAULT false,
        linked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )",
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
    ok(['tables_created'=>$created],'Installation terminee ! Toutes les tables ont ete creees.');
}
