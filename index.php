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
    $h = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if(!str_starts_with($h,'Bearer ')) fail('Token manquant',401);
    $pl = jwt_check(substr($h,7));
    if(!$pl) fail('Token invalide ou expire',401);
    return $pl;
}
function ref() { return 'REF-'.strtoupper(date('Ymd')).'-'.strtoupper(substr(uniqid(),-6)); }
function uid() { return bin2hex(random_bytes(8)); }

function db(): PDO {
    static $pdo = null;
    if(!$pdo) {
        try {
            $pdo = new PDO(
                "pgsql:host=".DB_HOST.";port=".DB_PORT.";dbname=".DB_NAME,
                DB_USER, DB_PASS,
                [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]
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
    case 'health':
        ok(['status'=>'ok','app'=>'Rom_money','version'=>'1.0','time'=>date('Y-m-d H:i:s')]);
    case 'install':     route_install(); break;
    default:
        ok(['app'=>'Rom_money API','version'=>'1.0','routes'=>['/auth','/wallet','/transactions','/profile','/health','/install']]);
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
    $exist = q("SELECT id FROM users WHERE phone_number=$1", [$phone])->fetch();
    if($exist) fail('Ce numero est deja enregistre');
    db()->beginTransaction();
    try {
        $uid    = uid();
        $wid    = uid();
        $qrseed = strtoupper(bin2hex(random_bytes(5)));
        $pinh   = password_hash($pin, PASSWORD_BCRYPT);
        $passh  = password_hash(bin2hex(random_bytes(12)), PASSWORD_BCRYPT);
        q("INSERT INTO users (id,full_name,phone_number,email,operator,password_hash,pin_hash) VALUES ($1,$2,$3,$4,$5,$6,$7)",
          [$uid,$name,$phone,$email?:null,$op?:null,$passh,$pinh]);
        q("INSERT INTO wallets (id,user_id,balance,vault_balance,currency,qr_seed) VALUES ($1,$2,0,0,'FCFA',$3)",
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
    $user = q("SELECT u.*,w.id wid,w.balance,w.vault_balance,w.vault_locked,w.vault_lock_date,w.qr_seed FROM users u LEFT JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=$1", [$phone])->fetch();
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
    $user = q("SELECT pin_hash FROM users WHERE id=$1", [$pl['sub']])->fetch();
    if(!password_verify($cur, $user['pin_hash'])) fail('PIN actuel incorrect', 401);
    q("UPDATE users SET pin_hash=$1 WHERE id=$2", [password_hash($new,PASSWORD_BCRYPT), $pl['sub']]);
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
        default          => fail('Action inconnue',404)
    };
}

function wallet_balance() {
    $pl = auth();
    $w = q("SELECT w.*,u.full_name,u.phone_number,u.is_kyc,u.bio_enabled FROM wallets w JOIN users u ON w.user_id=u.id WHERE w.user_id=$1",[$pl['sub']])->fetch();
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
    $wid = q("SELECT id FROM wallets WHERE user_id=$1",[$pl['sub']])->fetchColumn();
    db()->beginTransaction();
    try {
        $reference = ref();
        q("INSERT INTO transactions (id,receiver_wallet_id,amount,type,status,reference,description) VALUES ($1,$2,$3,'deposit','completed',$4,'Recharge')",[uid(),$wid,$amt,$reference]);
        q("UPDATE wallets SET balance=balance+$1 WHERE id=$2",[$amt,$wid]);
        db()->commit();
        $bal = (float)q("SELECT balance FROM wallets WHERE id=$1",[$wid])->fetchColumn();
        ok(['reference'=>$reference,'amount'=>$amt,'new_balance'=>$bal],'Recharge effectuee');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur recharge',500); }
}

function vault_deposit() {
    $pl = auth(); $b = body();
    $amt = (float)($b['amount']??0);
    if($amt<=0) fail('Montant invalide');
    $w = q("SELECT * FROM wallets WHERE user_id=$1",[$pl['sub']])->fetch();
    if((float)$w['balance']<$amt) fail('Solde insuffisant');
    db()->beginTransaction();
    try {
        q("UPDATE wallets SET balance=balance-$1,vault_balance=vault_balance+$1 WHERE id=$2",[$amt,$w['id']]);
        q("INSERT INTO transactions (id,sender_wallet_id,amount,type,status,reference,description) VALUES ($1,$2,$3,'vault_deposit','completed',$4,'Depot coffre')",[uid(),$w['id'],$amt,ref()]);
        db()->commit();
        ok(['amount'=>$amt,'new_balance'=>(float)$w['balance']-$amt,'vault_balance'=>(float)$w['vault_balance']+$amt],'Depose dans le coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur depot',500); }
}

function vault_withdraw() {
    $pl = auth(); $b = body();
    $amt = (float)($b['amount']??0); $pin = trim($b['pin']??'');
    if($amt<=0) fail('Montant invalide');
    if(!preg_match('/^\d{6}$/',$pin)) fail('PIN invalide');
    $user = q("SELECT pin_hash FROM users WHERE id=$1",[$pl['sub']])->fetch();
    if(!password_verify($pin,$user['pin_hash'])) fail('PIN incorrect',401);
    $w = q("SELECT * FROM wallets WHERE user_id=$1",[$pl['sub']])->fetch();
    if($w['vault_locked'] && strtotime($w['vault_lock_date']??'0')>time())
        fail("Coffre verrouille jusqu'au ".date('d/m/Y',strtotime($w['vault_lock_date'])));
    if((float)$w['vault_balance']<$amt) fail('Solde coffre insuffisant');
    db()->beginTransaction();
    try {
        q("UPDATE wallets SET vault_balance=vault_balance-$1,balance=balance+$1,vault_locked=0 WHERE id=$2",[$amt,$w['id']]);
        q("INSERT INTO transactions (id,receiver_wallet_id,amount,type,status,reference,description) VALUES ($1,$2,$3,'vault_withdrawal','completed',$4,'Retrait coffre')",[uid(),$w['id'],$amt,ref()]);
        db()->commit();
        ok(['amount'=>$amt,'new_balance'=>(float)$w['balance']+$amt,'vault_balance'=>(float)$w['vault_balance']-$amt],'Retire du coffre');
    } catch(Exception $e) { db()->rollBack(); fail('Erreur retrait',500); }
}

function vault_lock() {
    $pl = auth(); $b = body();
    $date = trim($b['lock_date']??'');
    if(!$date || strtotime($date)<=time()) fail('Date invalide');
    q("UPDATE wallets SET vault_locked=1,vault_lock_date=$1 WHERE user_id=$2",[$date,$pl['sub']]);
    ok(['lock_date'=>$date],'Coffre verrouille');
}

function wallet_renew_qr() {
    $pl = auth();
    $seed = strtoupper(bin2hex(random_bytes(5)));
    q("UPDATE wallets SET qr_seed=$1,qr_renewed_at=NOW() WHERE user_id=$2",[$seed,$pl['sub']]);
    ok(['qr_seed'=>$seed],'QR renouvele');
}

function wallet_resolve_qr() {
    $pl = auth();
    $qr = $_GET['qr'] ?? '';
    if(!$qr) fail('QR requis');
    $parts = explode('|',$qr);
    if(count($parts)<2) fail('QR invalide');
    $u = q("SELECT u.full_name,u.phone_number FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.id=$1 AND w.qr_seed=$2",[$parts[0],$parts[1]])->fetch();
    if(!$u) fail('QR invalide',404);
    if($parts[0]===$pl['sub']) fail('Vous ne pouvez pas vous scanner vous-meme');
    ok($u,'Destinataire trouve');
}

function wallet_stats() {
    $pl = auth();
    $wid = q("SELECT id FROM wallets WHERE user_id=$1",[$pl['sub']])->fetchColumn();
    $stats = q("SELECT
        SUM(CASE WHEN receiver_wallet_id=$1 AND status='completed' THEN amount ELSE 0 END) as total_in,
        SUM(CASE WHEN sender_wallet_id=$2 AND status='completed' THEN amount ELSE 0 END) as total_out,
        COUNT(CASE WHEN (sender_wallet_id=$3 OR receiver_wallet_id=$4) AND status='completed' THEN 1 END) as tx_count,
        COUNT(CASE WHEN sender_wallet_id=$5 AND status='cancelled' THEN 1 END) as cancelled
        FROM transactions WHERE EXTRACT(MONTH FROM created_at)=EXTRACT(MONTH FROM NOW())
        AND (sender_wallet_id=$6 OR receiver_wallet_id=$7)",
        [$wid,$wid,$wid,$wid,$wid,$wid,$wid])->fetch();
    ok($stats);
}

// TRANSACTIONS
function route_tx($action) {
    match($action) {
        'send'    => tx_send(),
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
    $to  = trim($b['receiver_phone']??'');
    $amt = (float)($b['amount']??0);
    $pin = trim($b['pin']??'');
    $desc= trim($b['description']??'');
    if(!preg_match('/^\+?[0-9]{8,15}$/',preg_replace('/[\s\-]/','', $to))) fail('Numero invalide');
    if($amt<=0) fail('Montant invalide');
    if(!preg_match('/^\d{6}$/',$pin)) fail('PIN invalide');
    $user = q("SELECT pin_hash FROM users WHERE id=$1",[$pl['sub']])->fetch();
    if(!password_verify($pin,$user['pin_hash'])) fail('PIN incorrect',401);
    $sw = q("SELECT * FROM wallets WHERE user_id=$1",[$pl['sub']])->fetch();
    if((float)$sw['balance']<$amt) fail('Solde insuffisant');
    $recv = q("SELECT u.id,u.full_name,w.id wid FROM users u JOIN wallets w ON w.user_id=u.id WHERE u.phone_number=$1",[$to])->fetch();
    if(!$recv) fail('Destinataire introuvable');
    if($recv['id']===$pl['sub']) fail('Envoi a soi-meme impossible');
    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_wallet_id,receiver_wallet_id,amount,type,status,reference,description,cancel_deadline) VALUES ($1,$2,$3,$4,'transfer','pending',$5,$6,$7)",
          [$txid,$sw['id'],$recv['wid'],$amt,$reference,$desc?:null,$deadline]);
        $rows = q("UPDATE wallets SET balance=balance-$1 WHERE id=$2 AND balance>=$1",[$amt,$sw['id']])->rowCount();
        if(!$rows) throw new Exception('Solde insuffisant');
        q("UPDATE wallets SET balance=balance+$1 WHERE id=$2",[$amt,$recv['wid']]);
        q("UPDATE transactions SET status='completed' WHERE id=$1",[$txid]);
        db()->commit();
        ok(['transaction_id'=>$txid,'reference'=>$reference,'amount'=>$amt,
            'receiver_name'=>$recv['full_name'],'cancel_before'=>$deadline,
            'new_balance'=>(float)$sw['balance']-$amt],'Transfert effectue');
    } catch(Exception $e) { db()->rollBack(); fail(APP_DEBUG?$e->getMessage():'Echec transfert',500); }
}

function tx_pay() {
    $pl = auth(); $b = body();
    $code = trim($b['merchant_code']??'');
    $amt  = (float)($b['amount']??0);
    $pin  = trim($b['pin']??'');
    if(!$code) fail('Code marchand requis');
    if($amt<=0) fail('Montant invalide');
    if(!preg_match('/^\d{6}$/',$pin)) fail('PIN invalide');
    $user = q("SELECT pin_hash FROM users WHERE id=$1",[$pl['sub']])->fetch();
    if(!password_verify($pin,$user['pin_hash'])) fail('PIN incorrect',401);
    $w = q("SELECT * FROM wallets WHERE user_id=$1",[$pl['sub']])->fetch();
    if((float)$w['balance']<$amt) fail('Solde insuffisant');
    $deadline = date('Y-m-d H:i:s', time()+CANCEL_MINS*60);
    db()->beginTransaction();
    try {
        $txid = uid(); $reference = ref();
        q("INSERT INTO transactions (id,sender_wallet_id,amount,type,status,reference,description,cancel_deadline) VALUES ($1,$2,$3,'payment','pending',$4,$5,$6)",
          [$txid,$w['id'],$amt,$reference,"Paiement: $code",$deadline]);
        q("UPDATE wallets SET balance=balance-$1 WHERE id=$2",[$amt,$w['id']]);
        q("UPDATE transactions SET status='completed' WHERE id=$1",[$txid]);
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
    $user = q("SELECT pin_hash FROM users WHERE id=$1",[$pl['sub']])->fetch();
    if(!password_verify($pin,$user['pin_hash'])) fail('PIN incorrect',401);
    $tx = q("SELECT t.*,w.user_id sender_uid FROM transactions t JOIN wallets w ON t.sender_wallet_id=w.id WHERE t.id=$1",[$txid])->fetch();
    if(!$tx) fail('Transaction introuvable',404);
    if($tx['sender_uid']!==$pl['sub']) fail('Non autorise',403);
    if($tx['status']!=='completed') fail('Transaction non annulable');
    if($tx['cancelled_at']) fail('Deja annulee');
    if(strtotime($tx['cancel_deadline']??'0')<time()) fail('Delai annulation depasse');
    db()->beginTransaction();
    try {
        q("UPDATE wallets SET balance=balance+$1 WHERE id=$2",[$tx['amount'],$tx['sender_wallet_id']]);
        if($tx['type']==='transfer' && $tx['receiver_wallet_id'])
            q("UPDATE wallets SET balance=balance-$1 WHERE id=$2",[$tx['amount'],$tx['receiver_wallet_id']]);
        q("UPDATE transactions SET status='cancelled',cancelled_at=NOW(),cancel_reason='user_request' WHERE id=$1",[$txid]);
        db()->commit();
        $bal = (float)q("SELECT balance FROM wallets WHERE id=$1",[$tx['sender_wallet_id']])->fetchColumn();
        ok(['refunded'=>(float)$tx['amount'],'new_balance'=>$bal],'Transaction annulee');
    } catch(Exception $e) { db()->rollBack(); fail('Echec annulation',500); }
}

function tx_history() {
    $pl  = auth();
    $page = max(1,(int)($_GET['page']??1));
    $lim  = min(50,max(5,(int)($_GET['limit']??20)));
    $fil  = $_GET['filter']??'all';
    $off  = ($page-1)*$lim;
    $wid = q("SELECT id FROM wallets WHERE user_id=$1",[$pl['sub']])->fetchColumn();
    $where = "WHERE (t.sender_wallet_id=$1 OR t.receiver_wallet_id=$2)";
    $params = [$wid,$wid];
    if($fil==='credit'){$where.=" AND t.receiver_wallet_id=$3 AND t.status='completed'";$params[]=$wid;}
    elseif($fil==='debit'){$where.=" AND t.sender_wallet_id=$3 AND t.status='completed'";$params[]=$wid;}
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
    $wid = q("SELECT id FROM wallets WHERE user_id=$1",[$pl['sub']])->fetchColumn();
    $tx = q("SELECT t.*,
        CASE WHEN t.sender_wallet_id='$wid' THEN 'debit' ELSE 'credit' END direction,
        su.full_name sender_name, ru.full_name receiver_name
        FROM transactions t
        LEFT JOIN wallets sw ON t.sender_wallet_id=sw.id LEFT JOIN users su ON sw.user_id=su.id
        LEFT JOIN wallets rw ON t.receiver_wallet_id=rw.id LEFT JOIN users ru ON rw.user_id=ru.id
        WHERE t.id=$1 AND (t.sender_wallet_id='$wid' OR t.receiver_wallet_id='$wid')",[$id])->fetch();
    if(!$tx) fail('Transaction introuvable',404);
    $tx['can_cancel'] = $tx['status']==='completed' && $tx['direction']==='debit'
        && !$tx['cancelled_at'] && strtotime($tx['cancel_deadline']??'0')>time();
    ok($tx);
}

function tx_resolve() {
    $pl = auth();
    $phone = $_GET['phone']??'';
    if(!preg_match('/^\+?[0-9]{8,15}$/',preg_replace('/[\s\-]/','', $phone))) fail('Numero invalide');
    $u = q("SELECT full_name,phone_number,is_kyc FROM users WHERE phone_number=$1 AND id!=$2",[$phone,$pl['sub']])->fetch();
    if(!$u) fail('Aucun compte trouve',404);
    ok($u,'Compte trouve');
}

// PROFILE
function route_profile($action) {
    match($action) {
        'get'           => profile_get(),
        'update'        => profile_update(),
        'notifications' => profile_notif(),
        'toggle-bio'    => profile_bio(),
        default         => fail('Action inconnue',404)
    };
}

function profile_get() {
    $pl = auth();
    $u = q("SELECT u.id,u.full_name,u.phone_number,u.email,u.operator,u.bio_enabled,u.is_kyc,u.status,u.created_at,w.id wid FROM users u LEFT JOIN wallets w ON w.user_id=u.id WHERE u.id=$1",[$pl['sub']])->fetch();
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
    $notifs = q("SELECT * FROM notifications WHERE user_id=$1 ORDER BY sent_at DESC LIMIT 20",[$pl['sub']])->fetchAll();
    $unread = (int)q("SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND is_read=0",[$pl['sub']])->fetchColumn();
    ok(['notifications'=>$notifs,'unread'=>$unread]);
}

function profile_bio() {
    $pl = auth(); $b = body();
    $ena = (int)(bool)($b['enabled']??false);
    q("UPDATE users SET bio_enabled=$1 WHERE id=$2",[$ena,$pl['sub']]);
    ok(['bio_enabled'=>(bool)$ena]);
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
