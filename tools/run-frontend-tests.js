#!/usr/bin/env node
// Suite de tests "smoke" pour la logique frontend pure (pas de reseau, pas de
// DOM reel) : execute les <script> de chaque fichier dans un sandbox VM minimal,
// puis verifie des invariants qui ont deja casse par le passe dans ce projet :
//   - completude i18n (chaque cle I18N a un fr ET un en non vides — une chaine
//     vide est traitee comme "manquante" par t()/at() et retombe sur la cle brute)
//   - absence de cles I18N dupliquees (un objet JS garde silencieusement la
//     derniere definition, aucune erreur ne signale l'ecrasement)
//   - logique metier de txCatKey/canAnn/txCatLabel (index.html) : le champ
//     catKey pilote canAnn() independamment du texte affichable, avec repli
//     sur l'ancien mapping texte->cle pour les transactions deja en cache
//
// Usage : node tools/run-frontend-tests.js
// Sortie : code 0 si tout passe, 1 sinon.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const FILES = [
  { rel: 'index.html', abs: path.join(__dirname, '..', 'index.html') },
  { rel: 'ROM_BUSINESS/index.html', abs: path.join(__dirname, '..', 'ROM_BUSINESS', 'index.html') },
  { rel: 'ROM_GUICHET/index.html', abs: path.join(__dirname, '..', 'ROM_GUICHET', 'index.html') },
];

let totalPass = 0, totalFail = 0;
function check(label, ok, detail) {
  if (ok) { totalPass++; }
  else { totalFail++; console.log('FAIL - ' + label + (detail ? ' :: ' + detail : '')); }
}

function extractScripts(html) {
  return [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]).join('\n');
}

function makeSandbox() {
  const sandbox = {
    console,
    document: {
      addEventListener: () => {},
      querySelectorAll: () => [],
      getElementById: () => null,
      createElement: () => ({ style: {}, classList: { add() {}, remove() {} } }),
      body: { classList: { add() {}, remove() {} } },
    },
    navigator: { language: 'fr', onLine: true, serviceWorker: { register: () => Promise.resolve() } },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    location: { href: '', search: '', pathname: '/' },
    history: { pushState() {}, replaceState() {} },
    setTimeout, clearTimeout, setInterval, clearInterval,
    Date, Math, JSON, Promise, Number, String, Array, Object,
    fetch: () => Promise.resolve({ json: () => Promise.resolve({}) }),
    addEventListener: () => {},
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  vm.createContext(sandbox);
  return sandbox;
}

function findDuplicateI18nKeys(rawSrc) {
  const re = /^\s*([A-Za-z0-9_]+):\s*\{fr:/gm;
  const seen = {};
  let m;
  while ((m = re.exec(rawSrc))) {
    seen[m[1]] = (seen[m[1]] || 0) + 1;
  }
  return Object.keys(seen).filter((k) => seen[k] > 1);
}

for (const { rel, abs } of FILES) {
  if (!fs.existsSync(abs)) continue;
  console.log(`\n=== ${rel} ===`);
  const html = fs.readFileSync(abs, 'utf8');
  const src = extractScripts(html);
  const sandbox = makeSandbox();

  try {
    vm.runInContext(src, sandbox, { timeout: 5000 });
  } catch (e) {
    check(`${rel}: script executes without throwing`, false, e.message);
    continue;
  }
  check(`${rel}: script executes without throwing`, true);

  // --- i18n completeness ---
  const i18n = sandbox.I18N;
  if (!i18n || typeof i18n !== 'object') {
    check(`${rel}: I18N object present`, false);
  } else {
    check(`${rel}: I18N object present`, true);
    let missing = [];
    Object.keys(i18n).forEach((key) => {
      const entry = i18n[key];
      if (!entry || !entry.fr || !entry.en) missing.push(key);
    });
    check(`${rel}: all I18N keys have non-empty fr+en (${Object.keys(i18n).length} keys)`, missing.length === 0, missing.slice(0, 10).join(', '));
  }

  // --- duplicate I18N key definitions (textual, since JS silently collapses them) ---
  const dupes = findDuplicateI18nKeys(src);
  check(`${rel}: no duplicate I18N key definitions`, dupes.length === 0, dupes.join(', '));

  // --- index.html-specific business logic ---
  if (rel === 'index.html') {
    const { txCatKey, canAnn, txCatLabel, APP } = sandbox;
    if (typeof txCatKey !== 'function' || typeof canAnn !== 'function' || typeof txCatLabel !== 'function') {
      check('index.html: txCatKey/canAnn/txCatLabel defined', false);
    } else {
      check('index.html: txCatKey/canAnn/txCatLabel defined', true);

      check('txCatKey: catKey present takes priority', txCatKey({ cat: 'Marchand', catKey: 'merchant_payment' }) === 'merchant_payment');
      check('txCatKey: legacy fallback (QR)', txCatKey({ cat: 'QR' }) === 'qr');
      check('txCatKey: legacy fallback (Encaissement)', txCatKey({ cat: 'Encaissement' }) === 'collect');
      check('txCatKey: unknown cat falls back to other', txCatKey({ cat: 'Salaire' }) === 'other');

      const now = Date.now();
      check('canAnn: blocks merchant_payment via catKey', canAnn({ type: 'debit', ts: now, catKey: 'merchant_payment', cat: 'Marchand' }) === false);
      check('canAnn: blocks QR via legacy cat only', canAnn({ type: 'debit', ts: now, cat: 'QR' }) === false);
      check('canAnn: blocks Encaissement via legacy cat only', canAnn({ type: 'debit', ts: now, cat: 'Encaissement' }) === false);
      check('canAnn: allows transfer via catKey', canAnn({ type: 'debit', ts: now, catKey: 'transfer', cat: 'Transfert' }) === true);
      check('canAnn: allows transfer via legacy cat only', canAnn({ type: 'debit', ts: now, cat: 'Transfert' }) === true);
      check('canAnn: false for credit transactions', canAnn({ type: 'credit', ts: now, catKey: 'transfer' }) === false);

      APP.lang = 'fr';
      check('txCatLabel: fr transfer sent', txCatLabel({ catKey: 'transfer' }, false) === 'Transfert envoyé');
      APP.lang = 'en';
      check('txCatLabel: en transfer sent', txCatLabel({ catKey: 'transfer' }, false) === 'Transfer sent');
      check('txCatLabel: en transfer_africa received', txCatLabel({ catKey: 'transfer_africa' }, true) === 'Africa Transfer received');
      check('txCatLabel: en legacy cat without catKey', txCatLabel({ cat: 'Depot banque' }, false) === 'Bank deposit');
      check('txCatLabel: unknown falls back to raw cat text', txCatLabel({ cat: 'Salaire' }, false) === 'Salaire');
    }
  }
}

console.log(`\n${totalPass} passed, ${totalFail} failed.`);
process.exit(totalFail > 0 ? 1 : 0);
