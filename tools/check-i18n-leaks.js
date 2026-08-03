#!/usr/bin/env node
// Garde-fou anti-regression i18n.
//
// Detecte les textes utilisateur probablement non traduits (toast/alert/confirm
// avec chaine brute, ou innerHTML contenant du francais accentue sans passer par
// t()/at()) dans index.html (ROM_MONEY + admin) et ROM_BUSINESS/index.html.
//
// Usage : node tools/check-i18n-leaks.js
// Sortie : liste des lignes suspectes, groupees par fichier. Code de sortie 1
// si des toast()/alert()/confirm() a chaine brute sont trouves (haute confiance),
// 0 sinon (les innerHTML suspects sont juste des avertissements a verifier).

const fs = require('fs');
const path = require('path');

const FILES = [
  path.join(__dirname, '..', 'index.html'),
  path.join(__dirname, '..', 'ROM_BUSINESS', 'index.html'),
];

const ACCENTED = /[àâäéèêëîïôöùûüçÀÂÄÉÈÊËÎÏÔÖÙÛÜÇ]/;

// Faux positifs connus et acceptes : noms de pays (jamais traduits, ex.
// "Côte d'Ivoire" en valeur par defaut d'un <select>), et le libelle de secours
// copyID() qui ne s'affiche que si l'API Clipboard est indisponible (rare,
// "ID" se lit pareil en fr/en).
const ALLOWLIST = [
  /<option value="Côte d\\'Ivoire">/,
  /toast\('ID: '\+APP\.userID\)/,
];

function extractScripts(html) {
  const scripts = [];
  const re = /<script>([\s\S]*?)<\/script>/g;
  let m;
  while ((m = re.exec(html))) {
    const startLine = html.slice(0, m.index).split('\n').length;
    scripts.push({ code: m[1], startLine });
  }
  return scripts;
}

function checkFile(filePath) {
  const html = fs.readFileSync(filePath, 'utf8');
  const rel = path.relative(process.cwd(), filePath);
  const highConfidence = [];
  const warnings = [];

  for (const { code, startLine } of extractScripts(html)) {
    const lines = code.split('\n');
    lines.forEach((line, i) => {
      const lineNo = startLine + i;
      if (ALLOWLIST.some((re) => re.test(line))) return;

      // Haute confiance : toast('...')/alert('...')/confirm('...') avec chaine
      // litterale en premier argument (au lieu de t(...)/at(...)/une variable).
      const dlgMatch = line.match(/\b(toast|alert|confirm)\(\s*(['"])/);
      if (dlgMatch) {
        highConfidence.push({ lineNo, line: line.trim() });
        return;
      }

      // Avertissement : assignation innerHTML/textContent contenant du texte
      // accentue, sans aucun appel t(...)/at(...) sur la ligne. Heuristique
      // best-effort : a verifier manuellement, faux positifs possibles.
      if (/\.(innerHTML|textContent)\s*(\+?=)/.test(line) && ACCENTED.test(line)) {
        if (!/\bt\(|\bat\(/.test(line)) {
          warnings.push({ lineNo, line: line.trim() });
        }
      }
    });
  }

  return { rel, highConfidence, warnings };
}

let anyHighConfidence = false;

for (const filePath of FILES) {
  if (!fs.existsSync(filePath)) continue;
  const { rel, highConfidence, warnings } = checkFile(filePath);

  if (highConfidence.length) {
    anyHighConfidence = true;
    console.log(`\n${rel} — chaines brutes dans toast()/alert()/confirm() (${highConfidence.length}) :`);
    highConfidence.forEach(({ lineNo, line }) => console.log(`  L${lineNo}: ${line}`));
  }
  if (warnings.length) {
    console.log(`\n${rel} — innerHTML/textContent suspects a verifier (${warnings.length}) :`);
    warnings.forEach(({ lineNo, line }) => console.log(`  L${lineNo}: ${line}`));
  }
  if (!highConfidence.length && !warnings.length) {
    console.log(`\n${rel} — OK, aucun texte suspect detecte.`);
  }
}

console.log('');
process.exit(anyHighConfidence ? 1 : 0);
