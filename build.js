const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const JavaScriptObfuscator = require('javascript-obfuscator');

console.log('Iniciando build.js v2.2 (IRONCLAD v3)...');

const adminToken = crypto.randomBytes(32).toString('hex');
fs.writeFileSync('admin_token.txt', adminToken);
console.log('[BUILD] HMAC master secret guardado en admin_token.txt');

const dayNonce = String(Math.floor(Date.now() / 86400000));
const hourlyNonce = String(Math.floor(Date.now() / 3600000));
const todayAdminPath = crypto.createHmac('sha256', adminToken)
    .update(dayNonce + ':' + hourlyNonce)
    .digest('hex');
const minutesLeft = Math.ceil((3600000 - (Date.now() % 3600000)) / 60000);

const masterPublicPem = fs.readFileSync('master_public.pem', 'utf8').trim();
const pemContents = masterPublicPem
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .trim();

const obfuscationOptions = {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.8,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.4,
    identifierNamesGenerator: 'hexadecimal',
    numbersToExpressions: true,
    splitStrings: true,
    splitStringsChunkLength: 5,
    stringArray: true,
    stringArrayEncoding: ['base64'],
    stringArrayThreshold: 0.8,
    unicodeEscapeSequence: false
};

console.log('[BUILD] Procesando ztap-worker.js...');
const workerRaw = fs.readFileSync('src/ztap-worker.js', 'utf8');
const workerObfuscated = JavaScriptObfuscator.obfuscate(workerRaw, obfuscationOptions).getObfuscatedCode();
const goldHash = crypto.createHash('sha512').update(workerObfuscated).digest('hex');

console.log('[BUILD] Inyectando GOLD_HASH y Master Key en client.js...');
const clientJsRaw = fs.readFileSync('src/client.js', 'utf8');
const clientJsInjected = clientJsRaw
    .replace('INJECT_MASTER_PUBLIC_KEY', pemContents)
    .replace("expectedHash: ''", `expectedHash: '${goldHash}'`);

console.log('[BUILD] Ofuscando client.js...');
const clientObfuscated = JavaScriptObfuscator.obfuscate(clientJsInjected, obfuscationOptions).getObfuscatedCode();

console.log('[BUILD] Ofuscando admin-client.js...');
const adminClientRaw = fs.readFileSync('src/admin-client.js', 'utf8');
const adminClientObfuscated = JavaScriptObfuscator.obfuscate(adminClientRaw, obfuscationOptions).getObfuscatedCode();

fs.mkdirSync('public', { recursive: true });
fs.writeFileSync('public/ztap-worker.js', workerObfuscated);
fs.writeFileSync('public/client.js', clientObfuscated);
fs.writeFileSync('public/admin-client.js', adminClientObfuscated);
fs.copyFileSync('src/index.html', 'public/index.html');
fs.copyFileSync('src/admin.html', 'public/admin.html');
fs.writeFileSync('public/GOLD_HASH.txt', goldHash);

console.log('');
console.log('══════════════════════════════════════════════════════════════════');
console.log('  BUILD COMPLETADO — SISTEMA IRONCLAD v2.2 (SESSION-GOVERNED)');
console.log('══════════════════════════════════════════════════════════════════');
console.log('');
console.log('  [ADMIN] Ruta dinámica (hourly rotation):');
console.log(`  /${todayAdminPath}`);
console.log('  (Expira en ' + minutesLeft + ' min)');
console.log('');
console.log('  [HARDENING] Características de Seguridad Activas:');
console.log('  1. Handshake Timeout: 20s (Optimizado para Tor).');
console.log('  2. Session Governance: Basado en IDs únicos, no en usernames.');
console.log('  3. Anti-Replay INIT: Validación de timestamp y secuencia.');
console.log('  4. Worker Integrity: GOLD_HASH inyectado y verificado.');
console.log('  5. Memory Leak Guard: Handshakes atómicos por socket.');
console.log('');
console.log('  GOLD_HASH: ' + goldHash.slice(0, 32) + '...');
console.log('══════════════════════════════════════════════════════════════════');
console.log('');
