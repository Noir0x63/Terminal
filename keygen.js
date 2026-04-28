const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');

function askPassphrase(prompt) {
    return new Promise((resolve) => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        rl.question(prompt, (answer) => {
            rl.close();
            resolve(answer);
        });
    });
}

function encryptPrivateKey(pemString, passphrase) {
    const salt = crypto.randomBytes(32);
    const key = crypto.scryptSync(passphrase, salt, 32, { N: 131072, r: 8, p: 1 });
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(pemString, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    const envelope = {
        version: 2,
        kdf: 'scrypt',
        kdfParams: { N: 131072, r: 8, p: 1 },
        salt: salt.toString('hex'),
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        ciphertext: encrypted.toString('hex')
    };
    return JSON.stringify(envelope, null, 2);
}

async function main() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║     ZTAP KEYGEN — RSA-4096 + ENCRYPTED-AT-REST             ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log('');

    const passphrase = await askPassphrase('[KEYGEN] Ingresa la passphrase maestra para cifrar la clave privada: ');
    if (!passphrase || passphrase.length < 12) {
        console.error('[KEYGEN] ERROR: La passphrase debe tener al menos 12 caracteres.');
        process.exit(1);
    }
    const confirm = await askPassphrase('[KEYGEN] Confirma la passphrase: ');
    if (passphrase !== confirm) {
        console.error('[KEYGEN] ERROR: Las passphrases no coinciden.');
        process.exit(1);
    }

    console.log('[KEYGEN] Generando par de llaves RSA-4096...');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    fs.writeFileSync('master_public.pem', publicKey);

    console.log('[KEYGEN] Cifrando clave privada con scrypt + AES-256-GCM...');
    const encryptedBlob = encryptPrivateKey(privateKey, passphrase);
    fs.writeFileSync('master_private.enc', encryptedBlob);

    // Derive and store the admin HMAC secret from the passphrase deterministically
    // This eliminates admin_token.txt entirely (CRÍTICO 2)
    const adminSalt = crypto.randomBytes(32);
    const adminSecret = crypto.scryptSync(passphrase, Buffer.concat([adminSalt, Buffer.from('ztap:admin:hmac')]), 32, { N: 131072, r: 8, p: 1 });
    const serverNonce = crypto.randomBytes(32);
    const secretsEnvelope = {
        version: 2,
        adminSalt: adminSalt.toString('hex'),
        adminSecret: adminSecret.toString('hex'),
        serverNonce: serverNonce.toString('hex')
    };
    fs.writeFileSync('server_secrets.enc', JSON.stringify(secretsEnvelope, null, 2));

    console.log('');
    console.log('[KEYGEN] ✓ master_public.pem         — Clave pública (distribución segura)');
    console.log('[KEYGEN] ✓ master_private.enc         — Clave privada cifrada (AES-256-GCM + scrypt)');
    console.log('[KEYGEN] ✓ server_secrets.enc         — Secretos del servidor derivados');
    console.log('[KEYGEN] ✗ master_private.pem         — NO generada (nunca en disco plano)');
    console.log('[KEYGEN] ✗ admin_token.txt            — ELIMINADO (derivado de passphrase)');
    console.log('');
    console.log('[KEYGEN] ADVERTENCIA: Memoriza la passphrase. No hay recuperación sin ella.');
}

main().catch(e => { console.error(e); process.exit(1); });
