let localKey = null;
let adminPublicKey = null;
let attestHmacKey = null;
let initResolver;
const initPromise = new Promise(resolve => { initResolver = resolve; });

let sendCounter = 0;
let receiveCounter = 0;

function secureBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBuffer(b64) {
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
}

async function verifyIntegrity(expectedHash) {
    if (!expectedHash) return;
    try {
        const response = await fetch(self.location.href, { cache: 'no-store' });
        const code = await response.text();
        const hashBuffer = await crypto.subtle.digest('SHA-512', new TextEncoder().encode(code));
        const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        if (hashHex !== expectedHash) throw new Error('INTEGRITY_FAIL');
    } catch (e) { if (e.message === 'INTEGRITY_FAIL') throw new Error('SEC_FAULT_0x0'); }
}

async function deriveKey(token, salt) {
    const enc = new TextEncoder();
    const tokenBuf = enc.encode(token);
    const saltBuf = enc.encode(salt);
    const base = await crypto.subtle.importKey('raw', tokenBuf, 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBuf, iterations: 600000, hash: 'SHA-256' },
        base,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function deriveAttestKey(token, salt) {
    const enc = new TextEncoder();
    const saltBuf = enc.encode(salt + ":attest");
    const base = await crypto.subtle.importKey('raw', enc.encode(token), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBuf, iterations: 100000, hash: 'SHA-256' },
        base,
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign']
    );
}

async function aesGcmEncrypt(key, plaintext) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    const result = new Uint8Array(12 + ciphertext.byteLength);
    result.set(iv, 0); result.set(new Uint8Array(ciphertext), 12);
    return result;
}

async function aesGcmDecrypt(key, encryptedData) {
    const iv = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext));
}

async function solvePoW(challenge, difficulty) {
    let nonce = 0;
    const enc = new TextEncoder();
    while (true) {
        const candidate = nonce.toString(16) + challenge;
        const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(candidate));
        const hash = new Uint8Array(hashBuf);
        let zeroBits = 0;
        let solved = false;
        for (const byte of hash) {
            if (byte === 0) { zeroBits += 8; }
            else {
                let b = byte;
                while ((b & 0x80) === 0) { zeroBits++; b <<= 1; }
                break;
            }
            if (zeroBits >= difficulty) { solved = true; break; }
        }
        if (solved) return nonce.toString(16);
        nonce++;
        if (nonce % 2000 === 0) await new Promise(r => setTimeout(r, 0));
    }
}

self.onmessage = async (e) => {
    const d = e.data;
    try {
        if (d.type === 'INIT') {
            await verifyIntegrity(d.expectedHash);
            localKey = await deriveKey(d.token, d.username);
            attestHmacKey = await deriveAttestKey(d.token, d.username);

            const pemContents = d.masterPublicPem.replace(/-----(BEGIN|END) PUBLIC KEY-----|\s/g, '');
            const binaryDer = base64ToBuffer(pemContents);
            adminPublicKey = await crypto.subtle.importKey('spki', binaryDer, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);

            const enc = new TextEncoder();
            const initPayloadBuf = enc.encode(JSON.stringify({ token: d.token, username: d.username, ts: Date.now() }));
            const encInit = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, adminPublicKey, initPayloadBuf);
            
            initResolver();
            self.postMessage({ type: 'INITIALIZED', payload: secureBufferToBase64(encInit) });
            return;
        }

        if (d.type === 'ATTEST_CHALLENGE') {
            await initPromise;
            const challengeBuf = new TextEncoder().encode(d.challenge);
            const sig = await crypto.subtle.sign('HMAC', attestHmacKey, challengeBuf);
            self.postMessage({ type: 'ATTEST_RESPONSE', signature: secureBufferToBase64(sig), challenge: d.challenge });
            return;
        }

        if (d.type === 'SOLVE_POW') {
            const nonce = await solvePoW(d.challenge, d.difficulty);
            self.postMessage({ type: 'POW_SOLVED', nonce, challenge: d.challenge });
            return;
        }

        await initPromise;

        if (d.type === 'ENCRYPT_MSG') {
            const enc = new TextEncoder();
            sendCounter++;
            const payloadWithCounter = JSON.stringify({ p: d.payload, c: sendCounter, t: Date.now() });
            const encData = await aesGcmEncrypt(localKey, enc.encode(payloadWithCounter));
            self.postMessage({ type: 'ENCRYPT_VAULT_RESULT', payload: secureBufferToBase64(encData), msgId: d.msgId });

        } else if (d.type === 'DECRYPT_MSG') {
            const decBuf = await aesGcmDecrypt(localKey, new Uint8Array(d.payload));
            const decodedObj = JSON.parse(new TextDecoder().decode(decBuf));
            if (decodedObj.c <= receiveCounter) throw new Error('REPLAY');
            receiveCounter = decodedObj.c;
            self.postMessage({ type: 'DECRYPT_MSG_RESULT', payload: decodedObj.p, msgId: d.msgId });

        } else if (d.type === 'DECRYPT_FILE_CHUNK') {
            const decBuf = await aesGcmDecrypt(localKey, new Uint8Array(d.payload));
            self.postMessage({ type: 'DECRYPT_FILE_CHUNK_RESULT', chunkIndex: d.chunkIndex, totalChunks: d.totalChunks, filename: d.filename, payload: decBuf.buffer }, [decBuf.buffer]);
        }
    } catch (err) { self.postMessage({ type: 'ERROR', error: 'SEC_FAULT_0x1' }); }
};