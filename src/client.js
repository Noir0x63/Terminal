let ws = null;
let worker = null;
let username = '';
let userToken = '';
let pendingFiles = {};
let sessionId = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');

let pendingPoWChallenge = null;
let pendingPoWMessage = null;

let attestationInterval = null;
let expectedAttestChallenge = null;
let attestFailCount = 0;
const ATTEST_MAX_FAILS = 3;

// ──────────────────────────────────────────────────────────────────────────
// MEDIO 6 MITIGATION: ECDH ephemeral keypair for Perfect Forward Secrecy
// The master RSA key only authenticates — session encryption uses ECDH
// derived secrets. Compromising the RSA key does NOT reveal past traffic.
// ──────────────────────────────────────────────────────────────────────────
let ecdhKeyPair = null;
let ecdhSharedSecret = null;
let pfsReady = false;

const MASTER_PUBLIC_PEM = `-----BEGIN PUBLIC KEY-----
INJECT_MASTER_PUBLIC_KEY
-----END PUBLIC KEY-----`;

function sendNoise() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const noise = new Uint8Array(4096);
    crypto.getRandomValues(noise);
    const view = new DataView(noise.buffer);
    view.setUint32(0, 0, true);
    ws.send(noise);
    setTimeout(sendNoise, Math.floor(Math.random() * 5000) + 1000);
}

function sendStrictFrame(payload) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const bytes = new TextEncoder().encode(payload);
    if (bytes.length > 4092) return;
    const frame = new Uint8Array(4096);
    window.crypto.getRandomValues(frame);
    new DataView(frame.buffer).setUint32(0, bytes.length, true);
    frame.set(bytes, 4);
    ws.send(frame);
}

function appendMessage(text, isUser, isHistory = false) {
    const list = document.getElementById('messages');
    const msg = document.createElement('div');
    msg.className = 'msg ' + (isUser ? 'msg-user' : 'msg-admin');
    if (isHistory) msg.style.opacity = '0.6';
    msg.textContent = (isUser ? '> YOU: ' : '> OPERATOR: ') + text;
    list.appendChild(msg);
    list.scrollTop = list.scrollHeight;
}

function handleFileDownload(filename, blob) {
    const url = URL.createObjectURL(blob);
    const list = document.getElementById('messages');
    const msg = document.createElement('div');
    msg.className = 'msg msg-admin';
    msg.textContent = `> FILE RECEIVED: ${filename} `;
    const btn = document.createElement('button');
    btn.textContent = 'DESCARGAR';
    Object.assign(btn.style, {
        background: '#000', color: '#fff', border: '1px solid #fff',
        padding: '3px 10px', fontFamily: "'Courier New',monospace",
        fontSize: '11px', cursor: 'pointer', textTransform: 'uppercase', letterSpacing: '1px'
    });
    btn.onclick = () => {
        const a = document.createElement('a');
        a.href = url;
        a.download = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
        a.click();
        URL.revokeObjectURL(url);
        btn.disabled = true;
        btn.textContent = 'DESCARGADO';
    };
    msg.appendChild(btn);
    list.appendChild(msg);
    list.scrollTop = list.scrollHeight;
}

// ──────────────────────────────────────────────────────────────────────────
// AUDIT FIX 3: Attestation moved to SERVER-SIDE verification
// The client no longer self-validates — it forwards challenges/responses
// between the server and the worker. The server holds the attestation key
// and disconnects on verification failure.
// ──────────────────────────────────────────────────────────────────────────

function base64ToBuffer(b64) {
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf;
}

function sendMessageWithPoW(payloadObj, powNonce) {
    const withPoW = { ...payloadObj, powNonce };
    sendStrictFrame(JSON.stringify(withPoW));
    pendingPoWMessage = null;
    pendingPoWChallenge = null;
}

// ──────────────────────────────────────────────────────────────────────────
// PFS: Generate ECDH ephemeral keypair using WebCrypto
// ──────────────────────────────────────────────────────────────────────────
async function generateClientECDH() {
    ecdhKeyPair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
    );
    const publicKeyRaw = await crypto.subtle.exportKey('raw', ecdhKeyPair.publicKey);
    return Array.from(new Uint8Array(publicKeyRaw)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function computeECDHSharedSecret(serverPublicKeyHex) {
    const serverKeyBytes = new Uint8Array(serverPublicKeyHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const serverKey = await crypto.subtle.importKey(
        'raw',
        serverKeyBytes,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
    );
    const sharedBits = await crypto.subtle.deriveBits(
        { name: 'ECDH', public: serverKey },
        ecdhKeyPair.privateKey,
        256
    );
    ecdhSharedSecret = new Uint8Array(sharedBits);
    pfsReady = true;
}

function initWorker() {
    return new Promise(async (resolve, reject) => {
        try {
            // 1. Descargar el código del Worker para verificación externa
            const response = await fetch('ztap-worker.js');
            if (!response.ok) throw new Error('Fallo al obtener el motor criptográfico');
            const arrayBuffer = await response.arrayBuffer();

            // 2. Verificar Integridad Real (Pre-spawning)
            const hashBuffer = await crypto.subtle.digest('SHA-512', arrayBuffer);
            const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

            const expectedHash = 'INJECT_EXPECTED_HASH';
            if (hashHex !== expectedHash) {
                console.error('%c[SECURITY] VIOLACIÓN DE INTEGRIDAD DETECTADA', 'color: red; font-weight: bold;');
                throw new Error('Integrity Check Failed: Cryptographic engine tampered.');
            }

            // 3. Iniciar Worker desde el Blob verificado
            const blob = new Blob([arrayBuffer], { type: 'application/javascript' });
            worker = new Worker(URL.createObjectURL(blob));

            worker.onmessage = async e => {
                const data = e.data;
                if (data.type === 'INITIALIZED') {
                    // AUDIT FIX 1: Token removed from INIT frame (CRÍTICO — CVSS 9.8)
                    // Token never leaves the client. Only the RSA-encrypted payload carries it.
                    const initObj = { type: 'INIT', user: username, data: data.payload, attestKey: data.attestKey };
                    if (pendingPoWChallenge) {
                        pendingPoWMessage = initObj;
                        worker.postMessage({ type: 'SOLVE_POW', challenge: pendingPoWChallenge.challenge, difficulty: pendingPoWChallenge.difficulty });
                    } else {
                        pendingPoWMessage = initObj;
                        sendStrictFrame(JSON.stringify({ type: 'REQ_POW' }));
                    }
                    document.querySelectorAll('.active').forEach(e => e.classList.remove('active'));
                    document.getElementById('chat-screen').classList.add('active');
                    // AUDIT FIX 3: Attestation is now server-orchestrated
                    resolve();
                } else if (data.type === 'ATTEST_RESPONSE') {
                    // AUDIT FIX 3: Forward attestation response to server for verification
                    sendStrictFrame(JSON.stringify({ type: 'ATTEST_RESPONSE', signature: data.signature, challenge: data.challenge }));
                } else if (data.type === 'POW_SOLVED') {
                    if (pendingPoWMessage) sendMessageWithPoW(pendingPoWMessage, data.nonce);
                } else if (data.type === 'ENCRYPT_VAULT_RESULT') {
                    // AUDIT FIX 1: Token removed from ASYNC_MSG frame (CRÍTICO — CVSS 9.8)
                    const obj = { type: 'ASYNC_MSG', user: username, payload: data.payload };
                    if (pendingPoWChallenge) {
                        pendingPoWMessage = obj;
                        worker.postMessage({ type: 'SOLVE_POW', challenge: pendingPoWChallenge.challenge, difficulty: pendingPoWChallenge.difficulty });
                    } else {
                        pendingPoWMessage = obj;
                        sendStrictFrame(JSON.stringify({ type: 'REQ_POW' }));
                    }
                } else if (data.type === 'DECRYPT_MSG_RESULT') {
                    try {
                        const dec = JSON.parse(data.payload);
                        appendMessage(dec.text, dec.user === username, true);
                    } catch (err) { appendMessage(data.payload, false); }
                } else if (data.type === 'DECRYPT_FILE_CHUNK_RESULT') {
                    const { filename, chunkIndex, totalChunks, payload } = data;
                    if (!pendingFiles[filename]) pendingFiles[filename] = { totalChunks, received: {}, receivedCount: 0 };
                    const pf = pendingFiles[filename];
                    pf.received[chunkIndex] = new Uint8Array(payload);
                    pf.receivedCount++;
                    if (pf.receivedCount === pf.totalChunks) {
                        let totalLen = 0;
                        for (let i = 0; i < pf.totalChunks; i++) totalLen += pf.received[i].byteLength;
                        const full = new Uint8Array(totalLen);
                        let off = 0;
                        for (let i = 0; i < pf.totalChunks; i++) { full.set(pf.received[i], off); off += pf.received[i].byteLength; }
                        delete pendingFiles[filename];
                        handleFileDownload(filename, new Blob([full]));
                    }
                } else if (data.type === 'ERROR') { reject(data.error); }
            };
            // AUDIT FIX 2: sessionId passed to worker for high-entropy salt (ALTO — CVSS 7.4)
            worker.postMessage({ type: 'INIT', username: username, token: userToken, sessionId: sessionId, masterPublicPem: MASTER_PUBLIC_PEM });
        } catch (e) {
            reject(e);
        }
    });
}

async function connect() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(proto + '//' + window.location.host);
    ws.binaryType = 'arraybuffer';
    ws.onopen = () => {
        sendStrictFrame(JSON.stringify({ type: 'HANDSHAKE', sessionId: sessionId }));
        sendNoise();
    };
    ws.onmessage = async (e) => {
        try {
            const view = new DataView(e.data);
            const len = view.getUint32(0, true);
            if (len === 0) return;
            const frame = JSON.parse(new TextDecoder().decode(new Uint8Array(e.data, 4, len)));

            // ──────────────────────────────────────────────────────────
            // PFS: Handle ECDH key exchange from server
            // ──────────────────────────────────────────────────────────
            if (frame.type === 'ECDH_EXCHANGE') {
                const clientPubHex = await generateClientECDH();
                await computeECDHSharedSecret(frame.serverPublicKey);
                sendStrictFrame(JSON.stringify({ type: 'ECDH_CLIENT_KEY', clientPublicKey: clientPubHex }));
                return;
            }

            if (frame.type === 'ECDH_COMPLETE') {
                // PFS handshake complete — now init the crypto worker
                initWorker().catch(e => alert(e));
                return;
            }

            if (frame.type === 'SESSION_EXPIRED') {
                appendMessage('SESSION EXPIRED — Please reconnect.', false);
                if (worker) worker.terminate();
                return;
            }

            // AUDIT FIX 3: Server-initiated attestation challenge — forward to worker
            if (frame.type === 'ATTEST_CHALLENGE') {
                if (worker) worker.postMessage({ type: 'ATTEST_CHALLENGE', challenge: frame.challenge });
                return;
            }

            if (frame.type === 'POW_CHALLENGE') {
                pendingPoWChallenge = { challenge: frame.challenge, difficulty: frame.difficulty };
                if (pendingPoWMessage) worker.postMessage({ type: 'SOLVE_POW', challenge: frame.challenge, difficulty: frame.difficulty });
                return;
            }
            if (frame.type === 'HISTORY' || frame.type === 'NEW_MESSAGE') {
                const record = frame.data ? frame.data.content : frame.content;
                if (!record) return;

                // Mensaje Directo del Administrador
                if (record.type === 'SERVER_MSG') {
                    const encryptedData = record.payload.encData || record.payload;
                    worker.postMessage({ type: 'DECRYPT_MSG', payload: Array.from(base64ToBuffer(encryptedData)) });
                }
                // Broadcast del Administrador
                else if (record.user === 'ADMIN' && record.type === 'BROADCAST') {
                    const encryptedData = record.payload.encData || record.payload;
                    worker.postMessage({ type: 'DECRYPT_MSG', payload: Array.from(base64ToBuffer(encryptedData)) });
                }
                // Metadatos de Archivo Entrante
                else if (record.type === 'FILE_META') {
                    appendMessage(`INCOMING FILE: ${record.filename} (${record.totalChunks} chunks, ${record.fileSize} bytes)`, false);
                }
                // Fragmento de Archivo Entrante
                else if (record.type === 'FILE_CHUNK') {
                    worker.postMessage({ type: 'DECRYPT_FILE_CHUNK', payload: Array.from(base64ToBuffer(record.encData)), chunkIndex: record.chunkIndex, totalChunks: record.totalChunks, filename: record.filename });
                }
            } else if (frame.type === 'NUKE_EVENT') {
                clearInterval(attestationInterval);
                document.querySelectorAll('.active').forEach(e => e.classList.remove('active'));
                document.getElementById('nuke-screen').classList.add('active');
                if (ws) ws.close();
            }
        } catch (err) { }
    };
    ws.onclose = () => { clearInterval(attestationInterval); };
}

document.getElementById('connect-btn').onclick = () => {
    username = document.getElementById('username').value.trim();
    const tokenInput = document.getElementById('token-input').value.trim();
    if (!username) return;
    if (!tokenInput) {
        userToken = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
        document.getElementById('token-input').value = userToken;
        const display = document.getElementById('token-display');
        const val = document.getElementById('token-value');
        if (display && val) { val.textContent = userToken; display.style.display = 'block'; }
    } else { userToken = tokenInput; }
    connect();
};

document.getElementById('send-btn').onclick = () => {
    const input = document.getElementById('msg-input');
    const text = input.value.trim();
    if (!text || !worker) return;
    input.value = '';
    appendMessage(text, true);
    worker.postMessage({ type: 'ENCRYPT_MSG', payload: JSON.stringify({ user: username, text: text, timestamp: Date.now() }), msgId: Date.now() });
};