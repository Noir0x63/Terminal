let ws = null;
let masterPrivateKey = null;
let masterSignKey = null;
let users = {}; // sessionId -> data
let hashToId = {}; // sessionHash -> sessionId
let selectedSessionId = null;
let messages = [];
let sessionId = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');

function bufferToBase64(buf) {
    let binary = '';
    const bytes = new Uint8Array(buf);
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToBuffer(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function importKeys(pem) {
    const clean = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----|\s/g, '');
    const binary = base64ToBuffer(clean);
    masterPrivateKey = await crypto.subtle.importKey('pkcs8', binary.buffer, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    masterSignKey = await crypto.subtle.importKey('pkcs8', binary.buffer, { name: 'RSA-PSS', hash: 'SHA-256' }, false, ['sign']);
}

document.getElementById('file-input').onchange = async (e) => {
    const f = e.target.files[0];
    if (!f) return;
    const text = await f.text();
    try {
        await importKeys(text);
        document.getElementById('upload-status').textContent = 'KEY READY';
        document.getElementById('auth-btn').disabled = false;
    } catch (err) { alert('Invalid Key Format'); }
};

document.getElementById('pem-upload').onclick = () => document.getElementById('file-input').click();

async function deriveKey(token, salt) {
    const enc = new TextEncoder();
    const saltBuf = enc.encode(salt);
    const base = await crypto.subtle.importKey('raw', enc.encode(token), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: saltBuf, iterations: 600000, hash: 'SHA-256' },
        base,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function decryptAesGcm(buf, key) {
    const iv = buf.slice(0, 12);
    const c = buf.slice(12);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, c));
}

async function encryptAesGcm(buf, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const c = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, buf);
    const r = new Uint8Array(iv.length + c.byteLength);
    r.set(iv, 0); r.set(new Uint8Array(c), iv.length);
    return r;
}

function sendStrictFrame(obj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const bytes = new TextEncoder().encode(JSON.stringify(obj));
    if (bytes.length > 4092) return;
    const frame = new Uint8Array(4096);
    window.crypto.getRandomValues(frame);
    new DataView(frame.buffer).setUint32(0, bytes.length, true);
    frame.set(bytes, 4);
    ws.send(frame);
}

document.getElementById('auth-btn').onclick = () => {
    document.getElementById('login-screen').classList.remove('active');
    document.getElementById('admin-dashboard').classList.add('active');
    connectAdmin();
};

function connectAdmin() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${location.host}`);
    ws.binaryType = 'arraybuffer';
    ws.onopen = () => {
        sendStrictFrame({ type: 'HANDSHAKE', sessionId: sessionId });
        sendStrictFrame({ type: 'REQ_CHALLENGE' });
    };
    ws.onmessage = async (e) => {
        try {
            const view = new DataView(e.data);
            const len = view.getUint32(0, true);
            if (len === 0) return;
            const frame = JSON.parse(new TextDecoder().decode(new Uint8Array(e.data, 4, len)));
            
            if (frame.type === 'AUTH_CHALLENGE') {
                const sig = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, masterSignKey, new TextEncoder().encode(frame.nonce));
                sendStrictFrame({ type: 'ADMIN_AUTH', signature: bufferToBase64(sig) });
            }

            if (frame.type === 'HISTORY' || frame.type === 'NEW_MESSAGE') {
                const msg = frame.data ? frame.data.content : frame.content;
                if (!msg) return;

                if (msg.type === 'INIT') {
                    try {
                        const decrypted = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, masterPrivateKey, base64ToBuffer(msg.data).buffer);
                        const initData = JSON.parse(new TextDecoder().decode(decrypted));
                        const sessId = msg.sessionId;
                        const existing = users[sessId];
                        if (existing && initData.ts <= existing.lastInitTs) return;
                        if (Math.abs(Date.now() - initData.ts) > 600000) return;

                        users[sessId] = {
                            username: initData.username,
                            symmetricKey: await deriveKey(initData.token, initData.username),
                            receiveCounter: 0,
                            sendCounter: 0, // Añadido para consistencia con el Worker
                            lastInitTs: initData.ts
                        };
                        if (msg.sessionHash) hashToId[msg.sessionHash] = sessId;
                        updateUserList();
                    } catch (err) { }
                } else if (msg.type === 'ASYNC_MSG') {
                    try {
                        const sessHash = msg.s;
                        const sessId = hashToId[sessHash] || sessHash;
                        const u = users[sessId];
                        if (!u || !u.symmetricKey) return;

                        const decBuf = await decryptAesGcm(base64ToBuffer(msg.payload), u.symmetricKey);
                        const decodedObj = JSON.parse(new TextDecoder().decode(decBuf));
                        decBuf.fill(0);

                        if (decodedObj.c <= u.receiveCounter) return;
                        u.receiveCounter = decodedObj.c;

                        let text = decodedObj.p;
                        try { text = JSON.parse(text).text || text; } catch (e) { }
                        messages.push({ from: sessId, text });
                        if (selectedSessionId === sessId || selectedSessionId === null) renderMessages();
                    } catch (err) { }
                }
            } else if (frame.type === 'NUKE_EVENT') { location.reload(); }
        } catch (err) { }
    };
}

function updateUserList() {
    const list = document.getElementById('user-list');
    list.innerHTML = '';
    for (let sid in users) {
        const d = document.createElement('div');
        d.className = 'user-item' + (selectedSessionId === sid ? ' selected' : '');
        d.textContent = (users[sid].username || sid.slice(0, 12)) + ' (ON)';
        d.onclick = () => {
            selectedSessionId = sid;
            document.getElementById('chat-title').textContent = `MESSAGES: ${users[sid].username || sid.slice(0, 16)}`;
            updateUserList(); renderMessages();
        };
        list.appendChild(d);
    }
}

function renderMessages() {
    const div = document.getElementById('messages');
    div.innerHTML = '';
    const rel = messages.filter(m => selectedSessionId === null || m.from === selectedSessionId || m.to === selectedSessionId);
    rel.forEach(m => {
        const msg = document.createElement('div');
        msg.style.color = (m.from === 'ADMIN') ? '#aaa' : '#fff';
        const name = (m.from === 'ADMIN' ? 'YOU' : (users[m.from] ? users[m.from].username : m.from.slice(0,8)));
        msg.textContent = `> ${name}: ` + m.text;
        div.appendChild(msg);
    });
    div.scrollTop = div.scrollHeight;
}

document.getElementById('send-btn').onclick = async () => {
    const input = document.getElementById('msg-input');
    const text = input.value.trim();
    if (!text || !selectedSessionId) return;
    const u = users[selectedSessionId];
    if (!u || !u.symmetricKey) return;
    input.value = '';
    messages.push({ from: 'ADMIN', to: selectedSessionId, text });
    
    // Incrementar contador para anti-replay y compatibilidad con el Worker
    u.sendCounter++;
    const payload = JSON.stringify({ user: 'ADMIN', text });
    const wrapped = JSON.stringify({ p: payload, c: u.sendCounter, t: Date.now() });
    
    const encBuf = await encryptAesGcm(new TextEncoder().encode(wrapped), u.symmetricKey);
    sendStrictFrame({ type: 'SERVER_MSG', targetSession: selectedSessionId, payload: bufferToBase64(encBuf) });
    renderMessages();
};

document.getElementById('broadcast-btn').onclick = () => {
    selectedSessionId = null;
    document.getElementById('chat-title').textContent = 'MESSAGES: BROADCAST';
    updateUserList(); renderMessages();
};

document.getElementById('nuke-btn').onclick = async () => {
    if (!confirm('PURGE ALL DATA?')) return;
    try { sendStrictFrame({ type: 'NUKE' }); } catch (err) { }
};

document.getElementById('zip-upload').onchange = async (e) => {
    const file = e.target.files[0];
    if (!file || !selectedSessionId) { e.target.value = ''; return; }
    const u = users[selectedSessionId];
    if (!u || !u.symmetricKey) { e.target.value = ''; return; }
    await sendFileToUser(file, selectedSessionId, u.symmetricKey);
    e.target.value = '';
};

async function sendFileToUser(file, targetSession, symmetricKey) {
    const CHUNK_SIZE = 2048;
    const arrayBuffer = await file.arrayBuffer();
    const totalBytes = arrayBuffer.byteLength;
    const totalChunks = Math.ceil(totalBytes / CHUNK_SIZE) || 1;
    const safeName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
    messages.push({ from: 'ADMIN', to: targetSession, text: `Sending: ${safeName}` });
    if (selectedSessionId === targetSession) renderMessages();
    sendStrictFrame({ type: 'FILE_META', targetSession, filename: safeName, totalChunks, fileSize: totalBytes });
    for (let i = 0; i < totalChunks; i++) {
        const offset = i * CHUNK_SIZE;
        const chunk = new Uint8Array(arrayBuffer, offset, Math.min(CHUNK_SIZE, totalBytes - offset));
        const encrypted = await encryptAesGcm(chunk, symmetricKey);
        sendStrictFrame({ type: 'FILE_CHUNK', targetSession, filename: safeName, chunkIndex: i, totalChunks, encData: bufferToBase64(encrypted) });
        if (i % 10 === 9) await new Promise(r => setTimeout(r, 10));
    }
}