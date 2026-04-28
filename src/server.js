const crypto = require('crypto');
const fs = require('fs').promises;
const fsSync = require('fs');
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

const VAULT_FILE = path.join(__dirname, '../vault.json');
const MAX_VAULT_SIZE = 5000;
const CHALLENGE_TTL = 30000;
const MSG_RATE_LIMIT = 50; 
const BROADCAST_LIMIT_MS = 500; // 2 mensajes por segundo
const HANDSHAKE_TIMEOUT = 20000;
const MAX_CONN_PER_ID = 2;
const MAX_TOTAL_CONN = 500;

let HMAC_SECRET = null;
try {
    HMAC_SECRET = fsSync.readFileSync(path.join(__dirname, '../admin_token.txt'), 'utf8').trim();
} catch (e) {
    console.error('[SERVER] ADVERTENCIA: admin_token.txt no encontrado.');
}

function computeAdminPath(dayOffset = 0) {
    if (!HMAC_SECRET) return null;
    const dayNonce = String(Math.floor(Date.now() / 86400000) + dayOffset);
    const hourlyNonce = String(Math.floor(Date.now() / 3600000));
    return crypto.createHmac('sha256', HMAC_SECRET).update(dayNonce + ':' + hourlyNonce).digest('hex');
}

function isValidAdminPath(token) {
    if (!HMAC_SECRET || !token) return false;
    const current = computeAdminPath(0);
    const lastHour = crypto.createHmac('sha256', HMAC_SECRET)
        .update(String(Math.floor(Date.now() / 86400000)) + ':' + String(Math.floor(Date.now() / 3600000) - 1))
        .digest('hex');
    const tBuf = Buffer.from(token.padEnd(64, '0').slice(0, 64));
    const cBuf = Buffer.from(current.padEnd(64, '0').slice(0, 64));
    const lBuf = Buffer.from(lastHour.padEnd(64, '0').slice(0, 64));
    return crypto.timingSafeEqual(tBuf, cBuf) || crypto.timingSafeEqual(tBuf, lBuf);
}

const POW_DIFFICULTY = 16;
const powChallenges = new Map();

function generatePoWChallenge(ws) {
    const challenge = crypto.randomBytes(16).toString('hex');
    powChallenges.set(ws, { challenge, ts: Date.now() });
    return challenge;
}

function verifyPoW(ws, nonce) {
    const stored = powChallenges.get(ws);
    if (!stored || Date.now() - stored.ts > 60000) return false;
    const hash = crypto.createHash('sha256').update(nonce + stored.challenge).digest();
    let zeroBits = 0;
    for (const byte of hash) {
        if (byte === 0) { zeroBits += 8; }
        else {
            let b = byte;
            while ((b & 0x80) === 0) { zeroBits++; b <<= 1; }
            break;
        }
        if (zeroBits >= POW_DIFFICULTY) break;
    }
    if (zeroBits >= POW_DIFFICULTY) {
        powChallenges.delete(ws);
        return true;
    }
    return false;
}

let messageVault = [];
let adminSocket = null;
const sessionSockets = new Map(); // sessionId -> Set(ws)
const challenges = new Map();
const activeSessions = new Map(); // sessionId -> count
const connRateLimit = new Map(); // ip -> lastTime

async function loadVault() {
    try {
        const data = await fs.readFile(VAULT_FILE, 'utf8');
        messageVault = JSON.parse(data).slice(-MAX_VAULT_SIZE);
    } catch (e) { messageVault = []; }
}
loadVault();

async function saveVault() {
    try { await fs.writeFile(VAULT_FILE, JSON.stringify(messageVault, null, 2)); } catch (e) { }
}

function hashField(val) {
    const salt = HMAC_SECRET ? crypto.createHash('sha256').update(HMAC_SECRET).digest('hex').slice(0, 16) : 'static_salt';
    return crypto.createHash('sha256').update(String(val) + salt).digest('hex');
}

async function getMasterPublicKey() {
    try {
        return await fs.readFile(path.join(__dirname, '../master_public.pem'), 'utf8');
    } catch (e) {
        try { return await fs.readFile('master_public.pem', 'utf8'); } catch { return null; }
    }
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

app.use(cors());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' blob:; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss: blob:; img-src 'self' data:; frame-ancestors 'none';");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    next();
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));
app.get('/:token', (req, res, next) => {
    if (isValidAdminPath(req.params.token)) return res.sendFile(path.join(__dirname, '../public/admin.html'));
    next();
});
app.use(express.static(path.join(__dirname, '../public')));

server.on('upgrade', (request, socket, head) => {
    const ip = request.socket.remoteAddress;
    const now = Date.now();
    if (connRateLimit.has(ip) && now - connRateLimit.get(ip) < 1000) {
        socket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
        socket.destroy();
        return;
    }
    connRateLimit.set(ip, now);

    if (wss.clients.size >= MAX_TOTAL_CONN) {
        socket.write('HTTP/1.1 503 Service Unavailable\r\n\r\n');
        socket.destroy();
        return;
    }
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});

function sendStrictFrame(ws, payloadObj) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    try {
        const payloadBytes = Buffer.from(JSON.stringify(payloadObj), 'utf8');
        if (payloadBytes.length > 4092) return;
        const frame = Buffer.alloc(4096);
        crypto.randomFillSync(frame);
        frame.writeUint32LE(payloadBytes.length, 0);
        payloadBytes.copy(frame, 4);
        ws.send(frame);
    } catch (e) { }
}

wss.on('connection', (ws) => {
    ws.msgCount = 0;
    ws.lastReset = Date.now();
    ws.sessionId = null;
    ws.lastBroadcast = 0;

    const hTimeout = setTimeout(() => { if (!ws.sessionId) ws.close(1008); }, HANDSHAKE_TIMEOUT);

    ws.on('message', async (message) => {
        const now = Date.now();
        if (now - ws.lastReset > 10000) { ws.msgCount = 0; ws.lastReset = now; }
        if (++ws.msgCount > MSG_RATE_LIMIT) return ws.close(1008);
        if (message.length !== 4096) return;

        try {
            const len = message.readUint32LE(0);
            if (len === 0) return;
            const data = JSON.parse(message.subarray(4, 4 + len).toString('utf8'));

            if (!ws.sessionId && data.type !== 'HANDSHAKE') return ws.close(1008);

            if (data.type === 'HANDSHAKE') {
                if (ws.sessionId) return;
                if (!data.sessionId || data.sessionId.length !== 32) return ws.close(1008);
                const count = activeSessions.get(data.sessionId) || 0;
                if (count >= MAX_CONN_PER_ID) return ws.close(1008);
                clearTimeout(hTimeout);
                ws.sessionId = data.sessionId;
                activeSessions.set(ws.sessionId, count + 1);
                return;
            }

            if (data.type === 'REQ_POW') {
                const challenge = generatePoWChallenge(ws);
                return sendStrictFrame(ws, { type: 'POW_CHALLENGE', challenge, difficulty: POW_DIFFICULTY });
            }

            if (data.type === 'REQ_CHALLENGE') {
                const nonce = crypto.randomBytes(32).toString('hex');
                challenges.set(ws, { nonce, ts: Date.now() });
                return sendStrictFrame(ws, { type: 'AUTH_CHALLENGE', nonce });
            }

            if (data.type === 'ADMIN_AUTH') {
                const stored = challenges.get(ws);
                if (!stored || Date.now() - stored.ts > CHALLENGE_TTL) return ws.close(1008);
                const pubKey = await getMasterPublicKey();
                if (!pubKey) return ws.close(1008);
                const isValid = crypto.verify('sha256', Buffer.from(stored.nonce), {
                    key: pubKey,
                    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                    saltLength: 32
                }, Buffer.from(data.signature, 'base64'));
                if (isValid) {
                    if (adminSocket && adminSocket.readyState === WebSocket.OPEN) adminSocket.close(1000);
                    adminSocket = ws;
                    challenges.delete(ws);
                    for (let msg of messageVault) sendStrictFrame(ws, { type: 'HISTORY', data: msg });
                    for (let [sid, sockets] of sessionSockets) {
                        for (let s of sockets) {
                            if (s.initData) { sendStrictFrame(ws, { type: 'NEW_MESSAGE', data: { timestamp: Date.now(), content: s.initData } }); break; }
                        }
                    }
                } else { ws.close(1008); }
                return;
            }

            if (data.type === 'INIT') {
                if (!data.powNonce || !verifyPoW(ws, data.powNonce)) {
                    const challenge = generatePoWChallenge(ws);
                    return sendStrictFrame(ws, { type: 'POW_CHALLENGE', challenge, difficulty: POW_DIFFICULTY });
                }
                if (!data.user || data.user.length > 64) return ws.close(1008);
                ws.username = data.user;
                ws.initData = { ...data, sessionId: ws.sessionId };
                if (!sessionSockets.has(ws.sessionId)) sessionSockets.set(ws.sessionId, new Set());
                sessionSockets.get(ws.sessionId).add(ws);
                const sessHash = hashField(ws.sessionId);
                const history = messageVault.filter(m => m.content.s === sessHash || m.content.ts === sessHash);
                history.forEach(m => sendStrictFrame(ws, { type: 'HISTORY', data: m }));
                if (adminSocket) sendStrictFrame(adminSocket, { type: 'NEW_MESSAGE', data: { timestamp: Date.now(), content: ws.initData } });
                return;
            }

            if (data.type === 'ASYNC_MSG' || data.type === 'SERVER_MSG' || data.type === 'FILE_META' || data.type === 'FILE_CHUNK' || data.type === 'BROADCAST') {
                const isFromAdmin = (ws === adminSocket);
                
                // Rate limit: 2 mensajes por segundo para usuarios
                if (!isFromAdmin && now - ws.lastBroadcast < BROADCAST_LIMIT_MS) return; 
                ws.lastBroadcast = now;

                if (!isFromAdmin && (data.targetSession === 'ALL' || data.type === 'BROADCAST')) return; // Solo admin hace broadcast

                const needsVaultWrite = data.type !== 'FILE_CHUNK' && data.type !== 'FILE_META';
                if (needsVaultWrite && !isFromAdmin) {
                    if (!data.powNonce || !verifyPoW(ws, data.powNonce)) {
                        const challenge = generatePoWChallenge(ws);
                        return sendStrictFrame(ws, { type: 'POW_CHALLENGE', challenge, difficulty: POW_DIFFICULTY });
                    }
                }

                const safeContent = { ...data };
                delete safeContent.powNonce;
                safeContent.s = isFromAdmin ? 'ADMIN' : hashField(ws.sessionId);
                if (safeContent.targetSession && safeContent.targetSession !== 'ALL') safeContent.ts = hashField(safeContent.targetSession);
                
                const record = { timestamp: Date.now(), content: safeContent };
                if (needsVaultWrite) {
                    messageVault.push(record);
                    if (messageVault.length > MAX_VAULT_SIZE) messageVault.shift();
                    await saveVault();
                }

                if (adminSocket && !isFromAdmin) sendStrictFrame(adminSocket, { type: 'NEW_MESSAGE', data: record });

                if (data.targetSession === 'ALL' || data.type === 'BROADCAST') {
                    for (let [, sockets] of sessionSockets) {
                        for (let s of sockets) if (s !== ws && s.readyState === WebSocket.OPEN) sendStrictFrame(s, { type: 'NEW_MESSAGE', data: record });
                    }
                } else if (data.targetSession && data.targetSession !== 'ADMIN') {
                    const sockets = sessionSockets.get(data.targetSession);
                    if (sockets) for (let s of sockets) if (s.readyState === WebSocket.OPEN) sendStrictFrame(s, { type: 'NEW_MESSAGE', data: record });
                }
            }
        } catch (e) { }
    });

    ws.on('close', () => {
        clearTimeout(hTimeout);
        if (ws.sessionId) {
            const sockets = sessionSockets.get(ws.sessionId);
            if (sockets) { sockets.delete(ws); if (sockets.size === 0) sessionSockets.delete(ws.sessionId); }
            const count = activeSessions.get(ws.sessionId) || 1;
            if (count <= 1) activeSessions.delete(ws.sessionId);
            else activeSessions.set(ws.sessionId, count - 1);
        }
        if (ws === adminSocket) adminSocket = null;
        challenges.delete(ws);
        powChallenges.delete(ws);
    });
});

server.listen(process.env.PORT || 3000);