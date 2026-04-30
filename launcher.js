const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const THEME = {
    GREEN: '\x1b[32m',
    WHITE: '\x1b[37m',
    GRAY:  '\x1b[90m',
    BOLD:  '\x1b[1m',
    RESET: '\x1b[0m',
    CYAN:  '\x1b[36m'
};

function clearLine() {
    process.stdout.write('\r\x1b[K');
}

function drawProgressBar(percent, status = "Bootstrapping Tor") {
    const width = 30;
    const completed = Math.floor((percent / 100) * width);
    const remaining = width - completed;
    const bar = THEME.GREEN + '█'.repeat(completed) + THEME.GRAY + '░'.repeat(remaining) + THEME.RESET;
    
    clearLine();
    process.stdout.write(`${THEME.BOLD}[${bar}] ${percent}%${THEME.RESET} ${THEME.GRAY}${status}${THEME.RESET}`);
}

console.clear();
console.log(`${THEME.GREEN}${THEME.BOLD}====================================================${THEME.RESET}`);
console.log(`${THEME.GREEN}${THEME.BOLD}             TERMINAL - ZTAP PROTOCOL              ${THEME.RESET}`);
console.log(`${THEME.GREEN}${THEME.BOLD}              IRONCLAD v3.1 (HARDENED)              ${THEME.RESET}`);
console.log(`${THEME.GREEN}${THEME.BOLD}====================================================${THEME.RESET}\n`);

// 0. Verificar integridad de identidad (Keygen si falta algo)
if (!fs.existsSync('master_public.pem') || !fs.existsSync('master_private.enc')) {
    process.stdout.write(`${THEME.BOLD}[!]${THEME.RESET} ${THEME.WHITE}Identidad no detectada. Iniciando ZTAP KEYGEN...${THEME.RESET}\n\n`);
    try {
        execSync('node keygen.js', { stdio: 'inherit' });
        process.stdout.write(`\n${THEME.BOLD}[✓]${THEME.RESET} ${THEME.WHITE}Identidad generada correctamente.${THEME.RESET}\n\n`);
    } catch (e) {
        process.stdout.write(`\n${THEME.BOLD}[ERROR]${THEME.RESET} Fallo al generar identidad.\n`);
        process.exit(1);
    }
}

// 1. Rotación de Identidad
const torOnionDir = path.join(__dirname, 'Tor', 'onion_service');
if (fs.existsSync(torOnionDir)) {
    process.stdout.write(`${THEME.GRAY}> Rotando identidad para evasión...${THEME.RESET}\n`);
    const files = fs.readdirSync(torOnionDir);
    for (const file of files) {
        try {
            const filePath = path.join(torOnionDir, file);
            if (fs.statSync(filePath).isFile()) {
                fs.writeFileSync(filePath, crypto.randomBytes(fs.statSync(filePath).size));
            }
            fs.unlinkSync(filePath);
        } catch (e) {}
    }
} else {
    fs.mkdirSync(torOnionDir, { recursive: true });
}

// 2. Build Silencioso
process.stdout.write(`${THEME.GRAY}> Optimizando paquetes y rotando rutas admin...${THEME.RESET}\n`);
try {
    execSync('node build.js', { stdio: 'pipe' });
} catch (e) {
    console.log(`\n${THEME.BOLD}[ERROR]${THEME.RESET} Fallo en el build.`);
    process.exit(1);
}

// 3. Obtener ruta admin (se lee del build más reciente)
// Nota: Solo para mostrarla visualmente
const secrets = JSON.parse(fs.readFileSync('server_secrets.enc', 'utf8'));
const dayNonce = String(Math.floor(Date.now() / 86400000));
const hourlyNonce = String(Math.floor(Date.now() / 3600000));
const adminPath = crypto.createHmac('sha256', secrets.adminSecret)
    .update(dayNonce + ':' + hourlyNonce + ':' + secrets.serverNonce)
    .digest('hex');

console.log(`${THEME.CYAN}${THEME.BOLD}[ADMIN]${THEME.RESET} Ruta activa: /${adminPath}\n`);

// 4. Iniciar procesos
const server = spawn('node', ['src/server.js']);
const tor = spawn(path.join(__dirname, 'Tor', 'tor.exe'), ['-f', path.join(__dirname, 'Tor', 'torrc.txt')]);

let torReady = false;

tor.stdout.on('data', (data) => {
    const text = data.toString();
    const match = text.match(/Bootstrapped (\d+)%/);
    if (match) {
        const percent = parseInt(match[1]);
        let status = "Conectando a nodos...";
        if (percent > 10) status = "Negociando circuitos...";
        if (percent > 80) status = "Publicando Hidden Service...";
        if (percent === 100) status = "Servicio Activo";
        
        drawProgressBar(percent, status);
        
        if (percent === 100 && !torReady) {
            torReady = true;
            setTimeout(showFinalAddress, 2000);
        }
    }
});

function showFinalAddress() {
    const hostnamePath = path.join(torOnionDir, 'hostname');
    if (fs.existsSync(hostnamePath)) {
        const onion = fs.readFileSync(hostnamePath, 'utf8').trim();
        console.log(`\n\n${THEME.GREEN}${THEME.BOLD}====================================================${THEME.RESET}`);
        console.log(`${THEME.GREEN}${THEME.BOLD}   ONION: ${THEME.RESET}${THEME.WHITE}${THEME.BOLD}${onion}${THEME.RESET}`);
        console.log(`${THEME.GREEN}${THEME.BOLD}====================================================${THEME.RESET}\n`);
    }
}

process.on('SIGINT', () => {
    console.log(`\n${THEME.GRAY}> Cerrando búnker...${THEME.RESET}`);
    server.kill();
    tor.kill();
    process.exit();
});
