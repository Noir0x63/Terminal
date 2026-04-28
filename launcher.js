const { spawn, execSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

// Configuración de Tema: Hybrid Green/White
const THEME = {
    BANNER: '\x1b[32m',    // Verde
    TAG:    '\x1b[32m',    // Verde para [MODULO]
    TEXT:   '\x1b[37m',    // Blanco para el mensaje
    ERROR:  '\x1b[31m',    // Rojo para errores
    TIME:   '\x1b[90m',    // Gris para el tiempo
    RESET:  '\x1b[0m',
    BOLD:   '\x1b[1m'
};

function log(module, message, color = THEME.TEXT) {
    const timestamp = new Date().toLocaleTimeString();
    // Las etiquetas siempre son verdes (THEME.TAG)
    console.log(`${THEME.TIME}[${timestamp}]${THEME.RESET} ${THEME.BOLD}${THEME.TAG}[${module}]${THEME.RESET} ${color}${message}${THEME.RESET}`);
}

console.clear();
console.log(`${THEME.BANNER}${THEME.BOLD}====================================================${THEME.RESET}`);
console.log(`${THEME.BANNER}${THEME.BOLD}             TERMINAL - TOR HIDDEN SERVICE          ${THEME.RESET}`);
console.log(`${THEME.BANNER}${THEME.BOLD}              IRONCLAD v3.0 (HARDENED)              ${THEME.RESET}`);
console.log(`${THEME.BANNER}${THEME.BOLD}====================================================${THEME.RESET}\n`);

// 1. Verificar existencia de master_public.pem y master_private.enc
if (!fs.existsSync('master_public.pem') || !fs.existsSync('master_private.enc')) {
    log('SYSTEM', 'Archivos de clave maestra no encontrados. Ejecutando keygen.js...');
    log('SYSTEM', 'Se te pedirá una passphrase maestra para cifrar la clave privada.');
    try {
        execSync('node keygen.js', { stdio: 'inherit' });
        log('SYSTEM', 'Llaves generadas y cifradas correctamente.');
    } catch (e) {
        log('SYSTEM', 'Error fatal: No se pudo generar el par de llaves.', THEME.ERROR);
        process.exit(1);
    }
}

// Verify server_secrets.enc exists
if (!fs.existsSync('server_secrets.enc')) {
    log('SYSTEM', 'server_secrets.enc no encontrado. Ejecuta keygen.js para generar los secretos.', THEME.ERROR);
    process.exit(1);
}

// 2. Ejecutar Build (usa server_secrets.enc → nueva ruta admin)
log('BUILD', 'Iniciando proceso de empaquetado (sin ofuscación)...');
try {
    execSync('node build.js', { stdio: 'inherit' });
    log('BUILD', '¡Build completado con éxito!');
} catch (error) {
    log('BUILD', 'Error crítico durante el build.', THEME.ERROR);
    process.exit(1);
}

// 3. Purgar vault anterior (anti-forense al inicio)
const vaultPath = path.join(__dirname, 'vault.json');
try {
    if (fs.existsSync(vaultPath)) {
        fs.writeFileSync(vaultPath, '[]');
        log('VAULT', 'Historial anterior purgado.');
    }
} catch (e) {
    log('VAULT', 'Advertencia: no se pudo purgar el vault.', THEME.ERROR);
}

// Purge any legacy admin_token.txt if it exists (CRÍTICO 2: clean up)
const legacyTokenPath = path.join(__dirname, 'admin_token.txt');
if (fs.existsSync(legacyTokenPath)) {
    try {
        // Overwrite with random data before deletion (anti-forense)
        const randomFill = require('crypto').randomBytes(64);
        fs.writeFileSync(legacyTokenPath, randomFill);
        fs.unlinkSync(legacyTokenPath);
        log('SECURITY', 'admin_token.txt legacy eliminado de forma segura.');
    } catch (e) {
        log('SECURITY', 'Advertencia: no se pudo eliminar admin_token.txt legacy.', THEME.ERROR);
    }
}

// Purge any legacy master_private.pem if it exists (CRÍTICO 1: clean up)
const legacyPrivateKeyPath = path.join(__dirname, 'master_private.pem');
if (fs.existsSync(legacyPrivateKeyPath)) {
    try {
        const stat = fs.statSync(legacyPrivateKeyPath);
        const randomFill = require('crypto').randomBytes(stat.size);
        fs.writeFileSync(legacyPrivateKeyPath, randomFill);
        fs.unlinkSync(legacyPrivateKeyPath);
        log('SECURITY', 'master_private.pem legacy eliminado de forma segura (sobrescrito + eliminado).');
    } catch (e) {
        log('SECURITY', 'Advertencia: no se pudo eliminar master_private.pem legacy.', THEME.ERROR);
    }
}

console.log("");

// 4. Iniciar Servidor Relay
log('SERVER', 'Iniciando servidor Node.js (Zero-Store Mode)...');
const server = spawn('node', ['src/server.js']);

server.stdout.on('data', (data) => {
    const lines = data.toString().split('\n');
    lines.forEach(line => {
        if (line.trim()) log('SERVER', line.trim());
    });
});

server.stderr.on('data', (data) => {
    log('SERVER-ERR', data.toString().trim(), THEME.ERROR);
});

server.on('error', (err) => {
    log('SYSTEM', `Fallo al iniciar el servidor: ${err.message}`, THEME.ERROR);
    process.exit(1);
});

// 4. Iniciar Tor
log('TOR', 'Iniciando servicio oculto de Tor...');

// Asegurarse de que el directorio exista (evita errores de Tor)
const torOnionDir = path.join(__dirname, 'Tor', 'onion_service');
if (!fs.existsSync(torOnionDir)) {
    fs.mkdirSync(torOnionDir, { recursive: true });
}

const torExePath = path.join(__dirname, 'Tor', 'tor.exe');
const torConfigPath = path.join(__dirname, 'Tor', 'torrc.txt');

if (!fs.existsSync(torExePath)) {
    log('TOR', 'Error: Binario de Tor no encontrado en Tor/tor.exe', THEME.ERROR);
    log('TOR', 'Por favor, descarga Tor Expert Bundle y coloca tor.exe en la carpeta Tor/', THEME.TEXT);
    process.exit(1);
}

const tor = spawn(torExePath, ['-f', torConfigPath]);

tor.stdout.on('data', (data) => {
    const lines = data.toString().split('\n');
    lines.forEach(line => {
        const text = line.trim();
        if (!text) return;

        // Filtrar logs de Tor: Detalle operativo sin ruido de advertencias
        const textLower = text.toLowerCase();
        const isSpam = textLower.includes('warn') || textLower.includes('error') || textLower.includes('heartbeat');
        
        if (!isSpam && (
            text.includes('Bootstrapped') ||
            text.includes('Opened circuit') ||
            text.includes('Self-testing') ||
            text.includes('Ready to announce')
        )) {
            log('TOR', text);
        }

        // Si Tor ya está listo, buscamos el hostname
        if (text.includes('Bootstrapped 100%')) {
            log('TOR', 'Servicio oculto totalmente operativo.');
            checkOnionAddress();
        }
    });
});

tor.stderr.on('data', (data) => {
    log('TOR-ERR', data.toString().trim(), THEME.ERROR);
});

tor.on('error', (err) => {
    log('SYSTEM', `Fallo al iniciar Tor: ${err.message}`, THEME.ERROR);
    process.exit(1);
});

function checkOnionAddress() {
    const hostnamePath = path.join(torOnionDir, 'hostname');

    // Tor tarda unos segundos en generar el archivo la primera vez
    const interval = setInterval(() => {
        if (fs.existsSync(hostnamePath)) {
            const onionAddress = fs.readFileSync(hostnamePath, 'utf8').trim();
            console.log(`\n${THEME.BANNER}${THEME.BOLD}====================================================${THEME.RESET}`);
            console.log(`${THEME.BANNER}${THEME.BOLD}   DIRECCIÓN ONION ACTIVA: ${THEME.RESET}${THEME.TEXT}${THEME.BOLD}${onionAddress}${THEME.RESET}`);
            console.log(`${THEME.BANNER}${THEME.BOLD}====================================================${THEME.RESET}\n`);
            log('SYSTEM', 'El servicio está totalmente operativo.');
            clearInterval(interval);
        }
    }, 2000);
}

// Manejo de salida limpia
process.on('SIGINT', () => {
    log('SYSTEM', 'Cerrando procesos...');
    server.kill();
    tor.kill();
    process.exit();
});
