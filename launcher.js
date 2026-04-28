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
console.log(`${THEME.BANNER}${THEME.BOLD}====================================================${THEME.RESET}\n`);

// 1. Verificar existencia de master_public.pem
if (!fs.existsSync('master_public.pem')) {
    log('SYSTEM', 'Archivo master_public.pem no encontrado. Generando llaves maestras...');
    try {
        execSync('node keygen.js', { stdio: 'inherit' });
        log('SYSTEM', 'Llaves generadas correctamente.');
    } catch (e) {
        log('SYSTEM', 'Error fatal: No se pudo generar el par de llaves.', THEME.ERROR);
        process.exit(1);
    }
}

// 2. Ejecutar Build (genera nuevo HMAC secret → nueva ruta admin)
log('BUILD', 'Iniciando proceso de ofuscación y empaquetado...');
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

const tor = spawn(path.join(__dirname, 'Tor', 'tor.exe'), ['-f', path.join(__dirname, 'Tor', 'torrc.txt')]);

tor.stdout.on('data', (data) => {
    const lines = data.toString().split('\n');
    lines.forEach(line => {
        const text = line.trim();
        if (!text) return;

        // Filtrar logs irrelevantes de Tor para mantener limpieza
        if (text.includes('Bootstrapped') ||
            text.includes('Heartbeat') ||
            text.includes('Opened circuit') ||
            text.includes('Self-testing') ||
            text.includes('Ready to announce') ||
            text.toLowerCase().includes('error') ||
            text.toLowerCase().includes('warn')) {

            log('TOR', text);
        }

        // Si Tor ya está listo, buscamos el hostname
        if (text.includes('Bootstrapped 100%')) {
            log('TOR', 'Tor se ha conectado a la red al 100%.');
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
