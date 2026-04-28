const crypto = require('crypto');
const fs = require('fs');

console.log('Generando par de llaves RSA de 4096 bits...');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

fs.writeFileSync('master_public.pem', publicKey);
fs.writeFileSync('master_private.pem', privateKey);

console.log('master_public.pem y master_private.pem generados exitosamente.');
