const crypto = require('crypto');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
const IV_LENGTH = 16;

function generateDeterministicIV(email) {
    // Create a deterministic IV based on the email
    const hash = crypto.createHash('sha256').update(email).digest();
    return Buffer.from(hash.subarray(0, IV_LENGTH));
}

function encryptEmail(email) {
    // Use deterministic IV based on email
    const iv = generateDeterministicIV(email);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(email);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decryptEmail(encryptedEmail) {
    const textParts = encryptedEmail.split(':');
    const iv = Buffer.from(textParts[0], 'hex');
    const encryptedText = Buffer.from(textParts[1], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

module.exports = { encryptEmail, decryptEmail };