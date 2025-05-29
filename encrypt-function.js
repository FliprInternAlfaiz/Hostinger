const CryptoJS = require('crypto-js');
const moment = require('moment');

function generateKey(password, salt) {
    return CryptoJS.PBKDF2(password, CryptoJS.enc.Hex.parse(salt), {
        keySize: 256 / 32,
        iterations: 1989
    });
}

function encryptWithIvSalt(password, iv, salt, data) {
    var key = generateKey(password, salt);
    return CryptoJS.AES.encrypt(data, key, {
        iv: CryptoJS.enc.Hex.parse(iv)
    }).ciphertext.toString(CryptoJS.enc.Base64);
}

function decryptWithIvSalt(password, iv, salt, encryptedData) {
    var key = generateKey(password, salt);
    var ciphertext = CryptoJS.enc.Base64.parse(encryptedData);
    var decrypted = CryptoJS.AES.decrypt({
        ciphertext: ciphertext
    }, key, {
        iv: CryptoJS.enc.Hex.parse(iv)
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
}

function encrypt(password, data) {
    var iv = CryptoJS.lib.WordArray.random(128 / 8).toString(CryptoJS.enc.Hex);
    var salt = CryptoJS.lib.WordArray.random(256 / 8).toString(CryptoJS.enc.Hex);
    return salt + iv + encryptWithIvSalt(password, iv, salt, data);
}

function decrypt(password, encrypted) {
    var ivSize = 128 / 4;
    var keySize = 256 / 4;
    var salt = encrypted.substr(0, keySize);
    var iv = encrypted.substr(keySize, ivSize);
    var encryptedData = encrypted.substring(ivSize + keySize);
    return decryptWithIvSalt(password, iv, salt, encryptedData);
}

function getSHA256Hash(data) {
    return CryptoJS.SHA256(data).toString(CryptoJS.enc.Hex);
}

function encryptWithKey(data, key) {
    const sha256Hash = getSHA256Hash(key);
    const hashedKey = CryptoJS.enc.Hex.parse(sha256Hash);
    const encrypted = CryptoJS.AES.encrypt(data, hashedKey, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return encrypted.toString();
}

function decryptWithKey(encryptedData, key) {
    const sha256Hash = getSHA256Hash(key);
    const hashedKey = CryptoJS.enc.Hex.parse(sha256Hash);
    const decrypted = CryptoJS.AES.decrypt(encryptedData, hashedKey, {
        mode: CryptoJS.mode.ECB,
        padding: CryptoJS.pad.Pkcs7
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
}

const Ne = () => crypto.randomBytes(16);

const ke = {
    randomUUID:
        typeof crypto !== 'undefined' &&
        crypto.randomUUID &&
        crypto.randomUUID.bind(crypto),
};

const Me = [];
for (let e = 0; e < 256; ++e) Me.push((e + 256).toString(16).slice(1));

const Le = function (e, t, n) {
    if (ke.randomUUID && !t && !e) return ke.randomUUID();
    const r = (e = e || {}).random || (e.rng || Ne)();

    r[6] = (15 & r[6]) | 64;  // Version 4 UUID
    r[8] = (63 & r[8]) | 128; // Variant 1 UUID

    if (t) {
        n = n || 0;
        for (let i = 0; i < 16; ++i) t[n + i] = r[i];
        return t;
    }

    return (function (e, t = 0) {
        return (
            Me[e[t + 0]] +
            Me[e[t + 1]] +
            Me[e[t + 2]] +
            Me[e[t + 3]] +
            "-" +
            Me[e[t + 4]] +
            Me[e[t + 5]] +
            "-" +
            Me[e[t + 6]] +
            Me[e[t + 7]] +
            "-" +
            Me[e[t + 8]] +
            Me[e[t + 9]] +
            "-" +
            Me[e[t + 10]] +
            Me[e[t + 11]] +
            Me[e[t + 12]] +
            Me[e[t + 13]] +
            Me[e[t + 14]] +
            Me[e[t + 15]]
        );
    })(r);
};

function token() {
    return Le() + moment().format("MMYYYYHHmmss");
}

module.exports = {
    generateKey,
    encryptWithIvSalt,
    decryptWithIvSalt,
    encrypt,
    decrypt,
    getSHA256Hash,
    encryptWithKey,
    decryptWithKey,
    token,
};