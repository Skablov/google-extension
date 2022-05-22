const crypto = require("crypto-browserify");
const algorithm = "aes256";

const alice = crypto.createECDH('secp256k1');
alice.generateKeys();
const bob = crypto.createECDH('secp256k1');
bob.generateKeys();

const alicePublicKeyBase64 = alice.getPublicKey().toString('base64');
const bobPublicKeyBase64 = bob.getPublicKey().toString('base64');

const aliceSharedKey = alice.computeSecret(bobPublicKeyBase64, 'base64', 'hex');
const bobSharedKey = bob.computeSecret(alicePublicKeyBase64, 'base64', 'hex');

console.log(aliceSharedKey == bobSharedKey);

function encrypt(text, secret) {
    const key = crypto.createHash('sha256').update(String(secret)).digest('base64').substr(0, 32);
    const iv = crypto.randomBytes(8).toString("hex");

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let msg = cipher.update(text, 'utf8', 'hex');
    msg += cipher.final("hex");

    return `${msg}:${iv}`;
}

function decrypt(encryptedMsg, secret) {
    const [encryptedHash, iv] = encryptedMsg.split(":");
    const key = crypto.createHash('sha256').update(String(secret)).digest('base64').substr(0, 32);

    const decipher = crypto.createDecipheriv(algorithm, key, iv);

    let decrypted = decipher.update(encryptedHash, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
}
console.log(aliceSharedKey)
const encryptedMsg = encrypt("Hello world!!!!", "e26c53a1805c5322ce39f12772d05f404346f6e3615c58099e92c0688adfbf10");
console.log(encryptedMsg);

const decryptedMsg = decrypt(encryptedMsg, "e26c53a1805c5322ce39f12772d05f404346f6e3615c58099e92c0688adfbf10");
console.log(decryptedMsg);

// function encrypt(text, secret) {
//     const textBytes = aesJs.utils.utf8.toBytes(text);

//     const iv = crypto.randomBytes(8).toString("hex");
//     const key = aesJs.utils.utf8.toBytes(secret);

//     const aesCbc = new aesJs.ModeOfOperation.cbc(secret, iv);

//     return aesCbc.encrypt(textBytes);
// }

// console.log(encrypt("Hello world", aliceSecret));
// //console.log(alice.computeSecret(bob.getPublicKey()));
