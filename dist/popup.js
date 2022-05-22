const crypto = require("crypto-browserify");
const algorithm = "aes256";

let USER;

const generatePkButton = document.getElementById("generatePk");
const generatePrivateKeyButton = document.getElementById("generateSecretKey");

const encryptMessageButton = document.getElementById("encryptMessage");
const decryptMessageButton = document.getElementById("decryptMessage");

let secretKey = "";

decryptMessageButton.addEventListener("click", () => {
    decryptMessage();
})

encryptMessageButton.addEventListener("click", () => {
    encryptMessage();
})

generatePrivateKeyButton.addEventListener("click", () => {
    generatePrivateKey();
})

generatePkButton.addEventListener("click", () => {
    generatePk();
});

// ----------------------------

function generatePk() {
    USER = crypto.createECDH('secp256k1');
    USER.generateKeys();

    const publicKey = USER.getPublicKey().toString('base64');
    document.getElementById("publicKey").innerHTML = publicKey;
}

function generatePrivateKey() {
    try {
        const friendPk = document.getElementById("friendPk").value.toString("base64");
        secretKey = USER.computeSecret(friendPk, 'base64', 'hex');
    } catch (err) {
        console.log(err);
        alert("Incorrect public key from your friend!");
    }
}

function encryptMessage() {
    const msg = document.getElementById("msg").value;
    // console.log("Msg = ", msg);
    // const key = crypto.createHash('sha256').update(String(secretKey)).digest('base64').substr(0, 32);
    // console.log("Secret key = ", secretKey);
    // const iv = crypto.randomBytes(8).toString("hex");

    // const cipher = crypto.createCipheriv(algorithm, key, iv);
    // let encryptedMsg = cipher.update(msg, 'utf8', 'hex');
    // encryptedMsg += cipher.final("hex");
    console.log(encrypt(msg, secretKey))
    document.getElementById("encryptedMsg").innerHTML = encrypt(msg, secretKey);
}

function encrypt(text, secret) {
    const key = crypto.createHash('sha256').update(String(secret)).digest('base64').substr(0, 32);
    const iv = crypto.randomBytes(8).toString("hex");

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    let msg = cipher.update(text, 'utf8', 'hex');
    msg += cipher.final("hex");

    return `${msg}:${iv}`;
}

function decryptMessage() {
    try {
        console.log("Secret key = ", secretKey)
        const msg = document.getElementById("decryptMsg").value;
        const [encryptedHash, iv] = msg.split(":");
    
        console.log(encryptedHash, iv);
    
        const key = crypto.createHash('sha256').update(String(secretKey)).digest('base64').substr(0, 32);
        console.log("Key = ", key);
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
    
        let decrypted = decipher.update(encryptedHash, "hex", "utf8");
        decrypted += decipher.final("utf8");
        
        document.getElementById("decryptedMsg").innerHTML = decrypted;
    } catch (err) {
        console.log(err);
    }
}



