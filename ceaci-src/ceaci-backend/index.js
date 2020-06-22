const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 21567;

const keys = new Map();

// TEST VALUE, to be removed
keys.set('gica', 'testkey123');

app.use(bodyParser.json());

app.get('/api/hello', (req, res) => {
    res.send('Hello world');
});

app.post('/api/request', (req, res) => {
    console.log(req.body);
    if (!req.body) {
        res.status(400).send('Invalid payload');
        return;
    }

    // take the username, iv, salt and encoded message
    // get the password for that user and generate the aes key
    // the decrypt and check if the passwords match
    const payload = req.body;

    // convert arrays to typed arrays / buffers
    payload.salt = Buffer.from(payload.salt);
    payload.iv = Buffer.from(payload.iv);
    payload.message = Buffer.from(payload.message);

    // Print Hex for tests
    console.log(payload.salt.toString('hex'));
    console.log(payload.iv.toString('hex'));
    console.log(payload.message.toString('hex'));

    console.log('Payload: ', payload);
    console.log(typeof payload.salt);

    const userPass = keys.get('gica');
    const aesKey = generateAesKey(payload.salt, userPass);
    console.log('AES Key: ', aesKey);

    // TEST: Reencode data, extract auth tag and compare
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, payload.iv);
    let encrypted = cipher.update(new TextEncoder().encode('testkey123'));
    encrypted += cipher.final();
    const authTag = cipher.getAuthTag();

    console.log('Client encrypted:', payload.message);
    console.log('Buffer length:', payload.message.length);
    console.log('Buffer byteLength:', Buffer.byteLength(payload.message, 'utf8'));
    console.log('Server encrypted:', Buffer.from(encrypted));
    console.log('Server auth tag:', authTag);

    let msg;
    try {
        msg = decryptMessage(aesKey, payload.iv, payload.message);
    } catch (_) {
        console.warn('Failed to verify signature!');
        res.status(401).send('Mai incearca');
        return;
    }
    

    // check passwords
    if (msg === userPass) {
        console.log('The passwords match!!!');
        const respIv = crypto.randomBytes(12);
        const respCipher = crypto.createCipheriv('aes-256-gcm', aesKey, respIv);

        let endText = respCipher.update('Felicitari!', 'utf8', 'utf8');
        endText += respCipher.final('utf8');
        res.status(200).send(JSON.stringify({
            iv: respIv,
            message: endText
        }));
    } else {
        console.warn(`The passwords are different: ${msg} /\\ ${userPass}`);
        res.status(401).send('Mai incearca');
    }
});

function generateAesKey(salt, userPass) {
    const aesKey = crypto.pbkdf2Sync(userPass, salt, 50_000, 32, 'sha256');
    console.log('AES Key:', new Uint8Array(aesKey));
    return aesKey;
}

function decryptMessage(key, iv, msg) {
    console.log('Msg:', msg);
    const sepIndex = msg.length - 16;
    const ciphertext = msg.slice(0, sepIndex);
    const hmac = msg.slice(sepIndex);

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    let decrypted = decipher.update(ciphertext);
    decipher.setAuthTag(hmac);
    decrypted += decipher.final();

    return decrypted;
}

app.listen(PORT, '127.0.0.1', () => console.log('Started server'));
