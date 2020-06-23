const http = require('http');
const websocket = require('websocket').server;
const crypto = require('crypto');

const PORT = process.env.PORT || 21567;

const server = http.createServer();
server.listen(PORT);
console.log('Started server');

const ws = new websocket({
    httpServer: server
});

const keys = new Map();

// TEST VALUE, to be removed
keys.set('gica', 'testkey123');

ws.on('request', req => {
    const connection = req.accept(null, req.origin);

    connection.on('message', data => {
        console.log('Received message:', data);
        const payload = JSON.parse(data.utf8Data);

        console.log('Payload:', payload);
        // convert arrays to typed arrays / buffers
        payload.salt = Buffer.from(payload.salt);
        payload.iv = Buffer.from(payload.iv);
        payload.message = Buffer.from(payload.message);

        // encryption: PBKDF2 + AES
        if (payload.action === 'authenticate') {
            authenticateUser(connection, payload);
        }
        else
        // encryption: PBKDF2 + HKDF + AES
        if (payload.action === 'sendmsg') {
            // TODO
        }
    });

    connection.on('close', (reason, desc) => {
        console.log('Client disconnected:', reason, desc);
    });

    connection.on('error', err => {
        console.warn('Error:', err);
    });

    // also has binds for 'ping' and 'pong'
});

function authenticateUser(conn, payload) {
    // Print Hex for tests
    console.log(payload.salt.toString('hex'));
    console.log(payload.iv.toString('hex'));
    console.log(payload.message.toString('hex'));

    const userPass = keys.get(payload.username);
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
        console.error('Failed to authenticate user', payload.username);
        conn.sendUTF('Failed to authenticate');
        return;
    }
    

    // check passwords
    if (msg === userPass) {
        console.log('The passwords match!!!');
        const respIv = crypto.randomBytes(12);
        const respCipher = crypto.createCipheriv('aes-256-gcm', aesKey, respIv);

        let endText = respCipher.update(Buffer.from('Felicitari'));
        endText = Buffer.concat([endText, respCipher.final(), respCipher.getAuthTag()]);
        conn.sendUTF(JSON.stringify({
            iv: [...respIv],
            message: [...endText]
        }));
    } else {
        console.warn(`The passwords are different: ${msg} /\\ ${userPass}`);
        conn.sendUTF('Something wrong happened');
    }
}

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
