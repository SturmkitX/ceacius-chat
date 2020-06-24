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
const aesKeys = new Map();
const messagesLog = new Array();
const clients = new Array();

// TEST VALUE, to be removed
keys.set('gica', 'testkey123');

ws.on('request', req => {
    const connection = req.accept(null, req.origin);
    clients.push(connection);

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
        // encryption: PBKDF2 + AES
        if (payload.action === 'sendmsg') {
            console.log('Received message to broadcast');
            const aesKey = generateAesKey(payload.salt, keys.get(payload.username));
            const decrypted = decryptMessage(aesKey, payload.iv, payload.message).toString('utf8');
            const saveObj = {
                username: payload.username,
                message: decrypted,
                timestamp: Date.now()
            };

            console.log('Decrypted message:', saveObj);

            messagesLog.push(saveObj);
            clients.forEach(c => {
                const iv = crypto.randomBytes(12);
                const msg = encryptMessage(aesKey, iv, Buffer.from(JSON.stringify(saveObj), 'utf8'));
                const objToSend = {
                    action: 'new-msg',
                    succeeded: true,
                    iv: [...iv],
                    message: [...msg]
                };
                console.log('Obj to send:', objToSend);
                c.sendUTF(JSON.stringify(objToSend));
            });
        }
    });

    connection.on('close', (reason, desc) => {
        console.log('Client disconnected:', reason, desc);
        clients.splice(clients.findIndex(c => c === connection));
    });

    connection.on('error', err => {
        console.warn('Error:', err);
    });

    // also has binds for 'ping' and 'pong'
});

function authenticateUser(conn, payload) {
    const userPass = keys.get(payload.username);
    const aesKey = generateAesKey(payload.salt, userPass);
    console.log('AES Key: ', aesKey);

    let msg;
    try {
        msg = decryptMessage(aesKey, payload.iv, payload.message);
    } catch (_) {
        console.error('Failed to authenticate user', payload.username);
        conn.sendUTF(JSON.stringify({
            action: 'authenticate-response',
            succeeded: false
        }));
        return;
    }
    

    // check passwords
    if (msg.toString('utf8') === userPass) {
        console.log('The passwords match!!!');
        const respIv = crypto.randomBytes(12);
        const respCipher = crypto.createCipheriv('aes-256-gcm', aesKey, respIv);

        const refreshAesKey = crypto.randomBytes(32);
        const refreshAuthKey = crypto.randomBytes(16);

        let endText = respCipher.update(Buffer.from(JSON.stringify({
            refreshAesKey: [...refreshAesKey],
            refreshAuthKey: [...refreshAuthKey]
        })));
        // aesKeys.set(payload.username, refreshAesKey);
        // keys.set(payload.username, refreshAuthKey);

        endText = Buffer.concat([endText, respCipher.final(), respCipher.getAuthTag()]);
        conn.sendUTF(JSON.stringify({
            iv: [...respIv],
            message: [...endText],
            action: 'authenticate-response',
            succeeded: true
        }));
    } else {
        console.warn(`The passwords are different: ${msg} /\\ ${userPass}`);
        conn.sendUTF(JSON.stringify({
            action: 'authenticate-response',
            succeeded: false
        }));
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
    return Buffer.concat([decrypted, decipher.final()]);
}

function encryptMessage(key, iv, msg) {
    console.log('Raw msg:', msg);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(msg);

    return Buffer.concat([encrypted, cipher.final(), cipher.getAuthTag()]);
}
