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
const userAesKeys = new Map();
const messagesLog = new Array();
const clients = new Array();

// TEST VALUE, to be removed
keys.set('gica', Buffer.from('testkey123', 'utf8'));
keys.set('marica', Buffer.from('testus123', 'utf8'));
keys.set('gogu', Buffer.from('buncareala123', 'utf8'));
keys.set('bogu', Buffer.from('passs1234', 'utf8'));

ws.on('request', req => {
    const connection = req.accept(null, req.origin);

    connection.on('message', data => {
        console.log('Received message:', data);
        const payload = JSON.parse(data.utf8Data);

        // may need to change this logic
        if (!clients.find(c => c.username === payload.username)) {
            clients.push({username: payload.username, connection: connection});
        }

        console.log('Payload:', payload);
        // convert arrays to typed arrays / buffers
        payload.salt = Buffer.from(payload.salt);
        payload.iv = Buffer.from(payload.iv);
        payload.message = Buffer.from(payload.message);

        // encryption: PBKDF2 + AES
        if (payload.action === 'sendmsg') {
            const aesKey = generateAesKey(payload.salt, keys.get(payload.username));
            userAesKeys.set(payload.username, aesKey);
            const decrypted = decryptMessage(aesKey, payload.iv, payload.message).toString('utf8');
            const saveObj = {
                username: payload.username,
                message: decrypted,
                timestamp: Date.now()
            };

            console.log('Decrypted message:', saveObj);

            messagesLog.push(saveObj);
            console.log(`Number of clients to send: ${clients.length}`);
            for (let c of clients) {
                console.log(`Sending to client ${c.username}`);
                const userKey = userAesKeys.get(c.username);
                const iv = crypto.randomBytes(12);
                const msg = encryptMessage(userKey, iv, Buffer.from(JSON.stringify(saveObj), 'utf8'));
                const refreshAes = crypto.randomBytes(32);
                const objToSend = {
                    action: 'new-msg',
                    succeeded: true,
                    iv: [...iv],
                    refreshKey: [...refreshAes],
                    message: [...msg]
                };
                console.log('Obj to send:', objToSend);
                c.connection.sendUTF(JSON.stringify(objToSend));
                keys.set(c.username, refreshAes);
                console.log(`Sent to ${c.username}:`, objToSend);
            };
        }
    });

    connection.on('close', (reason, desc) => {
        console.log('Client disconnected:', reason, desc);
        clients.splice(clients.findIndex(c => c === connection), 1);
    });

    connection.on('error', err => {
        console.warn('Error:', err);
    });

    // also has binds for 'ping' and 'pong'
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
    return Buffer.concat([decrypted, decipher.final()]);
}

function encryptMessage(key, iv, msg) {
    console.log('Raw msg:', msg);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(msg);

    return Buffer.concat([encrypted, cipher.final(), cipher.getAuthTag()]);
}
