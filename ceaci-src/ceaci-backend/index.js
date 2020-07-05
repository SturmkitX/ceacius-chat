const http = require('http');
const websocket = require('websocket').server;
const crypto = require('crypto');
const { type } = require('os');
const sqlite3 = require('sqlite3').verbose();

const PORT = process.env.PORT || 21567;

const server = http.createServer();
server.listen(PORT, '127.0.0.1');
console.log('Started server');

const ws = new websocket({
    httpServer: server
});

const keys = new Map();
const userAesKeys = new Map();
const clients = new Array();

const db = new sqlite3.Database('./chat.db', (err) => {
    if (err) {
        throw err;
    }

    // update intenal list of keys
    db.all('SELECT name, password FROM users', (err, rows) => {
        if (err) {
            throw err;
        }

        for (let row of rows) {
            keys.set(row.name, row.password);
        }
    })

    process.on('exit', () => db.close());
});

// clear messages log every 6 hours
setInterval(() => db.run('DELETE FROM messages'), 1000 * 3600 * 6);

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

            db.run('INSERT INTO messages (name, timestamp, type, strmsg) VALUES (?, ?, ?, ?)',
                [saveObj.username, saveObj.timestamp, 'text', saveObj.decrypted]);
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
                db.run('UPDATE users SET password = ? WHERE name = ?', [refreshAes, payload.username]);

                console.log(`Sent to ${c.username}:`, objToSend);
            };
        } else if (payload.action === 'fetch') {
            const aesKey = generateAesKey(payload.salt, keys.get(payload.username));
            userAesKeys.set(payload.username, aesKey);
            const decrypted = decryptMessage(aesKey, payload.iv, payload.message).toString('utf8');

            if (decrypted === 'WASSUP') {
                console.log('Received correct message');
            } else {
                console.warn('Impostor detected!');
                connection.close();
                return;
            }

            db.all('SELECT name, timestamp, type, strmsg FROM messages', (err, rows) => {
                if (err) {
                    throw err;
                }

                const messagesLog = rows.map(r => new {
                    username: r.name,
                    timestamp: r.timestamp,
                    type: type,
                    message: r.strmsg
                });

                console.log(`Sending to client ${payload.username}`);
                const userKey = userAesKeys.get(payload.username);
                const iv = crypto.randomBytes(12);
                const msg = encryptMessage(userKey, iv, Buffer.from(JSON.stringify(messagesLog), 'utf8'));
                const refreshAes = crypto.randomBytes(32);
                const objToSend = {
                    action: 'fetch-response',
                    succeeded: true,
                    iv: [...iv],
                    refreshKey: [...refreshAes],
                    message: [...msg]
                };
                console.log('Obj to send:', objToSend);
                connection.sendUTF(JSON.stringify(objToSend));

                keys.set(payload.username, refreshAes);
                db.run('UPDATE users SET password = ? WHERE name = ?', [refreshAes, payload.username]);

                console.log(`Sent to ${payload.username}:`, objToSend);
            });
            
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
