const crypto = window.crypto;
const subtle = crypto.subtle;

const password = 'testkey123';
const conn = new WebSocket(`wss://${window.location.hostname}/chat/`);

let currentKey = undefined;

conn.addEventListener('open', () => {
    console.log('Successfully opened WS connection!');
    startEncryption();
});

conn.addEventListener('message', event => {
    console.log('Received message:', event);
    const payload = JSON.parse(event.data);

    console.log(payload.iv.constructor.name);
    console.log(payload.message.constructor.name)
    subtle.decrypt({
        name: 'AES-GCM',
        iv: new Uint8Array(payload.iv),
        tagLength: 128
    }, currentKey, new Uint8Array(payload.message)).then(decoded => {
        console.log('Decoded message:', new TextDecoder().decode(decoded));
    }).catch(err => {
        throw err;
    });
});

conn.addEventListener('error', err => {
    console.log('WS error:', err);
});

function startEncryption() {
    console.log('Generating salts');
    generateAes().then(keySalt => {
        // Send the encrypted message
        const key = keySalt.key;
        const salt = keySalt.salt;
        currentKey = key;

        const iv = crypto.getRandomValues(new Uint8Array(12));
        subtle.encrypt({
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128
        }, key, new TextEncoder().encode(password))
        .then(msg => {
            // send message to the server
            // req.addEventListener('load', () => decryptMessage(req, key));
            conn.send(JSON.stringify({
                username: 'gica',
                action: 'authenticate',
                iv: Array.from(iv),
                salt: Array.from(salt),
                message: Array.from(new Uint8Array(msg))
            }));
        }).catch(err => {
            throw err;
        });
    });
    
}

async function decryptMessage(req, key) {
    const response = JSON.parse(req.responseText);
    const rawMsg = await subtle.decrypt({
        name: 'AES-GCM',
        iv: response.iv
    }, key, response.message);

    console.log('Received message', new TextDecoder().decode(rawMsg));
};

async function generateAes() {
    const salt1 = crypto.getRandomValues(new Uint8Array(32));

    console.log('Generated salts!');
    console.log(salt1);

    // Import key
    const kdfkey = await subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);

    console.log('Generated PBK key:');
    console.log(kdfkey);

    console.log('Deriving key...');
    const aesKey = await subtle.deriveKey({
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: salt1,
        iterations: 50_000
    }, kdfkey, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    console.log('Successfully generated AES key!');
    console.log(aesKey);

    const expAes = await subtle.exportKey('raw', aesKey);
    console.log('AES Key:', new Uint8Array(expAes));

    return {
        key: aesKey,
        salt: salt1
    };
}
