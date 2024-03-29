const crypto = window.crypto;
const subtle = crypto.subtle;

// should add a MASTER password for encrypting / decrypting these values in the user space
// so they aren't plain text

let sessionUser = undefined;
let sessionPass = undefined;

if (localStorage.getItem('username') && localStorage.getItem('password')) {
    sessionUser = localStorage.getItem('username');
    sessionPass = new Uint8Array(JSON.parse(atob(localStorage.getItem('password'))));
    console.log('Already logged in.');
} else {
    console.log('No credentials saved locally.');
}

window.addEventListener('load', () => {
    document.getElementById('checkLoginBtn').addEventListener('click', () => {
        sessionUser = document.getElementById('userField').value;
        sessionPass = new TextEncoder().encode(document.getElementById('passField').value);

        localStorage.setItem('username', sessionUser);
        localStorage.setItem('password', btoa(JSON.stringify(Array.from(sessionPass))));

        console.log('Successfully set session variables!');

        fetchMessages();
    });
    document.getElementById('sendMsgBtn').addEventListener('click', 
        () => sendMessage(document.getElementById('msgInput').value)
    );
});

const conn = new WebSocket(`wss://${window.location.hostname}/chat/`);

let currentKey = undefined;

conn.addEventListener('open', () => {
    console.log('Successfully opened WS connection!');
    if (localStorage.getItem('username') && localStorage.getItem('password')) {
        fetchMessages();
    }
});

conn.addEventListener('message', event => {
    console.log('Received message:', event);
    const payload = JSON.parse(event.data);

    if (payload.succeeded === false) {
        console.error('Failed to decode data');
        conn.close();
        return;
    }

    subtle.decrypt({
        name: 'AES-GCM',
        iv: new Uint8Array(payload.iv)
    }, currentKey, new Uint8Array(payload.message)).then(decoded => {
        const status = JSON.parse(new TextDecoder().decode(decoded));
        console.log('Decoded message:', status);

        switch (payload.action) {
            case 'new-msg': {
                printIncomingMessage([status]);
            }; break;
            case 'fetch-response': {
                listAllPreviousMessages(status);
            }
        }

        sessionPass = new Uint8Array(payload.refreshKey);

        localStorage.setItem('password', btoa(JSON.stringify(Array.from(sessionPass))));
    }).catch(err => {
        console.error(err);
        throw err;
    });
});

conn.addEventListener('error', err => {
    console.log('WS error:', err);
});

function printIncomingMessage(messages) {
    // Format (status.message): {username: string, message: string, timestamp: number}
    console.log('New messages:', messages);
    const table = document.getElementById('msgLogTable');

    for (let status of messages) {
        const row = document.createElement('tr');

        let rowData = document.createElement('td');
        rowData.innerHTML = status.timestamp;
        row.appendChild(rowData);
    
        rowData = document.createElement('td');
        rowData.innerHTML = status.username;
        row.appendChild(rowData);
    
        rowData = document.createElement('td');
        rowData.innerHTML = status.message;
        row.appendChild(rowData);
    
        table.appendChild(row);
    }
}

function listAllPreviousMessages(status) {
    console.log('Message log for today:', status);
    printIncomingMessage(status);
}

async function generateAes() {
    console.log('Generating salts');
    const salt1 = crypto.getRandomValues(new Uint8Array(32));

    console.log('Generated salts!');
    // console.log(salt1);

    // Import key
    const kdfkey = await subtle.importKey('raw', sessionPass, 'PBKDF2', false, ['deriveKey']);

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

function sendMessage(input) {
    generateAes().then(keySalt => {
        currentKey = keySalt.key;
        const iv = crypto.getRandomValues(new Uint8Array(12));

        subtle.encrypt({
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128
        }, currentKey, new TextEncoder().encode(input)).then(payload => {
            conn.send(JSON.stringify({
                username: sessionUser,
                action: 'sendmsg',
                iv: Array.from(iv),
                salt: Array.from(keySalt.salt),
                message: Array.from(new Uint8Array(payload))
            }));
        });
    });
}

function fetchMessages() {
    generateAes().then(keySalt => {
        currentKey = keySalt.key;
        const iv = crypto.getRandomValues(new Uint8Array(12));

        subtle.encrypt({
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128
        }, currentKey, new TextEncoder().encode('WASSUP')).then(payload => {
            conn.send(JSON.stringify({
                username: sessionUser,
                action: 'fetch',
                iv: Array.from(iv),
                salt: Array.from(keySalt.salt),
                message: Array.from(new Uint8Array(payload))
            }));
        });
    });
}
