const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./chat.db');

createUsersDatabase();
createMessagesDatabase();

function createUsersDatabase() {
    db.run('CREATE TABLE users (name text, password blob)', err => {
        if (err) {
            console.error(err);
            return;
        }
        db.run('INSERT INTO users (name, password) VALUES (?, ?)', ['gica', Buffer.from('testkey123', 'utf8')]);
        db.run('INSERT INTO users (name, password) VALUES (?, ?)', ['marica', Buffer.from('testus123', 'utf8')]);
        db.run('INSERT INTO users (name, password) VALUES (?, ?)', ['gogu', Buffer.from('buncareala123', 'utf8')]);
        db.run('INSERT INTO users (name, password) VALUES (?, ?)', ['bogu', Buffer.from('passs1234', 'utf8')]);
    });
}

function createMessagesDatabase() {
    db.run('CREATE TABLE messages (name text, timestamp integer, type text, strmsg text, blobmsg blob)');
}