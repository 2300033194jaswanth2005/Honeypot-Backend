const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const path = require('path');

let db;

async function getDb() {
    if (!db) {
        db = await open({
            filename: path.join(__dirname, 'honeypot.db'),
            driver: sqlite3.Database
        });
        await db.run('PRAGMA journal_mode = WAL');
    }
    return db;
}

const pool = {
    query: async (sql, params = []) => {
        const database = await getDb();
        const trimmed = sql.trim().toUpperCase();
        if (trimmed.startsWith('SELECT')) {
            const rows = await database.all(sql, params);
            return [rows];
        }
        if (trimmed.startsWith('INSERT') || trimmed.startsWith('UPDATE') || trimmed.startsWith('DELETE')) {
            const result = await database.run(sql, params);
            return [result];
        }
        await database.exec(sql);
        return [[]];
    }
};

async function initDatabase() {
    const database = await getDb();
    try {
        await database.exec(`
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                port INTEGER,
                service_type TEXT,
                timestamp DATETIME DEFAULT (datetime('now','localtime')),
                payload TEXT,
                threat_level TEXT DEFAULT 'medium'
            )
        `);

        await database.exec(`
            CREATE TABLE IF NOT EXISTS attacker_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE,
                first_seen DATETIME DEFAULT (datetime('now','localtime')),
                last_seen DATETIME DEFAULT (datetime('now','localtime')),
                attack_count INTEGER DEFAULT 1,
                tools_detected TEXT DEFAULT '[]',
                ttps TEXT DEFAULT '[]',
                threat_score INTEGER DEFAULT 0,
                country TEXT,
                profile_data TEXT DEFAULT '{}'
            )
        `);

        await database.exec(`
            CREATE TABLE IF NOT EXISTS dynamic_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT,
                port INTEGER UNIQUE,
                protocol TEXT DEFAULT 'tcp',
                banner TEXT,
                active INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT (datetime('now','localtime'))
            )
        `);

        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Database init error:', error);
        throw error;
    }
}

module.exports = { pool, initDatabase };
