const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

let db;

async function getDb() {
    if (!db) {
        db = await open({
            filename: './honeypot.db',
            driver: sqlite3.Database
        });
    }
    return db;
}

const pool = {
    query: async (sql, params) => {
        const database = await getDb();
        if (sql.trim().toUpperCase().startsWith('SELECT')) {
            const rows = await database.all(sql, params);
            return [rows];
        }
        const result = await database.run(sql, params);
        return [result];
    }
};

async function initDatabase() {
    const database = await getDb();
    try {
        await database.exec(`
            CREATE TABLE IF NOT EXISTS attacks (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip VARCHAR(45),
                port INT,
                service_type VARCHAR(50),
                timestamp DATETIME DEFAULT (datetime('now')),
                payload TEXT,
                threat_level VARCHAR(20)
            )
        `);
        
        await database.exec(`
            CREATE TABLE IF NOT EXISTS attacker_profiles (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip VARCHAR(45) UNIQUE,
                first_seen DATETIME DEFAULT (datetime('now')),
                last_seen DATETIME DEFAULT (datetime('now')),
                attack_count INT DEFAULT 1,
                tools_detected TEXT,
                ttps TEXT,
                threat_score INT DEFAULT 0,
                country VARCHAR(50),
                profile_data JSON
            )
        `);
        
        await database.exec(`
            CREATE TABLE IF NOT EXISTS dynamic_services (
                id INT AUTO_INCREMENT PRIMARY KEY,
                service_name VARCHAR(50),
                port INT,
                protocol VARCHAR(20),
                banner TEXT,
                active BOOLEAN DEFAULT TRUE,
                created_at DATETIME DEFAULT (datetime('now'))
            )
        `);
        
        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Database init error:', error);
    }
}

module.exports = { pool, initDatabase };
