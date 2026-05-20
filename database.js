const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const path = require('path');

const dbPath = process.env.VERCEL ? '/tmp/honeypot.json' : path.join(__dirname, 'honeypot.json');
const adapter = new FileSync(dbPath);
const db = low(adapter);

function initDatabase() {
    db.defaults({
        attacks: [],
        attacker_profiles: [],
        dynamic_services: []
    }).write();
    console.log('Database initialized successfully');
}

const pool = {
    query: (type, data) => {
        switch (type) {
            case 'getAttacks':
                return db.get('attacks').orderBy('timestamp', 'desc').take(100).value();
            case 'insertAttack':
                db.get('attacks').push({
                    id: Date.now(),
                    ip: data.ip,
                    port: data.port,
                    service_type: data.service_type,
                    timestamp: new Date().toLocaleString(),
                    payload: data.payload,
                    threat_level: data.threat_level || 'medium'
                }).write();
                return true;
            case 'getProfiles':
                return db.get('attacker_profiles').orderBy('threat_score', 'desc').value();
            case 'getProfileByIp':
                return db.get('attacker_profiles').find({ ip: data.ip }).value();
            case 'insertProfile':
                db.get('attacker_profiles').push(data).write();
                return true;
            case 'updateProfile':
                db.get('attacker_profiles').find({ ip: data.ip }).assign(data).write();
                return true;
            case 'getServices':
                return db.get('dynamic_services').filter({ active: true }).value();
            case 'insertService':
                if (!db.get('dynamic_services').find({ port: data.port }).value()) {
                    db.get('dynamic_services').push({
                        id: Date.now(),
                        service_name: data.service_name,
                        port: data.port,
                        protocol: data.protocol || 'tcp',
                        banner: data.banner,
                        active: true,
                        created_at: new Date().toLocaleString()
                    }).write();
                }
                return true;
            case 'countAttacks':
                return db.get('attacks').size().value();
            case 'countProfiles':
                return db.get('attacker_profiles').size().value();
            case 'countHighThreat':
                return db.get('attacker_profiles').filter(p => p.threat_score >= 70).size().value();
            case 'countServices':
                return db.get('dynamic_services').filter({ active: true }).size().value();
            case 'attacksByService':
                const attacks = db.get('attacks').value();
                const grouped = {};
                attacks.forEach(a => {
                    grouped[a.service_type] = (grouped[a.service_type] || 0) + 1;
                });
                return Object.entries(grouped).map(([service_type, count]) => ({ service_type, count }));
            case 'getAllAttacks':
                return db.get('attacks').orderBy('timestamp', 'desc').value();
            case 'getAllProfiles':
                return db.get('attacker_profiles').orderBy('threat_score', 'desc').value();
            default:
                return null;
        }
    }
};

module.exports = { pool, initDatabase };
