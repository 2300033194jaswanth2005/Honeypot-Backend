const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bodyParser = require('body-parser');
const { pool, initDatabase } = require('./database');
const { getAttackerProfile } = require('./profiler');
const { profileAttacker } = require('./profiler');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: '*' },
    transports: ['polling'],
    allowUpgrades: false
});

app.use(cors());
app.use(bodyParser.json());

initDatabase();

app.get('/api/attacks', (req, res) => {
    try { res.json(pool.query('getAttacks') || []); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/profiles', (req, res) => {
    try { res.json(pool.query('getProfiles') || []); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/profiles/:ip', (req, res) => {
    try { res.json(getAttackerProfile(req.params.ip) || {}); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/services', (req, res) => {
    try { res.json(pool.query('getServices') || []); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/services/create', (req, res) => {
    const { serviceType, port } = req.body;
    if (!serviceType || !port) return res.status(400).json({ success: false, error: 'serviceType and port required' });
    try {
        pool.query('insertService', { service_name: serviceType, port: parseInt(port), protocol: 'tcp', banner: `${serviceType} honeypot` });
        io.emit('service-created', { service: serviceType, port, timestamp: new Date() });
        res.json({ success: true, message: `${serviceType} service registered on port ${port}` });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.post('/api/simulate-attack', (req, res) => {
    try {
        const services = ['ssh', 'ftp', 'mysql', 'http', 'telnet', 'smtp'];
        const payloads = ['root:password', 'admin:admin123', 'USER anonymous', 'GET / HTTP/1.1', 'EHLO attacker.com', 'SELECT * FROM users'];
        const ips = ['192.168.1.' + Math.floor(Math.random() * 254 + 1), '10.0.0.' + Math.floor(Math.random() * 254 + 1), '172.16.0.' + Math.floor(Math.random() * 254 + 1)];
        const service = services[Math.floor(Math.random() * services.length)];
        const ip = ips[Math.floor(Math.random() * ips.length)];
        const payload = payloads[Math.floor(Math.random() * payloads.length)];
        const ports = { ssh: 2222, ftp: 2121, mysql: 3307, http: 8080, telnet: 2323, smtp: 2525 };

        pool.query('insertAttack', { ip, port: ports[service], service_type: service, payload, threat_level: 'medium' });
        profileAttacker(ip, service, payload);

        const attack = { ip, port: ports[service], service, service_type: service, payload, timestamp: new Date(), threat_level: 'medium' };
        io.emit('attack', attack);
        res.json({ success: true, attack });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/threat-report', (req, res) => {
    try {
        res.json({
            totalAttacks: pool.query('countAttacks') || 0,
            uniqueAttackers: pool.query('countProfiles') || 0,
            highThreatAttackers: pool.query('countHighThreat') || 0,
            activeServices: pool.query('countServices') || 0,
            attacksByService: pool.query('attacksByService') || [],
            generatedAt: new Date()
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/export/attacks', (req, res) => {
    try {
        const attacks = pool.query('getAllAttacks') || [];
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=attacks.csv');
        let csv = 'ID,IP,Port,Service,Timestamp,Payload,ThreatLevel\n';
        attacks.forEach(a => {
            csv += `${a.id},"${a.ip}",${a.port},"${a.service_type}","${a.timestamp}","${(a.payload || '').replace(/"/g, '""')}","${a.threat_level}"\n`;
        });
        res.send(csv);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/export/profiles', (req, res) => {
    try { res.json(pool.query('getAllProfiles') || []); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

io.on('connection', (socket) => {
    console.log('Dashboard client connected');
    socket.on('disconnect', () => console.log('Dashboard client disconnected'));
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`AI Honeypot Backend running on port ${PORT}`));

module.exports = app;
