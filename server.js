const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bodyParser = require('body-parser');
const { pool, initDatabase } = require('./database');
const { createDynamicService, handlePortScan } = require('./serviceGenerator');
const { getAttackerProfile } = require('./profiler');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: '*' }
});

app.use(cors());
app.use(bodyParser.json());

app.get('/api/attacks', async (req, res) => {
    const [attacks] = await pool.query(
        'SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 100'
    );
    res.json(attacks);
});

app.get('/api/profiles', async (req, res) => {
    const [profiles] = await pool.query(
        'SELECT * FROM attacker_profiles ORDER BY threat_score DESC'
    );
    res.json(profiles.map(p => ({
        ...p,
        tools_detected: JSON.parse(p.tools_detected || '[]'),
        ttps: JSON.parse(p.ttps || '[]'),
        profile_data: JSON.parse(p.profile_data || '{}')
    })));
});

app.get('/api/profiles/:ip', async (req, res) => {
    const profile = await getAttackerProfile(req.params.ip);
    res.json(profile);
});

app.get('/api/services', async (req, res) => {
    const [services] = await pool.query(
        'SELECT * FROM dynamic_services WHERE active = TRUE'
    );
    res.json(services);
});

app.post('/api/services/create', async (req, res) => {
    const { serviceType, port } = req.body;
    try {
        await createDynamicService(serviceType, port, io);
        res.json({ success: true, message: `${serviceType} service created on port ${port}` });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.get('/api/threat-report', async (req, res) => {
    const [attacks] = await pool.query('SELECT COUNT(*) as total FROM attacks');
    const [profiles] = await pool.query('SELECT COUNT(*) as total FROM attacker_profiles');
    const [highThreat] = await pool.query(
        'SELECT COUNT(*) as total FROM attacker_profiles WHERE threat_score >= 70'
    );
    const [services] = await pool.query('SELECT COUNT(*) as total FROM dynamic_services');
    const [recentAttacks] = await pool.query(
        'SELECT service_type, COUNT(*) as count FROM attacks GROUP BY service_type'
    );
    
    res.json({
        totalAttacks: attacks[0].total,
        uniqueAttackers: profiles[0].total,
        highThreatAttackers: highThreat[0].total,
        activeServices: services[0].total,
        attacksByService: recentAttacks,
        generatedAt: new Date()
    });
});

app.get('/api/export/attacks', async (req, res) => {
    const [attacks] = await pool.query('SELECT * FROM attacks');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=attacks.csv');
    
    let csv = 'ID,IP,Port,Service,Timestamp,Payload,ThreatLevel\n';
    attacks.forEach(a => {
        csv += `${a.id},"${a.ip}",${a.port},"${a.service_type}","${a.timestamp}","${a.payload}","${a.threat_level}"\n`;
    });
    res.send(csv);
});

app.get('/api/export/profiles', async (req, res) => {
    const [profiles] = await pool.query('SELECT * FROM attacker_profiles');
    res.json(profiles.map(p => ({
        ...p,
        tools_detected: JSON.parse(p.tools_detected || '[]'),
        ttps: JSON.parse(p.ttps || '[]')
    })));
});

io.on('connection', (socket) => {
    console.log('Client connected to real-time feed');
    socket.on('disconnect', () => console.log('Client disconnected'));
});

initDatabase().then(() => {
    createDynamicService('ssh', 2222, io);
    createDynamicService('mysql', 3307, io);
    createDynamicService('ftp', 2121, io);
});

const PORT = 5000;
server.listen(PORT, () => {
    console.log(`AI Honeypot Backend running on port ${PORT}`);
    console.log(`WebSocket server ready for real-time updates`);
});
