const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bodyParser = require('body-parser');
const { pool, initDatabase } = require('./database');
const { createDynamicService } = require('./serviceGenerator');
const { getAttackerProfile } = require('./profiler');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

app.use(cors());
app.use(bodyParser.json());

app.get('/api/attacks', async (req, res) => {
    try {
        const [attacks] = await pool.query('SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 100');
        res.json(attacks);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/profiles', async (req, res) => {
    try {
        const [profiles] = await pool.query('SELECT * FROM attacker_profiles ORDER BY threat_score DESC');
        res.json(profiles.map(p => ({
            ...p,
            tools_detected: JSON.parse(p.tools_detected || '[]'),
            ttps: JSON.parse(p.ttps || '[]'),
            profile_data: JSON.parse(p.profile_data || '{}')
        })));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/profiles/:ip', async (req, res) => {
    try {
        const profile = await getAttackerProfile(req.params.ip);
        res.json(profile || {});
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/services', async (req, res) => {
    try {
        const [services] = await pool.query('SELECT * FROM dynamic_services WHERE active = 1');
        res.json(services);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/services/create', async (req, res) => {
    const { serviceType, port } = req.body;
    if (!serviceType || !port) {
        return res.status(400).json({ success: false, error: 'serviceType and port are required' });
    }
    try {
        await createDynamicService(serviceType, parseInt(port), io);
        res.json({ success: true, message: `${serviceType} service created on port ${port}` });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/api/threat-report', async (req, res) => {
    try {
        const [[{ total: totalAttacks }]] = await pool.query('SELECT COUNT(*) as total FROM attacks');
        const [[{ total: uniqueAttackers }]] = await pool.query('SELECT COUNT(*) as total FROM attacker_profiles');
        const [[{ total: highThreatAttackers }]] = await pool.query('SELECT COUNT(*) as total FROM attacker_profiles WHERE threat_score >= 70');
        const [[{ total: activeServices }]] = await pool.query('SELECT COUNT(*) as total FROM dynamic_services WHERE active = 1');
        const [attacksByService] = await pool.query('SELECT service_type, COUNT(*) as count FROM attacks GROUP BY service_type');

        res.json({ totalAttacks, uniqueAttackers, highThreatAttackers, activeServices, attacksByService, generatedAt: new Date() });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/export/attacks', async (req, res) => {
    try {
        const [attacks] = await pool.query('SELECT * FROM attacks ORDER BY timestamp DESC');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=attacks.csv');
        let csv = 'ID,IP,Port,Service,Timestamp,Payload,ThreatLevel\n';
        attacks.forEach(a => {
            const payload = (a.payload || '').replace(/"/g, '""');
            csv += `${a.id},"${a.ip}",${a.port},"${a.service_type}","${a.timestamp}","${payload}","${a.threat_level}"\n`;
        });
        res.send(csv);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/export/profiles', async (req, res) => {
    try {
        const [profiles] = await pool.query('SELECT * FROM attacker_profiles ORDER BY threat_score DESC');
        res.json(profiles.map(p => ({
            ...p,
            tools_detected: JSON.parse(p.tools_detected || '[]'),
            ttps: JSON.parse(p.ttps || '[]'),
            profile_data: JSON.parse(p.profile_data || '{}')
        })));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

io.on('connection', (socket) => {
    console.log('Dashboard client connected');
    socket.on('disconnect', () => console.log('Dashboard client disconnected'));
});

const PORT = 5000;

initDatabase()
    .then(() => {
        server.listen(PORT, () => {
            console.log(`AI Honeypot Backend running on port ${PORT}`);
            console.log(`WebSocket server ready for real-time updates`);
        });
        createDynamicService('ssh', 2222, io);
        createDynamicService('mysql', 3307, io);
        createDynamicService('ftp', 2121, io);
    })
    .catch(err => {
        console.error('Failed to initialize database:', err);
        process.exit(1);
    });
