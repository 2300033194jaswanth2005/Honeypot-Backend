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

initDatabase();

app.get('/api/attacks', (req, res) => {
    try { res.json(pool.query('getAttacks')); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/profiles', (req, res) => {
    try { res.json(pool.query('getProfiles')); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/profiles/:ip', (req, res) => {
    try { res.json(getAttackerProfile(req.params.ip) || {}); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/services', (req, res) => {
    try { res.json(pool.query('getServices')); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/services/create', (req, res) => {
    const { serviceType, port } = req.body;
    if (!serviceType || !port) return res.status(400).json({ success: false, error: 'serviceType and port required' });
    try {
        createDynamicService(serviceType, parseInt(port), io);
        res.json({ success: true, message: `${serviceType} service created on port ${port}` });
    } catch (err) {
        res.status(500).json({ success: false, error: err.message });
    }
});

app.get('/api/threat-report', (req, res) => {
    try {
        res.json({
            totalAttacks: pool.query('countAttacks'),
            uniqueAttackers: pool.query('countProfiles'),
            highThreatAttackers: pool.query('countHighThreat'),
            activeServices: pool.query('countServices'),
            attacksByService: pool.query('attacksByService'),
            generatedAt: new Date()
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/export/attacks', (req, res) => {
    try {
        const attacks = pool.query('getAllAttacks');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=attacks.csv');
        let csv = 'ID,IP,Port,Service,Timestamp,Payload,ThreatLevel\n';
        attacks.forEach(a => {
            csv += `${a.id},"${a.ip}",${a.port},"${a.service_type}","${a.timestamp}","${(a.payload||'').replace(/"/g,'""')}","${a.threat_level}"\n`;
        });
        res.send(csv);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/export/profiles', (req, res) => {
    try { res.json(pool.query('getAllProfiles')); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

io.on('connection', (socket) => {
    console.log('Dashboard client connected');
    socket.on('disconnect', () => console.log('Dashboard client disconnected'));
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`AI Honeypot Backend running on port ${PORT}`);
});

createDynamicService('ssh', 2222, io);
createDynamicService('mysql', 3307, io);
createDynamicService('ftp', 2121, io);
