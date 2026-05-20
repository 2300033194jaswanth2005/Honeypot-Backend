const net = require('net');
const { pool } = require('./database');
const { profileAttacker } = require('./profiler');

const serviceTemplates = {
    mysql: { banner: 'MySQL Server 5.7.33\r\n', responses: { default: 'ERROR 1045: Access denied\r\n' } },
    ssh: { banner: 'SSH-2.0-OpenSSH_7.4\r\n', responses: { default: 'Permission denied\r\n' } },
    ftp: { banner: '220 FTP Server Ready\r\n', responses: { USER: '331 Password required\r\n', PASS: '530 Login incorrect\r\n', default: '530 Login incorrect\r\n' } },
    http: { banner: 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html><body>Apache</body></html>', responses: { default: 'HTTP/1.1 403 Forbidden\r\n\r\n' } },
    telnet: { banner: 'Ubuntu 20.04 LTS\r\nlogin: ', responses: { default: 'Login incorrect\r\n' } },
    smtp: { banner: '220 mail.example.com ESMTP\r\n', responses: { default: '554 Access denied\r\n' } },
    generic: { banner: 'Service Ready\r\n', responses: { default: 'Access Denied\r\n' } }
};

const activeServices = new Map();

function createDynamicService(serviceType, targetPort, io) {
    if (activeServices.has(targetPort)) return activeServices.get(targetPort);

    const template = serviceTemplates[serviceType] || serviceTemplates.generic;

    const server = net.createServer((socket) => {
        const clientIp = socket.remoteAddress || 'unknown';
        socket.setTimeout(30000);
        socket.on('timeout', () => socket.destroy());
        socket.on('error', () => socket.destroy());
        try { socket.write(template.banner); } catch (e) { return; }

        socket.on('data', (data) => {
            const payload = data.toString().trim();
            if (!payload) return;
            try {
                pool.query('insertAttack', { ip: clientIp, port: targetPort, service_type: serviceType, payload: payload.substring(0, 500), threat_level: 'medium' });
                profileAttacker(clientIp, serviceType, payload);
                io.emit('attack', { ip: clientIp, port: targetPort, service: serviceType, service_type: serviceType, payload: payload.substring(0, 100), timestamp: new Date(), threat_level: 'medium' });
                const cmdKey = payload.split(' ')[0].toUpperCase();
                socket.write(template.responses[cmdKey] || template.responses.default);
            } catch (err) {
                console.error(`Error on port ${targetPort}:`, err.message);
            }
        });
    });

    server.on('error', (err) => {
        console.error(`Service error on port ${targetPort}: ${err.message}`);
        activeServices.delete(targetPort);
    });

    server.listen(targetPort, '0.0.0.0', () => {
        console.log(`Dynamic ${serviceType} service spawned on port ${targetPort}`);
    });

    pool.query('insertService', { service_name: serviceType, port: targetPort, protocol: 'tcp', banner: template.banner.substring(0, 100) });
    activeServices.set(targetPort, { server, serviceType });
    io.emit('service-created', { service: serviceType, port: targetPort, timestamp: new Date() });
    return { server, serviceType };
}

module.exports = { createDynamicService, activeServices };
