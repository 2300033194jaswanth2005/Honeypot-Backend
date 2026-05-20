const net = require('net');
const { pool } = require('./database');
const { profileAttacker } = require('./profiler');

const serviceTemplates = {
    mysql: {
        banner: 'MySQL Server 5.7.33 - Unauthorized\r\n',
        responses: { default: 'ERROR 1045 (28000): Access denied for user\r\n' }
    },
    ssh: {
        banner: 'SSH-2.0-OpenSSH_7.4\r\n',
        responses: { default: 'Permission denied (publickey,password)\r\n' }
    },
    ftp: {
        banner: '220 FTP Server Ready\r\n',
        responses: { USER: '331 Password required\r\n', PASS: '530 Login incorrect\r\n', default: '530 Login incorrect\r\n' }
    },
    http: {
        banner: 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Apache Server</h1></body></html>',
        responses: { default: 'HTTP/1.1 403 Forbidden\r\n\r\n' }
    },
    telnet: {
        banner: 'Ubuntu 20.04 LTS\r\nlogin: ',
        responses: { default: 'Login incorrect\r\n' }
    },
    smtp: {
        banner: '220 mail.example.com ESMTP Postfix\r\n',
        responses: { default: '554 5.7.1 Access denied\r\n' }
    },
    generic: {
        banner: 'Service Ready\r\n',
        responses: { default: 'Access Denied\r\n' }
    }
};

const activeServices = new Map();

function detectServiceFromPayload(data, port) {
    const dataStr = data.toString().toLowerCase();
    if (port === 3306 || dataStr.includes('mysql') || dataStr.includes('select') || dataStr.includes('union')) return 'mysql';
    if (port === 22 || dataStr.includes('ssh-')) return 'ssh';
    if (port === 21 || dataStr.startsWith('user ') || dataStr.startsWith('pass ')) return 'ftp';
    if (port === 80 || port === 8080 || dataStr.startsWith('get ') || dataStr.startsWith('post ')) return 'http';
    if (port === 23 || dataStr.includes('telnet')) return 'telnet';
    if (port === 25 || dataStr.includes('ehlo') || dataStr.includes('helo')) return 'smtp';
    return 'generic';
}

async function createDynamicService(serviceType, targetPort, io) {
    if (activeServices.has(targetPort)) {
        return activeServices.get(targetPort);
    }

    const template = serviceTemplates[serviceType] || serviceTemplates.generic;

    const server = net.createServer((socket) => {
        const clientIp = socket.remoteAddress || 'unknown';

        socket.setTimeout(30000);
        socket.on('timeout', () => socket.destroy());
        socket.on('error', () => socket.destroy());

        try {
            socket.write(template.banner);
        } catch (e) {
            return;
        }

        socket.on('data', async (data) => {
            const payload = data.toString().trim();
            if (!payload) return;

            try {
                await pool.query(
                    'INSERT INTO attacks (ip, port, service_type, payload, threat_level) VALUES (?, ?, ?, ?, ?)',
                    [clientIp, targetPort, serviceType, payload.substring(0, 500), 'medium']
                );

                await profileAttacker(clientIp, serviceType, payload);

                io.emit('attack', {
                    ip: clientIp,
                    port: targetPort,
                    service: serviceType,
                    service_type: serviceType,
                    payload: payload.substring(0, 100),
                    timestamp: new Date(),
                    threat_level: 'medium'
                });

                const cmdKey = payload.split(' ')[0].toUpperCase();
                const response = template.responses[cmdKey] || template.responses.default;
                socket.write(response);
            } catch (err) {
                console.error(`Error handling data on port ${targetPort}:`, err.message);
            }
        });
    });

    server.on('error', (err) => {
        console.error(`Service error on port ${targetPort}: ${err.message}`);
        activeServices.delete(targetPort);
    });

    await new Promise((resolve, reject) => {
        server.listen(targetPort, '0.0.0.0', () => {
            console.log(`Dynamic ${serviceType} service spawned on port ${targetPort}`);
            resolve();
        });
        server.on('error', reject);
    });

    try {
        await pool.query(
            'INSERT OR IGNORE INTO dynamic_services (service_name, port, protocol, banner) VALUES (?, ?, ?, ?)',
            [serviceType, targetPort, 'tcp', template.banner.substring(0, 100)]
        );
    } catch (err) {
        console.error('Error saving service to DB:', err.message);
    }

    activeServices.set(targetPort, { server, serviceType });

    io.emit('service-created', { service: serviceType, port: targetPort, timestamp: new Date() });

    return { server, serviceType };
}

async function handlePortScan(port, data, clientIp, io) {
    const serviceType = detectServiceFromPayload(data, port);
    await createDynamicService(serviceType, port, io);
}

module.exports = { createDynamicService, handlePortScan, activeServices };
