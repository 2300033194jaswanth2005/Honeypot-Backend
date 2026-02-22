const net = require('net');
const { pool } = require('./database');
const { profileAttacker } = require('./profiler');

const serviceTemplates = {
    mysql: {
        port: 3306,
        banner: '\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x33\x00MySQL Server 5.7.33',
        responses: {
            default: 'Access denied for user'
        }
    },
    ssh: {
        port: 22,
        banner: 'SSH-2.0-OpenSSH_7.4\r\n',
        responses: {
            default: 'Permission denied'
        }
    },
    ftp: {
        port: 21,
        banner: '220 FTP Server Ready\r\n',
        responses: {
            USER: '331 Password required\r\n',
            PASS: '530 Login incorrect\r\n'
        }
    },
    http: {
        port: 80,
        banner: 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n',
        responses: {
            default: '<html><body>Apache Server</body></html>'
        }
    },
    telnet: {
        port: 23,
        banner: 'Ubuntu 20.04 LTS\r\nlogin: ',
        responses: {
            default: 'Login incorrect'
        }
    },
    smtp: {
        port: 25,
        banner: '220 mail.example.com ESMTP Postfix\r\n',
        responses: {
            default: '554 Access denied'
        }
    }
};

const activeServices = new Map();

function detectServiceFromScan(data, port) {
    const dataStr = data.toString().toLowerCase();
    
    if (port === 3306 || dataStr.includes('mysql') || dataStr.includes('select')) return 'mysql';
    if (port === 22 || dataStr.includes('ssh')) return 'ssh';
    if (port === 21 || dataStr.includes('ftp') || dataStr.includes('user')) return 'ftp';
    if (port === 80 || dataStr.includes('http') || dataStr.includes('get')) return 'http';
    if (port === 23 || dataStr.includes('telnet')) return 'telnet';
    if (port === 25 || dataStr.includes('smtp') || dataStr.includes('mail')) return 'smtp';
    
    return 'generic';
}

async function createDynamicService(serviceType, targetPort, io) {
    if (activeServices.has(targetPort)) {
        return activeServices.get(targetPort);
    }
    
    const template = serviceTemplates[serviceType] || {
        port: targetPort,
        banner: 'Service Ready\r\n',
        responses: { default: 'Access Denied' }
    };
    
    const server = net.createServer((socket) => {
        const clientIp = socket.remoteAddress;
        
        socket.write(template.banner);
        
        socket.on('data', async (data) => {
            const payload = data.toString();
            
            await pool.query(
                'INSERT INTO attacks (ip, port, service_type, payload, threat_level) VALUES (?, ?, ?, ?, ?)',
                [clientIp, targetPort, serviceType, payload, 'medium']
            );
            
            await profileAttacker(clientIp, serviceType, payload);
            
            io.emit('attack', {
                ip: clientIp,
                port: targetPort,
                service: serviceType,
                payload: payload.substring(0, 100),
                timestamp: new Date()
            });
            
            const response = template.responses[payload.trim()] || template.responses.default;
            socket.write(response);
        });
        
        socket.on('error', () => socket.destroy());
    });
    
    server.listen(targetPort, () => {
        console.log(`Dynamic ${serviceType} service spawned on port ${targetPort}`);
    });
    
    await pool.query(
        'INSERT INTO dynamic_services (service_name, port, protocol, banner) VALUES (?, ?, ?, ?)',
        [serviceType, targetPort, 'tcp', template.banner]
    );
    
    activeServices.set(targetPort, { server, serviceType });
    
    io.emit('service-created', {
        service: serviceType,
        port: targetPort,
        timestamp: new Date()
    });
    
    return { server, serviceType };
}

async function handlePortScan(port, data, clientIp, io) {
    const serviceType = detectServiceFromScan(data, port);
    await createDynamicService(serviceType, port, io);
}

module.exports = { createDynamicService, handlePortScan, activeServices };
