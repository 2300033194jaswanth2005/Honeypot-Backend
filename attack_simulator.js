const net = require('net');

function simulateAttack(port, payloads, delay = 1000) {
    setTimeout(() => {
        const client = net.createConnection({ port }, () => {
            console.log(`Attacking port ${port}`);
            payloads.forEach((payload, i) => {
                setTimeout(() => {
                    client.write(payload + '\n');
                }, i * 500);
            });
            setTimeout(() => client.end(), payloads.length * 500 + 1000);
        });
    }, delay);
}

// Simulate multiple attacks
console.log('Starting attack simulation...');

// SSH brute force
simulateAttack(2222, ['root', '1234'], 0);
simulateAttack(2222, ['admin', 'password'], 2000);
simulateAttack(2222, ['root', 'admin'], 4000);

// MySQL injection attempts
simulateAttack(3307, ["SELECT * FROM users WHERE id=1 OR 1=1", "UNION SELECT"], 6000);

// FTP attacks
simulateAttack(2121, ['USER admin', 'PASS admin123'], 8000);
simulateAttack(2121, ['USER root', 'PASS toor'], 10000);

console.log('Attack simulation scheduled for next 12 seconds');
