const { pool } = require('./database');

const toolSignatures = {
    nmap: ['nmap', 'nse', 'script'],
    metasploit: ['metasploit', 'msf', 'meterpreter'],
    sqlmap: ['sqlmap', 'union select', 'information_schema'],
    hydra: ['hydra', 'thc-hydra'],
    nikto: ['nikto'],
    burp: ['burpsuite', 'burp'],
    zap: ['owasp-zap', 'zaproxy']
};

const ttpPatterns = {
    reconnaissance: ['scan', 'probe', 'enum', 'discover', 'nmap'],
    credential_access: ['login', 'auth', 'password', 'passwd', 'user', 'username'],
    initial_access: ['exploit', 'shell', 'payload', 'reverse'],
    persistence: ['cron', 'startup', 'autorun'],
    privilege_escalation: ['sudo', 'root', 'admin', 'privilege'],
    defense_evasion: ['encode', 'obfuscate', 'bypass', 'base64'],
    lateral_movement: ['ssh', 'rdp', 'smb', 'psexec'],
    collection: ['dump', 'extract', 'download'],
    exfiltration: ['upload', 'transfer', 'wget', 'curl']
};

function detectTools(payload) {
    const p = payload.toLowerCase();
    return Object.entries(toolSignatures)
        .filter(([, sigs]) => sigs.some(s => p.includes(s)))
        .map(([tool]) => tool);
}

function detectTTPs(payload, serviceType) {
    const p = payload.toLowerCase();
    const detected = Object.entries(ttpPatterns)
        .filter(([, patterns]) => patterns.some(pat => p.includes(pat)))
        .map(([ttp]) => ttp);
    if (['mysql', 'ssh', 'ftp', 'telnet'].includes(serviceType) && !detected.includes('credential_access')) {
        detected.push('credential_access');
    }
    return [...new Set(detected)];
}

function calculateThreatScore(attackCount, tools, ttps) {
    return Math.min(Math.min(attackCount * 3, 30) + tools.length * 15 + ttps.length * 10, 100);
}

function profileAttacker(ip, serviceType, payload) {
    try {
        const tools = detectTools(payload);
        const ttps = detectTTPs(payload, serviceType);
        const existing = pool.query('getProfileByIp', { ip });

        if (existing) {
            const updatedTools = [...new Set([...existing.tools_detected, ...tools])];
            const updatedTTPs = [...new Set([...existing.ttps, ...ttps])];
            const newCount = existing.attack_count + 1;
            pool.query('updateProfile', {
                ip,
                attack_count: newCount,
                tools_detected: updatedTools,
                ttps: updatedTTPs,
                threat_score: calculateThreatScore(newCount, updatedTools, updatedTTPs),
                last_seen: new Date().toLocaleString()
            });
        } else {
            pool.query('insertProfile', {
                id: Date.now(),
                ip,
                first_seen: new Date().toLocaleString(),
                last_seen: new Date().toLocaleString(),
                attack_count: 1,
                tools_detected: tools,
                ttps,
                threat_score: calculateThreatScore(1, tools, ttps),
                country: null,
                profile_data: { first_service: serviceType, first_payload: payload.substring(0, 200) }
            });
        }
    } catch (err) {
        console.error('Profiler error:', err.message);
    }
}

function getAttackerProfile(ip) {
    return pool.query('getProfileByIp', { ip }) || null;
}

module.exports = { profileAttacker, getAttackerProfile };
