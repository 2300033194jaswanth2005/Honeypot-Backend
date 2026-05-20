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
    collection: ['dump', 'extract', 'download', 'exfil'],
    exfiltration: ['upload', 'transfer', 'wget', 'curl']
};

function detectTools(payload) {
    const payloadLower = payload.toLowerCase();
    return Object.entries(toolSignatures)
        .filter(([, sigs]) => sigs.some(sig => payloadLower.includes(sig)))
        .map(([tool]) => tool);
}

function detectTTPs(payload, serviceType) {
    const payloadLower = payload.toLowerCase();
    const detected = Object.entries(ttpPatterns)
        .filter(([, patterns]) => patterns.some(p => payloadLower.includes(p)))
        .map(([ttp]) => ttp);

    if (['mysql', 'ssh', 'ftp', 'telnet'].includes(serviceType) && !detected.includes('credential_access')) {
        detected.push('credential_access');
    }
    if (['mysql'].includes(serviceType) && (payloadLower.includes('select') || payloadLower.includes('union'))) {
        if (!detected.includes('reconnaissance')) detected.push('reconnaissance');
    }

    return [...new Set(detected)];
}

function calculateThreatScore(attackCount, tools, ttps) {
    let score = Math.min(attackCount * 3, 30);
    score += tools.length * 15;
    score += ttps.length * 10;
    return Math.min(score, 100);
}

async function profileAttacker(ip, serviceType, payload) {
    try {
        const tools = detectTools(payload);
        const ttps = detectTTPs(payload, serviceType);

        const [existing] = await pool.query(
            'SELECT * FROM attacker_profiles WHERE ip = ?',
            [ip]
        );

        if (existing.length > 0) {
            const profile = existing[0];
            const existingTools = JSON.parse(profile.tools_detected || '[]');
            const existingTTPs = JSON.parse(profile.ttps || '[]');

            const updatedTools = [...new Set([...existingTools, ...tools])];
            const updatedTTPs = [...new Set([...existingTTPs, ...ttps])];
            const newCount = profile.attack_count + 1;
            const threatScore = calculateThreatScore(newCount, updatedTools, updatedTTPs);

            await pool.query(
                `UPDATE attacker_profiles
                 SET attack_count = ?, tools_detected = ?, ttps = ?, threat_score = ?,
                     last_seen = datetime('now','localtime')
                 WHERE ip = ?`,
                [newCount, JSON.stringify(updatedTools), JSON.stringify(updatedTTPs), threatScore, ip]
            );
        } else {
            const threatScore = calculateThreatScore(1, tools, ttps);
            await pool.query(
                `INSERT INTO attacker_profiles (ip, tools_detected, ttps, threat_score, profile_data)
                 VALUES (?, ?, ?, ?, ?)`,
                [ip, JSON.stringify(tools), JSON.stringify(ttps), threatScore,
                    JSON.stringify({ first_service: serviceType, first_payload: payload.substring(0, 200) })]
            );
        }
    } catch (err) {
        console.error('Profiler error:', err.message);
    }
}

async function getAttackerProfile(ip) {
    const [profile] = await pool.query(
        'SELECT * FROM attacker_profiles WHERE ip = ?',
        [ip]
    );
    if (profile.length === 0) return null;
    const p = profile[0];
    return {
        ip: p.ip,
        firstSeen: p.first_seen,
        lastSeen: p.last_seen,
        attackCount: p.attack_count,
        tools: JSON.parse(p.tools_detected || '[]'),
        ttps: JSON.parse(p.ttps || '[]'),
        threatScore: p.threat_score,
        profileData: JSON.parse(p.profile_data || '{}')
    };
}

module.exports = { profileAttacker, getAttackerProfile };
