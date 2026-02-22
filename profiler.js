const { pool } = require('./database');

const toolSignatures = {
    nmap: ['nmap', 'NSE', 'script'],
    metasploit: ['metasploit', 'msf', 'meterpreter'],
    sqlmap: ['sqlmap', 'union', 'select', 'injection'],
    hydra: ['hydra', 'thc'],
    nikto: ['nikto', 'scan'],
    burp: ['burp', 'scanner'],
    zap: ['zap', 'owasp']
};

const ttpPatterns = {
    reconnaissance: ['scan', 'probe', 'enum', 'discover'],
    credential_access: ['login', 'auth', 'password', 'user'],
    initial_access: ['exploit', 'shell', 'payload'],
    persistence: ['cron', 'service', 'startup'],
    privilege_escalation: ['sudo', 'root', 'admin'],
    defense_evasion: ['encode', 'obfuscate', 'bypass'],
    lateral_movement: ['ssh', 'rdp', 'smb'],
    collection: ['dump', 'extract', 'download'],
    exfiltration: ['upload', 'transfer', 'ftp']
};

function detectTools(payload) {
    const detected = [];
    const payloadLower = payload.toLowerCase();
    
    for (const [tool, signatures] of Object.entries(toolSignatures)) {
        if (signatures.some(sig => payloadLower.includes(sig))) {
            detected.push(tool);
        }
    }
    
    return detected;
}

function detectTTPs(payload, serviceType) {
    const detected = [];
    const payloadLower = payload.toLowerCase();
    
    for (const [ttp, patterns] of Object.entries(ttpPatterns)) {
        if (patterns.some(pattern => payloadLower.includes(pattern))) {
            detected.push(ttp);
        }
    }
    
    if (serviceType === 'mysql' || serviceType === 'ssh') {
        detected.push('credential_access');
    }
    
    return detected;
}

function calculateThreatScore(attackCount, tools, ttps) {
    let score = attackCount * 5;
    score += tools.length * 15;
    score += ttps.length * 10;
    return Math.min(score, 100);
}

async function profileAttacker(ip, serviceType, payload) {
    const tools = detectTools(payload);
    const ttps = detectTTPs(payload, serviceType);
    
    const [existing] = await pool.query(
        'SELECT * FROM attacker_profiles WHERE ip = ?',
        [ip]
    );
    
    if (existing.length > 0) {
        const profile = existing[0];
        const existingTools = profile.tools_detected ? JSON.parse(profile.tools_detected) : [];
        const existingTTPs = profile.ttps ? JSON.parse(profile.ttps) : [];
        
        const updatedTools = [...new Set([...existingTools, ...tools])];
        const updatedTTPs = [...new Set([...existingTTPs, ...ttps])];
        const newCount = profile.attack_count + 1;
        const threatScore = calculateThreatScore(newCount, updatedTools, updatedTTPs);
        
        await pool.query(
            `UPDATE attacker_profiles 
             SET attack_count = ?, tools_detected = ?, ttps = ?, threat_score = ?, last_seen = NOW()
             WHERE ip = ?`,
            [newCount, JSON.stringify(updatedTools), JSON.stringify(updatedTTPs), threatScore, ip]
        );
    } else {
        const threatScore = calculateThreatScore(1, tools, ttps);
        
        await pool.query(
            `INSERT INTO attacker_profiles (ip, tools_detected, ttps, threat_score, profile_data)
             VALUES (?, ?, ?, ?, ?)`,
            [ip, JSON.stringify(tools), JSON.stringify(ttps), threatScore, JSON.stringify({
                first_service: serviceType,
                first_payload: payload.substring(0, 200)
            })]
        );
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
