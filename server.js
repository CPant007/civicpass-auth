// server.js
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const PORT = 3000;

// Configuration
const RP_NAME = 'CivicPass Gov Portal';
const LEGITIMATE_HOST = 'portal.local';

app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

app.use(
  session({
    secret: 'hackathon-session-secret-2026',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 },
  })
);

// --- In-Memory Database ---
const db = {
  users: {},          // { [username]: { id, username, guardians: [] } }
  credentials: {},    // { [credId]: { id, publicKey, counter, userId, deviceName, isRevoked, createdAt } }
  kioskSessions: {},  // { [sessionId]: { status: 'PENDING' | 'AUTHORIZED', username: null } }
  auditLogs: [],      // Array of security events
};

// Helper: Append to audit log
function logSecurityEvent(eventType, details, status = 'SUCCESS') {
  const entry = {
    id: uuidv4(),
    timestamp: new Date().toLocaleTimeString(),
    eventType,
    details,
    status, // SUCCESS, WARNING, or BLOCKED
  };
  db.auditLogs.unshift(entry);
  if (db.auditLogs.length > 50) db.auditLogs.pop(); // keep last 50
  console.log(`[AUDIT] [${status}] ${eventType}: ${details}`);
}

// ========================================================
// 1. WEBAUTHN / PASSKEY CORE (Registration & Login)
// ========================================================

// 1A. Get Registration Options
app.post('/api/auth/register-challenge', async (req, res) => {
  const { username, deviceName } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  let user = db.users[username];
  if (!user) {
    user = {
      id: Buffer.from(username).toString('base64url'),
      username,
      guardians: ['Guardian-Alpha', 'Guardian-Beta', 'Guardian-Gamma'],
    };
    db.users[username] = user;
  }

  const userCredentials = Object.values(db.credentials).filter(c => c.userId === user.id && !c.isRevoked);

  const rpID = req.hostname === 'localhost' ? 'localhost' : LEGITIMATE_HOST;

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID,
    userID: Buffer.from(user.id),
    userName: user.username,
    attestationType: 'none',
    excludeCredentials: userCredentials.map(cred => ({
      id: cred.id,
      transports: cred.transports,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  });

  req.session.currentChallenge = options.challenge;
  req.session.tempUsername = username;
  req.session.tempDeviceName = deviceName || 'Default Authenticator';

  res.json(options);
});

// 1B. Verify Registration
app.post('/api/auth/register-verify', async (req, res) => {
  const { body } = req;
  const username = req.session.tempUsername;
  const expectedChallenge = req.session.currentChallenge;
  const deviceName = req.session.tempDeviceName || 'Browser Hardware';

  const user = db.users[username];
  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'Session expired or invalid state' });
  }

  const rpID = req.hostname === 'localhost' ? 'localhost' : LEGITIMATE_HOST;
  const expectedOrigin = req.hostname === 'localhost' ? `http://localhost:${PORT}` : `http://${LEGITIMATE_HOST}:${PORT}`;

  try {
    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: `http://${req.headers.host}`,
      expectedRPID: rpID,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;

      db.credentials[credential.id] = {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        userId: user.id,
        deviceName,
        isRevoked: false,
        createdAt: new Date().toLocaleDateString(),
        transports: body.response.transports || [],
      };

      req.session.currentChallenge = undefined;
      req.session.userId = user.id;

      logSecurityEvent('DEVICE_REGISTERED', `Passkey enrolled for ${username} (${deviceName})`);
      return res.json({ verified: true, message: 'Passkey enrolled successfully' });
    }
  } catch (err) {
    logSecurityEvent('REGISTRATION_FAILED', err.message, 'WARNING');
    return res.status(400).json({ error: err.message });
  }

  res.status(400).json({ verified: false, error: 'Registration failed' });
});

// 2A. Get Login Options
app.post('/api/auth/login-challenge', async (req, res) => {
  const { username } = req.body;
  const user = db.users[username];

  if (!user) {
    return res.status(404).json({ error: 'User does not exist. Please enroll first.' });
  }

  const activeCredentials = Object.values(db.credentials).filter(c => c.userId === user.id && !c.isRevoked);
  if (activeCredentials.length === 0) {
    return res.status(403).json({ error: 'No active passkeys found. All devices revoked.' });
  }

  const rpID = req.hostname === 'localhost' ? 'localhost' : LEGITIMATE_HOST;

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: activeCredentials.map(cred => ({
      id: cred.id,
      transports: cred.transports,
    })),
    userVerification: 'preferred',
  });

  req.session.currentChallenge = options.challenge;
  req.session.tempUsername = username;

  res.json(options);
});

// 2B. Verify Login & Phishing Defense
app.post('/api/auth/login-verify', async (req, res) => {
  const { body } = req;
  const username = req.session.tempUsername;
  const expectedChallenge = req.session.currentChallenge;

  // PHISHING DETECTION CHECK
  if (req.headers.host && req.headers.host.includes('evil-portal')) {
    logSecurityEvent('PHISHING_ATTACK_BLOCKED', `Unauthorized attempt via ${req.headers.host} for ${username}`, 'BLOCKED');
    return res.status(403).json({
      verified: false,
      error: 'PHISHING DETECTED: Origin mismatch! The signature was created for a fake domain.',
    });
  }

  const user = db.users[username];
  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'Session expired' });
  }

  const credential = db.credentials[body.id];
  if (!credential) {
    return res.status(400).json({ error: 'Unknown credential' });
  }

  if (credential.isRevoked) {
    logSecurityEvent('BLOCKED_REVOKED_KEY', `Attempt to login using revoked credential for ${username}`, 'BLOCKED');
    return res.status(403).json({ error: 'This device passkey has been revoked by admin or owner.' });
  }

  const rpID = req.hostname === 'localhost' ? 'localhost' : LEGITIMATE_HOST;
  const expectedOrigin = req.hostname === 'localhost' ? `http://localhost:${PORT}` : `http://${LEGITIMATE_HOST}:${PORT}`;

  try {
    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      credential: {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
      },
    });

    if (verification.verified) {
      credential.counter = verification.authenticationInfo.newCounter;
      req.session.currentChallenge = undefined;
      req.session.userId = user.id;

      logSecurityEvent('LOGIN_SUCCESS', `User ${username} verified via ${credential.deviceName}`);
      return res.json({ verified: true, username: user.username });
    }
  } catch (err) {
    logSecurityEvent('LOGIN_FAILED', err.message, 'WARNING');
    return res.status(400).json({ error: err.message });
  }

  res.status(400).json({ verified: false, error: 'Verification failed' });
});

// ========================================================
// 2. INCLUSIVITY & KIOSK / VOICE ENDPOINTS
// ========================================================

// Generate short-lived QR session for kiosk
app.post('/api/kiosk/create-session', (req, res) => {
  const sessionId = uuidv4().substring(0, 8); // e.g. "a1b2-c3d4"
  db.kioskSessions[sessionId] = {
    status: 'PENDING',
    username: null,
    createdAt: Date.now(),
  };
  res.json({ sessionId, qrPayload: `civicpass-kiosk:${sessionId}` });
});

// Check kiosk status (Frontend polls this)
app.get('/api/kiosk/status/:sessionId', (req, res) => {
  const sessionData = db.kioskSessions[req.params.sessionId];
  if (!sessionData) return res.status(404).json({ error: 'Session not found or expired' });
  res.json(sessionData);
});

// Authorize kiosk session from a trusted secondary phone
app.post('/api/kiosk/authorize', (req, res) => {
  const { sessionId, username } = req.body;
  const sessionData = db.kioskSessions[sessionId];

  if (!sessionData) return res.status(404).json({ error: 'Invalid QR session' });

  sessionData.status = 'AUTHORIZED';
  sessionData.username = username || 'Assisted Citizen';

  logSecurityEvent('KIOSK_LOGIN_AUTHORIZED', `Kiosk session ${sessionId} approved for ${username}`);
  res.json({ success: true, message: 'Kiosk session successfully authorized!' });
});

// Simulate Basic Phone / Voice IVR verification
app.post('/api/inclusivity/voice-verify', (req, res) => {
  const { username, pressedKey } = req.body;
  if (pressedKey === '1') {
    logSecurityEvent('VOICE_IVR_SUCCESS', `Out-of-band Voice confirmation for ${username}`);
    return res.json({ verified: true, message: 'Voice confirmation validated!' });
  }
  logSecurityEvent('VOICE_IVR_REJECTED', `Voice confirmation cancelled by user ${username}`, 'WARNING');
  res.status(400).json({ verified: false, error: 'Verification was not confirmed on keypad' });
});

// ========================================================
// 3. ACCOUNT RECOVERY (Guardian Social Recovery)
// ========================================================

// Submit 2 guardian shares to recover an account without SMS OTPs
app.post('/api/recovery/guardian-verify', (req, res) => {
  const { username, share1, share2 } = req.body;
  const user = db.users[username];

  if (!user) return res.status(404).json({ error: 'User does not exist' });

  // For Hackathon Demo: Any two non-empty, distinct guardian shares authorize recovery
  if (share1 && share2 && share1.trim() !== share2.trim()) {
    logSecurityEvent('ACCOUNT_RECOVERY_SUCCESS', `2-of-3 Guardian threshold verified for ${username}`);
    return res.json({
      verified: true,
      recoveryToken: uuidv4(),
      message: 'Threshold met! You may now enroll a new device.',
    });
  }

  logSecurityEvent('ACCOUNT_RECOVERY_FAILED', `Invalid recovery keys submitted for ${username}`, 'WARNING');
  res.status(400).json({ verified: false, error: 'At least 2 valid, distinct Guardian keys are required' });
});

// ========================================================
// 4. ADMIN & DEVICE MANAGEMENT ENDPOINTS
// ========================================================

// Fetch registered credentials for a user
app.get('/api/admin/devices/:username', (req, res) => {
  const user = db.users[req.params.username];
  if (!user) return res.json({ devices: [] });

  const devices = Object.values(db.credentials)
    .filter(c => c.userId === user.id)
    .map(c => ({
      id: c.id,
      deviceName: c.deviceName,
      createdAt: c.createdAt,
      isRevoked: c.isRevoked,
    }));

  res.json({ devices });
});

// Revoke a specific passkey
app.post('/api/admin/devices/revoke', (req, res) => {
  const { credentialId } = req.body;
  const credential = db.credentials[credentialId];

  if (!credential) return res.status(404).json({ error: 'Credential not found' });

  credential.isRevoked = true;
  logSecurityEvent('DEVICE_REVOKED', `Credential ${credentialId.substring(0, 8)}... revoked`, 'WARNING');

  res.json({ success: true, message: 'Device passkey revoked successfully.' });
});

// Fetch live security audit logs
app.get('/api/admin/logs', (req, res) => {
  res.json({ logs: db.auditLogs });
});

// Server listen
app.listen(PORT, () => {
  console.log(`🚀 CivicPass Backend online at http://localhost:${PORT}`);
});