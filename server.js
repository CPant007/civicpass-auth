// server.js
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const path = require('path');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const PORT = 3000;

// Relying Party (RP) settings
// For local development, rpID must match your domain/hostname (localhost)
const RP_NAME = 'CivicPass Gov Portal';
const RP_ID = 'localhost';
const EXPECTED_ORIGIN = `http://${RP_ID}:${PORT}`;

app.use(express.json());
app.use(cors());

// Serve static frontend files from the "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration to hold temporary challenges
app.use(
  session({
    secret: 'hackathon-super-secret-key-2026',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 },
  })
);

// In-Memory Database for fast Hackathon prototyping
const db = {
  users: {},        // { [username]: { id, username } }
  credentials: {},  // { [credentialID]: { id, publicKey, counter, userId, transports } }
};

// ==========================================
// 1. REGISTRATION ENDPOINTS (Enroll Passkey)
// ==========================================

// 1A. Generate registration challenge options
app.post('/api/auth/register-challenge', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username is required' });

  // Find or create user
  let user = db.users[username];
  if (!user) {
    user = {
      id: Buffer.from(username).toString('base64url'),
      username: username,
    };
    db.users[username] = user;
  }

  // Check if user already has credentials registered
  const userCredentials = Object.values(db.credentials).filter(c => c.userId === user.id);

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: Buffer.from(user.id),
    userName: user.username,
    attestationType: 'none',
    excludeCredentials: userCredentials.map(cred => ({
      id: cred.id,
      transports: cred.transports,
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred', // Triggers biometric (TouchID, FaceID, Windows Hello, PIN)
    },
  });

  // Store the challenge in the session for verification
  req.session.currentChallenge = options.challenge;
  req.session.tempUsername = username;

  res.json(options);
});

// 1B. Verify the device attestation and save the public key
app.post('/api/auth/register-verify', async (req, res) => {
  const { body } = req;
  const username = req.session.tempUsername;
  const expectedChallenge = req.session.currentChallenge;

  const user = db.users[username];
  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'Session expired or invalid challenge' });
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: expectedChallenge,
      expectedOrigin: EXPECTED_ORIGIN,
      expectedRPID: RP_ID,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential } = verification.registrationInfo;

      // Store the public key and credential metadata
      db.credentials[credential.id] = {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        userId: user.id,
        transports: body.response.transports || [],
      };

      req.session.currentChallenge = undefined;
      req.session.userId = user.id;

      return res.json({ verified: true, message: 'Passkey registered successfully!' });
    }
  } catch (error) {
    console.error('Registration verification error:', error);
    return res.status(400).json({ error: error.message });
  }

  res.status(400).json({ verified: false, error: 'Registration verification failed' });
});

// ==========================================
// 2. AUTHENTICATION ENDPOINTS (Sign In)
// ==========================================

// 2A. Generate login challenge options
app.post('/api/auth/login-challenge', async (req, res) => {
  const { username } = req.body;
  const user = db.users[username];

  if (!user) {
    return res.status(404).json({ error: 'User not found. Please enroll first.' });
  }

  const userCredentials = Object.values(db.credentials).filter(c => c.userId === user.id);

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: userCredentials.map(cred => ({
      id: cred.id,
      transports: cred.transports,
    })),
    userVerification: 'preferred',
  });

  req.session.currentChallenge = options.challenge;
  req.session.tempUsername = username;

  res.json(options);
});

// 2B. Verify device signature against stored public key
app.post('/api/auth/login-verify', async (req, res) => {
  const { body } = req;
  const username = req.session.tempUsername;
  const expectedChallenge = req.session.currentChallenge;

  const user = db.users[username];
  if (!user || !expectedChallenge) {
    return res.status(400).json({ error: 'Session expired or user not found' });
  }

  const credential = db.credentials[body.id];
  if (!credential) {
    return res.status(400).json({ error: 'Credential not recognized for this user' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge: expectedChallenge,
      expectedOrigin: EXPECTED_ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
      },
    });

    if (verification.verified) {
      // Update counter to mitigate replay attacks
      credential.counter = verification.authenticationInfo.newCounter;
      req.session.currentChallenge = undefined;
      req.session.userId = user.id;

      return res.json({ verified: true, username: user.username });
    }
  } catch (error) {
    console.error('Login verification error:', error);
    return res.status(400).json({ error: error.message });
  }

  res.status(400).json({ verified: false, error: 'Login failed' });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});