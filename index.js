// index.js
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
app.use(express.json());

// CORS: consenti solo l'origin del tuo sito GitHub Pages
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN; // es. https://danialcq.github.io
app.use(cors({
  origin: (origin, cb) => {
    if (!ALLOWED_ORIGIN) return cb(null, true); // fallback: accetta tutti
    try {
      const allowed = new URL(ALLOWED_ORIGIN).origin;
      if (!origin || new URL(origin).origin === allowed) return cb(null, true);
      return cb(new Error('Not allowed by CORS'));
    } catch {
      return cb(null, false);
    }
  },
  credentials: true
}));

// Env richieste
const {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  REPO_FULL_NAME // "DaniAlcq/asd-volley-96"
} = process.env;

// Health check
app.get('/', (req, res) => res.send('OK: volley96-auth-proxy up'));
app.get('/health', (req, res) => res.json({
  ok: true,
  hasClientId: !!GITHUB_CLIENT_ID,
  hasSecret: !!GITHUB_CLIENT_SECRET,
  repo: REPO_FULL_NAME,
  allowedOrigin: ALLOWED_ORIGIN
}));

/**
 * Avvio login per Decap CMS (GitHub backend) via Device Flow
 */
app.get('/auth/github', async (req, res) => {
  try {
    // ricava origin da query o header
    const origin =
      req.query.origin ||
      req.headers.origin ||
      (req.headers.referer ? new URL(req.headers.referer).origin : null);

    console.log('Login request from origin:', origin);

    // Richiesta device code a GitHub
    const deviceResp = await fetch('https://github.com/login/device/code', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ client_id: GITHUB_CLIENT_ID, scope: 'repo' })
    });
    const deviceData = await deviceResp.json();

    if (!deviceResp.ok) {
      console.error('Device code error:', deviceData);
      return res.status(500).json({ error: 'device_code_failed', details: deviceData });
    }

    // Risposta per Decap CMS
    res.json({
      provider: 'github',
      token: deviceData.device_code,
      verification_uri: deviceData.verification_uri,
      user_code: deviceData.user_code,
      expires_in: deviceData.expires_in,
      interval: deviceData.interval,
      origin: origin || null
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'auth_init_failed' });
  }
});

/**
 * Scambio device_code -> access_token
 */
app.post('/auth/github/callback', async (req, res) => {
  try {
    const { token: device_code } = req.body || {};
    if (!device_code) return res.status(400).json({ error: 'missing device_code' });

    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
      })
    });
    const tokenData = await tokenResp.json();

    if (!tokenResp.ok || tokenData.error) {
      console.error('Token exchange error:', tokenData);
      return res.status(400).json(tokenData);
    }

    res.json({
      token: tokenData.access_token,
      provider: 'github'
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'token_exchange_failed' });
  }
});

// Compatibilità fallback
app.get('/callback', (req, res) => {
  res.send('Callback ok (non usata nel device flow).');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth proxy listening on :${PORT}`);
});
