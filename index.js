// index.js
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
app.use(express.json());

// CORS: consenti l'origin del tuo sito GitHub Pages
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN; // es. https://danialcq.github.io/asd-volley-96
app.use(cors({
  origin: (origin, cb) => cb(null, true), // per debug; poi restringi a ALLOWED_ORIGIN
  credentials: true
}));

// Env richieste
const {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  REPO_FULL_NAME // "DaniAlcq/asd-volley-96"
} = process.env;

// Health / root
app.get('/', (req, res) => res.send('OK: volley96-auth-proxy up'));
app.get('/health', (req, res) => res.json({
  ok: true,
  hasClientId: !!GITHUB_CLIENT_ID,
  hasSecret: !!GITHUB_CLIENT_SECRET,
  repo: REPO_FULL_NAME,
  allowedOrigin: ALLOWED_ORIGIN
}));

/**
 * Avvio login per Netlify CMS (Github backend) via GitHub Device Flow.
 * Netlify CMS chiamerà: GET /auth/github?origin=<URL admin>
 * Rispondiamo con JSON nel formato atteso dal backend github del CMS:
 * { "token": "<device_code>", "provider": "github" }
 * (il CMS mostrerà l'UI per completare l'autorizzazione)
 */
app.get('/auth/github', async (req, res) => {
  try {
    const origin = req.query.origin; // es. https://danialcq.github.io/asd-volley-96/admin/
    if (!origin) return res.status(400).json({ error: 'missing origin' });

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

    // Ritorna al CMS il device_code come "token"
    // (Il CMS gestirà il polling verso /auth/github/callback per scambiare il token)
    res.json({
      provider: 'github',
      token: deviceData.device_code,
      // Extra facoltativi per debug
      verification_uri: deviceData.verification_uri,
      user_code: deviceData.user_code,
      expires_in: deviceData.expires_in,
      interval: deviceData.interval
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'auth_init_failed' });
  }
});

/**
 * Endpoint che il CMS userà per scambiare il device_code con l'access token.
 * Netlify CMS (github backend) di solito fa POST qui con { token: device_code }.
 */
app.post('/auth/github/callback', express.json(), async (req, res) => {
  try {
    const { token: device_code } = req.body || {};
    if (!device_code) return res.status(400).json({ error: 'missing device_code' });

    // Poll token
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

    // Ritorna al CMS l'access_token
    res.json({
      token: tokenData.access_token,
      provider: 'github'
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'token_exchange_failed' });
  }
});

// Facoltativo: compatibilità con config che punta a /callback (GET)
app.get('/callback', (req, res) => {
  res.send('Callback ok (non usata nel device flow).');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Auth proxy listening on :${PORT}`);
});
