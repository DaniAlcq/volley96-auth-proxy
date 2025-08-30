// index.js — OAuth flow per Decap/Netlify CMS (GitHub)
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
app.use(express.json());
app.set('trust proxy', 1);

// ===== Env =====
const {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  ALLOWED_ORIGIN,               // es: https://danialcq.github.io  (NO /asd-volley-96)
  CALLBACK_URL                  // es: https://volley96-auth-proxy.onrender.com/callback
} = process.env;

// Prende solo origin (schema+host+porta), elimina eventuale path
function originOnly(url) {
  try { return new URL(url).origin; } catch { return url || ''; }
}
const ORIGIN = originOnly(ALLOWED_ORIGIN) || 'https://danialcq.github.io';

// ===== CORS =====
app.use(cors({
  origin: (requestOrigin, cb) => {
    // consenti richieste senza origin (es. curl) e l’origin previsto
    if (!requestOrigin || originOnly(requestOrigin) === ORIGIN) return cb(null, true);
    return cb(new Error('Origin not allowed'), false);
  },
  credentials: true,
}));

// ===== Health =====
app.get('/', (_req, res) => res.send('✅ volley96-auth-proxy up'));
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    clientId: !!GITHUB_CLIENT_ID,
    secret: !!GITHUB_CLIENT_SECRET,
    allowedOriginEnv: ALLOWED_ORIGIN || null,
    allowedOriginEffective: ORIGIN,
    callbackUrl: CALLBACK_URL || `${req.protocol}://${req.get('host')}/callback`
  });
});

// ===== STEP 1 — Avvio login =====
// Decap chiama /auth?provider=github&scope=repo&site_id=...
app.get('/auth', (req, res) => {
  const scope = req.query.scope || 'repo';
  const redirectUri = CALLBACK_URL || `${req.protocol}://${req.get('host')}/callback`;

  const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
  authorizeUrl.searchParams.set('client_id', GITHUB_CLIENT_ID);
  authorizeUrl.searchParams.set('scope', scope);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);

  res.redirect(authorizeUrl.toString());
});

// ===== STEP 2 — Callback GitHub =====
app.get('/callback', async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send('❌ Missing code from GitHub');

    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code
      })
    });
    const tokenData = await tokenResp.json();

    if (!tokenResp.ok || tokenData.error || !tokenData.access_token) {
      console.error('❌ token exchange error:', tokenData);
      return res.send(renderPopupResult({
        ok: false,
        message: tokenData.error_description || tokenData.error || 'OAuth failed',
        origin: ORIGIN
      }));
    }

    return res.send(renderPopupResult({
      ok: true,
      token: tokenData.access_token,
      origin: ORIGIN
    }));
  } catch (e) {
    console.error('❌ callback error:', e);
    res.send(renderPopupResult({ ok: false, message: 'Unexpected error', origin: ORIGIN }));
  }
});

// ===== Paginetta che parla con la finestra del CMS =====
function renderPopupResult({ ok, token, message, origin }) {
  const payload = ok
    ? `authorization:github:success:${token}`
    : `authorization:github:error:${message || 'Error'}`;
  const targetOrigin = originOnly(origin) || '*';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Auth Proxy</title></head>
<body>
<script>
  (function() {
    try {
      // Manda il token alla finestra del CMS
      window.opener && window.opener.postMessage('${payload}', '${targetOrigin}');
    } catch(e) {
      // Ultimo fallback
      window.opener && window.opener.postMessage('${payload}', '*');
    }
    window.close();
  })();
</script>
<p>Puoi chiudere questa finestra.</p>
</body></html>`;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('🚀 Auth proxy listening on :' + PORT));
