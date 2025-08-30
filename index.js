// index.js — Auth proxy per Decap/Netlify CMS (GitHub OAuth “web app”)
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
app.use(express.json());
app.set('trust proxy', 1);

// ===== ENV richieste =====
const {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  ALLOWED_ORIGIN,               // ESATTO origin dell’admin, es: https://danialcq.github.io
  CALLBACK_URL                  // es: https://volley96-auth-proxy.onrender.com/callback
} = process.env;

// Origin del sito che apre /admin/ (protocollo + host, senza path)
const TARGET_ORIGIN = (ALLOWED_ORIGIN || 'https://danialcq.github.io').replace(/\/+$/, '');

// ===== CORS (consenti solo l’origin dell’admin) =====
app.use(
  cors({
    origin: (origin, cb) => {
      // consenti richieste dalla pagina admin o server-side (origin assente)
      if (!origin || origin === TARGET_ORIGIN) return cb(null, true);
      return cb(new Error(`Blocked by CORS: ${origin}`));
    },
    credentials: true,
  })
);

// ===== Info / health =====
app.get('/', (_req, res) => res.send('✅ volley96-auth-proxy up'));
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    clientId: !!GITHUB_CLIENT_ID,
    secret: !!GITHUB_CLIENT_SECRET,
    allowedOrigin: TARGET_ORIGIN,
    callbackUrl: CALLBACK_URL || 'auto',
  });
});
app.get('/version', (_req, res) => res.json({ version: '1.0.0' }));

// ===== STEP 1 — /auth: reindirizza a GitHub =====
// Decap chiama /auth?provider=github&scope=repo&site_id=...
app.get('/auth', (req, res) => {
  const scope = req.query.scope || 'repo';
  const redirectUri = (CALLBACK_URL || `${req.protocol}://${req.get('host')}/callback`).replace(/\/+$/, '');

  const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
  authorizeUrl.searchParams.set('client_id', GITHUB_CLIENT_ID);
  authorizeUrl.searchParams.set('scope', scope);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);

  console.log('GET /auth → redirect', {
    scope,
    redirectUri,
    to: authorizeUrl.toString(),
  });

  return res.redirect(authorizeUrl.toString());
});

// ===== STEP 2 — /callback: scambia code → token e manda postMessage all’admin =====
app.get('/callback', async (req, res) => {
  try {
    console.log('GET /callback query:', req.query);

    const code = req.query.code;
    if (!code) return res.status(400).send('❌ Missing code');

    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
      }),
    });

    const data = await tokenResp.json();
    console.log('Token exchange response:', data);

    if (!tokenResp.ok || data.error || !data.access_token) {
      console.error('❌ token exchange error:', data);
      return res.send(
        renderPopupResult({
          ok: false,
          message: data.error_description || 'OAuth failed',
          origin: TARGET_ORIGIN,
        })
      );
    }

    // OK → invia token alla finestra opener (Decap admin) e chiudi
    return res.send(
      renderPopupResult({
        ok: true,
        token: data.access_token,
        origin: TARGET_ORIGIN,
      })
    );
  } catch (e) {
    console.error('❌ callback error:', e);
    res.send(renderPopupResult({ ok: false, message: 'Unexpected error', origin: TARGET_ORIGIN }));
  }
});

// ===== Paginetta che fa postMessage all’opener e chiude la popup =====
function renderPopupResult({ ok, token, message, origin }) {
  const payload = ok
    ? `authorization:github:success:${token}`
    : `authorization:github:error:${message || 'Error'}`;

  const safeOrigin = origin || '*';

  return `<!doctype html><html><head><meta charset="utf-8"><title>Auth Proxy</title></head>
<body><script>
(function(){
  try {
    window.opener && window.opener.postMessage('${payload}', '${safeOrigin}');
  } catch(e) {
    try { window.opener && window.opener.postMessage('${payload}', '*'); } catch(_) {}
  }
  window.close();
})();
</script>
<p>Puoi chiudere questa finestra.</p></body></html>`;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('🚀 Auth proxy listening on :' + PORT, '→ origin:', TARGET_ORIGIN);
});
