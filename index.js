// index.js — OAuth flow per Decap/Netlify CMS (GitHub)
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
app.use(express.json());
app.set('trust proxy', 1);

const {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  ALLOWED_ORIGIN,               // es: https://danialcq.github.io
  CALLBACK_URL                  // es: https://volley96-auth-proxy.onrender.com/callback
} = process.env;

const allowedOrigin = ALLOWED_ORIGIN || 'https://danialcq.github.io';

// CORS: consenti solo il dominio del sito
app.use(cors({
  origin: allowedOrigin,
  credentials: true
}));

// Health check
app.get('/', (req, res) => res.send('✅ volley96-auth-proxy up'));
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    clientId: !!GITHUB_CLIENT_ID,
    secret: !!GITHUB_CLIENT_SECRET,
    allowedOrigin,
    callbackUrl: CALLBACK_URL || `${req.protocol}://${req.get('host')}/callback`
  });
});

/**
 * STEP 1 — Avvio login
 * Decap chiama /auth?provider=github&scope=repo&site_id=xxx
 * Noi lo redirigiamo a GitHub OAuth
 */
app.get('/auth', (req, res) => {
  const scope = req.query.scope || 'repo';
  const redirectUri = CALLBACK_URL || `${req.protocol}://${req.get('host')}/callback`;

  const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
  authorizeUrl.searchParams.set('client_id', GITHUB_CLIENT_ID);
  authorizeUrl.searchParams.set('scope', scope);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);

  return res.redirect(authorizeUrl.toString());
});

/**
 * STEP 2 — Callback da GitHub
 * GitHub ci restituisce il "code", noi lo scambiamo con l’access_token
 * Poi mandiamo il token a Decap CMS via postMessage
 */
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
        message: tokenData.error_description || 'OAuth failed',
        origin: allowedOrigin
      }));
    }

    return res.send(renderPopupResult({
      ok: true,
      token: tokenData.access_token,
      origin: allowedOrigin
    }));
  } catch (e) {
    console.error('❌ callback error:', e);
    res.send(renderPopupResult({ ok: false, message: 'Unexpected error', origin: allowedOrigin }));
  }
});

/**
 * Utility: restituisce una pagina che comunica a Decap il risultato
 */
function renderPopupResult({ ok, token, message, origin }) {
  const payload = ok
    ? `authorization:github:success:${token}`
    : `authorization:github:error:${message || 'Error'}`;

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Auth Proxy</title></head>
<body>
<script>
  (function() {
    try {
      window.opener.postMessage('${payload}', '${origin}');
    } catch(e) {
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
