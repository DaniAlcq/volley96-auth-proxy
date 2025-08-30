// index.js — OAuth flow per Decap/Netlify CMS (GitHub)
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
app.use(express.json());

// fidati del proxy (X-Forwarded-Proto) se serve
app.set('trust proxy', 1);

const {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  ALLOWED_ORIGIN,               // es: https://danialcq.github.io
  CALLBACK_URL                  // es: https://volley96-auth-proxy.onrender.com/callback
} = process.env;

app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }));

app.get('/', (req, res) => res.send('OK: volley96-auth-proxy up'));
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    clientId: !!GITHUB_CLIENT_ID,
    secret: !!GITHUB_CLIENT_SECRET,
    allowedOrigin: ALLOWED_ORIGIN || null,
    callbackUrl: CALLBACK_URL || null
  });
});

// Avvio login (Decap chiamerà /auth?provider=github&scope=repo)
app.get('/auth', (req, res) => {
  const scope = req.query.scope || 'repo';
  const redirectUri = CALLBACK_URL || `${req.protocol}://${req.get('host')}/callback`;

  const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
  authorizeUrl.searchParams.set('client_id', GITHUB_CLIENT_ID);
  authorizeUrl.searchParams.set('scope', scope);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);
  return res.redirect(authorizeUrl.toString());
});

// Callback da GitHub: scambia code -> token e manda postMessage a Decap
app.get('/callback', async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send('Missing code');

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
      console.error('token error:', tokenData);
      return res.send(renderPopupResult({ ok: false, message: tokenData.error_description || 'OAuth failed' }));
    }

    return res.send(renderPopupResult({
      ok: true,
      token: tokenData.access_token,
      origin: ALLOWED_ORIGIN || '*'
    }));
  } catch (e) {
    console.error(e);
    res.send(renderPopupResult({ ok: false, message: 'Unexpected error' }));
  }
});

function renderPopupResult({ ok, token, message, origin }) {
  const targetOrigin = origin || '*';
  const payload = ok
    ? `authorization:github:success:${token}`
    : `authorization:github:error:${message || 'Error'}`;

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Auth</title></head>
<body>
<script>
  (function() {
    try { window.opener.postMessage('${payload}', '${targetOrigin}'); }
    catch(e) { window.opener && window.opener.postMessage('${payload}', '*'); }
    window.close();
  })();
</script>
Chiudi questa finestra...
</body></html>`;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Auth proxy on :' + PORT));
