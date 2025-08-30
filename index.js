import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
app.use(express.json());
app.set('trust proxy', 1);

const {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  ALLOWED_ORIGIN,
  CALLBACK_URL
} = process.env;

const allowedOrigin = ALLOWED_ORIGIN || 'https://danialcq.github.io';

app.use(cors({ origin: allowedOrigin, credentials: true }));

app.get('/', (_req, res) => res.send('✅ volley96-auth-proxy up'));
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    clientId: !!GITHUB_CLIENT_ID,
    secret: !!GITHUB_CLIENT_SECRET,
    allowedOrigin,
    callbackUrl: CALLBACK_URL || 'N/A'
  });
});

// --- OAuth avvio
app.get('/auth', (req, res) => {
  const scope = req.query.scope || 'repo';
  const redirectUri = CALLBACK_URL || `${req.protocol}://${req.get('host')}/callback`;

  const u = new URL('https://github.com/login/oauth/authorize');
  u.searchParams.set('client_id', GITHUB_CLIENT_ID);
  u.searchParams.set('scope', scope);
  u.searchParams.set('redirect_uri', redirectUri);
  res.redirect(u.toString());
});

// --- OAuth callback
app.get('/callback', async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send('❌ Missing code');

    const r = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code
      })
    });
    const data = await r.json();
    if (!r.ok || data.error || !data.access_token) {
      console.error('token exchange error:', data);
      return res.send(renderPopupResult({ ok: false, message: data.error_description || 'OAuth failed' }));
    }
    return res.send(renderPopupResult({ ok: true, token: data.access_token }));
  } catch (e) {
    console.error('callback error:', e);
    res.send(renderPopupResult({ ok: false, message: 'Unexpected error' }));
  }
});

// --- popup result: postMessage SEMPRE con '*'
function renderPopupResult({ ok, token, message }) {
  const payload = ok
    ? `authorization:github:success:${token}`
    : `authorization:github:error:${message || 'Error'}`;

  return `<!doctype html><html><head><meta charset="utf-8"><title>Auth Proxy</title></head>
<body><script>
(function(){
  try { window.opener.postMessage('${payload}', '*'); } catch(e) {}
  window.close();
})();
</script>
<p>Puoi chiudere questa finestra.</p></body></html>`;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('🚀 Auth proxy listening on :' + PORT);
});
