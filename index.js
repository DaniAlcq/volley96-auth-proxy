// index.js  — OAuth flow per Decap/Netlify CMS (GitHub)
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
app.use(express.json());

const {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  ALLOWED_ORIGIN,   // es: https://danialcq.github.io
} = process.env;

// CORS (serve solo per eventuali chiamate XHR; il popup non ne ha bisogno)
app.use(cors({
  origin: (origin, cb) => cb(null, true),
  credentials: true
}));

app.get('/', (req, res) => res.send('OK: volley96-auth-proxy up'));

// Avvia login: Decap chiamerà /auth?provider=github&scope=repo
app.get('/auth', (req, res) => {
  const provider = req.query.provider || 'github';
  if (provider !== 'github') return res.status(400).send('Unsupported provider');

  const scope = req.query.scope || 'repo';
  const redirectUri = `${req.protocol}://${req.get('host')}/callback`;

  const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
  authorizeUrl.searchParams.set('client_id', GITHUB_CLIENT_ID);
  authorizeUrl.searchParams.set('scope', scope);
  authorizeUrl.searchParams.set('redirect_uri', redirectUri);

  // facoltativo: state
  // authorizeUrl.searchParams.set('state', 'abc123');

  res.redirect(authorizeUrl.toString());
});

// Callback da GitHub: scambia code -> access_token e postMessage al parent
app.get('/callback', async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send('Missing code');

    // Scambio code per token
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

    // Successo → manda messaggio al window.opener come si aspetta Decap
    return res.send(renderPopupResult({ ok: true, token: tokenData.access_token, origin: ALLOWED_ORIGIN }));
  } catch (e) {
    console.error(e);
    res.send(renderPopupResult({ ok: false, message: 'Unexpected error' }));
  }
});

function renderPopupResult({ ok, token, message, origin }) {
  // NB: Decap ascolta postMessage "authorization:github:success:<token>" oppure "authorization:github:error:<msg>"
  // origin: se vuoi limitare, metti l’origin del tuo sito; altrimenti usa "*"
  const targetOrigin = origin || '*';
  const payload = ok ? `authorization:github:success:${token}` : `authorization:github:error:${message || 'Error'}`;

  return `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Auth</title></head>
<body>
<script>
  (function() {
    function send() {
      try {
        window.opener.postMessage('${payload}', '${targetOrigin}');
      } catch (e) {
        // fallback
        window.opener && window.opener.postMessage('${payload}', '*');
      }
      window.close();
    }
    // Netlify/Decap invia prima "authorizing:github" per handshake,
    // ma possiamo inviare noi direttamente il risultato:
    send();
  })();
</script>
Chiudi questa finestra...
</body>
</html>`;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Auth proxy on :' + PORT));
