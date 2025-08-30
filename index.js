// index.js
import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';

const app = express();
app.use(express.json());
app.use(cookieParser());

// ====== CONFIG ======
const {
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  REPO_FULL_NAME,            // es: "DaniAlcq/asd-volley-96" (facoltativo)
  ALLOWED_ORIGIN,            // es: "https://danialcq.github.io"
  COOKIE_SECRET = 'cms_oauth_cookie_secret'
} = process.env;

// CORS: consenti il tuo sito (l'origin è schema+host+porta, niente path)
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);             // per richieste server-to-server
    if (!ALLOWED_ORIGIN) return cb(null, true);      // permissivo finché configuri
    if (origin === ALLOWED_ORIGIN) return cb(null, true);
    return cb(new Error(`Origin non consentito: ${origin}`));
  },
  credentials: true
}));

// Utility per state anti-CSRF
function makeState() {
  return crypto.randomBytes(16).toString('hex');
}

// Health
app.get('/', (req, res) => res.send('OK: volley96-auth-proxy up (OAuth web flow)'));
app.get('/health', (req, res) => {
  res.json({
    ok: true,
    hasClientId: !!GITHUB_CLIENT_ID,
    hasSecret: !!GITHUB_CLIENT_SECRET,
    repo: REPO_FULL_NAME || null,
    allowedOrigin: ALLOWED_ORIGIN || '* (dev)'
  });
});

/**
 * 1) Avvio login: reindirizza a GitHub OAuth authorize
 *    Decap CMS aprirà questo endpoint in un popup.
 *    Query utili: ?origin=<url admin> (Decap la passa; la teniamo per sicurezza)
 */
app.get('/auth/github', (req, res) => {
  try {
    const origin = req.query.origin || ALLOWED_ORIGIN; // es. https://danialcq.github.io
    if (!origin) {
      return res.status(400).send('Missing origin (configura ALLOWED_ORIGIN o passa ?origin=...)');
    }

    // genera state e salvalo in cookie (httpOnly false perché usiamo popup; va bene per questo caso)
    const state = makeState();
    res.cookie('oauth_state', state, { httpOnly: true, sameSite: 'lax', secure: true });
    res.cookie('cms_origin', origin, { httpOnly: true, sameSite: 'lax', secure: true });

    const params = new URLSearchParams({
      client_id: GITHUB_CLIENT_ID,
      scope: 'repo',
      state,
      // Deve puntare al tuo /callback pubblico
      redirect_uri: `https://${req.get('host')}/callback`
    });

    const authorizeUrl = `https://github.com/login/oauth/authorize?${params.toString()}`;
    return res.redirect(authorizeUrl);
  } catch (e) {
    console.error(e);
    res.status(500).send('auth init failed');
  }
});

/**
 * 2) Callback da GitHub: scambia code -> access_token e “consegna” il token al CMS
 *    tramite postMessage dal popup verso la finestra principale, poi chiude il popup.
 */
app.get('/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const savedState = req.cookies.oauth_state;
    const origin = req.cookies.cms_origin || ALLOWED_ORIGIN;

    if (!code || !state) return res.status(400).send('Missing code/state');
    if (state !== savedState) return res.status(400).send('Invalid state');

    // scambia code per access_token
    const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `https://${req.get('host')}/callback`,
        state
      })
    });
    const tokenData = await tokenResp.json();

    if (!tokenResp.ok || tokenData.error || !tokenData.access_token) {
      console.error('Token exchange error:', tokenData);
      return res.status(400).send('Token exchange failed');
    }

    const accessToken = tokenData.access_token;

    // Pagina HTML che comunica il token al CMS e chiude il popup
    // Decap si aspetta un postMessage con { token, provider: 'github' }
    const target = origin || '*';
    const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>GitHub OAuth Done</title></head>
<body>
<script>
  (function(){
    try {
      var data = { token: ${JSON.stringify(accessToken)}, provider: 'github' };
      if (window.opener) {
        window.opener.postMessage(data, ${JSON.stringify(target)});
        window.close();
      } else if (window.parent) {
        window.parent.postMessage(data, ${JSON.stringify(target)});
      }
    } catch(e) {
      console.error(e);
    }
  })();
</script>
<p>Login completato. Puoi chiudere questa finestra.</p>
</body>
</html>`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    return res.send(html);
  } catch (e) {
    console.error(e);
    res.status(500).send('callback failed');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth proxy listening on :${PORT}`));
