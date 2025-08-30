const express = require("express");
const fetch = require("node-fetch");
const dotenv = require("dotenv");
const cors = require("cors");

dotenv.config();

const app = express();
app.use(cors());

// Variabili d'ambiente
const CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const REPO = process.env.REPO_FULL_NAME;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN;

// Middleware CORS
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.header("Access-Control-Allow-Headers", "Content-Type");
  next();
});

// Endpoint login con GitHub
app.get("/auth", (req, res) => {
  const redirect = `https://github.com/login/oauth/authorize?client_id=${CLIENT_ID}&scope=repo,user&redirect_uri=${process.env.BASE_URL}/callback`;
  res.redirect(redirect);
});

// Callback GitHub
app.get("/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Code mancante");

  try {
    const response = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code
      })
    });

    const data = await response.json();

    if (data.error) {
      return res.status(400).json(data);
    }

    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).send("Errore server");
  }
});

// Porta dinamica per Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proxy attivo su porta ${PORT}`));
// Health & root
app.get('/', (req, res) => res.send('OK: volley96-auth-proxy up'));
app.get('/health', (req, res) => res.json({ ok: true, env: ['CLIENT_ID', !!process.env.GITHUB_CLIENT_ID, 'ORIGIN', process.env.ALLOWED_ORIGIN?.length > 0] }));
