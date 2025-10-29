const express = require('express');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const client = new OAuth2Client(process.env.CLIENT_ID);

// 🌐 Endpoint per gestire il redirect da Google OAuth2
app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;

  if (!code) {
    return res.status(400).json({ error: 'Codice mancante nella query string' });
  }

  try {
    // 🔁 Scambia il codice con i token
    const { tokens } = await client.getToken(code);

    if (!tokens.id_token) {
      return res.status(401).json({ error: 'Token ID non ricevuto da Google' });
    }

    // ✅ Verifica l'id_token
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.CLIENT_ID,
    });

    const payload = ticket.getPayload();

    // 📦 Rispondi con i dati utente
    res.json({
      userId: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      idToken: tokens.id_token // opzionale: utile per salvarlo lato client
    });

  } catch (err) {
    console.error('❌ Errore durante la verifica del codice OAuth2:', err);
    res.status(500).json({ error: 'Errore interno durante la verifica del token' });
  }
});

// 🚀 Avvio server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server avviato su http://localhost:${PORT}`);
});
