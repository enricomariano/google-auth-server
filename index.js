const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// 🔐 Crea client OAuth2 con client_id, client_secret e redirect_uri
const oauth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  'https://google-auth-server-obi8.onrender.com/oauth2callback' // ← deve combaciare con Google Console
);

// 🌐 Endpoint per gestire il redirect da Google OAuth2
app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;

  if (!code) {
    return res.status(400).json({ error: 'Codice mancante nella query string' });
  }

  try {
    // 🔁 Scambia il codice con i token
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    if (!tokens.id_token) {
      return res.status(401).json({ error: 'Token ID non ricevuto da Google' });
    }

    // ✅ Verifica l'id_token
    const ticket = await oauth2Client.verifyIdToken({
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
      idToken: tokens.id_token
    });

  } catch (err) {
    console.error('❌ Errore durante la verifica del codice OAuth2:', err.message);
    res.status(500).json({ error: 'Verifica fallita. Il codice potrebbe essere scaduto, già usato o non valido.' });
  }
});

// 🚀 Avvio server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server avviato su http://localhost:${PORT}`);
});
