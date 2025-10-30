const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const { MongoClient } = require('mongodb');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const mongoClient = new MongoClient(process.env.MONGO_URI);
let db;

// 🔐 Crea client OAuth2
const oauth2Client = new google.auth.OAuth2(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI
);

// 🌐 Endpoint per gestire il redirect da Google OAuth2
app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;

  if (!code) {
    console.warn('⚠️ Codice mancante nella query string');
    return res.status(400).json({ error: 'Codice mancante nella query string' });
  }

  console.log(`📥 Ricevuto codice: ${code}`);

  try {
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    if (!tokens.id_token) {
      console.warn('⚠️ Token ID non ricevuto da Google');
      return res.status(401).json({ error: 'Token ID non ricevuto da Google' });
    }

    const ticket = await oauth2Client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.CLIENT_ID,
    });

    const payload = ticket.getPayload();

    res.json({
      userId: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token || null
    });

    console.log(`[LOGIN] ${payload.email} @ ${new Date().toISOString()}`);
    console.log(`✅ Login riuscito per: ${payload.email}`);

  } catch (err) {
    const message = err.response?.data?.error_description || err.message;
    console.error('❌ Errore durante la verifica del codice OAuth2:', message);
    res.status(500).json({ error: `Verifica fallita: ${message}` });
  }
});

// 🔍 Verifica idToken
app.post('/verify', async (req, res) => {
  const { idToken } = req.body;

  if (!idToken) {
    return res.status(400).json({ error: 'Token mancante' });
  }

  try {
    const ticket = await oauth2Client.verifyIdToken({
      idToken,
      audience: process.env.CLIENT_ID,
    });

    const payload = ticket.getPayload();
    res.json({
      valid: true,
      userId: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture
    });

  } catch (err) {
    console.error('❌ Verifica token fallita:', err.message);
    res.status(401).json({ valid: false, error: 'Token non valido o scaduto' });
  }
});

// 🔁 Refresh token
app.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token mancante' });
  }

  try {
    oauth2Client.setCredentials({ refresh_token: refreshToken });
    const { credentials } = await oauth2Client.refreshAccessToken();

    if (!credentials.id_token) {
      return res.status(401).json({ error: 'Impossibile ottenere nuovo idToken' });
    }

    const ticket = await oauth2Client.verifyIdToken({
      idToken: credentials.id_token,
      audience: process.env.CLIENT_ID,
    });

    const payload = ticket.getPayload();

    res.json({
      userId: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      idToken: credentials.id_token,
      accessToken: credentials.access_token
    });

    console.log(`[REFRESH] ${payload.email} @ ${new Date().toISOString()}`);
    console.log(`🔁 Token aggiornato per: ${payload.email}`);
  } catch (err) {
    console.error('❌ Errore refresh token:', err.message);
    res.status(500).json({ error: 'Refresh fallito: ' + err.message });
  }
});

app.get('/ping-db', async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Database non disponibile' });

  try {
    const count = await db.collection('users').countDocuments();
    res.json({ status: 'ok', utenti: count });
  } catch (err) {
    console.error('❌ Errore ping-db:', err.message);
    res.status(500).json({ error: 'Errore durante il ping al database' });
  }
});


// ☁️ Sync utente su MongoDB
app.post('/user/update', async (req, res) => {
  if (!db) return res.status(503).json({ error: 'Database non disponibile' });

  const { userId, email, name, picture } = req.body;
  await db.collection('users').updateOne(
    { userId },
    { $set: { email, name, picture, lastLogin: new Date() } },
    { upsert: true }
  );
  res.json({ status: 'ok' });
});

// 🚀 Connessione MongoDB e avvio server
mongoClient.connect()
  .then(client => {
    db = client.db(process.env.DB_NAME || 'netboard');
    console.log('✅ Connessione a MongoDB riuscita');

    app.listen(PORT, () => {
      console.log(`✅ Server avviato su http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('❌ Errore connessione MongoDB:', err.message);
    process.exit(1);
  });
