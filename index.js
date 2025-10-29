const express = require('express');
const cors = require('cors');
const {OAuth2Client} = require('google-auth-library');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const client = new OAuth2Client(process.env.CLIENT_ID);

app.get('/oauth2callback', async (req, res) => {
  const token = req.query.id_token;
  if (!token) return res.status(400).json({ error: 'Token mancante' });

  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.CLIENT_ID,
    });
    const payload = ticket.getPayload();
    res.json({
      userId: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
    });
  } catch (err) {
    console.error('❌ Errore verifica token:', err);
    res.status(401).json({ error: 'Token non valido' });
  }
});

app.listen(3000, () => console.log('✅ Server avviato su http://localhost:3000'));
