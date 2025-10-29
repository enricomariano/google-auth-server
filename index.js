app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).json({ error: 'Codice mancante' });

  try {
    const { tokens } = await client.getToken(code);
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
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
    console.error('❌ Errore verifica codice:', err);
    res.status(401).json({ error: 'Codice non valido' });
  }
});
