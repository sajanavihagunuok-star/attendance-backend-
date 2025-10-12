// health.js (ES Module compatible)
import express from 'express';

const app = express();
const PORT = process.env.PORT || 3000;

app.get('/ping', (req, res) => res.send('pong'));

app.listen(PORT, () => {
  console.log(`Health check server running on ${PORT}`);
});