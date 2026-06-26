require('dotenv').config();
const express = require('express');
const cors = require('cors');
const scanRouter = require('./routes/scan');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({ origin: 'http://localhost:5173' }));
app.use(express.json());

app.use('/api/scan', scanRouter);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0' });
});

app.listen(PORT, () => {
  console.log(`🛡️  VulnScan AI backend running on http://localhost:${PORT}`);
});
