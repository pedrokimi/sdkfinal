import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import { createIdentitySdk } from './sdkMiddleware.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
// Honra cabeçalhos de proxy para obter IP real (X-Forwarded-For, etc.)
app.set('trust proxy', true);
app.use(cors());
app.use(bodyParser.json({ limit: '1mb' }));

// SDK configuration (can be tuned via env vars)
const sdk = createIdentitySdk({
  allowThreshold: Number(process.env.ALLOW_THRESHOLD || 70),
  reviewThreshold: Number(process.env.REVIEW_THRESHOLD || 50),
  abuseIpdb: {
    enabled: process.env.ABUSEIPDB_ENABLED === 'true',
    apiKey: process.env.ABUSEIPDB_API_KEY || '',
    days: Number(process.env.ABUSEIPDB_DAYS || 30),
    maliciousThreshold: Number(process.env.ABUSEIPDB_MALICIOUS_THRESHOLD || 75)
  },
  riskWeights: {
    ip: Number(process.env.WEIGHT_IP || 20),
    userAgent: Number(process.env.WEIGHT_UA || 25),
    timezone: Number(process.env.WEIGHT_TZ || 15),
    language: Number(process.env.WEIGHT_LANG || 15),
    resolution: Number(process.env.WEIGHT_RES || 10),
    abuseIpdb: Number(process.env.WEIGHT_ABUSE || 30)
  },
  challenges: {
    available: (process.env.CHALLENGES || 'OTP,EMAIL,BIOMETRIC').split(',').map(s => s.trim().toUpperCase()).filter(Boolean)
  },
  extraFieldRules: []
});

// Mount middleware under /identity
app.use('/identity', sdk.middleware());

// Runtime config API (adjust thresholds, weights and rules)
app.get('/identity/config', (req, res) => {
  res.json(sdk.getConfig());
});

app.put('/identity/config', (req, res) => {
  try {
    sdk.updateConfig(req.body || {});
    res.json({ ok: true, config: sdk.getConfig() });
  } catch (e) {
    res.status(400).json({ ok: false, error: String(e) });
  }
});

// Serve a static folder for any demo assets if needed
app.use('/static', express.static(path.join(__dirname, '../public')));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`[SDK] Backend listening on port ${PORT}`);
});


