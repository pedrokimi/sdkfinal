import express from 'express';
import { evaluateRisk } from './riskEngine.js';
import { logAccess, logChallenge } from './loggers/jsonLogger.js';
import { checkIpOnAbuseIpdb } from './services/abuseIpdb.js';
import { initiateOtpChallenge, verifyOtpChallenge } from './challenges/otp.js';
import { initiateEmailChallenge, verifyEmailChallenge } from './challenges/email.js';
import { initiateBiometricChallenge, verifyBiometricChallenge } from './challenges/biometric.js';

function getClientIp(req) {
  // Ordem de precedencia: Cloudflare > X-Real-IP > X-Forwarded-For > Express req.ip
  const cf = (req.headers['cf-connecting-ip'] || '').toString().trim();
  if (cf) return normalizeIp(cf);
  const xreal = (req.headers['x-real-ip'] || '').toString().trim();
  if (xreal) return normalizeIp(xreal);
  const xfwd = (req.headers['x-forwarded-for'] || '').toString();
  if (xfwd) return normalizeIp(xfwd.split(',')[0].trim());
  const direct = req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || '';
  return normalizeIp(direct);
}

function normalizeIp(ip) {
  if (!ip) return '';
  // Remove prefixo IPv6 mapeado ::ffff:
  if (ip.startsWith('::ffff:')) return ip.substring(7);
  // Tratamento de IPv6 localhost
  if (ip === '::1') return '127.0.0.1';
  return ip;
}

export function createIdentitySdk(userConfig = {}) {
  const config = {
    allowThreshold: 70,
    reviewThreshold: 50,
    riskWeights: { ip: 20, userAgent: 25, timezone: 15, language: 15, resolution: 10, abuseIpdb: 30 },
    abuseIpdb: { enabled: false, apiKey: '', days: 30, maliciousThreshold: 75 },
    challenges: { available: ['OTP', 'EMAIL'] },
    extraFieldRules: [],
    ...userConfig
  };

  function getConfig() {
    return JSON.parse(JSON.stringify(config));
  }

  function updateConfig(delta = {}) {
    if (delta.allowThreshold != null) config.allowThreshold = Number(delta.allowThreshold);
    if (delta.reviewThreshold != null) config.reviewThreshold = Number(delta.reviewThreshold);
    if (delta.riskWeights && typeof delta.riskWeights === 'object') {
      config.riskWeights = { ...config.riskWeights, ...delta.riskWeights };
    }
    if (delta.abuseIpdb && typeof delta.abuseIpdb === 'object') {
      config.abuseIpdb = { ...config.abuseIpdb, ...delta.abuseIpdb };
    }
    if (delta.challenges && typeof delta.challenges === 'object') {
      config.challenges = { ...config.challenges, ...delta.challenges };
    }
    if (Array.isArray(delta.extraFieldRules)) {
      config.extraFieldRules = delta.extraFieldRules.slice(0, 100);
    }
  }

  function decideChallenge(result, input) {
    // If AbuseIPDB says malicious or status is review/deny, propose a challenge
    const available = config.challenges.available || [];
    if (input?.abuseIpdb?.malicious || result.status !== 'allow') {
      // Prefer OTP, fallback to EMAIL
      if (available.includes('OTP')) return 'OTP';
      if (available.includes('EMAIL')) return 'EMAIL';
    }
    return null;
  }

  function middleware() {
    const router = express.Router();

    router.post('/verify', async (req, res) => {
      const start = Date.now();
      try {
        const clientIp = getClientIp(req);
        const userAgent = req.headers['user-agent'] || '';
        const {
          timezoneOffset,
          language,
          screen,
          sessionMeta,
          extraSignals,
          faceEmbedding
        } = req.body || {};

        let abuseIpdbData = null;
        if (config.abuseIpdb?.enabled && clientIp) {
          abuseIpdbData = await checkIpOnAbuseIpdb(clientIp, config.abuseIpdb);
        }

        const riskInput = {
          ip: clientIp,
          userAgent,
          timezoneOffset,
          language,
          screen,
          abuseIpdb: abuseIpdbData || undefined,
          extraSignals,
          faceEmbedding
        };

        const result = evaluateRisk(riskInput, config);

        const challenge = decideChallenge(result, riskInput);
        if (abuseIpdbData?.malicious && challenge && result.status === 'allow') {
          // Force at least review if malicious
          result.status = 'review';
        }

        const response = {
          status: result.status,
          score: result.score,
          reasons: result.reasons,
          suggestedChallenge: challenge,
          challengeRequired: Boolean(challenge) && (Boolean(abuseIpdbData?.malicious) || result.status !== 'allow'),
          thresholds: {
            allow: config.allowThreshold,
            review: config.reviewThreshold
          },
          tookMs: Date.now() - start,
          ip: clientIp
        };

        logAccess({
          ip: clientIp,
          userAgent,
          sessionMeta,
          request: { timezoneOffset, language, screen },
          result: response,
          abuseIpdb: abuseIpdbData
        });

        res.status(200).json(response);
      } catch (err) {
        res.status(500).json({ error: 'internal_error', message: String(err) });
      }
    });

    router.post('/challenge/initiate', async (req, res) => {
      try {
        const { type, email, userLabel, referenceEmbedding } = req.body || {};
        let out;
        if (String(type).toUpperCase() === 'OTP') {
          out = await initiateOtpChallenge({ userLabel });
        } else if (String(type).toUpperCase() === 'EMAIL') {
          const transporterConfig = {
            host: process.env.SMTP_HOST,
            port: Number(process.env.SMTP_PORT || 587),
            secure: String(process.env.SMTP_SECURE || 'false') === 'true',
            auth: {
              user: process.env.SMTP_USER,
              pass: process.env.SMTP_PASS
            },
            from: process.env.SMTP_FROM || process.env.SMTP_USER
          };
          out = await initiateEmailChallenge({ to: email, transporterConfig });
        } else if (String(type).toUpperCase() === 'BIOMETRIC') {
          out = await initiateBiometricChallenge({ referenceEmbedding, ttlMs: 5 * 60 * 1000 });
        } else {
          return res.status(400).json({ error: 'unsupported_type' });
        }
        logChallenge({ action: 'initiate', type, email, result: out });
        res.json(out);
      } catch (err) {
        res.status(500).json({ error: 'internal_error', message: String(err) });
      }
    });

    router.post('/challenge/verify', async (req, res) => {
      try {
        const { type, challengeId, code, embedding } = req.body || {};
        let verified = { verified: false };
        if (String(type).toUpperCase() === 'OTP') {
          verified = verifyOtpChallenge({ challengeId, code });
        } else if (String(type).toUpperCase() === 'EMAIL') {
          verified = verifyEmailChallenge({ challengeId, code });
        } else if (String(type).toUpperCase() === 'BIOMETRIC') {
          const threshold = Number(process.env.BIOMETRIC_SIMILARITY || 0.6);
          verified = verifyBiometricChallenge({ challengeId, embedding, threshold });
        } else {
          return res.status(400).json({ error: 'unsupported_type' });
        }
        logChallenge({ action: 'verify', type, challengeId, verified });
        res.json(verified);
      } catch (err) {
        res.status(500).json({ error: 'internal_error', message: String(err) });
      }
    });

    return router;
  }

  return { middleware, getConfig, updateConfig };
}


