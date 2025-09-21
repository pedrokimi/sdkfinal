import fetch from 'node-fetch';
import { logAbuseIpdb } from '../loggers/jsonLogger.js';

export async function checkIpOnAbuseIpdb(ip, config) {
  const enabled = config?.enabled;
  const apiKey = config?.apiKey;
  const days = config?.days || 30;
  if (!enabled) return { enabled: false, skipped: true };
  if (!apiKey) return { enabled: true, skipped: true, reason: 'missing_api_key' };

  const url = `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}/json?key=${encodeURIComponent(apiKey)}&days=${encodeURIComponent(days)}`;
  try {
    const res = await fetch(url, { method: 'GET' });
    const data = await res.json();

    let abuseConfidenceScore = 0;
    // Normalize common shapes
    if (typeof data?.data?.abuseConfidenceScore === 'number') {
      abuseConfidenceScore = data.data.abuseConfidenceScore;
    } else if (typeof data?.abuseConfidenceScore === 'number') {
      abuseConfidenceScore = data.abuseConfidenceScore;
    } else if (typeof data?.score === 'number') {
      abuseConfidenceScore = data.score;
    }

    const result = {
      enabled: true,
      skipped: false,
      raw: data,
      abuseConfidenceScore,
      malicious: abuseConfidenceScore >= (config?.maliciousThreshold || 75)
    };

    logAbuseIpdb({ ip, url, abuseConfidenceScore, malicious: result.malicious, raw: data });
    return result;
  } catch (err) {
    logAbuseIpdb({ ip, url, error: String(err) });
    return { enabled: true, skipped: false, error: String(err) };
  }
}


