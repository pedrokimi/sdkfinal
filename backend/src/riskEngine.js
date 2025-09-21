// Simple rules-based risk engine.

function normalizeScore(raw) {
  if (raw < 0) return 0;
  if (raw > 100) return 100;
  return Math.round(raw);
}

function applyExtraFieldRules(extraSignals = {}, rules = [], reasons, baseWeights = {}) {
  let delta = 0;
  for (const rule of rules) {
    if (!rule || !rule.field) continue;
    const value = extraSignals[rule.field];
    const weight = Number(rule.weight ?? 0);
    const type = String(rule.type || 'presence').toLowerCase();
    let matched = false;
    if (type === 'presence') {
      matched = typeof value !== 'undefined' && value !== null && value !== '';
    } else if (type === 'boolean') {
      matched = value === true;
    } else if (type === 'numeric_range') {
      const v = Number(value);
      matched = !Number.isNaN(v) && v >= Number(rule.min ?? -Infinity) && v <= Number(rule.max ?? Infinity);
    } else if (type === 'string_in') {
      const set = Array.isArray(rule.in) ? rule.in : [];
      matched = set.includes(String(value));
    }
    if (matched && weight) {
      delta += weight;
      reasons.push(`extra_${rule.field}`);
    }
  }
  return delta;
}

export function evaluateRisk(input, config) {
  const weights = config.riskWeights || {};

  let score = 50; // neutral baseline
  const reasons = [];

  // IP heuristic (backend should derive IP). If missing or private, slight risk reduction; if present unknown, neutral.
  if (!input.ip) {
    score -= Math.min(5, weights.ip || 0);
    reasons.push('ip_missing');
  }

  // userAgent heuristics
  const ua = (input.userAgent || '').toLowerCase();
  if (!ua) {
    score += Math.min(10, weights.userAgent || 0);
    reasons.push('ua_missing');
  } else {
    if (ua.includes('headless') || ua.includes('puppeteer') || ua.includes('playwright')) {
      score += weights.userAgent || 25;
      reasons.push('ua_headless');
    }
  }

  // timezone
  if (typeof input.timezoneOffset === 'number') {
    const tzAbs = Math.abs(input.timezoneOffset);
    if (tzAbs > 12 * 60) {
      score += Math.min(10, (weights.timezone || 15));
      reasons.push('tz_unusual');
    }
  } else {
    score += Math.min(5, (weights.timezone || 15));
    reasons.push('tz_missing');
  }

  // language
  if (!input.language) {
    score += Math.min(5, (weights.language || 15));
    reasons.push('lang_missing');
  }

  // resolution
  if (input.screen && input.screen.width && input.screen.height) {
    const { width, height } = input.screen;
    if (width < 640 || height < 480 || width > 4000 || height > 3000) {
      score += Math.min(10, (weights.resolution || 10));
      reasons.push('res_suspicious');
    }
  } else {
    score += Math.min(5, (weights.resolution || 10));
    reasons.push('res_missing');
  }

  // AbuseIPDB effect if present from upstream call
  if (input.abuseIpdb && typeof input.abuseIpdb.abuseConfidenceScore === 'number') {
    const abuseScore = input.abuseIpdb.abuseConfidenceScore; // 0..100
    const add = Math.round((weights.abuseIpdb || 30) * (abuseScore / 100));
    score += add;
    if (abuseScore >= (config.abuseIpdb?.maliciousThreshold || 75)) {
      reasons.push('abuseipdb_malicious');
    } else if (abuseScore > 0) {
      reasons.push('abuseipdb_warning');
    }
  }

  // Extra signals rules
  if (input.extraSignals && Array.isArray(config.extraFieldRules)) {
    score += applyExtraFieldRules(input.extraSignals, config.extraFieldRules, reasons, weights);
  }

  score = normalizeScore(score);

  // Decision
  const allowThreshold = config.allowThreshold ?? 70;
  const reviewThreshold = config.reviewThreshold ?? 50;
  let status = 'deny';
  if (score >= allowThreshold) status = 'allow';
  else if (score >= reviewThreshold) status = 'review';

  return { score, status, reasons };
}


