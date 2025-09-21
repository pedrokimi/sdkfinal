import fs from 'fs';
import path from 'path';

const LOG_DIR = path.join(process.cwd(), 'logs');

function ensureDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function ts() {
  return new Date().toISOString().replace(/[:]/g, '-');
}

export function writeJsonLog(prefix) {
  return (payload) => {
    try {
      ensureDir();
      const file = path.join(LOG_DIR, `${prefix}-${ts()}.json`);
      const data = {
        timestamp: new Date().toISOString(),
        ...payload
      };
      fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf-8');
      return file;
    } catch (err) {
      console.error('[logger] failed to write JSON log', err);
      return null;
    }
  };
}

function appendNdjson(streamName, payload) {
  try {
    ensureDir();
    const file = path.join(LOG_DIR, `${streamName}.ndjson`);
    const line = JSON.stringify({ timestamp: new Date().toISOString(), ...payload }) + '\n';
    fs.appendFileSync(file, line, 'utf-8');
    return file;
  } catch (err) {
    console.error('[logger] failed to append NDJSON', err);
    return null;
  }
}

export function logAccess(payload) {
  const file = writeJsonLog('acess')(payload); // requirement: acess-datahora.json
  appendNdjson('access', payload);
  return file;
}

export function logAbuseIpdb(payload) {
  const file = writeJsonLog('apubeipdb')(payload); // requirement: apubeipdb-datahora.json
  appendNdjson('abuseipdb', payload);
  return file;
}

export function logChallenge(payload) {
  const file = writeJsonLog('challenge')(payload);
  appendNdjson('challenge', payload);
  return file;
}


