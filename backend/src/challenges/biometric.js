import { createChallenge, getChallenge, deleteChallenge } from './store.js'

function cosineSimilarity(a, b) {
  if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return 0;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    const va = Number(a[i]) || 0;
    const vb = Number(b[i]) || 0;
    dot += va * vb;
    na += va * va;
    nb += vb * vb;
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb) || 1;
  return dot / denom;
}

export function initiateBiometricChallenge({ referenceEmbedding, ttlMs }) {
  if (!Array.isArray(referenceEmbedding) || referenceEmbedding.length === 0) {
    throw new Error('reference_embedding_required')
  }
  const rec = createChallenge({ type: 'BIOMETRIC', ref: referenceEmbedding, ttlMs })
  return { challengeId: rec.id }
}

export function verifyBiometricChallenge({ challengeId, embedding, threshold = 0.6 }) {
  const rec = getChallenge(challengeId)
  if (!rec || rec.type !== 'BIOMETRIC') return { verified: false, error: 'invalid_or_expired' }
  if (!Array.isArray(embedding) || embedding.length === 0) return { verified: false, error: 'embedding_required' }
  const sim = cosineSimilarity(rec.ref, embedding)
  const ok = sim >= threshold
  if (ok) deleteChallenge(challengeId)
  return { verified: ok, similarity: sim }
}


