import { authenticator } from 'otplib'
import qrcode from 'qrcode'
import { createChallenge, getChallenge, deleteChallenge } from './store.js'

export async function initiateOtpChallenge({ userLabel = 'NexShopUser', issuer = 'NexShop' } = {}) {
  const secret = authenticator.generateSecret()
  const otpauth = authenticator.keyuri(userLabel, issuer, secret)
  const qrDataUrl = await qrcode.toDataURL(otpauth)
  const record = createChallenge({ type: 'OTP', secret })
  return { challengeId: record.id, otpauthUrl: otpauth, qrDataUrl }
}

export function verifyOtpChallenge({ challengeId, code }) {
  const rec = getChallenge(challengeId)
  if (!rec || rec.type !== 'OTP') return { verified: false, error: 'invalid_or_expired' }
  const ok = authenticator.check(code, rec.secret)
  if (ok) deleteChallenge(challengeId)
  return { verified: ok }
}


