import nodemailer from 'nodemailer'
import crypto from 'crypto'
import { createChallenge, getChallenge, deleteChallenge } from './store.js'

function generateCode() {
  return ('' + (crypto.randomInt(0, 999999) + 100000)).slice(-6)
}

export async function initiateEmailChallenge({ to, transporterConfig }) {
  if (!to) throw new Error('email_required')
  const code = generateCode()
  const record = createChallenge({ type: 'EMAIL', code, to })

  const transporter = nodemailer.createTransport(transporterConfig)
  await transporter.sendMail({
    from: transporterConfig.from,
    to,
    subject: 'Seu código de verificação',
    text: `Seu código é: ${code}`
  })

  return { challengeId: record.id, sent: true }
}

export function verifyEmailChallenge({ challengeId, code }) {
  const rec = getChallenge(challengeId)
  if (!rec || rec.type !== 'EMAIL') return { verified: false, error: 'invalid_or_expired' }
  const ok = String(code) === String(rec.code)
  if (ok) deleteChallenge(challengeId)
  return { verified: ok }
}


