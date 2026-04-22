import { authenticator } from 'otplib'
import QRCode from 'qrcode'

authenticator.options = {
  window: 1,          // allow ±1 step (±30s) drift
  step: 30,
  digits: 6,
}

const ISSUER = 'Plan-B SIEM'

export function generateTotpSecret(): string {
  return authenticator.generateSecret()
}

export function buildOtpauthUri(username: string, secret: string, issuer = ISSUER): string {
  return authenticator.keyuri(username, issuer, secret)
}

export async function generateQrDataUrl(otpauthUri: string): Promise<string> {
  return QRCode.toDataURL(otpauthUri, { errorCorrectionLevel: 'M', margin: 1, width: 240 })
}

export function verifyTotp(token: string, secret: string): boolean {
  if (!token || !secret) return false
  try {
    return authenticator.verify({ token: token.replace(/\s+/g, ''), secret })
  } catch {
    return false
  }
}
