import { NextResponse } from 'next/server'
import { requireUser } from '@/lib/auth-require'
import { generateTotpSecret, buildOtpauthUri, generateQrDataUrl } from '@/lib/auth-totp'
import { updateUserFields } from '@/lib/auth-users'

export async function POST() {
  const auth = await requireUser()
  if ('errorResponse' in auth) return auth.errorResponse
  const { user } = auth

  // Only allow enrolment when MFA is not already active. Re-enrolment after
  // loss of authenticator goes through the admin "Clear MFA" flow — this
  // prevents a hijacked session from rebinding MFA to the attacker's device.
  if (user.mfa_enrolled) {
    return NextResponse.json({ error: 'MFA is already enrolled. Ask an administrator to clear it first.' }, { status: 400 })
  }

  // Overwriting a non-confirmed secret is fine — mfa_enrolled is still 0.
  const secret = generateTotpSecret()
  updateUserFields(user.id, { mfa_secret: secret })

  const otpauthUri = buildOtpauthUri(user.username, secret)
  const qr = await generateQrDataUrl(otpauthUri)
  return NextResponse.json({ secret, otpauth_uri: otpauthUri, qr_data_url: qr })
}
