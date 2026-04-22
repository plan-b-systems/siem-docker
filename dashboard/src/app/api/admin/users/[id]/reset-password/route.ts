import crypto from 'crypto'
import { NextResponse } from 'next/server'
import { requireAdmin, getClientIp } from '@/lib/auth-require'
import { findUserById, setPassword, updateUserFields } from '@/lib/auth-users'
import { revokeAllSessionsForUser } from '@/lib/auth-session'
import { audit } from '@/lib/auth-audit'
import { sendEmail, isEmailConfigured } from '@/lib/auth-email'

function generatePassword(): string {
  return crypto.randomBytes(12).toString('base64').replace(/[+/=]/g, '') + 'Aa1'
}

export async function POST(req: Request, { params }: { params: { id: string } }) {
  const auth = await requireAdmin()
  if ('errorResponse' in auth) return auth.errorResponse
  const ip = getClientIp(req)
  const userAgent = req.headers.get('user-agent')

  const target = findUserById(params.id)
  if (!target) return NextResponse.json({ error: 'Not found' }, { status: 404 })

  const tempPassword = generatePassword()
  await setPassword(target.id, tempPassword)
  updateUserFields(target.id, { must_change_password: true, failed_attempts: 0, locked_until: null })
  revokeAllSessionsForUser(target.id)

  let emailSent = false
  if (target.email && isEmailConfigured()) {
    const text = `An administrator has reset your Plan-B SIEM password.\n\nUsername: ${target.username}\nTemporary password: ${tempPassword}\n\nYou will be required to change it on your next login.`
    const html = `<p>An administrator has reset your Plan-B SIEM password.</p><ul><li>Username: <strong>${target.username}</strong></li><li>Temporary password: <code>${tempPassword}</code></li></ul><p>You will be required to change it on your next login.</p>`
    const r = await sendEmail(target.email, 'Plan-B SIEM — Password reset', html, text)
    emailSent = r.sent
  }

  audit({
    userId: auth.user.id,
    actorUsername: auth.user.username,
    action: 'admin.user_password_reset',
    targetType: 'user',
    targetId: target.id,
    ip,
    userAgent,
    success: true,
    message: emailSent ? 'temp_password_emailed' : 'temp_password_shown_to_admin',
  })

  return NextResponse.json({
    success: true,
    temp_password: emailSent ? undefined : tempPassword,
    email_sent: emailSent,
  })
}
