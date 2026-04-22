import nodemailer from 'nodemailer'

type SmtpConfig = {
  host: string
  port: number
  user: string | null
  pass: string | null
  from: string
}

function readConfig(): SmtpConfig | null {
  const host = process.env.SMTP_HOST
  if (!host) return null
  return {
    host,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    user: process.env.SMTP_USER || null,
    pass: process.env.SMTP_PASS || null,
    from: process.env.SMTP_FROM || 'no-reply@plan-b.systems',
  }
}

export function isEmailConfigured(): boolean {
  return !!process.env.SMTP_HOST
}

export async function sendEmail(to: string, subject: string, html: string, text: string): Promise<{ sent: boolean; reason?: string }> {
  const cfg = readConfig()
  if (!cfg) {
    // Fallback: log to container stdout so SSH-assisted recovery remains possible.
    console.warn('[auth-email] SMTP not configured; printing email to stdout')
    console.log(`[auth-email] To: ${to}\n[auth-email] Subject: ${subject}\n[auth-email] Body:\n${text}`)
    return { sent: false, reason: 'smtp-not-configured' }
  }
  try {
    const transport = nodemailer.createTransport({
      host: cfg.host,
      port: cfg.port,
      secure: cfg.port === 465,
      auth: cfg.user ? { user: cfg.user, pass: cfg.pass || '' } : undefined,
    })
    await transport.sendMail({ from: cfg.from, to, subject, html, text })
    return { sent: true }
  } catch (err) {
    console.error('[auth-email] SMTP send failed:', err)
    return { sent: false, reason: 'send-failed' }
  }
}
