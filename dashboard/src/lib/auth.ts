import { SignJWT, jwtVerify } from 'jose'
import { cookies } from 'next/headers'
import { config } from './config'

const JWT_COOKIE = 'plansb_session'
const JWT_EXPIRY = '24h'

function getSecret() {
  return new TextEncoder().encode(config.jwtSecret)
}

export async function createSession(): Promise<string> {
  const token = await new SignJWT({ role: 'admin' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(JWT_EXPIRY)
    .sign(getSecret())

  return token
}

export async function verifySession(token: string): Promise<boolean> {
  try {
    await jwtVerify(token, getSecret())
    return true
  } catch {
    return false
  }
}

export function setSessionCookie(token: string) {
  cookies().set(JWT_COOKIE, token, {
    httpOnly: true,
    secure: false, // on-prem may not have HTTPS initially
    sameSite: 'lax',
    maxAge: 60 * 60 * 24, // 24 hours
    path: '/',
  })
}

export function getSessionCookie(): string | undefined {
  return cookies().get(JWT_COOKIE)?.value
}

export function clearSessionCookie() {
  cookies().delete(JWT_COOKIE)
}
