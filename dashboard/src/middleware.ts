import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { jwtVerify } from 'jose'

// Routes accessible without an authenticated session.
const PUBLIC_PATHS = [
  '/login',
  '/forgot-password',
  '/reset-password',
  '/api/auth/login',
  '/api/auth/verify-mfa',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
  '/api/auth/logout',
  '/api/health',
]

function getSecret() {
  return new TextEncoder().encode(process.env.JWT_SECRET || 'dev-secret-change-in-production')
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl

  if (
    PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(p + '/')) ||
    pathname.startsWith('/_next') ||
    pathname.startsWith('/logo') ||
    pathname === '/favicon.ico'
  ) {
    return NextResponse.next()
  }

  const token = request.cookies.get('plan_b_session')?.value
  if (!token) {
    return pathname.startsWith('/api/')
      ? NextResponse.json({ error: 'Not authenticated' }, { status: 401 })
      : NextResponse.redirect(new URL('/login', request.url))
  }

  try {
    // Edge-compatible signature + expiry check. Revocation / idle timeout /
    // user-state checks happen in the app layout and per-route requireUser().
    await jwtVerify(token, getSecret())
    return NextResponse.next()
  } catch {
    return pathname.startsWith('/api/')
      ? NextResponse.json({ error: 'Invalid session' }, { status: 401 })
      : NextResponse.redirect(new URL('/login', request.url))
  }
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
