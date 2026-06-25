import { redirect } from 'next/navigation'
import Sidebar from '@/components/Sidebar'
import { LanguageProvider } from '@/components/LanguageProvider'
import AiChat from '@/components/AiChat'
import PortalBanner from '@/components/PortalBanner'
import { requireUser } from '@/lib/auth-require'
import { ensureBootstrapped } from '@/lib/auth-bootstrap'

export const dynamic = 'force-dynamic'

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  await ensureBootstrapped()
  const auth = await requireUser()
  if ('errorResponse' in auth) redirect('/login')

  if (auth.user.must_change_password) redirect('/change-password')
  if (!auth.user.mfa_enrolled) redirect('/enroll-mfa')

  return (
    <LanguageProvider>
      <div className="min-h-screen">
        <Sidebar />
        <main className="ml-60 rtl:ml-0 rtl:mr-60 min-h-screen transition-all duration-200">
          <PortalBanner />
          {children}
        </main>
        <AiChat />
      </div>
    </LanguageProvider>
  )
}
