import { redirect } from 'next/navigation'
import { requireAdmin } from '@/lib/auth-require'

export const dynamic = 'force-dynamic'

export default async function AdminLayout({ children }: { children: React.ReactNode }) {
  const auth = await requireAdmin()
  if ('errorResponse' in auth) redirect('/overview')
  return <>{children}</>
}
