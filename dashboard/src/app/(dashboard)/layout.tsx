import Sidebar from '@/components/Sidebar'
import { LanguageProvider } from '@/components/LanguageProvider'
import AiChat from '@/components/AiChat'

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <LanguageProvider>
      <div className="min-h-screen">
        <Sidebar />
        <main className="ml-60 rtl:ml-0 rtl:mr-60 min-h-screen transition-all duration-200">
          {children}
        </main>
        <AiChat />
      </div>
    </LanguageProvider>
  )
}
