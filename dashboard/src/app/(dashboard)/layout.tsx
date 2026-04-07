import Sidebar from '@/components/Sidebar'

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen">
      <Sidebar />
      <main className="ml-60 min-h-screen transition-all duration-200">
        {children}
      </main>
    </div>
  )
}
