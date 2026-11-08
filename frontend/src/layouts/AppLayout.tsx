import { useState, useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from '@/components/layout/Sidebar'
import Header from '@/components/layout/Header'
import { usePageTitle } from '@/hooks/usePageTitle'

export default function AppLayout() {
  const { title, subtitle } = usePageTitle()
  const [collapsed, setCollapsed] = useState(() => {
    return localStorage.getItem('vapt_sidebar_collapsed') === 'true'
  })

  const toggleCollapse = () => {
    setCollapsed((prev) => {
      const next = !prev
      localStorage.setItem('vapt_sidebar_collapsed', String(next))
      return next
    })
  }

  return (
    <div className="flex min-h-screen bg-[#020611] text-slate-100 font-sans selection:bg-cyan-500/30 selection:text-cyan-200 relative">
      {/* Subtle hacker ambient cyber-grid overlay */}
      <div
        className="fixed inset-0 pointer-events-none opacity-[0.03] z-0"
        style={{
          backgroundImage: `linear-gradient(to right, #00f0ff 1px, transparent 1px), linear-gradient(to bottom, #00f0ff 1px, transparent 1px)`,
          backgroundSize: '36px 36px',
        }}
      />
      <div className="relative z-10 flex min-h-screen w-full">
        <Sidebar collapsed={collapsed} onToggleCollapse={toggleCollapse} />
        <div className="flex-1 flex flex-col min-w-0 bg-[#020611]">
          <Header title={title} subtitle={subtitle} />
          <main className="flex-1 p-5 md:p-7 overflow-y-auto animate-fade-in">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  )
}
