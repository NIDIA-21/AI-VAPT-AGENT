import { useState, useEffect } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  ShieldCheck,
  PlusCircle,
  Bot,
  Activity,
  ShieldAlert,
  FileSearch,
  CheckCircle2,
  FileText,
  Wrench,
  Settings,
  Shield,
  ChevronLeft,
  ChevronRight,
  Radio,
} from 'lucide-react'
import { clsx } from 'clsx'

interface NavItem {
  label: string
  icon: React.ElementType
  path: string
  badge?: number | string
  badgeColor?: string
}

const navItems: NavItem[] = [
  { label: 'Dashboard', icon: LayoutDashboard, path: '/' },
  { label: 'Target Scope', icon: ShieldCheck, path: '/targets' },
  { label: 'New Assessment', icon: PlusCircle, path: '/assessment/new' },
  { label: 'AI Security Agent', icon: Bot, path: '/agent' },
  { label: 'Scan Activity', icon: Activity, path: '/scans' },
  { label: 'Vulnerabilities', icon: ShieldAlert, path: '/vulnerabilities' },
  { label: 'Evidence Explorer', icon: FileSearch, path: '/evidence' },
  { label: 'Approval Center', icon: CheckCircle2, path: '/approvals' },
  { label: 'Reports', icon: FileText, path: '/reports' },
  { label: 'Tool Integrations', icon: Wrench, path: '/integrations' },
  { label: 'Settings', icon: Settings, path: '/settings' },
]

interface SidebarProps {
  collapsed?: boolean
  onToggleCollapse?: () => void
}

export default function Sidebar({ collapsed: externalCollapsed, onToggleCollapse }: SidebarProps) {
  const location = useLocation()
  const [internalCollapsed, setInternalCollapsed] = useState(false)

  // Load persistence if external handler not provided
  useEffect(() => {
    if (externalCollapsed === undefined) {
      const saved = localStorage.getItem('vapt_sidebar_collapsed')
      if (saved) setInternalCollapsed(saved === 'true')
    }
  }, [externalCollapsed])

  const isCollapsed = externalCollapsed !== undefined ? externalCollapsed : internalCollapsed

  const toggle = () => {
    if (onToggleCollapse) {
      onToggleCollapse()
    } else {
      const next = !internalCollapsed
      setInternalCollapsed(next)
      localStorage.setItem('vapt_sidebar_collapsed', String(next))
    }
  }

  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/'
    return location.pathname.startsWith(path)
  }

  return (
    <aside
      className={clsx(
        'min-h-screen bg-navy-900 border-r border-slate-800 flex flex-col transition-all duration-300 relative z-40 select-none shadow-2xl',
        isCollapsed ? 'w-20' : 'w-64'
      )}
    >
      {/* ── Brand Logo & Header ────────────────────────────────────────────── */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-slate-800/80 bg-navy-950/40">
        <div className="flex items-center gap-3 overflow-hidden">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600/30 to-cyan-500/20 border border-cyan-500/30 flex items-center justify-center flex-shrink-0 shadow-glow-cyan">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          {!isCollapsed && (
            <div className="min-w-0 transition-opacity duration-200">
              <div className="text-sm font-bold tracking-wider text-slate-100 flex items-center gap-1.5">
                <span>AI-VAPT</span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 bg-cyan-500/20 text-cyan-400 rounded border border-cyan-500/30">
                  AGENT
                </span>
              </div>
              <p className="text-[10px] text-slate-400 font-mono tracking-tight truncate">
                Unified SecOps Suite
              </p>
            </div>
          )}
        </div>

        {/* Collapse toggle button */}
        <button
          onClick={toggle}
          title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={clsx(
            'w-7 h-7 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-slate-100 flex items-center justify-center border border-slate-700/60 transition-all duration-200',
            isCollapsed && 'mx-auto'
          )}
        >
          {isCollapsed ? <ChevronRight className="w-4 h-4 text-cyan-400" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* ── Scope Status Pill ─────────────────────────────────────────────── */}
      {!isCollapsed ? (
        <div className="mx-3 mt-4 px-3 py-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20 flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-[11px] font-medium text-emerald-300 truncate">
            Strict Scope Allowlist Active
          </span>
        </div>
      ) : (
        <div className="mx-auto mt-4" title="Strict Scope Allowlist Active">
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
        </div>
      )}

      {/* ── Navigation Links ──────────────────────────────────────────────── */}
      <nav className="flex-1 px-3 py-4 space-y-1.5 overflow-y-auto">
        {navItems.map((item) => {
          const active = isActive(item.path)
          const Icon = item.icon
          return (
            <NavLink
              key={item.path}
              to={item.path}
              title={isCollapsed ? item.label : undefined}
              className={clsx(
                'group flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-150 relative',
                active
                  ? 'text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 shadow-glow-cyan'
                  : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
              )}
            >
              {/* Active glow vertical strip */}
              {active && (
                <span className="absolute left-0 top-2 bottom-2 w-1 bg-cyan-400 rounded-r shadow-glow-cyan" />
              )}

              <Icon
                className={clsx(
                  'w-5 h-5 flex-shrink-0 transition-colors duration-150',
                  active ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-200'
                )}
              />

              {!isCollapsed && (
                <span className="flex-1 truncate tracking-tight">{item.label}</span>
              )}

              {!isCollapsed && item.badge !== undefined && (
                <span
                  className={clsx(
                    'text-[10px] font-semibold px-2 py-0.5 rounded-full border',
                    item.badgeColor || 'bg-slate-800 text-slate-300 border-slate-700'
                  )}
                >
                  {item.badge}
                </span>
              )}

              {/* Tooltip for collapsed state */}
              {isCollapsed && (
                <div className="absolute left-full ml-3 px-2.5 py-1 bg-slate-900 text-slate-100 text-xs rounded-md shadow-xl border border-slate-700 whitespace-nowrap opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity duration-150 z-50">
                  {item.label}
                </div>
              )}
            </NavLink>
          )
        })}
      </nav>

      {/* ── Footer / Operational Guard ────────────────────────────────────── */}
      <div className="p-3 border-t border-slate-800/80 bg-navy-950/30">
        {!isCollapsed ? (
          <div className="flex items-center justify-between text-[11px] text-slate-400 px-2 py-1.5 rounded-lg bg-slate-800/40 border border-slate-800">
            <div className="flex items-center gap-2">
              <Radio className="w-3.5 h-3.5 text-cyan-400" />
              <span className="font-mono">AUTHORIZED ONLY</span>
            </div>
            <span className="text-[10px] text-slate-400">v0.2.0</span>
          </div>
        ) : (
          <div className="flex justify-center" title="Authorized Scope Only">
            <Radio className="w-4 h-4 text-cyan-400" />
          </div>
        )}
      </div>
    </aside>
  )
}
