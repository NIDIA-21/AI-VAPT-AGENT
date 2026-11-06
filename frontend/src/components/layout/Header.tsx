import { useState, useEffect, useRef } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  Bell,
  RefreshCw,
  Wifi,
  WifiOff,
  Shield,
  ChevronRight,
  User,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
} from 'lucide-react'
import { healthApi } from '@/services/api'
import { clsx } from 'clsx'

interface HeaderProps {
  title: string
  subtitle?: string
}

export default function Header({ title, subtitle }: HeaderProps) {
  const location = useLocation()
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null)
  const [checking, setChecking] = useState(false)
  const [showNotifications, setShowNotifications] = useState(false)
  const [showUserMenu, setShowUserMenu] = useState(false)
  const notifRef = useRef<HTMLDivElement>(null)
  const userRef = useRef<HTMLDivElement>(null)

  const checkHealth = async () => {
    setChecking(true)
    try {
      await healthApi.check()
      setBackendOnline(true)
    } catch {
      setBackendOnline(false)
    } finally {
      setChecking(false)
    }
  }

  useEffect(() => {
    checkHealth()
    const interval = setInterval(checkHealth, 30_000)
    return () => clearInterval(interval)
  }, [])

  // Close popovers on click outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifications(false)
      }
      if (userRef.current && !userRef.current.contains(e.target as Node)) {
        setShowUserMenu(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Breadcrumbs calculation
  const getBreadcrumbs = () => {
    const parts = location.pathname.split('/').filter(Boolean)
    if (parts.length === 0) {
      return [{ label: 'SecOps', path: '/' }, { label: 'Dashboard', path: '/' }]
    }
    return [
      { label: 'SecOps', path: '/' },
      ...parts.map((p, idx) => ({
        label: p.charAt(0).toUpperCase() + p.slice(1).replace(/-/g, ' '),
        path: '/' + parts.slice(0, idx + 1).join('/'),
      })),
    ]
  }

  const breadcrumbs = getBreadcrumbs()

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between px-6 py-3.5 bg-navy-900/90 backdrop-blur-md border-b border-slate-800">
      {/* ── Left: Logo + Breadcrumbs & Page Title ─────────────────────────── */}
      <div className="flex items-center gap-4 min-w-0">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-glow-cyan">
            <Shield className="w-4 h-4" />
          </div>
          <span className="font-bold text-sm text-slate-100 tracking-tight hidden sm:inline">
            AI-VAPT <span className="text-cyan-400">AGENT</span>
          </span>
        </div>

        <div className="h-4 w-px bg-slate-800 hidden md:block" />

        {/* Breadcrumb Navigation */}
        <nav aria-label="Breadcrumb" className="hidden md:flex items-center gap-1.5 text-xs text-slate-400">
          {breadcrumbs.map((bc, idx) => (
            <div key={idx} className="flex items-center gap-1.5">
              {idx > 0 && <ChevronRight className="w-3.5 h-3.5 text-slate-400" />}
              {idx === breadcrumbs.length - 1 ? (
                <span className="font-medium text-slate-200">{bc.label}</span>
              ) : (
                <Link to={bc.path} className="hover:text-cyan-400 transition-colors">
                  {bc.label}
                </Link>
              )}
            </div>
          ))}
        </nav>

        {/* Mobile Page Title */}
        <div className="md:hidden">
          <h1 className="text-sm font-semibold text-slate-200 truncate">{title}</h1>
        </div>
      </div>

      {/* ── Right: Status, Notifications & Profile ────────────────────────── */}
      <div className="flex items-center gap-3">
        {/* System Status Indicator */}
        <button
          onClick={checkHealth}
          disabled={checking}
          title="Click to re-verify API connection"
          className={clsx(
            'flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all duration-200 select-none',
            backendOnline === null
              ? 'border-slate-700 text-slate-400 bg-slate-800/40'
              : backendOnline
              ? 'border-emerald-500/30 text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/15'
              : 'border-red-500/30 text-red-300 bg-red-500/10 hover:bg-red-500/15'
          )}
        >
          {checking ? (
            <RefreshCw className="w-3 h-3 animate-spin text-slate-400" />
          ) : backendOnline ? (
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          ) : (
            <WifiOff className="w-3 h-3 text-red-400" />
          )}
          <span className="hidden sm:inline">
            {backendOnline === null ? 'Checking…' : backendOnline ? 'System Operational' : 'API Offline'}
          </span>
        </button>

        {/* ── Notifications Dropdown ────────────────────────────────────────── */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative w-9 h-9 rounded-lg bg-slate-800/60 hover:bg-slate-700/80 border border-slate-700/60 text-slate-300 hover:text-white flex items-center justify-center transition-all duration-150"
            title="Notifications & Audit Alerts"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-cyan-400 rounded-full shadow-glow-cyan" />
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-navy-900 border border-slate-700/80 rounded-xl shadow-2xl p-4 z-50 animate-fade-in">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                  Security Notifications
                </span>
                <span className="text-[10px] text-cyan-400 font-mono">Live Audit</span>
              </div>
              <div className="mt-3 space-y-2.5 max-h-64 overflow-y-auto">
                <div className="flex items-start gap-2.5 p-2 rounded-lg bg-slate-800/40 border border-slate-800 text-xs">
                  <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-slate-200 font-medium">Scope Enforcement Guard</p>
                    <p className="text-slate-400 text-[11px] mt-0.5">
                      Target allowlist active. All unauthorized hosts will be rejected.
                    </p>
                    <span className="text-[10px] text-slate-400 font-mono">Active</span>
                  </div>
                </div>

                <div className="flex items-start gap-2.5 p-2 rounded-lg bg-slate-800/40 border border-slate-800 text-xs">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="text-slate-200 font-medium">Scanner Probes Ready</p>
                    <p className="text-slate-400 text-[11px] mt-0.5">
                      7 tools configured: Nmap, ZAP, Nikto, Nessus, OpenVAS, Burp, Metasploit.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* ── User Profile Section ─────────────────────────────────────────── */}
        <div className="relative" ref={userRef}>
          <button
            onClick={() => setShowUserMenu(!showUserMenu)}
            className="flex items-center gap-2.5 pl-2 pr-3 py-1 rounded-xl bg-slate-800/60 hover:bg-slate-700/80 border border-slate-700/60 text-left transition-all duration-150"
          >
            <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-600 to-cyan-600 flex items-center justify-center text-white text-xs font-bold shadow-glow-blue">
              SA
            </div>
            <div className="hidden lg:block">
              <p className="text-xs font-semibold text-slate-200 leading-none">Security Analyst</p>
              <p className="text-[10px] text-cyan-400/80 font-mono mt-0.5 leading-none">SecOps Lead</p>
            </div>
          </button>

          {showUserMenu && (
            <div className="absolute right-0 mt-2 w-64 bg-navy-900 border border-slate-700/80 rounded-xl shadow-2xl p-3 z-50 animate-fade-in">
              <div className="px-2 py-2 border-b border-slate-800">
                <p className="text-xs font-semibold text-slate-200">Security Analyst</p>
                <p className="text-[11px] text-slate-400 font-mono">operator@vapt-agent.local</p>
                <div className="mt-2 inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 text-[10px]">
                  <ShieldCheck className="w-3 h-3" />
                  <span>Authorized Operator</span>
                </div>
              </div>
              <div className="mt-2 py-1 space-y-1 text-xs">
                <Link
                  to="/settings"
                  onClick={() => setShowUserMenu(false)}
                  className="flex items-center justify-between px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800/60 transition-colors"
                >
                  <span>Operator Settings</span>
                  <ExternalLink className="w-3 h-3 text-slate-400" />
                </Link>
                <Link
                  to="/approvals"
                  onClick={() => setShowUserMenu(false)}
                  className="flex items-center justify-between px-2.5 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800/60 transition-colors"
                >
                  <span>Approval Center</span>
                  <span className="text-[10px] font-mono text-cyan-400">0 Pending</span>
                </Link>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
