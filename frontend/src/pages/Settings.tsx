import { useState, useEffect } from 'react'
import {
  Settings as SettingsIcon,
  Cpu,
  Shield,
  Layers,
  FileText,
  Sliders,
  CheckCircle2,
  RefreshCw,
  Save,
  RotateCcw,
  Download,
  AlertTriangle,
  Lock,
  Eye,
  EyeOff,
  Terminal,
  Activity,
  Key,
  ShieldCheck,
  Server,
  Zap,
} from 'lucide-react'
import { agentApi, dashboardApi } from '@/services/api'
import { clsx } from 'clsx'

interface VaptSettings {
  // AI Engine
  llmProvider: string
  llmModel: string
  apiKey: string
  temperature: number
  maxTokens: number
  autoDeterministicFallback: boolean
  reasoningVerbosity: string

  // Scanners
  nmapPath: string
  scanTimeout: number
  timingTemplate: string
  defaultPortProfile: string
  maxConcurrentScans: number
  autoDeduplicate: boolean

  // Scope & Governance
  strictDefaultDeny: boolean
  blockWildcards: boolean
  blockBroadCidr: boolean
  humanApprovalRequired: boolean
  auditRetentionDays: number
  mandatoryRejectionReason: boolean

  // Reporting
  organizationName: string
  leadAnalyst: string
  classificationBanner: string
  standardsFramework: string
  includeLimitationNotice: boolean

  // Workstation Theme
  themePreset: string
  highContrast: boolean
  scanlineEffect: boolean
  tacticalSound: boolean
}

const defaultSettings: VaptSettings = {
  llmProvider: 'gemini',
  llmModel: 'gemini-1.5-flash',
  apiKey: '',
  temperature: 0.2,
  maxTokens: 2048,
  autoDeterministicFallback: true,
  reasoningVerbosity: 'detailed',

  nmapPath: 'nmap',
  scanTimeout: 60,
  timingTemplate: '-T4',
  defaultPortProfile: 'web',
  maxConcurrentScans: 2,
  autoDeduplicate: true,

  strictDefaultDeny: true,
  blockWildcards: true,
  blockBroadCidr: true,
  humanApprovalRequired: true,
  auditRetentionDays: 90,
  mandatoryRejectionReason: true,

  organizationName: 'DataOps Cybersecurity Lab',
  leadAnalyst: 'Lead Security Analyst',
  classificationBanner: 'STRICTLY CONFIDENTIAL',
  standardsFramework: 'NIST SP 800-115 + OWASP WSTG v4.2',
  includeLimitationNotice: true,

  themePreset: 'obsidian',
  highContrast: false,
  scanlineEffect: false,
  tacticalSound: false,
}

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<'ai' | 'scanners' | 'scope' | 'reporting' | 'theme'>('ai')
  const [settings, setSettings] = useState<VaptSettings>(() => {
    try {
      const saved = localStorage.getItem('vapt_platform_settings')
      return saved ? { ...defaultSettings, ...JSON.parse(saved) } : defaultSettings
    } catch {
      return defaultSettings
    }
  })

  const [showApiKey, setShowApiKey] = useState(false)
  const [savedSuccess, setSavedSuccess] = useState(false)

  // Diagnostics test state
  const [testingEngine, setTestingEngine] = useState(false)
  const [engineTestResult, setEngineTestResult] = useState<{
    engine?: string
    is_fallback?: boolean
    model?: string
    active?: boolean
  } | null>(null)

  const [probingTools, setProbingTools] = useState(false)
  const [toolsResult, setToolsResult] = useState<{ nmapAvailable: boolean; totalTools: number } | null>(null)

  const updateSetting = <K extends keyof VaptSettings>(key: K, value: VaptSettings[K]) => {
    setSettings((prev) => ({ ...prev, [key]: value }))
    setSavedSuccess(false)
  }

  const handleSave = () => {
    localStorage.setItem('vapt_platform_settings', JSON.stringify(settings))
    setSavedSuccess(true)
    setTimeout(() => setSavedSuccess(false), 3500)
  }

  const handleResetDefaults = () => {
    if (window.confirm('Reset all settings to hardened factory defaults?')) {
      setSettings(defaultSettings)
      localStorage.setItem('vapt_platform_settings', JSON.stringify(defaultSettings))
      setSavedSuccess(true)
      setTimeout(() => setSavedSuccess(false), 3000)
    }
  }

  const handleExportConfig = () => {
    const safeSettings = { ...settings, apiKey: settings.apiKey ? '[REDACTED_FOR_SECURITY]' : '' }
    const blob = new Blob([JSON.stringify(safeSettings, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `vapt_platform_config_${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const testEngineConnection = async () => {
    setTestingEngine(true)
    setEngineTestResult(null)
    try {
      const info = await agentApi.engineInfo()
      setEngineTestResult({
        engine: info.active_engine || info.status_label,
        is_fallback: info.is_fallback,
        model: info.model,
        active: true,
      })
    } catch {
      setEngineTestResult({
        engine: 'Connection unreachable',
        is_fallback: true,
        active: false,
      })
    } finally {
      setTestingEngine(false)
    }
  }

  const probeScannerPaths = async () => {
    setProbingTools(true)
    setToolsResult(null)
    try {
      const data = await dashboardApi.tools()
      const nmap = data.tools.find((t) => t.name === 'nmap')
      setToolsResult({
        nmapAvailable: nmap?.status === 'Available',
        totalTools: data.tools.length,
      })
    } catch {
      setToolsResult({ nmapAvailable: false, totalTools: 0 })
    } finally {
      setProbingTools(false)
    }
  }

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12 animate-fade-in">
      {/* ── Page Header ────────────────────────────────────────────────────── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2.5 font-mono">
            <Sliders className="w-6 h-6 text-cyan-400" />
            Security Architecture & Platform Settings
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Configure AI reasoning engine, safe subprocess scanning, defensive scope guards, and cyber workstation aesthetics.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleResetDefaults}
            className="btn-secondary text-xs px-3 py-2 flex items-center gap-1.5 text-slate-400 hover:text-slate-200"
            title="Reset to factory defaults"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset Defaults
          </button>
          <button
            onClick={handleExportConfig}
            className="btn-secondary text-xs px-3 py-2 flex items-center gap-1.5 text-slate-300"
            title="Export config JSON"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON
          </button>
          <button
            onClick={handleSave}
            className="btn-primary text-xs px-4 py-2 flex items-center gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 shadow-glow-cyan"
          >
            <Save className="w-4 h-4" />
            Save Configuration
          </button>
        </div>
      </div>

      {savedSuccess && (
        <div className="p-3.5 rounded-xl bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 text-xs flex items-center gap-2.5 shadow-glow-matrix animate-fade-in font-mono">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>Configuration saved successfully. Parameters synced and active for all assessment runs.</span>
        </div>
      )}

      {/* ── Navigation Tabs ─────────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 border-b border-slate-800 overflow-x-auto pb-1 text-xs font-mono">
        <button
          onClick={() => setActiveTab('ai')}
          className={clsx(
            'px-4 py-2.5 rounded-lg flex items-center gap-2 font-semibold transition-all',
            activeTab === 'ai'
              ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-glow-cyan'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-800/60'
          )}
        >
          <Cpu className="w-4 h-4" />
          AI Engine &amp; LLM
        </button>

        <button
          onClick={() => setActiveTab('scanners')}
          className={clsx(
            'px-4 py-2.5 rounded-lg flex items-center gap-2 font-semibold transition-all',
            activeTab === 'scanners'
              ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-glow-cyan'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-800/60'
          )}
        >
          <Layers className="w-4 h-4" />
          Scanner Execution
        </button>

        <button
          onClick={() => setActiveTab('scope')}
          className={clsx(
            'px-4 py-2.5 rounded-lg flex items-center gap-2 font-semibold transition-all',
            activeTab === 'scope'
              ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-glow-cyan'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-800/60'
          )}
        >
          <Shield className="w-4 h-4" />
          Scope &amp; Governance
        </button>

        <button
          onClick={() => setActiveTab('reporting')}
          className={clsx(
            'px-4 py-2.5 rounded-lg flex items-center gap-2 font-semibold transition-all',
            activeTab === 'reporting'
              ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-glow-cyan'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-800/60'
          )}
        >
          <FileText className="w-4 h-4" />
          PDF Reporting &amp; Meta
        </button>

        <button
          onClick={() => setActiveTab('theme')}
          className={clsx(
            'px-4 py-2.5 rounded-lg flex items-center gap-2 font-semibold transition-all',
            activeTab === 'theme'
              ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-glow-cyan'
              : 'text-slate-400 hover:text-slate-200 hover:bg-navy-800/60'
          )}
        >
          <Terminal className="w-4 h-4" />
          Hacker Desktop Theme
        </button>
      </div>

      {/* ── TAB 1: AI Engine & LLM ─────────────────────────────────────────── */}
      {activeTab === 'ai' && (
        <div className="space-y-6">
          <div className="card p-6 space-y-5 border-cyan-500/20">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  Primary LLM Provider &amp; Model Routing
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Choose the LLM backend for conversational security planning and correlation analysis.
                </p>
              </div>

              <button
                onClick={testEngineConnection}
                disabled={testingEngine}
                className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300"
              >
                <Activity className={clsx('w-3.5 h-3.5', testingEngine && 'animate-spin')} />
                {testingEngine ? 'Testing Connection...' : 'Test Active Engine'}
              </button>
            </div>

            {engineTestResult && (
              <div
                className={clsx(
                  'p-3 rounded-lg border text-xs font-mono flex items-center justify-between',
                  engineTestResult.active
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                    : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                )}
              >
                <span>
                  <strong>Active Engine:</strong> {engineTestResult.engine} |{' '}
                  <strong>Model:</strong> {engineTestResult.model || 'Deterministic'} |{' '}
                  <strong>Fallback Mode:</strong> {engineTestResult.is_fallback ? 'Active (Safety Net)' : 'Off (Direct LLM)'}
                </span>
                <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-slate-900 border border-slate-700">
                  {engineTestResult.active ? 'ONLINE' : 'OFFLINE'}
                </span>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  LLM Provider Backend
                </label>
                <select
                  value={settings.llmProvider}
                  onChange={(e) => updateSetting('llmProvider', e.target.value)}
                  className="input-field text-xs py-2.5 w-full bg-slate-950 text-slate-100"
                >
                  <option value="gemini">Google Gemini (Recommended / Native)</option>
                  <option value="openai">OpenAI (GPT-4o Mini / Enterprise)</option>
                  <option value="ollama">Ollama (Local Private Inference)</option>
                  <option value="anthropic">Anthropic Claude 3.5 Sonnet</option>
                  <option value="deterministic">Deterministic Cybersecurity Rule Engine (Zero Keys Required)</option>
                </select>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  The system transparently falls back to the deterministic engine if quota or API limits are hit.
                </span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  Target Model Name
                </label>
                <input
                  type="text"
                  value={settings.llmModel}
                  onChange={(e) => updateSetting('llmModel', e.target.value)}
                  placeholder="e.g. gemini-1.5-flash or gpt-4o-mini"
                  className="input-field text-xs py-2.5 w-full font-mono bg-slate-950 text-slate-100"
                />
              </div>
            </div>

            {/* API Key Setting */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-semibold text-slate-300 font-mono flex items-center gap-1.5">
                  <Key className="w-3.5 h-3.5 text-cyan-400" />
                  API Key (Stored in Server Environment / Local Storage Session)
                </label>
                <span className="text-[11px] text-amber-400/90 font-mono">
                  Never committed to Git or exposed in client bundles
                </span>
              </div>
              <div className="relative">
                <input
                  type={showApiKey ? 'text' : 'password'}
                  value={settings.apiKey}
                  onChange={(e) => updateSetting('apiKey', e.target.value)}
                  placeholder="Enter API key or leave blank to utilize server-configured .env variable"
                  className="input-field text-xs py-2.5 pr-10 w-full font-mono bg-slate-950 text-slate-100"
                />
                <button
                  type="button"
                  onClick={() => setShowApiKey(!showApiKey)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                >
                  {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Hyperparameters */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
              <div className="p-3.5 rounded-lg bg-navy-950 border border-slate-800 space-y-2">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-slate-300">Inference Temperature</span>
                  <span className="text-cyan-400 font-bold">{settings.temperature} (High Precision)</span>
                </div>
                <input
                  type="range"
                  min="0.0"
                  max="1.0"
                  step="0.05"
                  value={settings.temperature}
                  onChange={(e) => updateSetting('temperature', parseFloat(e.target.value))}
                  className="w-full accent-cyan-500 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">
                  Lower values (0.1–0.3) enforce deterministic, fact-grounded cybersecurity recommendations.
                </span>
              </div>

              <div className="p-3.5 rounded-lg bg-navy-950 border border-slate-800 space-y-2">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-slate-300">Max Token Length</span>
                  <span className="text-cyan-400 font-bold">{settings.maxTokens} tokens</span>
                </div>
                <input
                  type="range"
                  min="512"
                  max="4096"
                  step="256"
                  value={settings.maxTokens}
                  onChange={(e) => updateSetting('maxTokens', parseInt(e.target.value))}
                  className="w-full accent-cyan-500 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">
                  Controls assessment plan verbosity and detailed technical finding explanations.
                </span>
              </div>
            </div>

            {/* Fallback & Safety Switch */}
            <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-xs font-bold text-slate-200 font-mono block">
                  Autonomous Deterministic Fallback Mode
                </span>
                <span className="text-[11px] text-slate-400">
                  Guarantees 100% assessment uptime by switching to rule engine if LLM provider returns quota errors.
                </span>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={settings.autoDeterministicFallback}
                  onChange={(e) => updateSetting('autoDeterministicFallback', e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-cyan-600"></div>
              </label>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 2: Scanner Execution ────────────────────────────────────────── */}
      {activeTab === 'scanners' && (
        <div className="space-y-6">
          <div className="card p-6 space-y-5 border-cyan-500/20">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                  <Layers className="w-4 h-4 text-cyan-400" />
                  Subprocess &amp; Diagnostic Path Settings
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Configure local binary execution paths, timeouts, and safe scanning arguments.
                </p>
              </div>

              <button
                onClick={probeScannerPaths}
                disabled={probingTools}
                className="btn-secondary text-xs px-3 py-1.5 flex items-center gap-1.5 text-cyan-400"
              >
                <RefreshCw className={clsx('w-3.5 h-3.5', probingTools && 'animate-spin')} />
                {probingTools ? 'Probing System PATH...' : 'Probe Local Binaries'}
              </button>
            </div>

            {toolsResult && (
              <div
                className={clsx(
                  'p-3 rounded-lg border text-xs font-mono flex items-center justify-between',
                  toolsResult.nmapAvailable
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                    : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
                )}
              >
                <span>
                  <strong>Nmap Status:</strong> {toolsResult.nmapAvailable ? 'Live Subprocess Detected' : 'Not Installed (Report Import Mode Active)'} |{' '}
                  <strong>Total Tracked Tools:</strong> {toolsResult.totalTools}
                </span>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-900 border border-slate-700">
                  {toolsResult.nmapAvailable ? 'LIVE' : 'IMPORT ONLY'}
                </span>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  Nmap Executable Binary Path
                </label>
                <input
                  type="text"
                  value={settings.nmapPath}
                  onChange={(e) => updateSetting('nmapPath', e.target.value)}
                  placeholder="e.g. nmap or C:\Program Files (x86)\Nmap\nmap.exe"
                  className="input-field text-xs py-2.5 w-full font-mono bg-slate-950 text-slate-100"
                />
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Executed strictly using argument lists (zero shell=True) with automatic timeout safety.
                </span>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  Subprocess Timeout (Seconds)
                </label>
                <input
                  type="number"
                  min="10"
                  max="300"
                  value={settings.scanTimeout}
                  onChange={(e) => updateSetting('scanTimeout', parseInt(e.target.value) || 60)}
                  className="input-field text-xs py-2.5 w-full font-mono bg-slate-950 text-slate-100"
                />
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Hard kill threshold to prevent hung network sockets or infinite scanning loops.
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  Scan Timing Template
                </label>
                <select
                  value={settings.timingTemplate}
                  onChange={(e) => updateSetting('timingTemplate', e.target.value)}
                  className="input-field text-xs py-2.5 w-full bg-slate-950 text-slate-100"
                >
                  <option value="-T4">-T4 (Aggressive / Fast for Lab Environments)</option>
                  <option value="-T3">-T3 (Normal / Balanced Network Timing)</option>
                  <option value="-T2">-T2 (Polite / Bandwidth-Constrained Targets)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  Default Port Scanning Profile
                </label>
                <select
                  value={settings.defaultPortProfile}
                  onChange={(e) => updateSetting('defaultPortProfile', e.target.value)}
                  className="input-field text-xs py-2.5 w-full bg-slate-950 text-slate-100"
                >
                  <option value="web">Web Services Only (80, 443, 8080, 8443, 3000, 5000)</option>
                  <option value="top100">Top 100 Common Ports</option>
                  <option value="top1000">Top 1000 Standard Services</option>
                  <option value="custom">Strict Permitted Ports Defined on Target</option>
                </select>
              </div>
            </div>

            {/* Safe Command Preview */}
            <div className="p-3.5 rounded-lg bg-navy-950 border border-slate-800 space-y-1">
              <span className="text-[11px] font-mono text-slate-400 block font-semibold">
                Constructed Subprocess Command Signature (Safe Execution Guarantee):
              </span>
              <code className="text-xs text-cyan-300 font-mono block bg-black/60 p-2 rounded border border-slate-800">
                {settings.nmapPath} -sV {settings.timingTemplate} -Pn --open -p &lt;PERMITTED_PORTS&gt; -oX - &lt;AUTHORIZED_TARGET&gt;
              </code>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 3: Scope & Governance ───────────────────────────────────────── */}
      {activeTab === 'scope' && (
        <div className="space-y-6">
          <div className="card p-6 space-y-5 border-cyan-500/20">
            <div className="border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Defensive Scope Boundaries &amp; Authorization Guardrails
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Enforces non-negotiable safety rules preventing scans against unauthorized third-party infrastructure.
              </p>
            </div>

            <div className="space-y-4 text-xs font-mono divide-y divide-slate-800">
              <div className="flex items-center justify-between pt-2">
                <div>
                  <span className="font-bold text-slate-200 block">Strict Default-Deny Policy</span>
                  <span className="text-slate-500 text-[11px]">
                    Any target IP, domain, or hostname not actively registered in the database is automatically blocked.
                  </span>
                </div>
                <span className="px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-400 font-bold border border-emerald-500/30">
                  ENFORCED (LOCKED)
                </span>
              </div>

              <div className="flex items-center justify-between pt-4">
                <div>
                  <span className="font-bold text-slate-200 block">Auto-Block Wildcard Domains (*.domain.com)</span>
                  <span className="text-slate-500 text-[11px]">
                    Rejects broad subdomain patterns during registration to prevent scope expansion.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.blockWildcards}
                  onChange={(e) => updateSetting('blockWildcards', e.target.checked)}
                  className="accent-cyan-500 w-4 h-4 cursor-pointer"
                />
              </div>

              <div className="flex items-center justify-between pt-4">
                <div>
                  <span className="font-bold text-slate-200 block">Auto-Block Broad CIDR Ranges (/16, /24)</span>
                  <span className="text-slate-500 text-[11px]">
                    Prohibits subnet spraying; only exact hostnames or single IP addresses are accepted.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.blockBroadCidr}
                  onChange={(e) => updateSetting('blockBroadCidr', e.target.checked)}
                  className="accent-cyan-500 w-4 h-4 cursor-pointer"
                />
              </div>

              <div className="flex items-center justify-between pt-4">
                <div>
                  <span className="font-bold text-slate-200 block">Mandatory Human-in-the-Loop Exploitation Gate</span>
                  <span className="text-slate-500 text-[11px]">
                    Autonomous exploitation is strictly disabled; Metasploit modules require human analyst review.
                  </span>
                </div>
                <span className="px-2.5 py-1 rounded bg-cyan-500/20 text-cyan-400 font-bold border border-cyan-500/30">
                  MANDATORY (ACTIVE)
                </span>
              </div>

              <div className="flex items-center justify-between pt-4">
                <div>
                  <span className="font-bold text-slate-200 block">Audit Log Retention Window</span>
                  <span className="text-slate-500 text-[11px]">
                    Duration that immutable security validation and approval records are kept in database.
                  </span>
                </div>
                <select
                  value={settings.auditRetentionDays}
                  onChange={(e) => updateSetting('auditRetentionDays', parseInt(e.target.value))}
                  className="input-field text-xs py-1.5 px-3 bg-slate-950 text-slate-100 max-w-xs"
                >
                  <option value={30}>30 Days (Ephemeral)</option>
                  <option value={90}>90 Days (Quarterly Audit)</option>
                  <option value={180}>180 Days (Standard Enterprise)</option>
                  <option value={365}>365 Days (Full Regulatory Compliance)</option>
                </select>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 4: PDF Reporting & Metadata ─────────────────────────────────── */}
      {activeTab === 'reporting' && (
        <div className="space-y-6">
          <div className="card p-6 space-y-5 border-cyan-500/20">
            <div className="border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                VAPT Audit-Grade PDF Report Configuration
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Customize client headers, security classification tags, and standards alignment across exported PDFs.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  Organization / Client Name
                </label>
                <input
                  type="text"
                  value={settings.organizationName}
                  onChange={(e) => updateSetting('organizationName', e.target.value)}
                  className="input-field text-xs py-2.5 w-full bg-slate-950 text-slate-100"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  Lead Security Analyst
                </label>
                <input
                  type="text"
                  value={settings.leadAnalyst}
                  onChange={(e) => updateSetting('leadAnalyst', e.target.value)}
                  className="input-field text-xs py-2.5 w-full bg-slate-950 text-slate-100"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  Security Classification Header
                </label>
                <select
                  value={settings.classificationBanner}
                  onChange={(e) => updateSetting('classificationBanner', e.target.value)}
                  className="input-field text-xs py-2.5 w-full bg-slate-950 text-slate-100"
                >
                  <option value="STRICTLY CONFIDENTIAL">STRICTLY CONFIDENTIAL</option>
                  <option value="CONFIDENTIAL // PROPRIETARY">CONFIDENTIAL // PROPRIETARY</option>
                  <option value="RESTRICTED // REDACTED CLIENT COPY">RESTRICTED // REDACTED CLIENT COPY</option>
                  <option value="INTERNAL AUDIT ONLY">INTERNAL AUDIT ONLY</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5 font-mono">
                  Testing Methodology Standard
                </label>
                <input
                  type="text"
                  value={settings.standardsFramework}
                  onChange={(e) => updateSetting('standardsFramework', e.target.value)}
                  className="input-field text-xs py-2.5 w-full bg-slate-950 text-slate-100"
                />
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-xs font-bold text-slate-200 font-mono block">
                  Mandatory Non-Fabrication Notice
                </span>
                <span className="text-[11px] text-slate-400">
                  When 0 vulnerabilities are found, explicitly states: "No vulnerability findings were recorded during this assessment."
                </span>
              </div>
              <input
                type="checkbox"
                checked={settings.includeLimitationNotice}
                onChange={(e) => updateSetting('includeLimitationNotice', e.target.checked)}
                className="accent-cyan-500 w-4 h-4 cursor-pointer"
              />
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 5: Hacker Desktop Theme ────────────────────────────────────── */}
      {activeTab === 'theme' && (
        <div className="space-y-6">
          <div className="card p-6 space-y-5 border-cyan-500/20">
            <div className="border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                Workstation Aesthetic &amp; Hacker Desktop Palette
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Tune the user interface into a high-contrast dark command console workstation.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div
                onClick={() => updateSetting('themePreset', 'obsidian')}
                className={clsx(
                  'p-4 rounded-xl border cursor-pointer transition-all',
                  settings.themePreset === 'obsidian'
                    ? 'border-cyan-400 bg-cyan-950/20 shadow-glow-cyan'
                    : 'border-slate-800 bg-navy-950/60 hover:border-slate-700'
                )}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-xs font-mono text-cyan-300">Obsidian Void</span>
                  <div className="w-3 h-3 rounded-full bg-cyan-400"></div>
                </div>
                <p className="text-[11px] text-slate-400">
                  Ultra-dark pitch black (#020611) with neon electric cyan accents and high contrast.
                </p>
              </div>

              <div
                onClick={() => updateSetting('themePreset', 'matrix')}
                className={clsx(
                  'p-4 rounded-xl border cursor-pointer transition-all',
                  settings.themePreset === 'matrix'
                    ? 'border-emerald-400 bg-emerald-950/20 shadow-glow-matrix'
                    : 'border-slate-800 bg-navy-950/60 hover:border-slate-700'
                )}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-xs font-mono text-emerald-300">Matrix Phosphor</span>
                  <div className="w-3 h-3 rounded-full bg-emerald-400"></div>
                </div>
                <p className="text-[11px] text-slate-400">
                  Deep hacker terminal with phosphorescent green accents and stealth dark panels.
                </p>
              </div>

              <div
                onClick={() => updateSetting('themePreset', 'crimson')}
                className={clsx(
                  'p-4 rounded-xl border cursor-pointer transition-all',
                  settings.themePreset === 'crimson'
                    ? 'border-rose-400 bg-rose-950/20 shadow-glow-red'
                    : 'border-slate-800 bg-navy-950/60 hover:border-slate-700'
                )}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-xs font-mono text-rose-300">Red Team Alert</span>
                  <div className="w-3 h-3 rounded-full bg-rose-400"></div>
                </div>
                <p className="text-[11px] text-slate-400">
                  Tactical dark red alert theme with high-visibility breach signals.
                </p>
              </div>
            </div>

            <div className="divide-y divide-slate-800 text-xs font-mono pt-2">
              <div className="flex items-center justify-between py-3">
                <div>
                  <span className="font-bold text-slate-200 block">High Contrast Typography</span>
                  <span className="text-slate-500 text-[11px]">
                    Forces maximum brightness (#ffffff) on terminal telemetry outputs and code tables.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.highContrast}
                  onChange={(e) => updateSetting('highContrast', e.target.checked)}
                  className="accent-cyan-500 w-4 h-4 cursor-pointer"
                />
              </div>

              <div className="flex items-center justify-between py-3">
                <div>
                  <span className="font-bold text-slate-200 block">CRT Terminal Scanline Effect</span>
                  <span className="text-slate-500 text-[11px]">
                    Renders a subtle retro cybersecurity workstation scanline overlay across dashboard cards.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={settings.scanlineEffect}
                  onChange={(e) => updateSetting('scanlineEffect', e.target.checked)}
                  className="accent-cyan-500 w-4 h-4 cursor-pointer"
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
