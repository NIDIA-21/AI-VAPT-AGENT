import { useState, useEffect } from 'react'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  RefreshCw,
  FileText,
  Shield,
  Layers,
  Globe,
  Server,
  FileCode,
  Flame,
  UploadCloud,
  FileUp,
  Terminal,
  Sparkles,
} from 'lucide-react'
import type { ToolStatusItem, ToolIntegrationState, AuthorizedTarget } from '@/types'
import { dashboardApi, scannersApi, targetsApi } from '@/services/api'
import { clsx } from 'clsx'

const statusBadgeStyles: Record<
  ToolIntegrationState,
  { label: string; badgeClass: string; icon: React.ElementType }
> = {
  Available: {
    label: 'LIVE AVAILABLE',
    badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 shadow-glow-cyan',
    icon: CheckCircle2,
  },
  'Not Installed': {
    label: 'Not Installed',
    badgeClass: 'bg-slate-800 text-slate-400 border-slate-700',
    icon: XCircle,
  },
  'Not Configured': {
    label: 'Not Configured',
    badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    icon: AlertTriangle,
  },
  'Import Only': {
    label: 'IMPORT ONLY',
    badgeClass: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    icon: FileText,
  },
  Planned: {
    label: 'Planned',
    badgeClass: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
    icon: Clock,
  },
  Unsupported: {
    label: 'Unsupported',
    badgeClass: 'bg-red-500/10 text-red-400 border-red-500/30',
    icon: XCircle,
  },
}

const toolIcons: Record<string, React.ElementType> = {
  nmap: Layers,
  zap: Globe,
  nikto: Server,
  nessus: Shield,
  openvas: FileCode,
  burpsuite: Globe,
  metasploit: Flame,
}

export default function Integrations() {
  const [tools, setTools] = useState<ToolStatusItem[]>([])
  const [targets, setTargets] = useState<AuthorizedTarget[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [lastChecked, setLastChecked] = useState<Date | null>(null)

  // Report Ingestion state
  const [importTab, setImportTab] = useState<'zap' | 'nikto' | 'nmap'>('zap')
  const [targetHost, setTargetHost] = useState('')
  const [reportFormat, setReportFormat] = useState<'json' | 'xml'>('json')
  const [reportContent, setReportContent] = useState('')
  const [importing, setImporting] = useState(false)
  const [importSuccess, setImportSuccess] = useState<string | null>(null)
  const [importError, setImportError] = useState<string | null>(null)

  const fetchTools = async () => {
    setLoading(true)
    setError(null)
    try {
      const [toolsData, targetsData] = await Promise.all([
        dashboardApi.tools(),
        targetsApi.list({ status: 'ACTIVE' }),
      ])
      setTools(toolsData.tools)
      setTargets(targetsData)
      if (targetsData.length > 0 && !targetHost) {
        setTargetHost(targetsData[0].host)
      }
      setLastChecked(new Date())
    } catch (err: any) {
      setError(err?.userMessage ?? 'Failed to probe tool integrations')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchTools()
  }, [])

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    const isXml = file.name.endsWith('.xml')
    setReportFormat(isXml ? 'xml' : 'json')

    const reader = new FileReader()
    reader.onload = (event) => {
      const content = event.target?.result as string
      setReportContent(content)
    }
    reader.readAsText(file)
  }

  const handleImportSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!reportContent.trim() || !targetHost.trim()) return

    setImporting(true)
    setImportSuccess(null)
    setImportError(null)

    try {
      let job: any
      if (importTab === 'zap') {
        job = await scannersApi.importZap({
          target_host: targetHost,
          report_content: reportContent,
          format: reportFormat,
        })
      } else if (importTab === 'nikto') {
        job = await scannersApi.importNikto({
          target_host: targetHost,
          report_content: reportContent,
          format: reportFormat,
        })
      } else {
        job = await scannersApi.importNmap({
          target_host: targetHost,
          report_content: reportContent,
          format: 'xml',
        })
      }

      setImportSuccess(
        `Successfully ingested ${job.scanner} report! Extracted and deduplicated ${job.findings_count ?? 'multiple'} findings for ${targetHost}.`
      )
      setReportContent('')
    } catch (err: any) {
      setImportError(err?.userMessage || 'Failed to parse and import report.')
    } finally {
      setImporting(false)
    }
  }

  const availableCount = tools.filter((t) => t.status === 'Available').length

  return (
    <div className="space-y-8 animate-fade-in pb-10">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            Scanner Integrations & Report Ingestion Hub
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Honest tool status tracking (Live, Import Only, Not Installed) and official report ingestion.
          </p>
        </div>

        <button
          onClick={fetchTools}
          disabled={loading}
          className="btn-secondary text-xs py-2 px-3 self-start sm:self-auto flex items-center gap-1.5"
        >
          <RefreshCw className={clsx('w-3.5 h-3.5', loading && 'animate-spin text-cyan-400')} />
          <span>Re-probe Tools</span>
        </button>
      </div>

      {/* Summary banner */}
      {!loading && !error && (
        <div
          className={clsx(
            'flex items-center gap-3 p-4 rounded-xl border text-xs',
            availableCount > 0
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              : 'bg-slate-900 border-cyan-500/30 text-cyan-300'
          )}
        >
          <Shield className="w-4 h-4 flex-shrink-0" />
          <span>
            <strong>Phase 5 Active Engine:</strong> Safe scoped Nmap execution + genuine report parsers for OWASP ZAP (JSON/XML), Nikto (JSON/XML), and Nmap XML.
          </span>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
          {error}
        </div>
      )}

      {/* Report Import Section */}
      <div className="card p-6 border-cyan-500/30 bg-slate-900/60 shadow-xl space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 flex-wrap gap-2">
          <div>
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <UploadCloud className="w-5 h-5 text-cyan-400" />
              Ingest Scanner Reports into Unified Vulnerability Schema
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Strict scope validation guarantees reports can only be ingested for actively authorized targets.
            </p>
          </div>

          {/* Import Tabs */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            <button
              onClick={() => {
                setImportTab('zap')
                setReportFormat('json')
              }}
              className={clsx(
                'px-3 py-1.5 rounded transition-all font-semibold',
                importTab === 'zap'
                  ? 'bg-cyan-600 text-white shadow-glow-cyan'
                  : 'text-slate-400 hover:text-slate-200'
              )}
            >
              OWASP ZAP (JSON/XML)
            </button>
            <button
              onClick={() => {
                setImportTab('nikto')
                setReportFormat('json')
              }}
              className={clsx(
                'px-3 py-1.5 rounded transition-all font-semibold',
                importTab === 'nikto'
                  ? 'bg-cyan-600 text-white shadow-glow-cyan'
                  : 'text-slate-400 hover:text-slate-200'
              )}
            >
              Nikto (JSON/XML)
            </button>
            <button
              onClick={() => {
                setImportTab('nmap')
                setReportFormat('xml')
              }}
              className={clsx(
                'px-3 py-1.5 rounded transition-all font-semibold',
                importTab === 'nmap'
                  ? 'bg-cyan-600 text-white shadow-glow-cyan'
                  : 'text-slate-400 hover:text-slate-200'
              )}
            >
              Nmap XML (-oX)
            </button>
          </div>
        </div>

        {importSuccess && (
          <div className="p-3 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
            <span>{importSuccess}</span>
          </div>
        )}

        {importError && (
          <div className="p-3 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
            <XCircle className="w-4 h-4 flex-shrink-0" />
            <span>{importError}</span>
          </div>
        )}

        <form onSubmit={handleImportSubmit} className="space-y-4 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Target Host (Must Match Authorized Scope)
              </label>
              <select
                value={targetHost}
                onChange={(e) => setTargetHost(e.target.value)}
                className="input-field w-full text-xs"
                required
              >
                {targets.map((t) => (
                  <option key={t.id} value={t.host}>
                    {t.name} ({t.host})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Report Format
              </label>
              <div className="flex items-center gap-3 mt-1.5">
                <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                  <input
                    type="radio"
                    name="format"
                    value="json"
                    checked={reportFormat === 'json'}
                    onChange={() => setReportFormat('json')}
                    disabled={importTab === 'nmap'}
                  />
                  <span>JSON</span>
                </label>
                <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                  <input
                    type="radio"
                    name="format"
                    value="xml"
                    checked={reportFormat === 'xml'}
                    onChange={() => setReportFormat('xml')}
                  />
                  <span>XML</span>
                </label>
              </div>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block text-xs font-semibold text-slate-300">
                Paste Report Content or Upload File
              </label>
              <label className="text-[11px] text-cyan-400 hover:text-cyan-300 cursor-pointer flex items-center gap-1">
                <FileUp className="w-3.5 h-3.5" />
                <span>Upload Report File</span>
                <input
                  type="file"
                  accept=".json,.xml,.txt"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
            </div>
            <textarea
              rows={6}
              value={reportContent}
              onChange={(e) => setReportContent(e.target.value)}
              placeholder={
                importTab === 'zap'
                  ? 'Paste official OWASP ZAP JSON or XML report text here...'
                  : importTab === 'nikto'
                  ? 'Paste official Nikto JSON or XML report text here...'
                  : 'Paste Nmap XML (-oX) report text here...'
              }
              className="input-field w-full font-mono text-[11px]"
              required
            />
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={importing || !reportContent.trim()}
              className="btn-primary text-xs px-4 py-2 flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500"
            >
              {importing ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  Validating Scope & Normalizing Findings...
                </>
              ) : (
                <>
                  <UploadCloud className="w-3.5 h-3.5" />
                  Ingest & Process Findings
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Scanner grid */}
      <div>
        <h3 className="text-sm font-bold text-slate-200 mb-3 uppercase tracking-wider font-mono">
          System Scanner Support & Diagnostic Matrix
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {loading
            ? [1, 2, 3, 4, 5, 6, 7].map((i) => (
                <div key={i} className="card h-44 animate-pulse bg-navy-800/60" />
              ))
            : tools.map((tool) => {
                const Icon = toolIcons[tool.name] || Shield
                const style = statusBadgeStyles[tool.status] || statusBadgeStyles['Not Installed']
                const StatusIcon = style.icon

                return (
                  <div
                    key={tool.name}
                    className={clsx(
                      'card flex flex-col justify-between transition-all duration-200 hover:border-slate-600/80',
                      tool.status === 'Available' ? 'border-emerald-500/30' : 'border-slate-800'
                    )}
                  >
                    <div>
                      <div className="flex items-start justify-between gap-2 mb-3">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-cyan-400 flex-shrink-0">
                            <Icon className="w-5 h-5" />
                          </div>
                          <div>
                            <h3 className="text-sm font-semibold text-slate-100">{tool.display_name}</h3>
                            <span className="text-[11px] text-slate-400 font-mono">{tool.category}</span>
                          </div>
                        </div>

                        <span
                          className={clsx(
                            'inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border flex-shrink-0',
                            style.badgeClass
                          )}
                        >
                          <StatusIcon className="w-3 h-3" />
                          {style.label}
                        </span>
                      </div>

                      <p className="text-xs text-slate-400 mb-3 leading-relaxed">{tool.description}</p>

                      {tool.path && (
                        <p className="text-[10px] font-mono text-slate-400 truncate bg-slate-900/60 p-1.5 rounded border border-slate-800">
                          {tool.path}
                        </p>
                      )}
                    </div>

                    <div className="mt-4 pt-3 border-t border-slate-800/80">
                      <span className="text-[10px] text-slate-400 uppercase font-mono block mb-1.5">
                        Capabilities
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {tool.capabilities.map((cap) => (
                          <span
                            key={cap}
                            className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700/50"
                          >
                            {cap}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                )
              })}
        </div>
      </div>
    </div>
  )
}
