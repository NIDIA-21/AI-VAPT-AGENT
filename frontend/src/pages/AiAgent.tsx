import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Bot,
  Send,
  Plus,
  Trash2,
  Shield,
  ShieldCheck,
  ShieldAlert,
  Sliders,
  Layers,
  Wrench,
  CheckCircle2,
  XCircle,
  Clock,
  Sparkles,
  ChevronDown,
  ChevronRight,
  Info,
  RefreshCw,
  Play,
  ArrowRight,
  Lock,
  Terminal,
} from 'lucide-react'
import { clsx } from 'clsx'
import { agentApi, targetsApi } from '@/services/api'
import type {
  AgentChatMessage,
  AgentChatSession,
  AssessmentPlan,
  AuthorizedTarget,
  EngineInfo,
  PlanDecision,
} from '@/types'

function FormattedMessage({ content }: { content: string }) {
  const isMismatch = content.includes('TARGET SCOPE MISMATCH')
  const lines = content.split('\n')

  return (
    <div className={clsx('space-y-1.5 text-xs leading-relaxed', isMismatch && 'text-slate-100')}>
      {lines.map((line, idx) => {
        const trimmed = line.trim()
        if (!trimmed) return <div key={idx} className="h-1" />

        // Headings
        if (trimmed.startsWith('### ')) {
          return (
            <div key={idx} className="pt-2 pb-1 border-b border-slate-800/80 mb-1">
              <span className="text-xs font-bold font-mono text-cyan-300 uppercase tracking-wider">{trimmed.slice(4)}</span>
            </div>
          )
        }
        if (trimmed.startsWith('#### ')) {
          return (
            <h5 key={idx} className="font-bold text-xs text-slate-200 mt-2 font-mono">
              {trimmed.slice(5)}
            </h5>
          )
        }

        // Table Rows
        if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
          if (trimmed.replace(/[|\-:\s]/g, '') === '') {
            return null // separator row
          }
          const cells = trimmed.split('|').map((c) => c.trim()).filter((_, i, arr) => i > 0 && i < arr.length - 1)
          const isHeader = lines[idx + 1]?.trim().startsWith('|---') || lines[idx + 1]?.trim().startsWith('|:---')
          return (
            <div
              key={idx}
              className={clsx(
                'grid grid-flow-col auto-cols-fr gap-2 px-2.5 py-1.5 rounded text-[11px] font-mono border my-0.5',
                isHeader
                  ? 'bg-slate-800/90 border-slate-700 text-cyan-300 font-bold'
                  : 'bg-navy-900/80 border-slate-800 text-slate-300'
              )}
            >
              {cells.map((cell, cIdx) => (
                <span key={cIdx} className="truncate">
                  {renderInlineFormatted(cell)}
                </span>
              ))}
            </div>
          )
        }

        // Blockquotes
        if (trimmed.startsWith('>')) {
          return (
            <div
              key={idx}
              className="p-2.5 rounded-lg bg-navy-900 border-l-2 border-cyan-400 text-slate-300 text-[11px] my-1 font-mono"
            >
              {renderInlineFormatted(trimmed.replace(/^>\s*/, ''))}
            </div>
          )
        }

        // Bullet lists
        if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
          return (
            <div key={idx} className="flex items-start gap-2 pl-2 text-slate-300 my-0.5">
              <span className="text-cyan-400 font-mono text-xs flex-shrink-0">•</span>
              <span>{renderInlineFormatted(trimmed.slice(2))}</span>
            </div>
          )
        }

        // Numbered list
        const numMatch = trimmed.match(/^(\d+)\.\s+(.*)$/)
        if (numMatch) {
          return (
            <div key={idx} className="flex items-start gap-2 pl-2 text-slate-300 my-0.5">
              <span className="text-cyan-400 font-mono text-xs flex-shrink-0">{numMatch[1]}.</span>
              <span>{renderInlineFormatted(numMatch[2])}</span>
            </div>
          )
        }

        // Paragraph
        return (
          <p key={idx} className="text-slate-200">
            {renderInlineFormatted(trimmed)}
          </p>
        )
      })}
    </div>
  )
}

function renderInlineFormatted(text: string): React.ReactNode {
  const tokens = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g)
  return tokens.map((part, i) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return (
        <strong key={i} className="font-bold text-slate-100">
          {part.slice(2, -2)}
        </strong>
      )
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code
          key={i}
          className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-[10px] border border-slate-700/60"
        >
          {part.slice(1, -1)}
        </code>
      )
    }
    return part
  })
}

export default function AiAgent() {
  const navigate = useNavigate()

  // State
  const [sessions, setSessions] = useState<AgentChatSession[]>([])
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null)
  const [messages, setMessages] = useState<AgentChatMessage[]>([])
  const [inputMessage, setInputMessage] = useState('')
  const [sending, setSending] = useState(false)
  const [loadingHistory, setLoadingHistory] = useState(false)

  // Target context
  const [targets, setTargets] = useState<AuthorizedTarget[]>([])
  const [selectedTargetId, setSelectedTargetId] = useState<string>('')

  // Engine status
  const [engineInfo, setEngineInfo] = useState<EngineInfo | null>(null)

  // Active plan & decision trace modal
  const [activePlan, setActivePlan] = useState<AssessmentPlan | null>(null)
  const [viewingDecisions, setViewingDecisions] = useState<PlanDecision[] | null>(null)

  const messagesEndRef = useRef<HTMLDivElement>(null)

  // Scroll to bottom
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages, sending])

  // Initial load
  useEffect(() => {
    async function init() {
      try {
        const [engRes, targRes, sessRes] = await Promise.all([
          agentApi.engineInfo().catch(() => null),
          targetsApi.list().catch(() => []),
          agentApi.listSessions().catch(() => []),
        ])
        if (engRes) setEngineInfo(engRes)
        setTargets(targRes)
        setSessions(sessRes)

        // Select first session or create initial view
        if (sessRes.length > 0) {
          loadSession(sessRes[0].id)
        }
      } catch (err) {
        console.error('Failed to initialize AI Agent view', err)
      }
    }
    init()
  }, [])

  // Load a session
  const loadSession = async (sessionId: string) => {
    try {
      setLoadingHistory(true)
      setCurrentSessionId(sessionId)
      const detail = await agentApi.getSession(sessionId)
      setMessages(detail.messages)
      if (detail.target_id) {
        setSelectedTargetId(detail.target_id)
      }
    } catch (err) {
      console.error('Failed to load session', err)
    } finally {
      setLoadingHistory(false)
    }
  }

  // Create new session
  const handleNewSession = () => {
    setCurrentSessionId(null)
    setMessages([])
    setActivePlan(null)
  }

  // Delete a session
  const handleDeleteSession = async (e: React.MouseEvent, sessionId: string) => {
    e.stopPropagation()
    try {
      await agentApi.deleteSession(sessionId)
      setSessions((prev) => prev.filter((s) => s.id !== sessionId))
      if (currentSessionId === sessionId) {
        handleNewSession()
      }
    } catch (err) {
      console.error('Failed to delete session', err)
    }
  }

  // Send message
  const handleSendMessage = async (e?: React.FormEvent, customText?: string) => {
    if (e) e.preventDefault()
    const textToSend = customText || inputMessage
    if (!textToSend.trim() || sending) return

    setInputMessage('')
    setSending(true)

    // Optimistic user message
    const tempUserMsg: AgentChatMessage = {
      id: `temp-${Date.now()}`,
      session_id: currentSessionId || '',
      role: 'user',
      content: textToSend,
      created_at: new Date().toISOString(),
    }
    setMessages((prev) => [...prev, tempUserMsg])

    try {
      const res = await agentApi.chat({
        message: textToSend,
        session_id: currentSessionId || undefined,
        target_id: selectedTargetId || undefined,
        user_name: 'lead_analyst',
      })

      // Update session ID if newly created
      if (!currentSessionId) {
        setCurrentSessionId(res.session_id)
        // Refresh session list
        agentApi.listSessions().then(setSessions)
      }

      // Assistant message
      const assistantMsg: AgentChatMessage = {
        id: res.message_id,
        session_id: res.session_id,
        role: res.role,
        content: res.content,
        meta_info: JSON.stringify({
          plan: res.plan,
          decisions: res.decisions,
          engine_info: res.engine_info,
        }),
        created_at: res.created_at,
      }

      setMessages((prev) => [...prev, assistantMsg])

      // If a plan was returned, expose it
      if (res.plan) {
        setActivePlan(res.plan)
      }
      if (res.engine_info) {
        setEngineInfo(res.engine_info)
      }
    } catch (err: any) {
      const errorMsg: AgentChatMessage = {
        id: `err-${Date.now()}`,
        session_id: currentSessionId || '',
        role: 'assistant',
        content: `### ❌ Request Error\n\n${err?.userMessage || err?.response?.data?.detail || 'An error occurred while contacting the AI Security Agent.'}`,
        created_at: new Date().toISOString(),
      }
      setMessages((prev) => [...prev, errorMsg])
    } finally {
      setSending(false)
    }
  }

  // Pre-fill prompt templates
  const applyPromptTemplate = (template: string) => {
    const targetObj = targets.find((t) => t.id === selectedTargetId)
    const targetText = targetObj ? targetObj.host : '10.10.20.50'
    const filled = template.replace('{target}', targetText)
    handleSendMessage(undefined, filled)
  }

  return (
    <div className="flex h-[calc(100vh-8rem)] max-w-7xl mx-auto gap-4 pb-4">
      {/* ── Left Sidebar: Chat Sessions & Target Context ─────────── */}
      <div className="w-72 flex-shrink-0 flex flex-col bg-navy-900/90 border border-slate-800 rounded-2xl shadow-xl overflow-hidden">
        {/* Sidebar Header */}
        <div className="p-3 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bot className="w-4 h-4 text-cyan-400" />
            <span className="text-xs font-mono font-bold text-slate-100">AI SESSIONS</span>
          </div>
          <button
            onClick={handleNewSession}
            title="Start new chat session"
            className="p-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-mono transition-colors flex items-center gap-1"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New</span>
          </button>
        </div>

        {/* Target Context Selector */}
        <div className="p-3 border-b border-slate-800 bg-navy-950/40 space-y-1.5">
          <label className="text-[10px] font-mono uppercase tracking-wider text-slate-400 flex items-center justify-between">
            <span>Target Context:</span>
            {selectedTargetId && (
              <span className="text-emerald-400 font-bold">LOCKED</span>
            )}
          </label>
          <select
            value={selectedTargetId}
            onChange={(e) => setSelectedTargetId(e.target.value)}
            className="w-full px-2 py-1.5 text-xs rounded-lg bg-navy-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-mono"
          >
            <option value="">-- No specific target --</option>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.host} [{t.status}]
              </option>
            ))}
          </select>
          <p className="text-[10px] text-slate-500">
            Locks planning context strictly to this authorized target.
          </p>
        </div>

        {/* Sessions List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {sessions.length === 0 ? (
            <div className="text-center py-8 text-xs text-slate-500 font-mono">
              No previous chat sessions
            </div>
          ) : (
            sessions.map((sess) => {
              const active = currentSessionId === sess.id
              return (
                <div
                  key={sess.id}
                  onClick={() => loadSession(sess.id)}
                  className={clsx(
                    'group flex items-center justify-between p-2.5 rounded-xl cursor-pointer text-xs transition-all',
                    active
                      ? 'bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 shadow-glow-cyan'
                      : 'hover:bg-slate-800/60 text-slate-400 hover:text-slate-200 border border-transparent'
                  )}
                >
                  <div className="min-w-0 flex-1 pr-2">
                    <p className="truncate font-medium text-slate-200">{sess.title}</p>
                    <div className="flex items-center gap-2 mt-0.5 text-[10px] text-slate-500 font-mono">
                      <span>{new Date(sess.created_at).toLocaleDateString()}</span>
                      {sess.target_host && (
                        <span className="text-cyan-400 truncate max-w-[100px]">{sess.target_host}</span>
                      )}
                    </div>
                  </div>
                  <button
                    onClick={(e) => handleDeleteSession(e, sess.id)}
                    title="Delete session"
                    className="opacity-0 group-hover:opacity-100 p-1 text-slate-500 hover:text-rose-400 transition-opacity"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              )
            })
          )}
        </div>

        {/* Prompt Templates */}
        <div className="p-3 border-t border-slate-800 bg-navy-950/30 space-y-1.5">
          <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Quick Actions</p>
          <button
            onClick={() => applyPromptTemplate('Plan a comprehensive vulnerability assessment for target {target}')}
            className="w-full text-left p-1.5 rounded bg-slate-800/40 hover:bg-slate-800 text-[11px] text-slate-300 border border-slate-700/60 truncate"
          >
            ⚡ Plan assessment for target
          </button>
          <button
            onClick={() => applyPromptTemplate('Recommend the best scanners and flags for assessing target {target}')}
            className="w-full text-left p-1.5 rounded bg-slate-800/40 hover:bg-slate-800 text-[11px] text-slate-300 border border-slate-700/60 truncate"
          >
            🛠️ Recommend tools for target
          </button>
          <button
            onClick={() => applyPromptTemplate('Explain how OWASP ZAP and Nikto differ in web security testing')}
            className="w-full text-left p-1.5 rounded bg-slate-800/40 hover:bg-slate-800 text-[11px] text-slate-300 border border-slate-700/60 truncate"
          >
            📖 Explain tool differences
          </button>
        </div>
      </div>

      {/* ── Main Chat Area ────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col bg-navy-900/90 border border-slate-800 rounded-2xl shadow-xl overflow-hidden">
        {/* Chat Header */}
        <div className="p-3.5 border-b border-slate-800 bg-navy-950/40 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-glow-cyan">
              <Bot className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-slate-100 font-mono">AI SECURITY AGENT</span>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              </div>
              <p className="text-[10px] text-slate-400 font-mono">
                Scope-Bounded Autonomous Assessment Planner & Cybersecurity Advisory
              </p>
            </div>
          </div>

          {/* Engine Status Badge */}
          {engineInfo && (
            <div
              className={clsx(
                'px-2.5 py-1 rounded-lg border text-[11px] font-mono flex items-center gap-1.5',
                engineInfo.is_fallback
                  ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
              )}
              title={engineInfo.status_label}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>{engineInfo.active_engine}</span>
            </div>
          )}
        </div>

        {/* Message Stream */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 font-sans">
          {loadingHistory ? (
            <div className="flex items-center justify-center h-full text-xs text-slate-400 font-mono">
              <RefreshCw className="w-4 h-4 animate-spin text-cyan-400 mr-2" />
              <span>Loading conversation history...</span>
            </div>
          ) : messages.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-center max-w-md mx-auto space-y-3">
              <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-glow-cyan">
                <Bot className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-slate-200 font-mono">
                Conversational AI Security Assistant
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                I help security analysts configure scope-enforced vulnerability assessments, recommend scanner
                tools (Nmap, ZAP, Nikto), and explain findings.
              </p>
              <div className="p-3 rounded-xl bg-navy-950/60 border border-slate-800 text-[11px] text-slate-400 font-mono text-left w-full space-y-1">
                <div className="text-cyan-400 font-semibold mb-1">💡 Try asking:</div>
                <div>• "Plan an authorized assessment for target 10.10.20.50"</div>
                <div>• "Which tools should I select for an authenticated REST API?"</div>
                <div>• "Explain how strict scope enforcement prevents unintended scans"</div>
              </div>
            </div>
          ) : (
            messages.map((msg) => {
              const isUser = msg.role === 'user'
              let parsedMeta: any = null
              try {
                if (msg.meta_info) parsedMeta = JSON.parse(msg.meta_info)
              } catch (_) {}

              return (
                <div
                  key={msg.id}
                  className={clsx(
                    'flex gap-3 text-xs leading-relaxed max-w-4xl',
                    isUser ? 'ml-auto flex-row-reverse' : 'mr-auto'
                  )}
                >
                  {/* Avatar */}
                  <div
                    className={clsx(
                      'w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 text-xs font-mono font-bold',
                      isUser
                        ? 'bg-blue-600 text-white'
                        : 'bg-gradient-to-br from-cyan-500 to-blue-600 text-navy-950 shadow-glow-cyan'
                    )}
                  >
                    {isUser ? 'SA' : <Bot className="w-4 h-4" />}
                  </div>

                  {/* Bubble */}
                  <div
                    className={clsx(
                      'p-4 rounded-2xl border space-y-3',
                      isUser
                        ? 'bg-blue-600/10 border-blue-500/30 text-blue-100 rounded-tr-none'
                        : 'bg-navy-950/80 border-slate-800 text-slate-200 rounded-tl-none shadow-md'
                    )}
                  >
                    {/* Render message text with structured markdown and alert card formatting */}
                    <FormattedMessage content={msg.content} />

                    {/* Engine Execution Badge & Timestamp */}
                    {!isUser && (
                      <div className="flex items-center justify-between pt-2 border-t border-slate-800/60 text-[10px] font-mono">
                        <span
                          className={clsx(
                            'px-2 py-0.5 rounded border flex items-center gap-1',
                            parsedMeta?.engine_info?.is_fallback
                              ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                              : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                          )}
                        >
                          <Sparkles className="w-2.5 h-2.5" />
                          <span>
                            {parsedMeta?.engine_info?.is_fallback
                              ? 'RULE-BASED FALLBACK ENGINE'
                              : 'LLM-GENERATED INTELLIGENCE'}
                          </span>
                        </span>
                        <span className="text-slate-500">
                          {new Date(msg.created_at).toLocaleTimeString()}
                        </span>
                      </div>
                    )}

                    {/* If message attached a plan, render Plan Action Banner */}
                    {parsedMeta?.plan && (
                      <div className="mt-3 pt-3 border-t border-slate-800 space-y-3">
                        <div className="flex items-center justify-between bg-navy-900 p-2.5 rounded-xl border border-cyan-500/30">
                          <div className="flex items-center gap-2 text-cyan-300 font-mono font-bold">
                            <ShieldCheck className="w-4 h-4 text-cyan-400" />
                            <span>Plan Generated: {parsedMeta.plan.stages.length} Stages</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {parsedMeta.decisions && (
                              <button
                                onClick={() => setViewingDecisions(parsedMeta.decisions)}
                                className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-mono border border-slate-700"
                              >
                                View Decision Trace ({parsedMeta.decisions.length})
                              </button>
                            )}
                            <button
                              onClick={() => {
                                navigate('/assessment/new', {
                                  state: {
                                    targetId: parsedMeta.plan.target_id,
                                    planSummary: parsedMeta.plan.summary,
                                    decisionIds: parsedMeta.decisions?.map((d: any) => d.id) || [],
                                  },
                                })
                              }}
                              className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-navy-950 font-bold text-[11px] shadow-glow-cyan"
                            >
                              <Play className="w-3 h-3 fill-current" />
                              <span>Initialize Assessment</span>
                            </button>
                          </div>
                        </div>
                      </div>
                    )}

                    {isUser && (
                      <div className="text-[10px] text-blue-300 font-mono text-right">
                        {new Date(msg.created_at).toLocaleTimeString()}
                      </div>
                    )}
                  </div>
                </div>
              )
            })
          )}

          {sending && (
            <div className="flex gap-3 text-xs leading-relaxed max-w-md mr-auto">
              <div className="w-7 h-7 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-glow-cyan flex-shrink-0">
                <RefreshCw className="w-4 h-4 animate-spin" />
              </div>
              <div className="p-3 rounded-2xl bg-navy-950/80 border border-slate-800 text-slate-400 font-mono text-[11px] flex items-center gap-2">
                <span>AI Agent is analyzing scope and evaluating security plan...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <form onSubmit={handleSendMessage} className="p-3 border-t border-slate-800 bg-navy-950/60 flex gap-2">
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            placeholder="Type your assessment request or security question (e.g. 'Plan assessment for 10.10.20.50')..."
            disabled={sending}
            className="flex-1 px-4 py-2 text-xs rounded-xl bg-navy-900 border border-slate-700 text-slate-200 focus:outline-none focus:border-cyan-400 font-sans"
          />
          <button
            type="submit"
            disabled={sending || !inputMessage.trim()}
            className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-navy-950 font-bold text-xs shadow-glow-cyan flex items-center gap-1.5 transition-all"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Send</span>
          </button>
        </form>
      </div>

      {/* ── Decision Trace Modal ────────────────────────────────────── */}
      {viewingDecisions && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-navy-950/80 backdrop-blur-sm overflow-y-auto">
          <div className="relative w-full max-w-3xl my-8 p-6 rounded-2xl bg-navy-900 border border-slate-700 shadow-2xl space-y-4 text-xs font-sans">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <h3 className="text-base font-bold text-slate-100 font-mono">
                  AI AGENT DECISION TRACE & REASONING AUDIT
                </h3>
              </div>
              <button
                onClick={() => setViewingDecisions(null)}
                className="text-slate-400 hover:text-slate-100 text-sm p-1"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Each AI assessment decision explicitly separates concrete observations (allowlist rules, confirmed
              ports, policy limits) from AI inferences (deductions regarding threat surface).
            </p>

            <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-1">
              {viewingDecisions.map((dec, idx) => (
                <div key={dec.id || idx} className="p-3.5 rounded-xl bg-navy-950 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between font-mono text-[11px]">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold">
                        {dec.selected_tool}
                      </span>
                      <span className="text-slate-400 font-semibold">{dec.stage}</span>
                    </div>
                    <span
                      className={clsx(
                        'px-2 py-0.5 rounded text-[10px] font-bold border',
                        dec.execution_status === 'PLANNED'
                          ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                          : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                      )}
                    >
                      {dec.execution_status}
                    </span>
                  </div>

                  <p className="text-slate-300 font-medium">{dec.rationale}</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-2 border-t border-slate-800/80 text-[11px]">
                    <div className="p-2 rounded bg-navy-900 border border-slate-800/80">
                      <span className="text-cyan-400 font-mono font-semibold block mb-0.5">
                        🔍 Concrete Observations:
                      </span>
                      <span className="text-slate-300">{dec.evidence_and_observations}</span>
                    </div>
                    <div className="p-2 rounded bg-navy-900 border border-slate-800/80">
                      <span className="text-amber-400 font-mono font-semibold block mb-0.5">
                        🧠 AI Inference:
                      </span>
                      <span className="text-slate-300">{dec.ai_inferences}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setViewingDecisions(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300"
              >
                Close Trace
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
