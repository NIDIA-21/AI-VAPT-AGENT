import { Construction } from 'lucide-react'

interface PlaceholderPageProps {
  title: string
  description: string
  phase?: string
}

export default function PlaceholderPage({ title, description, phase = 'Phase 2' }: PlaceholderPageProps) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center animate-fade-in">
      <div className="w-20 h-20 rounded-2xl bg-navy-800 border border-slate-700/50 flex items-center justify-center mb-6 shadow-card">
        <Construction className="w-9 h-9 text-blue-400/60" />
      </div>
      <h2 className="text-xl font-semibold text-slate-200 mb-2">{title}</h2>
      <p className="text-slate-500 text-sm max-w-md leading-relaxed">{description}</p>
      <div className="mt-4 px-3 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-medium">
        Planned for {phase}
      </div>
    </div>
  )
}
