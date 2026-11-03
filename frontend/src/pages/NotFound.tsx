import { Link } from 'react-router-dom'
import { Home, AlertTriangle } from 'lucide-react'

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh] text-center animate-fade-in">
      <div className="w-20 h-20 rounded-2xl bg-navy-800 border border-slate-700/50 flex items-center justify-center mb-6">
        <AlertTriangle className="w-9 h-9 text-yellow-400/60" />
      </div>
      <h2 className="text-2xl font-bold text-slate-100 mb-2">404 — Page Not Found</h2>
      <p className="text-slate-500 text-sm mb-6">The page you're looking for doesn't exist.</p>
      <Link to="/" className="btn-primary">
        <Home className="w-4 h-4" />
        Back to Dashboard
      </Link>
    </div>
  )
}
