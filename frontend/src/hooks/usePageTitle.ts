import { useLocation } from 'react-router-dom'

interface PageMeta {
  title: string
  subtitle?: string
}

const PAGE_META: Record<string, PageMeta> = {
  '/': { title: 'Dashboard', subtitle: 'Security assessment overview and status' },
  '/targets': {
    title: 'Target Scope Registry',
    subtitle: 'Authorized target registration and strict scope enforcement',
  },
  '/assessment/new': {
    title: 'New Assessment',
    subtitle: 'Define scope and configure a new VAPT engagement',
  },
  '/agent': {
    title: 'AI Security Agent',
    subtitle: 'Conversational AI assistant for vulnerability assessment planning',
  },
  '/scans': { title: 'Scan Activity', subtitle: 'Monitor active and historical scan jobs' },
  '/vulnerabilities': {
    title: 'Vulnerabilities',
    subtitle: 'Normalised and prioritised vulnerability data',
  },
  '/findings': {
    title: 'Vulnerabilities',
    subtitle: 'Normalised and prioritised vulnerability data',
  },
  '/evidence': {
    title: 'Evidence Explorer',
    subtitle: 'Raw scanner evidence and cross-tool correlation',
  },
  '/approvals': {
    title: 'Approval Center',
    subtitle: 'Review and approve active validation steps',
  },
  '/reports': { title: 'Reports', subtitle: 'Generate and download professional PDF reports' },
  '/integrations': {
    title: 'Tool Integrations',
    subtitle: 'Scanner and tool connectivity status',
  },
  '/settings': { title: 'Settings', subtitle: 'Application and scanner configuration' },
}

export function usePageTitle(): PageMeta {
  const location = useLocation()
  return (
    PAGE_META[location.pathname] ?? {
      title: 'AI-VAPT Agent',
      subtitle: undefined,
    }
  )
}
