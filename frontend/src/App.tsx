import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import AppLayout from '@/layouts/AppLayout'
import Dashboard from '@/pages/Dashboard'
import TargetManagement from '@/pages/TargetManagement'
import NewAssessment from '@/pages/NewAssessment'
import AiAgent from '@/pages/AiAgent'
import ScanActivity from '@/pages/ScanActivity'
import Findings from '@/pages/Findings'
import Evidence from '@/pages/Evidence'
import Approvals from '@/pages/Approvals'
import Reports from '@/pages/Reports'
import Integrations from '@/pages/Integrations'
import SettingsPage from '@/pages/Settings'
import NotFound from '@/pages/NotFound'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="/targets" element={<TargetManagement />} />
          <Route path="/assessment/new" element={<NewAssessment />} />
          <Route path="/agent" element={<AiAgent />} />
          <Route path="/scans" element={<ScanActivity />} />
          <Route path="/vulnerabilities" element={<Findings />} />
          <Route path="/findings" element={<Navigate to="/vulnerabilities" replace />} />
          <Route path="/evidence" element={<Evidence />} />
          <Route path="/approvals" element={<Approvals />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/integrations" element={<Integrations />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  )
}
