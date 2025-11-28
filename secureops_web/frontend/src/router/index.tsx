import { useRoutes } from 'react-router-dom';
import Dashboard from '../pages/Dashboard/Dashboard';
import ThreatIntel from '../pages/ThreatIntel/ThreatIntel';
import ScanReports from '../pages/ScanReports/ScanReports';
import AIAnalysis from '../pages/AIAnalysis/AIAnalysis';
import Auth from '../pages/Auth/Auth';
import Settings from '../pages/Settings/Settings';

export const AppRoutes = () =>
  useRoutes([
    { path: '/', element: <Dashboard /> },
    { path: '/threat-intel', element: <ThreatIntel /> },
    { path: '/scan-reports', element: <ScanReports /> },
    { path: '/ai-analysis', element: <AIAnalysis /> },
    { path: '/auth/*', element: <Auth /> },
    { path: '/settings', element: <Settings /> },
  ]);
