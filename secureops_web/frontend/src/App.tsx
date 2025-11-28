import React from 'react';
import { Routes, Route } from 'react-router-dom';
import Dashboard from './pages/Dashboard/Dashboard';
import ThreatIntel from './pages/ThreatIntel/ThreatIntel';
import ScanReports from './pages/ScanReports/ScanReports';
import AIAnalysis from './pages/AIAnalysis/AIAnalysis';
import Auth from './pages/Auth/Auth';
import Settings from './pages/Settings/Settings';
import MainLayout from './components/layout/MainLayout';

function App() {
  return (
    <MainLayout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/threat-intel" element={<ThreatIntel />} />
        <Route path="/scan-reports" element={<ScanReports />} />
        <Route path="/ai-analysis" element={<AIAnalysis />} />
        <Route path="/auth/*" element={<Auth />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </MainLayout>
  );
}

export default App;
