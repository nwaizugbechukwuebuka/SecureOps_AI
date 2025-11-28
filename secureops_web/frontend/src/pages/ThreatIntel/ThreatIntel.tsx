import React from 'react';
import { DashboardLayout } from '../../components/layout/DashboardLayout';
import { ThreatBarChart } from '../../components/charts/ThreatBarChart';
import { ThreatIntelFeed } from '../../components/widgets/ThreatIntelFeed';

const ThreatIntel: React.FC = () => (
  <DashboardLayout>
    <h2 className="text-2xl font-bold mb-6">Threat Intelligence</h2>
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <ThreatBarChart />
      <ThreatIntelFeed />
    </div>
  </DashboardLayout>
);

export default ThreatIntel;
