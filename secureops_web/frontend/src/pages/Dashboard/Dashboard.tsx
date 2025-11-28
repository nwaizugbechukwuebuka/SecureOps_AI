import React from 'react';
import { DashboardLayout } from '../../components/layout/DashboardLayout';
import { MetricCard } from '../../components/cards/MetricCard';
import { RiskScoreCard } from '../../components/cards/RiskScoreCard';
import { VulnerabilityCard } from '../../components/cards/VulnerabilityCard';
import { ScanStatusCard } from '../../components/cards/ScanStatusCard';
import { ThreatBarChart } from '../../components/charts/ThreatBarChart';
import { RiskPieChart } from '../../components/charts/RiskPieChart';
import { TrafficLineChart } from '../../components/charts/TrafficLineChart';
import { ScanHistoryAreaChart } from '../../components/charts/ScanHistoryAreaChart';
import { RecentScansWidget } from '../../components/widgets/RecentScansWidget';
import { ThreatIntelFeed } from '../../components/widgets/ThreatIntelFeed';
import { AIAnalysisSummary } from '../../components/widgets/AIAnalysisSummary';
import { ActivityTimeline } from '../../components/widgets/ActivityTimeline';

const Dashboard: React.FC = () => (
  <DashboardLayout>
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      <MetricCard title="Total Scans" value={128} badge="+12 today" color="accent" />
      <RiskScoreCard score={72} level="Medium" />
      <VulnerabilityCard count={34} critical={5} />
      <ScanStatusCard status="Completed" lastScan="2025-11-27 09:00" />
    </div>
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      <ThreatBarChart />
      <RiskPieChart />
      <TrafficLineChart />
      <ScanHistoryAreaChart />
    </div>
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <RecentScansWidget />
      <ThreatIntelFeed />
      <AIAnalysisSummary />
      <ActivityTimeline />
    </div>
  </DashboardLayout>
);

export default Dashboard;
