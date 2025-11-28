import React from 'react';
import { DashboardLayout } from '../../components/layout/DashboardLayout';
import { RecentScansWidget } from '../../components/widgets/RecentScansWidget';
import { ScanHistoryAreaChart } from '../../components/charts/ScanHistoryAreaChart';

const ScanReports: React.FC = () => (
  <DashboardLayout>
    <h2 className="text-2xl font-bold mb-6">Scan Reports</h2>
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <RecentScansWidget />
      <ScanHistoryAreaChart />
    </div>
  </DashboardLayout>
);

export default ScanReports;
