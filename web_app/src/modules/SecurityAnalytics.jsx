

import React, { useEffect, useState } from 'react';
import { apiFetch } from '../api';
import Toast from '../components/Toast.jsx';
import '../components/Toast.css';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';

export default function SecurityAnalytics() {
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [toast, setToast] = useState({ message: '', type: 'info' });
  const [refreshing, setRefreshing] = useState(false);

  const fetchAnalytics = () => {
    setLoading(true);
    apiFetch('/api/analytics/security')
      .then(data => {
        setAnalytics(data);
        setLoading(false);
      })
      .catch(e => {
        setError(e.message);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    setToast({ message: '', type: 'info' });
    try {
      await fetchAnalytics();
      setToast({ message: 'Analytics refreshed', type: 'success' });
    } catch (e) {
      setToast({ message: 'Refresh failed: ' + e.message, type: 'error' });
    }
    setRefreshing(false);
  };


  if (loading) return <div>Loading security analytics...</div>;
  if (error) return <div className="error">Error: {error}</div>;
  if (!analytics) return <div>No analytics data available.</div>;


  // Prepare chart data based on new backend structure
  const threatData = [
    { name: 'Critical', value: analytics.critical_events || 0 },
    { name: 'High', value: analytics.high_events || 0 },
    { name: 'Medium', value: analytics.medium_events || 0 },
    { name: 'Low', value: analytics.low_events || 0 }
  ];
  
  const trendData = analytics.threat_trends || [];
  const topThreats = analytics.top_threats || [];
  
  const COLORS = ['#e53e3e', '#d69e2e', '#3182ce', '#38a169'];

  // Status badge for threat level based on total events
  const getThreatBadge = (analytics) => {
    const total = analytics.total_events || 0;
    const critical = analytics.critical_events || 0;
    if (critical > 10) return <span className="badge badge-danger">Critical</span>;
    if (total > 50) return <span className="badge badge-warning">Elevated</span>;
    if (total > 0) return <span className="badge badge-info">Low</span>;
    return <span className="badge badge-success">None</span>;
  };

  return (
    <div className="security-analytics">
      <h2>Security Analytics</h2>
      <button onClick={handleRefresh} disabled={refreshing} style={{ marginBottom: '1rem' }}>
        {refreshing ? 'Refreshing...' : 'Refresh'}
      </button>
      <div className="analytics-grid">
        <div className="analytics-card highlight-card">
          <h3>Threat Level {getThreatBadge(analytics)}</h3>
          <div className="stats-summary">
            <div>Total Events: <strong>{analytics.total_events}</strong></div>
            <div>Critical: <strong>{analytics.critical_events}</strong></div>
          </div>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={threatData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={60} label isAnimationActive>
                {threatData.map((entry, idx) => (
                  <Cell key={`cell-${idx}`} fill={COLORS[idx % COLORS.length]} />
                ))}
              </Pie>
              <Legend />
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="analytics-card">
          <h3>Threat Trends</h3>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={trendData} isAnimationActive>
              <XAxis dataKey="date" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="threats" fill="#3182ce" />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="analytics-card">
          <h3>Top Threats</h3>
          <div className="threats-list">
            {topThreats.map((threat, i) => (
              <div key={i} className="threat-item">
                <span className={`threat-severity ${threat.severity}`}>{threat.name}</span>
                <span className="threat-count">{threat.count}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="analytics-card">
          <h3>Geographic Distribution</h3>
          <div className="geo-data">
            {(analytics.geographic_data || []).map((geo, i) => (
              <div key={i} className="geo-item">
                <span>{geo.country}</span>
                <span className="geo-count">{geo.threats}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      <Toast message={toast.message} type={toast.type} onClose={() => setToast({ message: '', type: 'info' })} />
    </div>
  );
}
