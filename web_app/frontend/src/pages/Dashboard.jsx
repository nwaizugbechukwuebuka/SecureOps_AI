import React, { useState, useEffect } from 'react';
import Card from '../components/Card.jsx';
import { fetchDashboardData } from '../services/api.js';

export default function Dashboard() {
  const [dashboardData, setDashboardData] = useState({
    activeThreats: 0,
    totalUsers: 0,
    systemHealth: 'healthy',
    recentAlerts: []
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const data = await fetchDashboardData();
      setDashboardData(data);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="dashboard-loading">
        <div className="loading-spinner"></div>
        <p>Loading dashboard...</p>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>SecureOps AI Dashboard</h1>
        <p>Security Operations & Monitoring Center</p>
      </div>
      
      <div className="dashboard-grid">
        <Card
          title="Active Threats"
          value={dashboardData.activeThreats}
          icon="🔒"
          color="danger"
        />
        <Card
          title="Total Users"
          value={dashboardData.totalUsers}
          icon="👤"
          color="info"
        />
        <Card
          title="System Health"
          value={dashboardData.systemHealth}
          icon="💻"
          color={dashboardData.systemHealth === 'healthy' ? 'success' : 'warning'}
        />
        <Card
          title="Recent Alerts"
          value={dashboardData.recentAlerts.length}
          icon="🔔"
          color="warning"
        />
      </div>

      <div className="dashboard-modules">
        <div className="module-grid">
          <div className="module-card">
            <h3>Security Analytics</h3>
            <p>Monitor threats, analyze patterns, and view security metrics</p>
            <button className="btn btn-primary">View Analytics</button>
          </div>
          <div className="module-card">
            <h3>User Management</h3>
            <p>Manage users, roles, permissions, and access control</p>
            <button className="btn btn-primary">Manage Users</button>
          </div>
          <div className="module-card">
            <h3>System Monitoring</h3>
            <p>Monitor system health, performance, and resource usage</p>
            <button className="btn btn-primary">View System</button>
          </div>
          <div className="module-card">
            <h3>AI Operations</h3>
            <p>Automated security tasks and AI-powered recommendations</p>
            <button className="btn btn-primary">AI Tasks</button>
          </div>
        </div>
      </div>
    </div>
  );
}