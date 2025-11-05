import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  Chip,
  IconButton,
  useTheme,
  alpha,
  Skeleton,
  Alert,
  Tabs,
  Tab,
  Divider
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Timeline as TimelineIcon,
  Refresh as RefreshIcon,
  BugReport as BugReportIcon,
  Shield as ShieldIcon,
  Speed as SpeedIcon,
  Assignment as AssignmentIcon
} from '@mui/icons-material';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  BarElement
} from 'chart.js';
import { api } from '../services/api';
import { useWebSocket } from '../services/websocket';
import ActivityFeed from './ActivityFeed';
import ComplianceGraph from './ComplianceGraph';
import VulnerabilityTable from './VulnerabilityTable';

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  BarElement
);

const Dashboard = () => {
  const theme = useTheme();
  const { realTimeData } = useWebSocket();
  
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedTab, setSelectedTab] = useState(0);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadDashboardData();
  }, []);

  useEffect(() => {
    if (realTimeData) {
      // Update dashboard with real-time data
      setDashboardData(prev => ({
        ...prev,
        ...realTimeData
      }));
    }
  }, [realTimeData]);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await api.get('/dashboard/overview');
      setDashboardData(response.data);
    } catch (err) {
      setError('Failed to load dashboard data');
      console.error('Dashboard error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadDashboardData();
    setRefreshing(false);
  };

  const handleTabChange = (event, newValue) => {
    setSelectedTab(newValue);
  };

  const getProgressColor = (value) => {
    if (value >= 80) return theme.palette.success.main;
    if (value >= 60) return theme.palette.warning.main;
    return theme.palette.error.main;
  };

  const formatNumber = (num) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
  };

  const getTrendIcon = (trend) => {
    if (trend > 0) return <TrendingUpIcon sx={{ color: theme.palette.success.main }} />;
    if (trend < 0) return <TrendingDownIcon sx={{ color: theme.palette.error.main }} />;
    return <TimelineIcon sx={{ color: theme.palette.text.secondary }} />;
  };

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Grid container spacing={3}>
          {[...Array(8)].map((_, index) => (
            <Grid item xs={12} sm={6} md={3} key={index}>
              <Card>
                <CardContent>
                  <Skeleton variant="text" height={60} />
                  <Skeleton variant="rectangular" height={40} />
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error" action={
          <IconButton color="inherit" size="small" onClick={handleRefresh}>
            <RefreshIcon />
          </IconButton>
        }>
          {error}
        </Alert>
      </Box>
    );
  }

  const {
    overview = {},
    vulnerabilities = {},
    pipelines = {},
    compliance = {},
    trends = {},
    recentActivity = []
  } = dashboardData || {};

  // Chart configurations
  const vulnerabilityTrendData = {
    labels: trends.dates || [],
    datasets: [
      {
        label: 'Critical',
        data: trends.critical || [],
        borderColor: theme.palette.error.main,
        backgroundColor: alpha(theme.palette.error.main, 0.1),
        tension: 0.4
      },
      {
        label: 'High',
        data: trends.high || [],
        borderColor: theme.palette.warning.main,
        backgroundColor: alpha(theme.palette.warning.main, 0.1),
        tension: 0.4
      },
      {
        label: 'Medium',
        data: trends.medium || [],
        borderColor: theme.palette.info.main,
        backgroundColor: alpha(theme.palette.info.main, 0.1),
        tension: 0.4
      }
    ]
  };

  const severityDistributionData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [
        vulnerabilities.critical || 0,
        vulnerabilities.high || 0,
        vulnerabilities.medium || 0,
        vulnerabilities.low || 0
      ],
      backgroundColor: [
        theme.palette.error.main,
        theme.palette.warning.main,
        theme.palette.info.main,
        theme.palette.success.main
      ],
      borderWidth: 0
    }]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          usePointStyle: true,
          padding: 20
        }
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: {
          color: alpha(theme.palette.divider, 0.1)
        }
      },
      x: {
        grid: {
          display: false
        }
      }
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" sx={{ fontWeight: 600 }}>
          Security Dashboard
        </Typography>
        <IconButton 
          onClick={handleRefresh} 
          disabled={refreshing}
          sx={{ 
            animation: refreshing ? 'spin 1s linear infinite' : 'none',
            '@keyframes spin': {
              '0%': { transform: 'rotate(0deg)' },
              '100%': { transform: 'rotate(360deg)' }
            }
          }}
        >
          <RefreshIcon />
        </IconButton>
      </Box>

      {/* Key Metrics Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Total Vulnerabilities */}
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ 
            background: `linear-gradient(135deg, ${alpha(theme.palette.error.main, 0.1)} 0%, ${alpha(theme.palette.error.main, 0.05)} 100%)`,
            border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`
          }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Total Vulnerabilities
                  </Typography>
                  <Typography variant="h4" sx={{ fontWeight: 600 }}>
                    {formatNumber(vulnerabilities.total || 0)}
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                    {getTrendIcon(vulnerabilities.trend)}
                    <Typography variant="caption" color="text.secondary" sx={{ ml: 0.5 }}>
                      {Math.abs(vulnerabilities.trend || 0)}% vs last week
                    </Typography>
                  </Box>
                </Box>
                <BugReportIcon sx={{ fontSize: 48, color: theme.palette.error.main, opacity: 0.7 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Active Pipelines */}
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ 
            background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)`,
            border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`
          }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Active Pipelines
                  </Typography>
                  <Typography variant="h4" sx={{ fontWeight: 600 }}>
                    {pipelines.active || 0}
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', mt: 1 }}>
                    <CheckCircleIcon sx={{ color: theme.palette.success.main, fontSize: 16 }} />
                    <Typography variant="caption" color="text.secondary" sx={{ ml: 0.5 }}>
                      {pipelines.success_rate || 0}% success rate
                    </Typography>
                  </Box>
                </Box>
                <SpeedIcon sx={{ fontSize: 48, color: theme.palette.primary.main, opacity: 0.7 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Security Score */}
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ 
            background: `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.1)} 0%, ${alpha(theme.palette.success.main, 0.05)} 100%)`,
            border: `1px solid ${alpha(theme.palette.success.main, 0.2)}`
          }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box sx={{ width: '100%' }}>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Security Score
                  </Typography>
                  <Typography variant="h4" sx={{ fontWeight: 600, mb: 1 }}>
                    {overview.security_score || 0}/100
                  </Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={overview.security_score || 0}
                    sx={{ 
                      height: 8, 
                      borderRadius: 4,
                      backgroundColor: alpha(theme.palette.success.main, 0.2),
                      '& .MuiLinearProgress-bar': {
                        backgroundColor: getProgressColor(overview.security_score || 0),
                        borderRadius: 4
                      }
                    }}
                  />
                </Box>
                <ShieldIcon sx={{ fontSize: 48, color: theme.palette.success.main, opacity: 0.7, ml: 2 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Compliance Score */}
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ 
            background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.1)} 0%, ${alpha(theme.palette.info.main, 0.05)} 100%)`,
            border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`
          }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box sx={{ width: '100%' }}>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Compliance Score
                  </Typography>
                  <Typography variant="h4" sx={{ fontWeight: 600, mb: 1 }}>
                    {compliance.overall_score || 0}%
                  </Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={compliance.overall_score || 0}
                    sx={{ 
                      height: 8, 
                      borderRadius: 4,
                      backgroundColor: alpha(theme.palette.info.main, 0.2),
                      '& .MuiLinearProgress-bar': {
                        backgroundColor: getProgressColor(compliance.overall_score || 0),
                        borderRadius: 4
                      }
                    }}
                  />
                </Box>
                <AssignmentIcon sx={{ fontSize: 48, color: theme.palette.info.main, opacity: 0.7, ml: 2 }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs for different views */}
      <Card sx={{ mb: 3 }}>
        <Tabs 
          value={selectedTab} 
          onChange={handleTabChange}
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab label="Overview" />
          <Tab label="Vulnerabilities" />
          <Tab label="Compliance" />
          <Tab label="Activity" />
        </Tabs>

        <CardContent>
          {/* Overview Tab */}
          {selectedTab === 0 && (
            <Grid container spacing={3}>
              {/* Vulnerability Trend Chart */}
              <Grid item xs={12} md={8}>
                <Typography variant="h6" gutterBottom>
                  Vulnerability Trends (Last 30 Days)
                </Typography>
                <Box sx={{ height: 300 }}>
                  <Line data={vulnerabilityTrendData} options={chartOptions} />
                </Box>
              </Grid>

              {/* Severity Distribution */}
              <Grid item xs={12} md={4}>
                <Typography variant="h6" gutterBottom>
                  Severity Distribution
                </Typography>
                <Box sx={{ height: 300 }}>
                  <Doughnut data={severityDistributionData} options={{ responsive: true, maintainAspectRatio: false }} />
                </Box>
              </Grid>

              {/* Quick Stats */}
              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>
                  Quick Statistics
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card variant="outlined">
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h5" color="error">
                          {vulnerabilities.critical || 0}
                        </Typography>
                        <Typography variant="caption">Critical Issues</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card variant="outlined">
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h5" color="primary">
                          {pipelines.total || 0}
                        </Typography>
                        <Typography variant="caption">Total Pipelines</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card variant="outlined">
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h5" color="success.main">
                          {overview.scans_today || 0}
                        </Typography>
                        <Typography variant="caption">Scans Today</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Card variant="outlined">
                      <CardContent sx={{ textAlign: 'center' }}>
                        <Typography variant="h5" color="info.main">
                          {overview.alerts_resolved || 0}
                        </Typography>
                        <Typography variant="caption">Resolved Today</Typography>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              </Grid>
            </Grid>
          )}

          {/* Vulnerabilities Tab */}
          {selectedTab === 1 && (
            <VulnerabilityTable limit={10} showFilters={false} />
          )}

          {/* Compliance Tab */}
          {selectedTab === 2 && (
            <ComplianceGraph />
          )}

          {/* Activity Tab */}
          {selectedTab === 3 && (
            <ActivityFeed limit={20} />
          )}
        </CardContent>
      </Card>
    </Box>
  );
};

export default Dashboard;