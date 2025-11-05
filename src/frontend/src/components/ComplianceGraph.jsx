import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  LinearProgress,
  Chip,
  IconButton,
  Tooltip,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  useTheme,
  alpha,
  Paper,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider
} from '@mui/material';
import {
  Assessment as AssessmentIcon,
  Security as SecurityIcon,
  Shield as ShieldIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Refresh as RefreshIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Policy as PolicyIcon
} from '@mui/icons-material';
import { Radar, Bar, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler,
  Tooltip as ChartTooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement
} from 'chart.js';
import { api } from '../services/api';
import { useWebSocket } from '../services/websocket';

// Register Chart.js components
ChartJS.register(
  RadialLinearScale,
  PointElement,
  LineElement,
  Filler,
  ChartTooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement
);

const ComplianceGraph = ({ framework = 'all', height = 400 }) => {
  const theme = useTheme();
  const { realTimeCompliance } = useWebSocket();
  
  const [complianceData, setComplianceData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedFramework, setSelectedFramework] = useState(framework);
  const [viewType, setViewType] = useState('radar');

  const complianceFrameworks = {
    'owasp_top_10': { name: 'OWASP Top 10', color: theme.palette.error.main },
    'nist_csf': { name: 'NIST Cybersecurity Framework', color: theme.palette.primary.main },
    'soc2': { name: 'SOC 2', color: theme.palette.success.main },
    'gdpr': { name: 'GDPR', color: theme.palette.warning.main },
    'pci_dss': { name: 'PCI DSS', color: theme.palette.info.main },
    'iso_27001': { name: 'ISO 27001', color: theme.palette.secondary.main },
    'hipaa': { name: 'HIPAA', color: theme.palette.error.light },
    'sox': { name: 'SOX', color: theme.palette.success.light }
  };

  useEffect(() => {
    loadComplianceData();
  }, [selectedFramework]);

  useEffect(() => {
    if (realTimeCompliance) {
      setComplianceData(prev => ({
        ...prev,
        ...realTimeCompliance
      }));
    }
  }, [realTimeCompliance]);

  const loadComplianceData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const params = selectedFramework !== 'all' ? { framework: selectedFramework } : {};
      const response = await api.get('/compliance/dashboard', { params });
      setComplianceData(response.data);
    } catch (err) {
      setError('Failed to load compliance data');
      console.error('Compliance error:', err);
    } finally {
      setLoading(false);
    }
  };

  const getComplianceColor = (score) => {
    if (score >= 90) return theme.palette.success.main;
    if (score >= 75) return theme.palette.info.main;
    if (score >= 60) return theme.palette.warning.main;
    return theme.palette.error.main;
  };

  const getComplianceIcon = (score) => {
    if (score >= 90) return <CheckCircleIcon sx={{ color: theme.palette.success.main }} />;
    if (score >= 75) return <InfoIcon sx={{ color: theme.palette.info.main }} />;
    if (score >= 60) return <WarningIcon sx={{ color: theme.palette.warning.main }} />;
    return <ErrorIcon sx={{ color: theme.palette.error.main }} />;
  };

  const generateRadarData = () => {
    if (!complianceData?.frameworks) return null;

    const frameworks = Object.entries(complianceData.frameworks);
    
    return {
      labels: frameworks.map(([key, data]) => complianceFrameworks[key]?.name || key),
      datasets: [
        {
          label: 'Compliance Score',
          data: frameworks.map(([_, data]) => data.score || 0),
          backgroundColor: alpha(theme.palette.primary.main, 0.2),
          borderColor: theme.palette.primary.main,
          borderWidth: 2,
          pointBackgroundColor: theme.palette.primary.main,
          pointBorderColor: '#fff',
          pointHoverBackgroundColor: '#fff',
          pointHoverBorderColor: theme.palette.primary.main
        }
      ]
    };
  };

  const generateBarData = () => {
    if (!complianceData?.frameworks) return null;

    const frameworks = Object.entries(complianceData.frameworks);
    
    return {
      labels: frameworks.map(([key, data]) => complianceFrameworks[key]?.name || key),
      datasets: [
        {
          label: 'Passed Controls',
          data: frameworks.map(([_, data]) => data.passed || 0),
          backgroundColor: theme.palette.success.main,
          borderColor: theme.palette.success.dark,
          borderWidth: 1
        },
        {
          label: 'Failed Controls',
          data: frameworks.map(([_, data]) => data.failed || 0),
          backgroundColor: theme.palette.error.main,
          borderColor: theme.palette.error.dark,
          borderWidth: 1
        },
        {
          label: 'Warning Controls',
          data: frameworks.map(([_, data]) => data.warnings || 0),
          backgroundColor: theme.palette.warning.main,
          borderColor: theme.palette.warning.dark,
          borderWidth: 1
        }
      ]
    };
  };

  const generateDoughnutData = () => {
    if (!complianceData?.overall) return null;

    const { passed = 0, failed = 0, warnings = 0, not_applicable = 0 } = complianceData.overall;
    
    return {
      labels: ['Passed', 'Failed', 'Warnings', 'Not Applicable'],
      datasets: [
        {
          data: [passed, failed, warnings, not_applicable],
          backgroundColor: [
            theme.palette.success.main,
            theme.palette.error.main,
            theme.palette.warning.main,
            theme.palette.grey[400]
          ],
          borderColor: [
            theme.palette.success.dark,
            theme.palette.error.dark,
            theme.palette.warning.dark,
            theme.palette.grey[600]
          ],
          borderWidth: 2
        }
      ]
    };
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          padding: 20,
          usePointStyle: true
        }
      }
    }
  };

  const radarOptions = {
    ...chartOptions,
    scales: {
      r: {
        beginAtZero: true,
        max: 100,
        grid: {
          color: alpha(theme.palette.divider, 0.2)
        },
        angleLines: {
          color: alpha(theme.palette.divider, 0.2)
        },
        pointLabels: {
          font: {
            size: 12
          }
        }
      }
    }
  };

  const barOptions = {
    ...chartOptions,
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

  if (loading) {
    return (
      <Card sx={{ height }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>Compliance Dashboard</Typography>
          <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: height - 100 }}>
            <Typography>Loading compliance data...</Typography>
          </Box>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card sx={{ height }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>Compliance Dashboard</Typography>
          <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: height - 100 }}>
            <Typography color="error">{error}</Typography>
          </Box>
        </CardContent>
      </Card>
    );
  }

  const radarData = generateRadarData();
  const barData = generateBarData();
  const doughnutData = generateDoughnutData();

  return (
    <Box>
      {/* Header Controls */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6">Compliance Dashboard</Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Framework</InputLabel>
            <Select
              value={selectedFramework}
              label="Framework"
              onChange={(e) => setSelectedFramework(e.target.value)}
            >
              <MenuItem value="all">All Frameworks</MenuItem>
              {Object.entries(complianceFrameworks).map(([key, config]) => (
                <MenuItem key={key} value={key}>{config.name}</MenuItem>
              ))}
            </Select>
          </FormControl>
          
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>View</InputLabel>
            <Select
              value={viewType}
              label="View"
              onChange={(e) => setViewType(e.target.value)}
            >
              <MenuItem value="radar">Radar Chart</MenuItem>
              <MenuItem value="bar">Bar Chart</MenuItem>
              <MenuItem value="overview">Overview</MenuItem>
            </Select>
          </FormControl>
          
          <Tooltip title="Refresh">
            <IconButton onClick={loadComplianceData}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      <Grid container spacing={3}>
        {/* Overall Compliance Score */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Overall Compliance Score
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Typography variant="h3" sx={{ fontWeight: 600, mr: 1 }}>
                  {complianceData?.overall_score || 0}%
                </Typography>
                {getComplianceIcon(complianceData?.overall_score || 0)}
              </Box>
              <LinearProgress
                variant="determinate"
                value={complianceData?.overall_score || 0}
                sx={{
                  height: 8,
                  borderRadius: 4,
                  backgroundColor: alpha(theme.palette.grey[500], 0.2),
                  '& .MuiLinearProgress-bar': {
                    backgroundColor: getComplianceColor(complianceData?.overall_score || 0),
                    borderRadius: 4
                  }
                }}
              />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                {complianceData?.trend > 0 ? 'Improving' : complianceData?.trend < 0 ? 'Declining' : 'Stable'} 
                {complianceData?.trend !== 0 && (
                  <Box component="span" sx={{ ml: 0.5 }}>
                    {complianceData?.trend > 0 ? <TrendingUpIcon sx={{ fontSize: 16, color: 'success.main' }} /> : <TrendingDownIcon sx={{ fontSize: 16, color: 'error.main' }} />}
                  </Box>
                )}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Compliance Breakdown */}
        <Grid item xs={12} md={8}>
          <Card sx={{ height: height - 50 }}>
            <CardContent sx={{ height: '100%' }}>
              {viewType === 'radar' && radarData && (
                <Box sx={{ height: '100%' }}>
                  <Radar data={radarData} options={radarOptions} />
                </Box>
              )}
              
              {viewType === 'bar' && barData && (
                <Box sx={{ height: '100%' }}>
                  <Bar data={barData} options={barOptions} />
                </Box>
              )}
              
              {viewType === 'overview' && (
                <Grid container spacing={2} sx={{ height: '100%' }}>
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle1" gutterBottom>
                      Control Status Distribution
                    </Typography>
                    {doughnutData && (
                      <Box sx={{ height: 250 }}>
                        <Doughnut data={doughnutData} options={chartOptions} />
                      </Box>
                    )}
                  </Grid>
                  
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle1" gutterBottom>
                      Framework Scores
                    </Typography>
                    <List dense>
                      {complianceData?.frameworks && Object.entries(complianceData.frameworks).map(([key, data]) => (
                        <ListItem key={key}>
                          <ListItemIcon>
                            <PolicyIcon sx={{ color: complianceFrameworks[key]?.color }} />
                          </ListItemIcon>
                          <ListItemText
                            primary={complianceFrameworks[key]?.name || key}
                            secondary={
                              <Box sx={{ display: 'flex', alignItems: 'center', mt: 0.5 }}>
                                <LinearProgress
                                  variant="determinate"
                                  value={data.score || 0}
                                  sx={{
                                    width: 100,
                                    mr: 1,
                                    '& .MuiLinearProgress-bar': {
                                      backgroundColor: getComplianceColor(data.score || 0)
                                    }
                                  }}
                                />
                                <Typography variant="body2">
                                  {data.score || 0}%
                                </Typography>
                              </Box>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Grid>
                </Grid>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Compliance Issues */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Recent Compliance Issues
              </Typography>
              {complianceData?.recent_issues?.length > 0 ? (
                <List>
                  {complianceData.recent_issues.map((issue, index) => (
                    <React.Fragment key={index}>
                      <ListItem>
                        <ListItemIcon>
                          {getComplianceIcon(0)}
                        </ListItemIcon>
                        <ListItemText
                          primary={issue.title}
                          secondary={
                            <Box>
                              <Typography variant="body2" color="text.secondary">
                                {issue.description}
                              </Typography>
                              <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                                <Chip size="small" label={issue.framework} />
                                <Chip size="small" label={issue.control_id} />
                                <Chip 
                                  size="small" 
                                  label={issue.severity} 
                                  color={issue.severity === 'high' ? 'error' : 'warning'}
                                />
                              </Box>
                            </Box>
                          }
                        />
                      </ListItem>
                      {index < complianceData.recent_issues.length - 1 && <Divider />}
                    </React.Fragment>
                  ))}
                </List>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  No recent compliance issues found.
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default ComplianceGraph;
