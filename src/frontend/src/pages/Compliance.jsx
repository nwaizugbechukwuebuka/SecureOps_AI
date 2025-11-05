import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Stack,
  Alert,
  Tooltip,
  Chip,
  useTheme,
  alpha,
  LinearProgress,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow
} from '@mui/material';
import {
  Assessment as AssessmentIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Settings as SettingsIcon,
  Download as DownloadIcon,
  Policy as PolicyIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
  Timeline as TimelineIcon
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import ComplianceGraph from '../components/ComplianceGraph';
import { api } from '../services/api';
import { useWebSocket } from '../services/websocket';

const Compliance = () => {
  const theme = useTheme();
  const { realTimeCompliance } = useWebSocket();
  
  const [complianceData, setComplianceData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedFramework, setSelectedFramework] = useState('all');
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [reportOpen, setReportOpen] = useState(false);

  const frameworks = {
    'owasp_top_10': { 
      name: 'OWASP Top 10', 
      description: 'Top 10 Web Application Security Risks',
      color: '#e74c3c'
    },
    'nist_csf': { 
      name: 'NIST Cybersecurity Framework', 
      description: 'Comprehensive cybersecurity guidelines',
      color: '#3498db'
    },
    'soc2': { 
      name: 'SOC 2', 
      description: 'Service Organization Control 2',
      color: '#2ecc71'
    },
    'gdpr': { 
      name: 'GDPR', 
      description: 'General Data Protection Regulation',
      color: '#f39c12'
    },
    'pci_dss': { 
      name: 'PCI DSS', 
      description: 'Payment Card Industry Data Security Standard',
      color: '#9b59b6'
    },
    'iso_27001': { 
      name: 'ISO 27001', 
      description: 'Information Security Management',
      color: '#34495e'
    },
    'hipaa': { 
      name: 'HIPAA', 
      description: 'Health Insurance Portability and Accountability Act',
      color: '#e67e22'
    },
    'sox': { 
      name: 'SOX', 
      description: 'Sarbanes-Oxley Act',
      color: '#1abc9c'
    }
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
      const response = await api.get('/compliance', { params });
      setComplianceData(response.data);
    } catch (err) {
      setError('Failed to load compliance data');
      console.error('Compliance error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleExportReport = async () => {
    try {
      const response = await api.get('/compliance/report', { 
        responseType: 'blob',
        params: { framework: selectedFramework }
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `compliance_report_${selectedFramework}_${new Date().toISOString().split('T')[0]}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export error:', err);
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

  const getStatusIcon = (status) => {
    const icons = {
      passed: <CheckCircleIcon sx={{ color: theme.palette.success.main }} />,
      failed: <ErrorIcon sx={{ color: theme.palette.error.main }} />,
      warning: <WarningIcon sx={{ color: theme.palette.warning.main }} />,
      not_applicable: <InfoIcon sx={{ color: theme.palette.grey[500] }} />
    };
    return icons[status] || icons.not_applicable;
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        duration: 0.6,
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: {
        duration: 0.5,
        ease: "easeOut"
      }
    }
  };

  return (
    <Container maxWidth="xl" sx={{ py: 3 }}>
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
      >
        {/* Header */}
        <motion.div variants={itemVariants}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Box>
              <Typography 
                variant="h4" 
                sx={{ 
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  mb: 1
                }}
              >
                <AssessmentIcon sx={{ mr: 2, fontSize: 36 }} />
                Compliance Dashboard
              </Typography>
              <Typography variant="subtitle1" color="text.secondary">
                Monitor compliance with security frameworks and regulations
              </Typography>
            </Box>
            
            <Stack direction="row" spacing={1}>
              <FormControl size="small" sx={{ minWidth: 200 }}>
                <InputLabel>Framework</InputLabel>
                <Select
                  value={selectedFramework}
                  label="Framework"
                  onChange={(e) => setSelectedFramework(e.target.value)}
                >
                  <MenuItem value="all">All Frameworks</MenuItem>
                  {Object.entries(frameworks).map(([key, config]) => (
                    <MenuItem key={key} value={key}>
                      {config.name}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              <Tooltip title="Export report">
                <IconButton onClick={handleExportReport}>
                  <DownloadIcon />
                </IconButton>
              </Tooltip>
              
              <Tooltip title="Settings">
                <IconButton onClick={() => setSettingsOpen(true)}>
                  <SettingsIcon />
                </IconButton>
              </Tooltip>
              
              <Tooltip title="Refresh">
                <IconButton onClick={loadComplianceData}>
                  <RefreshIcon />
                </IconButton>
              </Tooltip>
            </Stack>
          </Box>
        </motion.div>

        {/* Error Alert */}
        {error && (
          <motion.div variants={itemVariants}>
            <Alert severity="error" sx={{ mb: 3 }}>
              {error}
            </Alert>
          </motion.div>
        )}

        {/* Overall Compliance Score */}
        <motion.div variants={itemVariants}>
          <Card sx={{ mb: 4, background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)` }}>
            <CardContent>
              <Grid container spacing={3} alignItems="center">
                <Grid item xs={12} md={4}>
                  <Box sx={{ textAlign: { xs: 'center', md: 'left' } }}>
                    <Typography variant="h2" sx={{ fontWeight: 700, mb: 1 }}>
                      {complianceData?.overall_score || 0}%
                    </Typography>
                    <Typography variant="h6" color="text.secondary">
                      Overall Compliance Score
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: { xs: 'center', md: 'flex-start' }, mt: 1 }}>
                      {complianceData?.trend > 0 ? (
                        <TrendingUpIcon sx={{ color: 'success.main', mr: 0.5 }} />
                      ) : (
                        <TrendingDownIcon sx={{ color: 'error.main', mr: 0.5 }} />
                      )}
                      <Typography variant="body2">
                        {Math.abs(complianceData?.trend || 0)}% vs last month
                      </Typography>
                    </Box>
                  </Box>
                </Grid>
                
                <Grid item xs={12} md={8}>
                  <Grid container spacing={2}>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="h4" sx={{ color: 'success.main', fontWeight: 600 }}>
                          {complianceData?.controls?.passed || 0}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Passed
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="h4" sx={{ color: 'error.main', fontWeight: 600 }}>
                          {complianceData?.controls?.failed || 0}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Failed
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="h4" sx={{ color: 'warning.main', fontWeight: 600 }}>
                          {complianceData?.controls?.warnings || 0}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          Warnings
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: 'center' }}>
                        <Typography variant="h4" sx={{ color: 'text.secondary', fontWeight: 600 }}>
                          {complianceData?.controls?.not_applicable || 0}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          N/A
                        </Typography>
                      </Box>
                    </Grid>
                  </Grid>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </motion.div>

        {/* Framework Scores */}
        {complianceData?.frameworks && (
          <motion.div variants={itemVariants}>
            <Grid container spacing={3} sx={{ mb: 4 }}>
              {Object.entries(complianceData.frameworks).map(([key, data]) => (
                <Grid item xs={12} sm={6} md={3} key={key}>
                  <Card sx={{ 
                    height: '100%',
                    borderLeft: 4,
                    borderLeftColor: frameworks[key]?.color || theme.palette.primary.main,
                    background: `linear-gradient(135deg, ${alpha(frameworks[key]?.color || theme.palette.primary.main, 0.1)} 0%, ${alpha(frameworks[key]?.color || theme.palette.primary.main, 0.05)} 100%)`
                  }}>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                        <PolicyIcon sx={{ color: frameworks[key]?.color, mr: 1 }} />
                        <Typography variant="h6" sx={{ fontWeight: 600 }}>
                          {data.score || 0}%
                        </Typography>
                      </Box>
                      <Typography variant="body1" sx={{ fontWeight: 500, mb: 1 }}>
                        {frameworks[key]?.name || key}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        {frameworks[key]?.description || 'Compliance framework'}
                      </Typography>
                      <LinearProgress
                        variant="determinate"
                        value={data.score || 0}
                        sx={{
                          height: 8,
                          borderRadius: 4,
                          backgroundColor: alpha(frameworks[key]?.color || theme.palette.primary.main, 0.2),
                          '& .MuiLinearProgress-bar': {
                            backgroundColor: frameworks[key]?.color || theme.palette.primary.main,
                            borderRadius: 4
                          }
                        }}
                      />
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 1 }}>
                        <Typography variant="caption">
                          {data.passed || 0} passed
                        </Typography>
                        <Typography variant="caption">
                          {data.failed || 0} failed
                        </Typography>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </motion.div>
        )}

        {/* Compliance Visualization */}
        <motion.div variants={itemVariants}>
          <Card sx={{ mb: 4 }}>
            <CardContent>
              <ComplianceGraph framework={selectedFramework} height={500} />
            </CardContent>
          </Card>
        </motion.div>

        {/* Recent Compliance Issues */}
        <motion.div variants={itemVariants}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Recent Compliance Issues
                  </Typography>
                  {complianceData?.recent_issues?.length > 0 ? (
                    <List>
                      {complianceData.recent_issues.slice(0, 5).map((issue, index) => (
                        <ListItem key={index} divider={index < 4}>
                          <ListItemIcon>
                            {getStatusIcon(issue.status)}
                          </ListItemIcon>
                          <ListItemText
                            primary={issue.control_id}
                            secondary={
                              <Box>
                                <Typography variant="body2" color="text.secondary">
                                  {issue.description}
                                </Typography>
                                <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                                  <Chip size="small" label={issue.framework} />
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

            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Control Categories
                  </Typography>
                  {complianceData?.categories && (
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Category</TableCell>
                            <TableCell align="right">Score</TableCell>
                            <TableCell align="right">Controls</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {Object.entries(complianceData.categories).map(([category, data]) => (
                            <TableRow key={category}>
                              <TableCell>
                                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                  {getComplianceIcon(data.score)}
                                  <Typography variant="body2" sx={{ ml: 1 }}>
                                    {category.replace(/_/g, ' ').toUpperCase()}
                                  </Typography>
                                </Box>
                              </TableCell>
                              <TableCell align="right">
                                <Chip 
                                  size="small" 
                                  label={`${data.score}%`}
                                  sx={{ 
                                    backgroundColor: alpha(getComplianceColor(data.score), 0.1),
                                    color: getComplianceColor(data.score)
                                  }}
                                />
                              </TableCell>
                              <TableCell align="right">
                                <Typography variant="body2">
                                  {data.passed}/{data.total}
                                </Typography>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  )}
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </motion.div>
      </motion.div>

      {/* Settings Dialog */}
      <Dialog 
        open={settingsOpen} 
        onClose={() => setSettingsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Compliance Settings</DialogTitle>
        <DialogContent>
          <Typography variant="body1" paragraph>
            Configure compliance frameworks, thresholds, and reporting settings.
          </Typography>
          
          <Stack spacing={2}>
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Active Frameworks
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Select which compliance frameworks to monitor and track.
                </Typography>
                <Stack direction="row" spacing={1} sx={{ mt: 2, flexWrap: 'wrap', gap: 1 }}>
                  {Object.entries(frameworks).map(([key, config]) => (
                    <Chip
                      key={key}
                      label={config.name}
                      variant="outlined"
                      sx={{ 
                        borderColor: config.color,
                        color: config.color,
                        '&:hover': {
                          backgroundColor: alpha(config.color, 0.1)
                        }
                      }}
                    />
                  ))}
                </Stack>
              </CardContent>
            </Card>
            
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Thresholds
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Set minimum compliance scores and alert thresholds.
                </Typography>
                <Button size="small" sx={{ mt: 1 }}>
                  Configure Thresholds
                </Button>
              </CardContent>
            </Card>
            
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Reporting
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Configure automated compliance reports and schedules.
                </Typography>
                <Button size="small" sx={{ mt: 1 }}>
                  Setup Reports
                </Button>
              </CardContent>
            </Card>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSettingsOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default Compliance;
