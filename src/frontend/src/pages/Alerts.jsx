import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Stack,
  Alert,
  Tooltip,
  useTheme,
  alpha,
  Fab,
  Badge
} from '@mui/material';
import {
  Add as AddIcon,
  FilterList as FilterListIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  Notifications as NotificationsIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  Settings as SettingsIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import AlertList from '../components/AlertList';
import { api } from '../services/api';
import { useWebSocket } from '../services/websocket';

const Alerts = () => {
  const theme = useTheme();
  const { realTimeAlerts, alertMetrics } = useWebSocket();
  
  const [alertStats, setAlertStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    resolved_today: 0,
    trend: 0
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [createAlertOpen, setCreateAlertOpen] = useState(false);
  const [alertsConfigOpen, setAlertsConfigOpen] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  // New alert form state
  const [newAlert, setNewAlert] = useState({
    title: '',
    description: '',
    severity: 'medium',
    type: 'manual',
    pipeline: '',
    assignee: ''
  });

  useEffect(() => {
    loadAlertStats();
  }, []);

  useEffect(() => {
    if (alertMetrics) {
      setAlertStats(prev => ({
        ...prev,
        ...alertMetrics
      }));
    }
  }, [alertMetrics]);

  const loadAlertStats = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await api.get('/alerts/stats');
      setAlertStats(response.data);
    } catch (err) {
      setError('Failed to load alert statistics');
      console.error('Alert stats error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateAlert = async () => {
    try {
      await api.post('/alerts', newAlert);
      setCreateAlertOpen(false);
      setNewAlert({
        title: '',
        description: '',
        severity: 'medium',
        type: 'manual',
        pipeline: '',
        assignee: ''
      });
      setRefreshKey(prev => prev + 1);
    } catch (err) {
      console.error('Create alert error:', err);
    }
  };

  const handleExportAlerts = async () => {
    try {
      const response = await api.get('/alerts/export', { 
        responseType: 'blob' 
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `alerts_${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export error:', err);
    }
  };

  const handleRefresh = () => {
    loadAlertStats();
    setRefreshKey(prev => prev + 1);
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: theme.palette.error.main,
      high: theme.palette.warning.main,
      medium: theme.palette.info.main,
      low: theme.palette.success.main
    };
    return colors[severity] || theme.palette.grey[500];
  };

  const getSeverityIcon = (severity) => {
    const icons = {
      critical: ErrorIcon,
      high: WarningIcon,
      medium: InfoIcon,
      low: CheckCircleIcon
    };
    const IconComponent = icons[severity] || InfoIcon;
    return <IconComponent sx={{ color: getSeverityColor(severity) }} />;
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
                <NotificationsIcon sx={{ mr: 2, fontSize: 36 }} />
                Security Alerts
              </Typography>
              <Typography variant="subtitle1" color="text.secondary">
                Monitor and manage security alerts across your CI/CD pipelines
              </Typography>
            </Box>
            
            <Stack direction="row" spacing={1}>
              <Tooltip title="Export alerts">
                <IconButton onClick={handleExportAlerts}>
                  <DownloadIcon />
                </IconButton>
              </Tooltip>
              
              <Tooltip title="Alert settings">
                <IconButton onClick={() => setAlertsConfigOpen(true)}>
                  <SettingsIcon />
                </IconButton>
              </Tooltip>
              
              <Tooltip title="Refresh">
                <IconButton onClick={handleRefresh}>
                  <RefreshIcon />
                </IconButton>
              </Tooltip>
              
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => setCreateAlertOpen(true)}
              >
                Create Alert
              </Button>
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

        {/* Alert Statistics */}
        <motion.div variants={itemVariants}>
          <Grid container spacing={3} sx={{ mb: 4 }}>
            {/* Total Alerts */}
            <Grid item xs={12} sm={6} md={2.4}>
              <Card sx={{ 
                background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`
              }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4" sx={{ fontWeight: 600, mb: 1 }}>
                    {alertStats.total}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Alerts
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mt: 1 }}>
                    {alertStats.trend > 0 ? (
                      <TrendingUpIcon sx={{ color: 'error.main', fontSize: 16, mr: 0.5 }} />
                    ) : (
                      <TrendingDownIcon sx={{ color: 'success.main', fontSize: 16, mr: 0.5 }} />
                    )}
                    <Typography variant="caption">
                      {Math.abs(alertStats.trend)}% this week
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Critical Alerts */}
            <Grid item xs={12} sm={6} md={2.4}>
              <Card sx={{ 
                background: `linear-gradient(135deg, ${alpha(theme.palette.error.main, 0.1)} 0%, ${alpha(theme.palette.error.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`
              }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 1 }}>
                    {getSeverityIcon('critical')}
                    <Typography variant="h4" sx={{ fontWeight: 600, ml: 1 }}>
                      {alertStats.critical}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Critical
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            {/* High Alerts */}
            <Grid item xs={12} sm={6} md={2.4}>
              <Card sx={{ 
                background: `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.1)} 0%, ${alpha(theme.palette.warning.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.warning.main, 0.2)}`
              }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 1 }}>
                    {getSeverityIcon('high')}
                    <Typography variant="h4" sx={{ fontWeight: 600, ml: 1 }}>
                      {alertStats.high}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    High
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            {/* Medium Alerts */}
            <Grid item xs={12} sm={6} md={2.4}>
              <Card sx={{ 
                background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.1)} 0%, ${alpha(theme.palette.info.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`
              }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 1 }}>
                    {getSeverityIcon('medium')}
                    <Typography variant="h4" sx={{ fontWeight: 600, ml: 1 }}>
                      {alertStats.medium}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Medium
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            {/* Resolved Today */}
            <Grid item xs={12} sm={6} md={2.4}>
              <Card sx={{ 
                background: `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.1)} 0%, ${alpha(theme.palette.success.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.success.main, 0.2)}`
              }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 1 }}>
                    <CheckCircleIcon sx={{ color: 'success.main' }} />
                    <Typography variant="h4" sx={{ fontWeight: 600, ml: 1 }}>
                      {alertStats.resolved_today}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Resolved Today
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </motion.div>

        {/* Alerts List */}
        <motion.div variants={itemVariants}>
          <AlertList 
            key={refreshKey}
            showFilters={true}
            showPagination={true}
            limit={25}
          />
        </motion.div>

        {/* Floating Action Button for Quick Actions */}
        <AnimatePresence>
          {realTimeAlerts && (
            <motion.div
              initial={{ scale: 0, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0, opacity: 0 }}
              style={{
                position: 'fixed',
                bottom: 24,
                right: 24,
                zIndex: 1000
              }}
            >
              <Badge 
                badgeContent={realTimeAlerts.length} 
                color="error"
                max={99}
              >
                <Fab 
                  color="primary" 
                  onClick={() => setRefreshKey(prev => prev + 1)}
                  sx={{
                    animation: 'pulse 2s infinite'
                  }}
                >
                  <NotificationsIcon />
                </Fab>
              </Badge>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* Create Alert Dialog */}
      <Dialog 
        open={createAlertOpen} 
        onClose={() => setCreateAlertOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Create New Alert</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Alert Title"
              fullWidth
              value={newAlert.title}
              onChange={(e) => setNewAlert(prev => ({ ...prev, title: e.target.value }))}
              required
            />
            
            <TextField
              label="Description"
              fullWidth
              multiline
              rows={3}
              value={newAlert.description}
              onChange={(e) => setNewAlert(prev => ({ ...prev, description: e.target.value }))}
              required
            />
            
            <FormControl fullWidth>
              <InputLabel>Severity</InputLabel>
              <Select
                value={newAlert.severity}
                label="Severity"
                onChange={(e) => setNewAlert(prev => ({ ...prev, severity: e.target.value }))}
              >
                <MenuItem value="critical">Critical</MenuItem>
                <MenuItem value="high">High</MenuItem>
                <MenuItem value="medium">Medium</MenuItem>
                <MenuItem value="low">Low</MenuItem>
              </Select>
            </FormControl>
            
            <TextField
              label="Pipeline (Optional)"
              fullWidth
              value={newAlert.pipeline}
              onChange={(e) => setNewAlert(prev => ({ ...prev, pipeline: e.target.value }))}
            />
            
            <TextField
              label="Assignee (Optional)"
              fullWidth
              value={newAlert.assignee}
              onChange={(e) => setNewAlert(prev => ({ ...prev, assignee: e.target.value }))}
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateAlertOpen(false)}>Cancel</Button>
          <Button 
            variant="contained" 
            onClick={handleCreateAlert}
            disabled={!newAlert.title || !newAlert.description}
          >
            Create Alert
          </Button>
        </DialogActions>
      </Dialog>

      {/* Alert Configuration Dialog */}
      <Dialog 
        open={alertsConfigOpen} 
        onClose={() => setAlertsConfigOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Alert Configuration</DialogTitle>
        <DialogContent>
          <Typography variant="body1" paragraph>
            Configure alert rules, notification channels, and escalation policies.
          </Typography>
          
          <Stack spacing={2}>
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Notification Channels
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Configure email, Slack, and webhook notifications for different alert severities.
                </Typography>
                <Button size="small" sx={{ mt: 1 }}>
                  Configure Channels
                </Button>
              </CardContent>
            </Card>
            
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Alert Rules
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Define custom rules for automatic alert generation based on scan results.
                </Typography>
                <Button size="small" sx={{ mt: 1 }}>
                  Manage Rules
                </Button>
              </CardContent>
            </Card>
            
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Escalation Policies
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Set up escalation rules for unresolved critical and high-severity alerts.
                </Typography>
                <Button size="small" sx={{ mt: 1 }}>
                  Configure Escalation
                </Button>
              </CardContent>
            </Card>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAlertsConfigOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default Alerts;
