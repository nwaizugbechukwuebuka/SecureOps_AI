import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Grid,
  Card,
  CardContent,
  CardHeader,
  Button,
  IconButton,
  Switch,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Stack,
  Alert,
  Tooltip,
  Chip,
  Divider,
  useTheme,
  alpha,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControlLabel,
  RadioGroup,
  Radio,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Badge,
  Tab,
  Tabs,
<<<<<<< HEAD
=======
  TabPanel,
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3
  Snackbar
} from '@mui/material';
import {
  Settings as SettingsIcon,
  Save as SaveIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  Notifications as NotificationsIcon,
  IntegrationInstructions as IntegrationIcon,
  StorageOutlined as StorageIcon,
  Schedule as ScheduleIcon,
  AccountCircle as AccountCircleIcon,
  VpnKey as VpnKeyIcon,
  Backup as BackupIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  Add as AddIcon,
  ExpandMore as ExpandMoreIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  CloudUpload as CloudUploadIcon,
  GitHub as GitHubIcon,
  Email as EmailIcon,
  Webhook as WebhookIcon
} from '@mui/icons-material';
import { motion } from 'framer-motion';
import { api } from '../services/api';

<<<<<<< HEAD

=======
const TabPanel = ({ children, value, index, ...other }) => (
  <div
    role="tabpanel"
    hidden={value !== index}
    id={`settings-tabpanel-${index}`}
    aria-labelledby={`settings-tab-${index}`}
    {...other}
  >
    {value === index && (
      <Box sx={{ p: 3 }}>
        {children}
      </Box>
    )}
  </div>
);
>>>>>>> 7c10f27ecb7c8b1a33ad81e0ccc85bf68459bdc3

const Settings = () => {
  const theme = useTheme();
  
  const [activeTab, setActiveTab] = useState(0);
  const [settings, setSettings] = useState({
    security: {
      mfa_enabled: false,
      session_timeout: 30,
      password_policy: 'strong',
      audit_logging: true,
      encryption: true
    },
    notifications: {
      email_enabled: true,
      webhook_enabled: false,
      slack_enabled: false,
      severity_threshold: 'medium',
      frequency: 'immediate',
      email: '',
      webhook_url: '',
      slack_webhook: ''
    },
    integrations: {
      github: { enabled: false, token: '', webhook_secret: '' },
      gitlab: { enabled: false, token: '', webhook_secret: '' },
      jenkins: { enabled: false, url: '', username: '', token: '' },
      azure_devops: { enabled: false, organization: '', token: '' }
    },
    scanning: {
      auto_scan: true,
      scan_schedule: 'daily',
      scan_timeout: 60,
      max_concurrent_scans: 3,
      retention_days: 90,
      enabled_scanners: ['trivy', 'safety', 'bandit']
    },
    system: {
      log_level: 'info',
      backup_enabled: true,
      backup_schedule: 'weekly',
      maintenance_window: '02:00',
      data_retention: 365
    }
  });
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [testDialog, setTestDialog] = useState({ open: false, type: '', loading: false });

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await api.get('/settings');
      setSettings(prev => ({ ...prev, ...response.data }));
    } catch (err) {
      setError('Failed to load settings');
      console.error('Settings error:', err);
    } finally {
      setLoading(false);
    }
  };

  const saveSettings = async () => {
    try {
      setSaving(true);
      setError(null);
      
      await api.put('/settings', settings);
      setSuccess(true);
    } catch (err) {
      setError('Failed to save settings');
      console.error('Save error:', err);
    } finally {
      setSaving(false);
    }
  };

  const testConnection = async (type) => {
    setTestDialog({ open: true, type, loading: true });
    
    try {
      await api.post(`/settings/test/${type}`, settings[type]);
      setTestDialog({ open: true, type, loading: false, success: true });
    } catch (err) {
      setTestDialog({ open: true, type, loading: false, success: false, error: err.response?.data?.message || 'Connection failed' });
    }
  };

  const updateSetting = (category, key, value) => {
    setSettings(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: value
      }
    }));
  };

  const updateIntegrationSetting = (platform, key, value) => {
    setSettings(prev => ({
      ...prev,
      integrations: {
        ...prev.integrations,
        [platform]: {
          ...prev.integrations[platform],
          [key]: value
        }
      }
    }));
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
                <SettingsIcon sx={{ mr: 2, fontSize: 36 }} />
                Settings
              </Typography>
              <Typography variant="subtitle1" color="text.secondary">
                Configure system settings, integrations, and preferences
              </Typography>
            </Box>
            
            <Stack direction="row" spacing={1}>
              <Button
                variant="outlined"
                startIcon={<RefreshIcon />}
                onClick={loadSettings}
                disabled={loading}
              >
                Refresh
              </Button>
              
              <Button
                variant="contained"
                startIcon={<SaveIcon />}
                onClick={saveSettings}
                disabled={saving}
              >
                Save Changes
              </Button>
            </Stack>
          </Box>
        </motion.div>

        {/* Error/Success Alerts */}
        {error && (
          <motion.div variants={itemVariants}>
            <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          </motion.div>
        )}

        {/* Settings Tabs */}
        <motion.div variants={itemVariants}>
          <Card>
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)}>
                <Tab icon={<SecurityIcon />} label="Security" />
                <Tab icon={<NotificationsIcon />} label="Notifications" />
                <Tab icon={<IntegrationIcon />} label="Integrations" />
                <Tab icon={<ScheduleIcon />} label="Scanning" />
                <Tab icon={<StorageIcon />} label="System" />
              </Tabs>
            </Box>

            {/* Security Settings */}
            <TabPanel value={activeTab} index={0}>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardHeader title="Authentication" />
                    <CardContent>
                      <Stack spacing={3}>
                        <FormControlLabel
                          control={
                            <Switch
                              checked={settings.security.mfa_enabled}
                              onChange={(e) => updateSetting('security', 'mfa_enabled', e.target.checked)}
                            />
                          }
                          label="Multi-Factor Authentication"
                        />
                        
                        <FormControl fullWidth>
                          <InputLabel>Session Timeout (minutes)</InputLabel>
                          <Select
                            value={settings.security.session_timeout}
                            label="Session Timeout (minutes)"
                            onChange={(e) => updateSetting('security', 'session_timeout', e.target.value)}
                          >
                            <MenuItem value={15}>15 minutes</MenuItem>
                            <MenuItem value={30}>30 minutes</MenuItem>
                            <MenuItem value={60}>1 hour</MenuItem>
                            <MenuItem value={240}>4 hours</MenuItem>
                            <MenuItem value={480}>8 hours</MenuItem>
                          </Select>
                        </FormControl>
                        
                        <FormControl fullWidth>
                          <InputLabel>Password Policy</InputLabel>
                          <Select
                            value={settings.security.password_policy}
                            label="Password Policy"
                            onChange={(e) => updateSetting('security', 'password_policy', e.target.value)}
                          >
                            <MenuItem value="basic">Basic (8+ characters)</MenuItem>
                            <MenuItem value="strong">Strong (8+ chars, mixed case, numbers)</MenuItem>
                            <MenuItem value="complex">Complex (12+ chars, special chars)</MenuItem>
                          </Select>
                        </FormControl>
                      </Stack>
                    </CardContent>
                  </Card>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardHeader title="Audit & Compliance" />
                    <CardContent>
                      <Stack spacing={3}>
                        <FormControlLabel
                          control={
                            <Switch
                              checked={settings.security.audit_logging}
                              onChange={(e) => updateSetting('security', 'audit_logging', e.target.checked)}
                            />
                          }
                          label="Audit Logging"
                        />
                        
                        <FormControlLabel
                          control={
                            <Switch
                              checked={settings.security.encryption}
                              onChange={(e) => updateSetting('security', 'encryption', e.target.checked)}
                            />
                          }
                          label="Data Encryption at Rest"
                        />
                        
                        <Box>
                          <Typography variant="body2" color="text.secondary" paragraph>
                            Enable comprehensive audit logging and data encryption for enhanced security compliance.
                          </Typography>
                        </Box>
                      </Stack>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </TabPanel>

            {/* Notifications Settings */}
            <TabPanel value={activeTab} index={1}>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardHeader title="Email Notifications" />
                    <CardContent>
                      <Stack spacing={3}>
                        <FormControlLabel
                          control={
                            <Switch
                              checked={settings.notifications.email_enabled}
                              onChange={(e) => updateSetting('notifications', 'email_enabled', e.target.checked)}
                            />
                          }
                          label="Enable Email Notifications"
                        />
                        
                        <TextField
                          fullWidth
                          label="Email Address"
                          value={settings.notifications.email}
                          onChange={(e) => updateSetting('notifications', 'email', e.target.value)}
                          disabled={!settings.notifications.email_enabled}
                        />
                        
                        <FormControl fullWidth>
                          <InputLabel>Severity Threshold</InputLabel>
                          <Select
                            value={settings.notifications.severity_threshold}
                            label="Severity Threshold"
                            onChange={(e) => updateSetting('notifications', 'severity_threshold', e.target.value)}
                          >
                            <MenuItem value="low">Low and above</MenuItem>
                            <MenuItem value="medium">Medium and above</MenuItem>
                            <MenuItem value="high">High only</MenuItem>
                            <MenuItem value="critical">Critical only</MenuItem>
                          </Select>
                        </FormControl>
                      </Stack>
                    </CardContent>
                  </Card>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardHeader title="Webhook & Integration Notifications" />
                    <CardContent>
                      <Stack spacing={3}>
                        <FormControlLabel
                          control={
                            <Switch
                              checked={settings.notifications.webhook_enabled}
                              onChange={(e) => updateSetting('notifications', 'webhook_enabled', e.target.checked)}
                            />
                          }
                          label="Webhook Notifications"
                        />
                        
                        <TextField
                          fullWidth
                          label="Webhook URL"
                          value={settings.notifications.webhook_url}
                          onChange={(e) => updateSetting('notifications', 'webhook_url', e.target.value)}
                          disabled={!settings.notifications.webhook_enabled}
                        />
                        
                        <FormControlLabel
                          control={
                            <Switch
                              checked={settings.notifications.slack_enabled}
                              onChange={(e) => updateSetting('notifications', 'slack_enabled', e.target.checked)}
                            />
                          }
                          label="Slack Notifications"
                        />
                        
                        <TextField
                          fullWidth
                          label="Slack Webhook URL"
                          value={settings.notifications.slack_webhook}
                          onChange={(e) => updateSetting('notifications', 'slack_webhook', e.target.value)}
                          disabled={!settings.notifications.slack_enabled}
                        />
                      </Stack>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </TabPanel>

            {/* Integrations Settings */}
            <TabPanel value={activeTab} index={2}>
              <Grid container spacing={3}>
                {Object.entries(settings.integrations).map(([platform, config]) => (
                  <Grid item xs={12} md={6} key={platform}>
                    <Card variant="outlined">
                      <CardHeader 
                        title={
                          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                              <GitHubIcon sx={{ mr: 1 }} />
                              {platform.replace('_', ' ').toUpperCase()}
                            </Box>
                            <FormControlLabel
                              control={
                                <Switch
                                  checked={config.enabled}
                                  onChange={(e) => updateIntegrationSetting(platform, 'enabled', e.target.checked)}
                                />
                              }
                              label=""
                            />
                          </Box>
                        }
                      />
                      <CardContent>
                        <Stack spacing={2}>
                          {platform === 'github' && (
                            <>
                              <TextField
                                fullWidth
                                label="GitHub Token"
                                type="password"
                                value={config.token}
                                onChange={(e) => updateIntegrationSetting(platform, 'token', e.target.value)}
                                disabled={!config.enabled}
                              />
                              <TextField
                                fullWidth
                                label="Webhook Secret"
                                type="password"
                                value={config.webhook_secret}
                                onChange={(e) => updateIntegrationSetting(platform, 'webhook_secret', e.target.value)}
                                disabled={!config.enabled}
                              />
                            </>
                          )}
                          
                          {platform === 'jenkins' && (
                            <>
                              <TextField
                                fullWidth
                                label="Jenkins URL"
                                value={config.url}
                                onChange={(e) => updateIntegrationSetting(platform, 'url', e.target.value)}
                                disabled={!config.enabled}
                              />
                              <TextField
                                fullWidth
                                label="Username"
                                value={config.username}
                                onChange={(e) => updateIntegrationSetting(platform, 'username', e.target.value)}
                                disabled={!config.enabled}
                              />
                              <TextField
                                fullWidth
                                label="API Token"
                                type="password"
                                value={config.token}
                                onChange={(e) => updateIntegrationSetting(platform, 'token', e.target.value)}
                                disabled={!config.enabled}
                              />
                            </>
                          )}
                          
                          <Button
                            variant="outlined"
                            size="small"
                            onClick={() => testConnection(platform)}
                            disabled={!config.enabled}
                          >
                            Test Connection
                          </Button>
                        </Stack>
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </TabPanel>

            {/* Scanning Settings */}
            <TabPanel value={activeTab} index={3}>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardHeader title="Scan Configuration" />
                    <CardContent>
                      <Stack spacing={3}>
                        <FormControlLabel
                          control={
                            <Switch
                              checked={settings.scanning.auto_scan}
                              onChange={(e) => updateSetting('scanning', 'auto_scan', e.target.checked)}
                            />
                          }
                          label="Automatic Scanning"
                        />
                        
                        <FormControl fullWidth>
                          <InputLabel>Scan Schedule</InputLabel>
                          <Select
                            value={settings.scanning.scan_schedule}
                            label="Scan Schedule"
                            onChange={(e) => updateSetting('scanning', 'scan_schedule', e.target.value)}
                          >
                            <MenuItem value="hourly">Hourly</MenuItem>
                            <MenuItem value="daily">Daily</MenuItem>
                            <MenuItem value="weekly">Weekly</MenuItem>
                            <MenuItem value="monthly">Monthly</MenuItem>
                          </Select>
                        </FormControl>
                        
                        <TextField
                          fullWidth
                          type="number"
                          label="Scan Timeout (minutes)"
                          value={settings.scanning.scan_timeout}
                          onChange={(e) => updateSetting('scanning', 'scan_timeout', parseInt(e.target.value))}
                        />
                        
                        <TextField
                          fullWidth
                          type="number"
                          label="Max Concurrent Scans"
                          value={settings.scanning.max_concurrent_scans}
                          onChange={(e) => updateSetting('scanning', 'max_concurrent_scans', parseInt(e.target.value))}
                        />
                      </Stack>
                    </CardContent>
                  </Card>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardHeader title="Scanner Configuration" />
                    <CardContent>
                      <Typography variant="body2" color="text.secondary" paragraph>
                        Select which security scanners to enable for your pipelines.
                      </Typography>
                      
                      <Stack spacing={2}>
                        {['trivy', 'safety', 'bandit', 'semgrep', 'codeql'].map((scanner) => (
                          <FormControlLabel
                            key={scanner}
                            control={
                              <Switch
                                checked={settings.scanning.enabled_scanners.includes(scanner)}
                                onChange={(e) => {
                                  const scanners = settings.scanning.enabled_scanners;
                                  if (e.target.checked) {
                                    updateSetting('scanning', 'enabled_scanners', [...scanners, scanner]);
                                  } else {
                                    updateSetting('scanning', 'enabled_scanners', scanners.filter(s => s !== scanner));
                                  }
                                }}
                              />
                            }
                            label={
                              <Box>
                                <Typography variant="body1">
                                  {scanner.charAt(0).toUpperCase() + scanner.slice(1)}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {scanner === 'trivy' && 'Container vulnerability scanner'}
                                  {scanner === 'safety' && 'Python dependency scanner'}
                                  {scanner === 'bandit' && 'Python security linter'}
                                  {scanner === 'semgrep' && 'Static analysis tool'}
                                  {scanner === 'codeql' && 'Semantic code analysis'}
                                </Typography>
                              </Box>
                            }
                          />
                        ))}
                      </Stack>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </TabPanel>

            {/* System Settings */}
            <TabPanel value={activeTab} index={4}>
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardHeader title="System Configuration" />
                    <CardContent>
                      <Stack spacing={3}>
                        <FormControl fullWidth>
                          <InputLabel>Log Level</InputLabel>
                          <Select
                            value={settings.system.log_level}
                            label="Log Level"
                            onChange={(e) => updateSetting('system', 'log_level', e.target.value)}
                          >
                            <MenuItem value="debug">Debug</MenuItem>
                            <MenuItem value="info">Info</MenuItem>
                            <MenuItem value="warning">Warning</MenuItem>
                            <MenuItem value="error">Error</MenuItem>
                          </Select>
                        </FormControl>
                        
                        <TextField
                          fullWidth
                          label="Maintenance Window"
                          value={settings.system.maintenance_window}
                          onChange={(e) => updateSetting('system', 'maintenance_window', e.target.value)}
                          placeholder="HH:MM"
                        />
                        
                        <TextField
                          fullWidth
                          type="number"
                          label="Data Retention (days)"
                          value={settings.system.data_retention}
                          onChange={(e) => updateSetting('system', 'data_retention', parseInt(e.target.value))}
                        />
                      </Stack>
                    </CardContent>
                  </Card>
                </Grid>
                
                <Grid item xs={12} md={6}>
                  <Card variant="outlined">
                    <CardHeader title="Backup & Recovery" />
                    <CardContent>
                      <Stack spacing={3}>
                        <FormControlLabel
                          control={
                            <Switch
                              checked={settings.system.backup_enabled}
                              onChange={(e) => updateSetting('system', 'backup_enabled', e.target.checked)}
                            />
                          }
                          label="Automatic Backups"
                        />
                        
                        <FormControl fullWidth>
                          <InputLabel>Backup Schedule</InputLabel>
                          <Select
                            value={settings.system.backup_schedule}
                            label="Backup Schedule"
                            onChange={(e) => updateSetting('system', 'backup_schedule', e.target.value)}
                            disabled={!settings.system.backup_enabled}
                          >
                            <MenuItem value="daily">Daily</MenuItem>
                            <MenuItem value="weekly">Weekly</MenuItem>
                            <MenuItem value="monthly">Monthly</MenuItem>
                          </Select>
                        </FormControl>
                        
                        <Button
                          variant="outlined"
                          startIcon={<BackupIcon />}
                          fullWidth
                        >
                          Create Manual Backup
                        </Button>
                      </Stack>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            </TabPanel>
          </Card>
        </motion.div>
      </motion.div>

      {/* Test Connection Dialog */}
      <Dialog open={testDialog.open} onClose={() => setTestDialog({ open: false, type: '', loading: false })}>
        <DialogTitle>Test Connection - {testDialog.type}</DialogTitle>
        <DialogContent>
          {testDialog.loading ? (
            <Box sx={{ display: 'flex', alignItems: 'center', p: 2 }}>
              <Typography>Testing connection...</Typography>
            </Box>
          ) : (
            <Box sx={{ display: 'flex', alignItems: 'center', p: 2 }}>
              {testDialog.success ? (
                <>
                  <CheckCircleIcon sx={{ color: 'success.main', mr: 1 }} />
                  <Typography>Connection successful!</Typography>
                </>
              ) : (
                <>
                  <ErrorIcon sx={{ color: 'error.main', mr: 1 }} />
                  <Typography>{testDialog.error || 'Connection failed'}</Typography>
                </>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTestDialog({ open: false, type: '', loading: false })}>
            Close
          </Button>
        </DialogActions>
      </Dialog>

      {/* Success Snackbar */}
      <Snackbar
        open={success}
        autoHideDuration={6000}
        onClose={() => setSuccess(false)}
      >
        <Alert onClose={() => setSuccess(false)} severity="success">
          Settings saved successfully!
        </Alert>
      </Snackbar>
    </Container>
  );
};

export default Settings;
