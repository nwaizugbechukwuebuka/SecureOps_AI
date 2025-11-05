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
  TextField,
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
  Fab,
  Tabs,
  Tab,
  Paper
} from '@mui/material';
import {
  Add as AddIcon,
  Refresh as RefreshIcon,
  Build as BuildIcon,
  PlayArrow as PlayArrowIcon,
  Stop as StopIcon,
  Settings as SettingsIcon,
  Timeline as TimelineIcon,
  Security as SecurityIcon,
  FilterList as FilterListIcon,
  ViewModule as ViewModuleIcon,
  ViewList as ViewListIcon
} from '@mui/icons-material';
import { motion, AnimatePresence } from 'framer-motion';
import PipelineCard from '../components/PipelineCard';
import { api } from '../services/api';
import { useWebSocket } from '../services/websocket';

const Pipelines = () => {
  const theme = useTheme();
  const { realTimePipelines, pipelineMetrics } = useWebSocket();
  
  const [pipelines, setPipelines] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedTab, setSelectedTab] = useState(0);
  const [viewMode, setViewMode] = useState('grid'); // 'grid' or 'list'
  const [filterPlatform, setFilterPlatform] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [addPipelineOpen, setAddPipelineOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  
  const [pipelineStats, setPipelineStats] = useState({
    total: 0,
    running: 0,
    success: 0,
    failed: 0,
    pending: 0
  });

  // New pipeline form state
  const [newPipeline, setNewPipeline] = useState({
    name: '',
    repository: '',
    branch: 'main',
    platform: 'github',
    webhook_url: '',
    token: ''
  });

  const platforms = [
    { value: 'github', label: 'GitHub Actions', icon: '🐙' },
    { value: 'gitlab', label: 'GitLab CI', icon: '🦊' },
    { value: 'jenkins', label: 'Jenkins', icon: '👨‍💼' },
    { value: 'azure', label: 'Azure DevOps', icon: '☁️' },
    { value: 'circleci', label: 'CircleCI', icon: '🔄' },
    { value: 'travis', label: 'Travis CI', icon: '🚀' }
  ];

  useEffect(() => {
    loadPipelines();
    loadPipelineStats();
  }, [filterPlatform, filterStatus]);

  useEffect(() => {
    if (realTimePipelines) {
      setPipelines(prev => {
        const updated = [...prev];
        realTimePipelines.forEach(updatedPipeline => {
          const index = updated.findIndex(p => p.id === updatedPipeline.id);
          if (index >= 0) {
            updated[index] = updatedPipeline;
          } else {
            updated.unshift(updatedPipeline);
          }
        });
        return updated;
      });
    }
  }, [realTimePipelines]);

  useEffect(() => {
    if (pipelineMetrics) {
      setPipelineStats(prev => ({
        ...prev,
        ...pipelineMetrics
      }));
    }
  }, [pipelineMetrics]);

  const loadPipelines = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const params = {};
      if (filterPlatform !== 'all') params.platform = filterPlatform;
      if (filterStatus !== 'all') params.status = filterStatus;
      
      const response = await api.get('/pipelines', { params });
      setPipelines(response.data.pipelines || []);
    } catch (err) {
      setError('Failed to load pipelines');
      console.error('Pipelines error:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadPipelineStats = async () => {
    try {
      const response = await api.get('/pipelines/stats');
      setPipelineStats(response.data);
    } catch (err) {
      console.error('Pipeline stats error:', err);
    }
  };

  const handleCreatePipeline = async () => {
    try {
      await api.post('/pipelines', newPipeline);
      setAddPipelineOpen(false);
      setNewPipeline({
        name: '',
        repository: '',
        branch: 'main',
        platform: 'github',
        webhook_url: '',
        token: ''
      });
      loadPipelines();
    } catch (err) {
      console.error('Create pipeline error:', err);
    }
  };

  const handlePipelineAction = async (pipelineId, action) => {
    try {
      await api.post(`/pipelines/${pipelineId}/${action}`);
      loadPipelines();
    } catch (err) {
      console.error(`Pipeline ${action} error:`, err);
    }
  };

  const handleBulkAction = async (action) => {
    const pipelineIds = getFilteredPipelines()
      .filter(p => p.status === 'running' || action === 'scan')
      .map(p => p.id);
    
    try {
      await api.post('/pipelines/bulk-action', {
        pipeline_ids: pipelineIds,
        action
      });
      loadPipelines();
    } catch (err) {
      console.error(`Bulk ${action} error:`, err);
    }
  };

  const getFilteredPipelines = () => {
    let filtered = pipelines;
    
    if (selectedTab === 1) filtered = filtered.filter(p => p.status === 'running');
    if (selectedTab === 2) filtered = filtered.filter(p => p.status === 'failed');
    if (selectedTab === 3) filtered = filtered.filter(p => p.status === 'success');
    
    return filtered;
  };

  const getStatusColor = (status) => {
    const colors = {
      running: theme.palette.info.main,
      success: theme.palette.success.main,
      failed: theme.palette.error.main,
      pending: theme.palette.warning.main,
      cancelled: theme.palette.grey[500]
    };
    return colors[status] || theme.palette.grey[500];
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

  const filteredPipelines = getFilteredPipelines();

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
                <BuildIcon sx={{ mr: 2, fontSize: 36 }} />
                CI/CD Pipelines
              </Typography>
              <Typography variant="subtitle1" color="text.secondary">
                Monitor and manage your DevSecOps pipelines across platforms
              </Typography>
            </Box>
            
            <Stack direction="row" spacing={1}>
              <Tooltip title="View mode">
                <IconButton onClick={() => setViewMode(viewMode === 'grid' ? 'list' : 'grid')}>
                  {viewMode === 'grid' ? <ViewListIcon /> : <ViewModuleIcon />}
                </IconButton>
              </Tooltip>
              
              <Tooltip title="Pipeline settings">
                <IconButton onClick={() => setSettingsOpen(true)}>
                  <SettingsIcon />
                </IconButton>
              </Tooltip>
              
              <Tooltip title="Refresh">
                <IconButton onClick={loadPipelines}>
                  <RefreshIcon />
                </IconButton>
              </Tooltip>
              
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => setAddPipelineOpen(true)}
              >
                Add Pipeline
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

        {/* Pipeline Statistics */}
        <motion.div variants={itemVariants}>
          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} sm={6} md={2.4}>
              <Card sx={{ 
                background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`
              }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4" sx={{ fontWeight: 600, mb: 1 }}>
                    {pipelineStats.total}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Total Pipelines
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6} md={2.4}>
              <Card sx={{ 
                background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.1)} 0%, ${alpha(theme.palette.info.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`
              }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4" sx={{ fontWeight: 600, mb: 1, color: 'info.main' }}>
                    {pipelineStats.running}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Running
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6} md={2.4}>
              <Card sx={{ 
                background: `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.1)} 0%, ${alpha(theme.palette.success.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.success.main, 0.2)}`
              }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4" sx={{ fontWeight: 600, mb: 1, color: 'success.main' }}>
                    {pipelineStats.success}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Successful
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6} md={2.4}>
              <Card sx={{ 
                background: `linear-gradient(135deg, ${alpha(theme.palette.error.main, 0.1)} 0%, ${alpha(theme.palette.error.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`
              }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4" sx={{ fontWeight: 600, mb: 1, color: 'error.main' }}>
                    {pipelineStats.failed}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Failed
                  </Typography>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} sm={6} md={2.4}>
              <Card sx={{ 
                background: `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.1)} 0%, ${alpha(theme.palette.warning.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.warning.main, 0.2)}`
              }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4" sx={{ fontWeight: 600, mb: 1, color: 'warning.main' }}>
                    {pipelineStats.pending}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Pending
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </motion.div>

        {/* Filters and Tabs */}
        <motion.div variants={itemVariants}>
          <Paper sx={{ mb: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', p: 2 }}>
              <Tabs 
                value={selectedTab} 
                onChange={(e, newValue) => setSelectedTab(newValue)}
              >
                <Tab label={`All (${pipelines.length})`} />
                <Tab label={`Running (${pipelines.filter(p => p.status === 'running').length})`} />
                <Tab label={`Failed (${pipelines.filter(p => p.status === 'failed').length})`} />
                <Tab label={`Success (${pipelines.filter(p => p.status === 'success').length})`} />
              </Tabs>
              
              <Stack direction="row" spacing={2}>
                <FormControl size="small" sx={{ minWidth: 120 }}>
                  <InputLabel>Platform</InputLabel>
                  <Select
                    value={filterPlatform}
                    label="Platform"
                    onChange={(e) => setFilterPlatform(e.target.value)}
                  >
                    <MenuItem value="all">All Platforms</MenuItem>
                    {platforms.map(platform => (
                      <MenuItem key={platform.value} value={platform.value}>
                        {platform.icon} {platform.label}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>

                <FormControl size="small" sx={{ minWidth: 120 }}>
                  <InputLabel>Status</InputLabel>
                  <Select
                    value={filterStatus}
                    label="Status"
                    onChange={(e) => setFilterStatus(e.target.value)}
                  >
                    <MenuItem value="all">All Status</MenuItem>
                    <MenuItem value="running">Running</MenuItem>
                    <MenuItem value="success">Success</MenuItem>
                    <MenuItem value="failed">Failed</MenuItem>
                    <MenuItem value="pending">Pending</MenuItem>
                  </Select>
                </FormControl>
              </Stack>
            </Box>
          </Paper>
        </motion.div>

        {/* Bulk Actions */}
        {filteredPipelines.length > 0 && (
          <motion.div variants={itemVariants}>
            <Box sx={{ mb: 3 }}>
              <Stack direction="row" spacing={1}>
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<SecurityIcon />}
                  onClick={() => handleBulkAction('scan')}
                >
                  Scan All
                </Button>
                
                {filteredPipelines.some(p => p.status === 'running') && (
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<StopIcon />}
                    onClick={() => handleBulkAction('stop')}
                    color="error"
                  >
                    Stop Running
                  </Button>
                )}
                
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<PlayArrowIcon />}
                  onClick={() => handleBulkAction('restart')}
                  color="success"
                >
                  Restart Failed
                </Button>
              </Stack>
            </Box>
          </motion.div>
        )}

        {/* Pipelines Grid/List */}
        <motion.div variants={itemVariants}>
          {loading ? (
            <Grid container spacing={3}>
              {[...Array(6)].map((_, index) => (
                <Grid item xs={12} sm={6} md={4} key={index}>
                  <Card>
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                        <Box sx={{ width: 40, height: 40, bgcolor: 'grey.200', borderRadius: 1, mr: 2 }} />
                        <Box sx={{ flexGrow: 1 }}>
                          <Box sx={{ height: 20, bgcolor: 'grey.200', borderRadius: 1, mb: 1 }} />
                          <Box sx={{ height: 16, bgcolor: 'grey.200', borderRadius: 1, width: '60%' }} />
                        </Box>
                      </Box>
                      <Box sx={{ height: 16, bgcolor: 'grey.200', borderRadius: 1, mb: 1 }} />
                      <Box sx={{ height: 16, bgcolor: 'grey.200', borderRadius: 1, width: '40%' }} />
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          ) : filteredPipelines.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 8 }}>
              <BuildIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
              <Typography variant="h6" color="text.secondary" gutterBottom>
                No pipelines found
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                {selectedTab === 0 
                  ? "Add your first pipeline to start monitoring your CI/CD security"
                  : "No pipelines match the current filter criteria"
                }
              </Typography>
              {selectedTab === 0 && (
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={() => setAddPipelineOpen(true)}
                >
                  Add First Pipeline
                </Button>
              )}
            </Box>
          ) : (
            <Grid container spacing={3}>
              <AnimatePresence>
                {filteredPipelines.map((pipeline, index) => (
                  <Grid item xs={12} sm={6} md={viewMode === 'grid' ? 4 : 12} key={pipeline.id}>
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -20 }}
                      transition={{ duration: 0.3, delay: index * 0.05 }}
                    >
                      <PipelineCard 
                        pipeline={pipeline}
                        onPipelineAction={handlePipelineAction}
                        compact={viewMode === 'list'}
                      />
                    </motion.div>
                  </Grid>
                ))}
              </AnimatePresence>
            </Grid>
          )}
        </motion.div>

        {/* Floating Action Button */}
        <Fab
          color="primary"
          onClick={() => setAddPipelineOpen(true)}
          sx={{
            position: 'fixed',
            bottom: 24,
            right: 24
          }}
        >
          <AddIcon />
        </Fab>
      </motion.div>

      {/* Add Pipeline Dialog */}
      <Dialog 
        open={addPipelineOpen} 
        onClose={() => setAddPipelineOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Add New Pipeline</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Pipeline Name"
              fullWidth
              value={newPipeline.name}
              onChange={(e) => setNewPipeline(prev => ({ ...prev, name: e.target.value }))}
              required
            />
            
            <TextField
              label="Repository URL"
              fullWidth
              value={newPipeline.repository}
              onChange={(e) => setNewPipeline(prev => ({ ...prev, repository: e.target.value }))}
              required
              placeholder="https://github.com/user/repo"
            />
            
            <TextField
              label="Branch"
              fullWidth
              value={newPipeline.branch}
              onChange={(e) => setNewPipeline(prev => ({ ...prev, branch: e.target.value }))}
            />
            
            <FormControl fullWidth>
              <InputLabel>Platform</InputLabel>
              <Select
                value={newPipeline.platform}
                label="Platform"
                onChange={(e) => setNewPipeline(prev => ({ ...prev, platform: e.target.value }))}
              >
                {platforms.map(platform => (
                  <MenuItem key={platform.value} value={platform.value}>
                    {platform.icon} {platform.label}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            
            <TextField
              label="Webhook URL (Optional)"
              fullWidth
              value={newPipeline.webhook_url}
              onChange={(e) => setNewPipeline(prev => ({ ...prev, webhook_url: e.target.value }))}
              placeholder="https://api.secureops.local/webhooks/pipeline"
            />
            
            <TextField
              label="Access Token"
              fullWidth
              type="password"
              value={newPipeline.token}
              onChange={(e) => setNewPipeline(prev => ({ ...prev, token: e.target.value }))}
              required
              helperText="Required for API access to your CI/CD platform"
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddPipelineOpen(false)}>Cancel</Button>
          <Button 
            variant="contained" 
            onClick={handleCreatePipeline}
            disabled={!newPipeline.name || !newPipeline.repository || !newPipeline.token}
          >
            Add Pipeline
          </Button>
        </DialogActions>
      </Dialog>

      {/* Settings Dialog */}
      <Dialog 
        open={settingsOpen} 
        onClose={() => setSettingsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Pipeline Settings</DialogTitle>
        <DialogContent>
          <Typography variant="body1" paragraph>
            Configure global pipeline settings and integrations.
          </Typography>
          
          <Stack spacing={2}>
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Platform Integrations
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Configure API tokens and webhook endpoints for your CI/CD platforms.
                </Typography>
                <Button size="small" sx={{ mt: 1 }}>
                  Manage Integrations
                </Button>
              </CardContent>
            </Card>
            
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Security Scanners
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Configure security scanning tools and their execution settings.
                </Typography>
                <Button size="small" sx={{ mt: 1 }}>
                  Configure Scanners
                </Button>
              </CardContent>
            </Card>
            
            <Card variant="outlined">
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Notification Rules
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Set up notifications for pipeline events and security findings.
                </Typography>
                <Button size="small" sx={{ mt: 1 }}>
                  Configure Notifications
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

export default Pipelines;
