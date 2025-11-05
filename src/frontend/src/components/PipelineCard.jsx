import React, { useState } from 'react';
import {
  Card,
  CardContent,
  CardActions,
  Typography,
  Box,
  Chip,
  IconButton,
  Button,
  LinearProgress,
  Tooltip,
  Avatar,
  Stack,
  Divider,
  Menu,
  MenuItem,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  useTheme,
  alpha
} from '@mui/material';
import {
  PlayArrow as PlayArrowIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  MoreVert as MoreVertIcon,
  Schedule as ScheduleIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Pause as PauseIcon,
  History as HistoryIcon,
  Build as BuildIcon,
  Security as SecurityIcon,
  BugReport as BugReportIcon,
  Assignment as AssignmentIcon,
  Person as PersonIcon,
  Link as LinkIcon,
  OpenInNew as OpenInNewIcon,
  Timeline as TimelineIcon
} from '@mui/icons-material';
import { formatDistanceToNow, parseISO, format } from 'date-fns';
import { api } from '../services/api';

const PipelineCard = ({ 
  pipeline, 
  onPipelineClick, 
  onPipelineAction,
  showActions = true,
  compact = false 
}) => {
  const theme = useTheme();
  const [anchorEl, setAnchorEl] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [actionLoading, setActionLoading] = useState('');

  const statusConfig = {
    running: { 
      color: 'info', 
      icon: PlayArrowIcon, 
      label: 'Running',
      bgColor: alpha(theme.palette.info.main, 0.1),
      borderColor: theme.palette.info.main
    },
    success: { 
      color: 'success', 
      icon: CheckCircleIcon, 
      label: 'Success',
      bgColor: alpha(theme.palette.success.main, 0.1),
      borderColor: theme.palette.success.main
    },
    failed: { 
      color: 'error', 
      icon: ErrorIcon, 
      label: 'Failed',
      bgColor: alpha(theme.palette.error.main, 0.1),
      borderColor: theme.palette.error.main
    },
    pending: { 
      color: 'warning', 
      icon: ScheduleIcon, 
      label: 'Pending',
      bgColor: alpha(theme.palette.warning.main, 0.1),
      borderColor: theme.palette.warning.main
    },
    cancelled: { 
      color: 'default', 
      icon: StopIcon, 
      label: 'Cancelled',
      bgColor: alpha(theme.palette.grey[500], 0.1),
      borderColor: theme.palette.grey[500]
    },
    paused: { 
      color: 'warning', 
      icon: PauseIcon, 
      label: 'Paused',
      bgColor: alpha(theme.palette.warning.main, 0.1),
      borderColor: theme.palette.warning.main
    }
  };

  const platformConfig = {
    github: { name: 'GitHub Actions', color: '#24292e', icon: '🐙' },
    gitlab: { name: 'GitLab CI', color: '#fc6d26', icon: '🦊' },
    jenkins: { name: 'Jenkins', color: '#d33833', icon: '👨‍💼' },
    azure: { name: 'Azure DevOps', color: '#0078d4', icon: '☁️' },
    circleci: { name: 'CircleCI', color: '#343434', icon: '🔄' },
    travis: { name: 'Travis CI', color: '#3eaaaf', icon: '🚀' }
  };

  const handleMenuOpen = (event) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handlePipelineAction = async (action) => {
    setActionLoading(action);
    try {
      await api.post(`/pipelines/${pipeline.id}/${action}`);
      if (onPipelineAction) {
        onPipelineAction(pipeline.id, action);
      }
    } catch (err) {
      console.error(`Pipeline ${action} error:`, err);
    } finally {
      setActionLoading('');
      handleMenuClose();
    }
  };

  const handleCardClick = () => {
    if (onPipelineClick) {
      onPipelineClick(pipeline);
    } else {
      setDetailsOpen(true);
    }
  };

  const getStatusIcon = () => {
    const config = statusConfig[pipeline.status] || statusConfig.pending;
    const IconComponent = config.icon;
    return <IconComponent sx={{ fontSize: compact ? 16 : 20 }} />;
  };

  const getStatusChip = () => {
    const config = statusConfig[pipeline.status] || statusConfig.pending;
    return (
      <Chip
        size={compact ? "small" : "medium"}
        label={config.label}
        color={config.color}
        icon={getStatusIcon()}
        variant="outlined"
      />
    );
  };

  const getPlatformChip = () => {
    const config = platformConfig[pipeline.platform] || { name: pipeline.platform, color: '#666', icon: '🔧' };
    return (
      <Chip
        size="small"
        label={config.name}
        sx={{ 
          backgroundColor: alpha(config.color, 0.1),
          color: config.color,
          border: `1px solid ${alpha(config.color, 0.3)}`
        }}
        avatar={<Avatar sx={{ bgcolor: 'transparent !important' }}>{config.icon}</Avatar>}
      />
    );
  };

  const getProgress = () => {
    if (pipeline.status === 'running' && pipeline.progress) {
      return pipeline.progress;
    }
    if (pipeline.status === 'success') return 100;
    if (pipeline.status === 'failed' || pipeline.status === 'cancelled') return 0;
    return 0;
  };

  const formatDuration = (duration) => {
    if (!duration) return 'N/A';
    const minutes = Math.floor(duration / 60);
    const seconds = duration % 60;
    return `${minutes}m ${seconds}s`;
  };

  const formatDateTime = (timestamp) => {
    try {
      const date = typeof timestamp === 'string' ? parseISO(timestamp) : timestamp;
      return format(date, 'MMM d, yyyy HH:mm');
    } catch (err) {
      return 'Invalid date';
    }
  };

  const formatTimeAgo = (timestamp) => {
    try {
      const date = typeof timestamp === 'string' ? parseISO(timestamp) : timestamp;
      return formatDistanceToNow(date, { addSuffix: true });
    } catch (err) {
      return 'Unknown time';
    }
  };

  const config = statusConfig[pipeline.status] || statusConfig.pending;

  return (
    <>
      <Card 
        sx={{ 
          height: '100%',
          cursor: 'pointer',
          transition: 'all 0.2s ease-in-out',
          borderLeft: 4,
          borderLeftColor: config.borderColor,
          background: `linear-gradient(135deg, ${config.bgColor} 0%, ${alpha(config.bgColor, 0.3)} 100%)`,
          '&:hover': {
            transform: 'translateY(-2px)',
            boxShadow: theme.shadows[4],
            backgroundColor: alpha(config.bgColor, 0.15)
          }
        }}
        onClick={handleCardClick}
      >
        <CardContent sx={{ pb: compact ? 1 : 2 }}>
          {/* Header */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1 }}>
            <Box sx={{ flexGrow: 1, minWidth: 0 }}>
              <Typography 
                variant={compact ? "body1" : "h6"} 
                sx={{ 
                  fontWeight: 600,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap'
                }}
              >
                {pipeline.name}
              </Typography>
              <Typography 
                variant="body2" 
                color="text.secondary"
                sx={{
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap'
                }}
              >
                {pipeline.repository || pipeline.project}
              </Typography>
            </Box>
            
            {showActions && (
              <IconButton 
                size="small" 
                onClick={(e) => {
                  e.stopPropagation();
                  handleMenuOpen(e);
                }}
              >
                <MoreVertIcon />
              </IconButton>
            )}
          </Box>

          {/* Status and Platform */}
          <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
            {getStatusChip()}
            {getPlatformChip()}
          </Box>

          {/* Progress Bar */}
          {pipeline.status === 'running' && (
            <Box sx={{ mb: 2 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}>
                <Typography variant="caption" color="text.secondary">
                  Progress
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {getProgress()}%
                </Typography>
              </Box>
              <LinearProgress 
                variant="determinate" 
                value={getProgress()}
                sx={{
                  height: 6,
                  borderRadius: 3,
                  backgroundColor: alpha(theme.palette.primary.main, 0.1),
                  '& .MuiLinearProgress-bar': {
                    borderRadius: 3
                  }
                }}
              />
            </Box>
          )}

          {/* Metrics */}
          {!compact && (
            <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
              {pipeline.vulnerabilities_count !== undefined && (
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <BugReportIcon sx={{ fontSize: 16, mr: 0.5, color: 'error.main' }} />
                  <Typography variant="caption">
                    {pipeline.vulnerabilities_count} vuln{pipeline.vulnerabilities_count !== 1 ? 's' : ''}
                  </Typography>
                </Box>
              )}
              
              {pipeline.security_score !== undefined && (
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <SecurityIcon sx={{ fontSize: 16, mr: 0.5, color: 'primary.main' }} />
                  <Typography variant="caption">
                    {pipeline.security_score}% secure
                  </Typography>
                </Box>
              )}
              
              {pipeline.compliance_score !== undefined && (
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                  <AssignmentIcon sx={{ fontSize: 16, mr: 0.5, color: 'info.main' }} />
                  <Typography variant="caption">
                    {pipeline.compliance_score}% compliant
                  </Typography>
                </Box>
              )}
            </Stack>
          )}

          {/* Timing Info */}
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Box>
              <Typography variant="caption" color="text.secondary">
                {pipeline.status === 'running' ? 'Started' : 'Last run'}
              </Typography>
              <Typography variant="body2">
                {formatTimeAgo(pipeline.started_at || pipeline.updated_at)}
              </Typography>
            </Box>
            
            {pipeline.duration && (
              <Box sx={{ textAlign: 'right' }}>
                <Typography variant="caption" color="text.secondary">
                  Duration
                </Typography>
                <Typography variant="body2">
                  {formatDuration(pipeline.duration)}
                </Typography>
              </Box>
            )}
          </Box>

          {/* Branch/Commit Info */}
          {!compact && pipeline.branch && (
            <Box sx={{ mt: 1, pt: 1, borderTop: 1, borderColor: 'divider' }}>
              <Typography variant="caption" color="text.secondary">
                Branch: {pipeline.branch}
              </Typography>
              {pipeline.commit_hash && (
                <Typography variant="caption" color="text.secondary" sx={{ ml: 2 }}>
                  Commit: {pipeline.commit_hash.substring(0, 8)}
                </Typography>
              )}
            </Box>
          )}
        </CardContent>

        {/* Actions */}
        {showActions && !compact && (
          <CardActions sx={{ pt: 0 }}>
            <Button 
              size="small" 
              startIcon={<TimelineIcon />}
              onClick={(e) => {
                e.stopPropagation();
                // Navigate to pipeline details
              }}
            >
              View Details
            </Button>
            
            {pipeline.external_url && (
              <Button 
                size="small" 
                startIcon={<OpenInNewIcon />}
                onClick={(e) => {
                  e.stopPropagation();
                  window.open(pipeline.external_url, '_blank');
                }}
              >
                Open in {platformConfig[pipeline.platform]?.name || 'Platform'}
              </Button>
            )}
          </CardActions>
        )}
      </Card>

      {/* Action Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
      >
        {pipeline.status === 'running' && (
          <MenuItem 
            onClick={() => handlePipelineAction('stop')}
            disabled={actionLoading === 'stop'}
          >
            <StopIcon sx={{ mr: 1 }} />
            Stop Pipeline
          </MenuItem>
        )}
        
        {pipeline.status !== 'running' && (
          <MenuItem 
            onClick={() => handlePipelineAction('restart')}
            disabled={actionLoading === 'restart'}
          >
            <RefreshIcon sx={{ mr: 1 }} />
            Restart Pipeline
          </MenuItem>
        )}
        
        <MenuItem 
          onClick={() => handlePipelineAction('scan')}
          disabled={actionLoading === 'scan'}
        >
          <SecurityIcon sx={{ mr: 1 }} />
          Run Security Scan
        </MenuItem>
        
        <MenuItem onClick={() => setDetailsOpen(true)}>
          <HistoryIcon sx={{ mr: 1 }} />
          View History
        </MenuItem>
        
        {pipeline.external_url && (
          <MenuItem onClick={() => window.open(pipeline.external_url, '_blank')}>
            <LinkIcon sx={{ mr: 1 }} />
            Open External
          </MenuItem>
        )}
      </Menu>

      {/* Pipeline Details Dialog */}
      <Dialog 
        open={detailsOpen} 
        onClose={() => setDetailsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Pipeline Details: {pipeline.name}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2}>
            <Box>
              <Typography variant="subtitle1" gutterBottom>
                Basic Information
              </Typography>
              <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
                {getStatusChip()}
                {getPlatformChip()}
              </Stack>
            </Box>
            
            <Divider />
            
            <Box>
              <Typography variant="subtitle1" gutterBottom>
                Repository Information
              </Typography>
              <Typography variant="body2">
                <strong>Repository:</strong> {pipeline.repository || 'N/A'}
              </Typography>
              <Typography variant="body2">
                <strong>Branch:</strong> {pipeline.branch || 'N/A'}
              </Typography>
              {pipeline.commit_hash && (
                <Typography variant="body2">
                  <strong>Commit:</strong> {pipeline.commit_hash}
                </Typography>
              )}
            </Box>
            
            <Divider />
            
            <Box>
              <Typography variant="subtitle1" gutterBottom>
                Execution Details
              </Typography>
              <Typography variant="body2">
                <strong>Started:</strong> {formatDateTime(pipeline.started_at)}
              </Typography>
              {pipeline.completed_at && (
                <Typography variant="body2">
                  <strong>Completed:</strong> {formatDateTime(pipeline.completed_at)}
                </Typography>
              )}
              <Typography variant="body2">
                <strong>Duration:</strong> {formatDuration(pipeline.duration)}
              </Typography>
            </Box>
            
            {(pipeline.vulnerabilities_count !== undefined || 
              pipeline.security_score !== undefined || 
              pipeline.compliance_score !== undefined) && (
              <>
                <Divider />
                <Box>
                  <Typography variant="subtitle1" gutterBottom>
                    Security Metrics
                  </Typography>
                  {pipeline.vulnerabilities_count !== undefined && (
                    <Typography variant="body2">
                      <strong>Vulnerabilities:</strong> {pipeline.vulnerabilities_count}
                    </Typography>
                  )}
                  {pipeline.security_score !== undefined && (
                    <Typography variant="body2">
                      <strong>Security Score:</strong> {pipeline.security_score}%
                    </Typography>
                  )}
                  {pipeline.compliance_score !== undefined && (
                    <Typography variant="body2">
                      <strong>Compliance Score:</strong> {pipeline.compliance_score}%
                    </Typography>
                  )}
                </Box>
              </>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsOpen(false)}>Close</Button>
          {pipeline.external_url && (
            <Button 
              variant="contained" 
              onClick={() => window.open(pipeline.external_url, '_blank')}
            >
              Open in Platform
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </>
  );
};

export default PipelineCard;
