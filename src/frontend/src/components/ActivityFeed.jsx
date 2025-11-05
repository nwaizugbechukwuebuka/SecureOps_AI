import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Avatar,
  Chip,
  IconButton,
  Divider,
  Skeleton,
  Alert,
  Button,
  useTheme,
  alpha,
  Tooltip,
  Badge
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Info as InfoIcon,
  Build as BuildIcon,
  Timeline as TimelineIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  OpenInNew as OpenInNewIcon
} from '@mui/icons-material';
import { formatDistanceToNow, parseISO } from 'date-fns';
import { api } from '../services/api';
import { useWebSocket } from '../services/websocket';

const ActivityFeed = ({ limit = 50, showHeader = true, height = 500 }) => {
  const theme = useTheme();
  const { realTimeActivity } = useWebSocket();
  
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [expanded, setExpanded] = useState(false);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);

  const activityTypes = {
    scan_completed: { icon: SecurityIcon, color: 'primary', label: 'Scan Completed' },
    vulnerability_detected: { icon: WarningIcon, color: 'warning', label: 'Vulnerability Detected' },
    critical_alert: { icon: ErrorIcon, color: 'error', label: 'Critical Alert' },
    vulnerability_resolved: { icon: CheckCircleIcon, color: 'success', label: 'Vulnerability Resolved' },
    pipeline_started: { icon: BuildIcon, color: 'info', label: 'Pipeline Started' },
    pipeline_completed: { icon: CheckCircleIcon, color: 'success', label: 'Pipeline Completed' },
    pipeline_failed: { icon: ErrorIcon, color: 'error', label: 'Pipeline Failed' },
    compliance_check: { icon: SecurityIcon, color: 'primary', label: 'Compliance Check' },
    policy_violation: { icon: WarningIcon, color: 'warning', label: 'Policy Violation' },
    user_action: { icon: InfoIcon, color: 'info', label: 'User Action' },
    system_event: { icon: TimelineIcon, color: 'default', label: 'System Event' }
  };

  useEffect(() => {
    loadActivities();
  }, [filter]);

  useEffect(() => {
    if (realTimeActivity) {
      setActivities(prev => [realTimeActivity, ...prev]);
    }
  }, [realTimeActivity]);

  const loadActivities = async (pageNum = 1, append = false) => {
    try {
      if (!append) {
        setLoading(true);
        setError(null);
      }
      
      const params = {
        page: pageNum,
        limit,
        filter: filter !== 'all' ? filter : undefined
      };
      
      const response = await api.get('/activity/feed', { params });
      const newActivities = response.data.activities || [];
      
      if (append) {
        setActivities(prev => [...prev, ...newActivities]);
      } else {
        setActivities(newActivities);
      }
      
      setHasMore(newActivities.length === limit);
      setPage(pageNum);
    } catch (err) {
      setError('Failed to load activity feed');
      console.error('Activity feed error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleLoadMore = () => {
    loadActivities(page + 1, true);
  };

  const handleRefresh = () => {
    loadActivities(1, false);
  };

  const getActivityIcon = (type) => {
    const config = activityTypes[type] || activityTypes.system_event;
    const IconComponent = config.icon;
    return (
      <Avatar sx={{ 
        bgcolor: theme.palette[config.color]?.main || theme.palette.grey[500],
        width: 32,
        height: 32
      }}>
        <IconComponent sx={{ fontSize: 18 }} />
      </Avatar>
    );
  };

  const getActivityColor = (type, severity) => {
    if (severity === 'critical') return theme.palette.error.main;
    if (severity === 'high') return theme.palette.warning.main;
    if (severity === 'medium') return theme.palette.info.main;
    if (severity === 'low') return theme.palette.success.main;
    
    const config = activityTypes[type] || activityTypes.system_event;
    return theme.palette[config.color]?.main || theme.palette.grey[500];
  };

  const formatActivityTime = (timestamp) => {
    try {
      const date = typeof timestamp === 'string' ? parseISO(timestamp) : timestamp;
      return formatDistanceToNow(date, { addSuffix: true });
    } catch (err) {
      return 'Unknown time';
    }
  };

  const getSeverityChip = (severity) => {
    if (!severity) return null;
    
    const severityConfig = {
      critical: { color: 'error', label: 'Critical' },
      high: { color: 'warning', label: 'High' },
      medium: { color: 'info', label: 'Medium' },
      low: { color: 'success', label: 'Low' }
    };
    
    const config = severityConfig[severity] || { color: 'default', label: severity };
    
    return (
      <Chip 
        size="small" 
        label={config.label}
        color={config.color}
        variant="outlined"
        sx={{ ml: 1, fontSize: '0.7rem', height: 20 }}
      />
    );
  };

  const getFilterOptions = () => [
    { value: 'all', label: 'All Activities', count: activities.length },
    { value: 'scan_completed', label: 'Scans', count: activities.filter(a => a.type === 'scan_completed').length },
    { value: 'vulnerability_detected', label: 'Vulnerabilities', count: activities.filter(a => a.type === 'vulnerability_detected').length },
    { value: 'critical_alert', label: 'Critical Alerts', count: activities.filter(a => a.type === 'critical_alert').length },
    { value: 'pipeline_started', label: 'Pipelines', count: activities.filter(a => a.type.includes('pipeline')).length }
  ];

  if (loading && activities.length === 0) {
    return (
      <Card sx={{ height: showHeader ? height : '100%' }}>
        {showHeader && (
          <CardContent sx={{ pb: 1 }}>
            <Typography variant="h6">Activity Feed</Typography>
          </CardContent>
        )}
        <CardContent sx={{ pt: showHeader ? 0 : 2 }}>
          <List>
            {[...Array(8)].map((_, index) => (
              <ListItem key={index}>
                <ListItemAvatar>
                  <Skeleton variant="circular" width={32} height={32} />
                </ListItemAvatar>
                <ListItemText
                  primary={<Skeleton variant="text" width="60%" />}
                  secondary={<Skeleton variant="text" width="40%" />}
                />
              </ListItem>
            ))}
          </List>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card sx={{ height: showHeader ? height : '100%' }}>
        {showHeader && (
          <CardContent sx={{ pb: 1 }}>
            <Typography variant="h6">Activity Feed</Typography>
          </CardContent>
        )}
        <CardContent>
          <Alert 
            severity="error" 
            action={
              <IconButton color="inherit" size="small" onClick={handleRefresh}>
                <RefreshIcon />
              </IconButton>
            }
          >
            {error}
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card sx={{ height: showHeader ? height : '100%', display: 'flex', flexDirection: 'column' }}>
      {showHeader && (
        <CardContent sx={{ pb: 1, borderBottom: 1, borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="h6">Activity Feed</Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Tooltip title="Filter activities">
                <IconButton size="small">
                  <FilterIcon />
                </IconButton>
              </Tooltip>
              <Tooltip title="Refresh">
                <IconButton size="small" onClick={handleRefresh}>
                  <RefreshIcon />
                </IconButton>
              </Tooltip>
            </Box>
          </Box>
          
          {/* Filter Chips */}
          <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
            {getFilterOptions().map((option) => (
              <Chip
                key={option.value}
                label={`${option.label} (${option.count})`}
                size="small"
                variant={filter === option.value ? 'filled' : 'outlined'}
                color={filter === option.value ? 'primary' : 'default'}
                onClick={() => setFilter(option.value)}
                sx={{ fontSize: '0.7rem' }}
              />
            ))}
          </Box>
        </CardContent>
      )}
      
      <CardContent sx={{ flexGrow: 1, overflow: 'auto', pt: showHeader ? 1 : 2 }}>
        {activities.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <TimelineIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
            <Typography variant="body1" color="text.secondary">
              No activities found
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Activities will appear here as they occur
            </Typography>
          </Box>
        ) : (
          <List sx={{ p: 0 }}>
            {activities.map((activity, index) => (
              <React.Fragment key={activity.id || index}>
                <ListItem 
                  sx={{ 
                    px: 0,
                    borderLeft: 3,
                    borderColor: getActivityColor(activity.type, activity.severity),
                    borderLeftStyle: 'solid',
                    '&:hover': {
                      backgroundColor: alpha(getActivityColor(activity.type, activity.severity), 0.05)
                    }
                  }}
                >
                  <ListItemAvatar>
                    {getActivityIcon(activity.type)}
                  </ListItemAvatar>
                  
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
                        <Typography variant="body2" sx={{ fontWeight: 500 }}>
                          {activity.title || activityTypes[activity.type]?.label || 'System Event'}
                        </Typography>
                        {getSeverityChip(activity.severity)}
                        {activity.pipeline && (
                          <Chip 
                            size="small" 
                            label={activity.pipeline}
                            variant="outlined"
                            sx={{ ml: 1, fontSize: '0.7rem', height: 20 }}
                          />
                        )}
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Typography variant="body2" color="text.secondary">
                          {activity.description || activity.message}
                        </Typography>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mt: 0.5 }}>
                          <Typography variant="caption" color="text.secondary">
                            {formatActivityTime(activity.timestamp)}
                          </Typography>
                          {activity.source && (
                            <Typography variant="caption" color="text.secondary">
                              {activity.source}
                            </Typography>
                          )}
                        </Box>
                        {activity.details && expanded && (
                          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                            {activity.details}
                          </Typography>
                        )}
                      </Box>
                    }
                  />
                  
                  {activity.url && (
                    <Tooltip title="View details">
                      <IconButton 
                        size="small" 
                        onClick={() => window.open(activity.url, '_blank')}
                        sx={{ ml: 1 }}
                      >
                        <OpenInNewIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  )}
                </ListItem>
                
                {index < activities.length - 1 && (
                  <Divider variant="inset" component="li" />
                )}
              </React.Fragment>
            ))}
          </List>
        )}
        
        {hasMore && activities.length > 0 && (
          <Box sx={{ textAlign: 'center', mt: 2 }}>
            <Button 
              variant="outlined" 
              size="small" 
              onClick={handleLoadMore}
              disabled={loading}
            >
              Load More
            </Button>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default ActivityFeed;
