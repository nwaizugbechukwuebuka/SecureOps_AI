import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  IconButton,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Tooltip,
  Alert,
  Skeleton,
  useTheme,
  alpha,
  Paper,
  Collapse,
  Stack
} from '@mui/material';
import {
  Error as ErrorIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Visibility as VisibilityIcon,
  Edit as EditIcon,
  Close as CloseIcon,
  FilterList as FilterListIcon,
  Refresh as RefreshIcon,
  Archive as ArchiveIcon,
  Assignment as AssignmentIcon,
  Schedule as ScheduleIcon,
  Person as PersonIcon,
  Link as LinkIcon
} from '@mui/icons-material';
import { formatDistanceToNow, parseISO, format } from 'date-fns';
import { api } from '../services/api';
import { useWebSocket } from '../services/websocket';

const AlertList = ({ 
  limit = 50, 
  showFilters = true, 
  showPagination = true,
  embedded = false,
  onAlertClick = null 
}) => {
  const theme = useTheme();
  const { realTimeAlerts } = useWebSocket();
  
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(limit);
  const [totalCount, setTotalCount] = useState(0);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [expandedRows, setExpandedRows] = useState({});
  
  // Filters
  const [filters, setFilters] = useState({
    severity: '',
    status: '',
    type: '',
    pipeline: '',
    assignee: '',
    dateFrom: '',
    dateTo: ''
  });

  const severityConfig = {
    critical: { color: 'error', icon: ErrorIcon, label: 'Critical' },
    high: { color: 'warning', icon: WarningIcon, label: 'High' },
    medium: { color: 'info', icon: InfoIcon, label: 'Medium' },
    low: { color: 'success', icon: CheckCircleIcon, label: 'Low' }
  };

  const statusConfig = {
    open: { color: 'error', label: 'Open' },
    in_progress: { color: 'warning', label: 'In Progress' },
    resolved: { color: 'success', label: 'Resolved' },
    false_positive: { color: 'info', label: 'False Positive' },
    acknowledged: { color: 'warning', label: 'Acknowledged' },
    wont_fix: { color: 'default', label: "Won't Fix" }
  };

  useEffect(() => {
    loadAlerts();
  }, [page, rowsPerPage, filters]);

  useEffect(() => {
    if (realTimeAlerts) {
      setAlerts(prev => [realTimeAlerts, ...prev.slice(0, -1)]);
    }
  }, [realTimeAlerts]);

  const loadAlerts = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const params = {
        page: page + 1,
        limit: rowsPerPage,
        ...Object.fromEntries(
          Object.entries(filters).filter(([_, value]) => value !== '')
        )
      };
      
      const response = await api.get('/alerts', { params });
      setAlerts(response.data.alerts || []);
      setTotalCount(response.data.total || 0);
    } catch (err) {
      setError('Failed to load alerts');
      console.error('Alerts error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleChangePage = (event, newPage) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleFilterChange = (field, value) => {
    setFilters(prev => ({ ...prev, [field]: value }));
    setPage(0);
  };

  const handleAlertAction = async (alertId, action, data = {}) => {
    try {
      await api.patch(`/alerts/${alertId}`, { action, ...data });
      await loadAlerts();
    } catch (err) {
      console.error('Alert action error:', err);
    }
  };

  const handleViewDetails = (alert) => {
    setSelectedAlert(alert);
    setDetailsOpen(true);
    if (onAlertClick) onAlertClick(alert);
  };

  const handleEditAlert = (alert) => {
    setSelectedAlert(alert);
    setEditOpen(true);
  };

  const handleExpandRow = (alertId) => {
    setExpandedRows(prev => ({
      ...prev,
      [alertId]: !prev[alertId]
    }));
  };

  const getSeverityIcon = (severity) => {
    const config = severityConfig[severity] || severityConfig.low;
    const IconComponent = config.icon;
    return <IconComponent sx={{ fontSize: 16, color: theme.palette[config.color].main }} />;
  };

  const getSeverityChip = (severity) => {
    const config = severityConfig[severity] || severityConfig.low;
    return (
      <Chip 
        size="small" 
        label={config.label}
        color={config.color}
        icon={getSeverityIcon(severity)}
        sx={{ minWidth: 80 }}
      />
    );
  };

  const getStatusChip = (status) => {
    const config = statusConfig[status] || statusConfig.open;
    return (
      <Chip 
        size="small" 
        label={config.label}
        color={config.color}
        variant="outlined"
        sx={{ minWidth: 90 }}
      />
    );
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

  if (loading && alerts.length === 0) {
    return (
      <Card sx={{ width: '100%' }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>Security Alerts</Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  {['Severity', 'Title', 'Status', 'Pipeline', 'Created', 'Actions'].map((header) => (
                    <TableCell key={header}>
                      <Skeleton variant="text" />
                    </TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {[...Array(5)].map((_, index) => (
                  <TableRow key={index}>
                    {[...Array(6)].map((_, cellIndex) => (
                      <TableCell key={cellIndex}>
                        <Skeleton variant="text" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card sx={{ width: '100%' }}>
        <CardContent>
          <Alert 
            severity="error" 
            action={
              <IconButton color="inherit" size="small" onClick={loadAlerts}>
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
    <Card sx={{ width: '100%' }}>
      <CardContent>
        {/* Header */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">Security Alerts</Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            {showFilters && (
              <Tooltip title="Toggle filters">
                <IconButton size="small" onClick={() => setFiltersOpen(!filtersOpen)}>
                  <FilterListIcon />
                </IconButton>
              </Tooltip>
            )}
            <Tooltip title="Refresh">
              <IconButton size="small" onClick={loadAlerts}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        {/* Filters */}
        {showFilters && (
          <Collapse in={filtersOpen}>
            <Paper sx={{ p: 2, mb: 2, backgroundColor: alpha(theme.palette.primary.main, 0.05) }}>
              <Typography variant="subtitle2" gutterBottom>Filters</Typography>
              <Stack direction="row" spacing={2} flexWrap="wrap" useFlexGap>
                <FormControl size="small" sx={{ minWidth: 120 }}>
                  <InputLabel>Severity</InputLabel>
                  <Select
                    value={filters.severity}
                    label="Severity"
                    onChange={(e) => handleFilterChange('severity', e.target.value)}
                  >
                    <MenuItem value="">All</MenuItem>
                    <MenuItem value="critical">Critical</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="low">Low</MenuItem>
                  </Select>
                </FormControl>

                <FormControl size="small" sx={{ minWidth: 120 }}>
                  <InputLabel>Status</InputLabel>
                  <Select
                    value={filters.status}
                    label="Status"
                    onChange={(e) => handleFilterChange('status', e.target.value)}
                  >
                    <MenuItem value="">All</MenuItem>
                    <MenuItem value="open">Open</MenuItem>
                    <MenuItem value="in_progress">In Progress</MenuItem>
                    <MenuItem value="resolved">Resolved</MenuItem>
                    <MenuItem value="false_positive">False Positive</MenuItem>
                  </Select>
                </FormControl>

                <TextField
                  size="small"
                  label="Pipeline"
                  value={filters.pipeline}
                  onChange={(e) => handleFilterChange('pipeline', e.target.value)}
                  sx={{ minWidth: 150 }}
                />

                <TextField
                  size="small"
                  label="Assignee"
                  value={filters.assignee}
                  onChange={(e) => handleFilterChange('assignee', e.target.value)}
                  sx={{ minWidth: 150 }}
                />
              </Stack>
            </Paper>
          </Collapse>
        )}

        {/* Alerts Table */}
        <TableContainer>
          <Table size={embedded ? "small" : "medium"}>
            <TableHead>
              <TableRow>
                <TableCell width="20"></TableCell>
                <TableCell>Severity</TableCell>
                <TableCell>Title</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Pipeline</TableCell>
                <TableCell>Created</TableCell>
                <TableCell>Assignee</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {alerts.map((alert) => (
                <React.Fragment key={alert.id}>
                  <TableRow 
                    hover
                    sx={{ 
                      '&:last-child td, &:last-child th': { border: 0 },
                      cursor: 'pointer'
                    }}
                  >
                    <TableCell>
                      <IconButton 
                        size="small" 
                        onClick={() => handleExpandRow(alert.id)}
                      >
                        {expandedRows[alert.id] ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                      </IconButton>
                    </TableCell>
                    
                    <TableCell>
                      {getSeverityChip(alert.severity)}
                    </TableCell>
                    
                    <TableCell>
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>
                        {alert.title}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {alert.type}
                      </Typography>
                    </TableCell>
                    
                    <TableCell>
                      {getStatusChip(alert.status)}
                    </TableCell>
                    
                    <TableCell>
                      <Typography variant="body2">
                        {alert.pipeline || 'N/A'}
                      </Typography>
                    </TableCell>
                    
                    <TableCell>
                      <Typography variant="body2">
                        {formatDateTime(alert.created_at)}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {formatTimeAgo(alert.created_at)}
                      </Typography>
                    </TableCell>
                    
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        {alert.assignee ? (
                          <>
                            <PersonIcon sx={{ fontSize: 16, mr: 0.5 }} />
                            <Typography variant="body2">
                              {alert.assignee}
                            </Typography>
                          </>
                        ) : (
                          <Typography variant="body2" color="text.secondary">
                            Unassigned
                          </Typography>
                        )}
                      </Box>
                    </TableCell>
                    
                    <TableCell align="right">
                      <Box sx={{ display: 'flex', gap: 0.5 }}>
                        <Tooltip title="View details">
                          <IconButton size="small" onClick={() => handleViewDetails(alert)}>
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Edit">
                          <IconButton size="small" onClick={() => handleEditAlert(alert)}>
                            <EditIcon />
                          </IconButton>
                        </Tooltip>
                        {alert.status === 'open' && (
                          <Tooltip title="Resolve">
                            <IconButton 
                              size="small" 
                              onClick={() => handleAlertAction(alert.id, 'resolve')}
                            >
                              <CheckCircleIcon />
                            </IconButton>
                          </Tooltip>
                        )}
                      </Box>
                    </TableCell>
                  </TableRow>
                  
                  {/* Expanded Row Details */}
                  <TableRow>
                    <TableCell colSpan={8} sx={{ py: 0 }}>
                      <Collapse in={expandedRows[alert.id]}>
                        <Box sx={{ p: 2, backgroundColor: alpha(theme.palette.background.default, 0.5) }}>
                          <Typography variant="body2" gutterBottom>
                            <strong>Description:</strong> {alert.description}
                          </Typography>
                          {alert.details && (
                            <Typography variant="body2" gutterBottom>
                              <strong>Details:</strong> {alert.details}
                            </Typography>
                          )}
                          {alert.remediation && (
                            <Typography variant="body2" gutterBottom>
                              <strong>Remediation:</strong> {alert.remediation}
                            </Typography>
                          )}
                          <Box sx={{ display: 'flex', gap: 2, mt: 1 }}>
                            {alert.vulnerability_id && (
                              <Chip 
                                size="small" 
                                label={`Vuln: ${alert.vulnerability_id}`}
                                icon={<LinkIcon />}
                              />
                            )}
                            {alert.rule_id && (
                              <Chip 
                                size="small" 
                                label={`Rule: ${alert.rule_id}`}
                                icon={<AssignmentIcon />}
                              />
                            )}
                            {alert.updated_at && (
                              <Chip 
                                size="small" 
                                label={`Updated: ${formatTimeAgo(alert.updated_at)}`}
                                icon={<ScheduleIcon />}
                              />
                            )}
                          </Box>
                        </Box>
                      </Collapse>
                    </TableCell>
                  </TableRow>
                </React.Fragment>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Pagination */}
        {showPagination && (
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={totalCount}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
          />
        )}
      </CardContent>

      {/* Alert Details Dialog */}
      <Dialog 
        open={detailsOpen} 
        onClose={() => setDetailsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          Alert Details
          <IconButton
            aria-label="close"
            onClick={() => setDetailsOpen(false)}
            sx={{ position: 'absolute', right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent>
          {selectedAlert && (
            <Box>
              <Typography variant="h6" gutterBottom>
                {selectedAlert.title}
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                {getSeverityChip(selectedAlert.severity)}
                {getStatusChip(selectedAlert.status)}
              </Box>
              <Typography variant="body1" paragraph>
                {selectedAlert.description}
              </Typography>
              {selectedAlert.details && (
                <>
                  <Typography variant="subtitle2" gutterBottom>
                    Technical Details:
                  </Typography>
                  <Typography variant="body2" paragraph>
                    {selectedAlert.details}
                  </Typography>
                </>
              )}
              {selectedAlert.remediation && (
                <>
                  <Typography variant="subtitle2" gutterBottom>
                    Recommended Remediation:
                  </Typography>
                  <Typography variant="body2" paragraph>
                    {selectedAlert.remediation}
                  </Typography>
                </>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
};

export default AlertList;
