import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { apiService } from '../services/api';
import { formatTimeAgo, getSeverityColor, getStatusColor, capitalize } from '../utils/helpers';
import { useTheme } from '../utils/theme';
import { 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Clock, 
  Filter, 
  Search,
  RefreshCw,
  Eye,
  Trash2
} from 'lucide-react';
import toast from 'react-hot-toast';

const Alerts = () => {
  const { user } = useAuth();
  const { isDark } = useTheme();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedAlert, setSelectedAlert] = useState(null);

  // Filter options
  const filterOptions = [
    { value: 'all', label: 'All Alerts' },
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' },
    { value: 'acknowledged', label: 'Acknowledged' },
    { value: 'pending', label: 'Pending' }
  ];

  // Load alerts
  const loadAlerts = async () => {
    try {
      setLoading(true);
      const data = await apiService.getAlerts();
      setAlerts(data || []);
    } catch (error) {
      console.error('Error loading alerts:', error);
      toast.error('Failed to load alerts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
    
    // Set up real-time updates
    const ws = apiService.createWebSocket('/alerts/ws');
    ws.onmessage = (event) => {
      const alertUpdate = JSON.parse(event.data);
      setAlerts(prev => {
        const index = prev.findIndex(alert => alert.id === alertUpdate.id);
        if (index >= 0) {
          return prev.map((alert, i) => i === index ? alertUpdate : alert);
        } else {
          return [alertUpdate, ...prev];
        }
      });
    };

    return () => {
      ws.close();
    };
  }, []);

  // Filter alerts based on selected filter and search term
  const filteredAlerts = alerts.filter(alert => {
    const matchesFilter = filter === 'all' || 
      alert.severity === filter || 
      alert.status === filter;
    
    const matchesSearch = !searchTerm || 
      alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    return matchesFilter && matchesSearch;
  });

  // Handle alert acknowledgment
  const handleAcknowledge = async (alertId) => {
    try {
      await apiService.acknowledgeAlert(alertId);
      setAlerts(prev => 
        prev.map(alert => 
          alert.id === alertId 
            ? { ...alert, status: 'acknowledged', acknowledged_at: new Date().toISOString() }
            : alert
        )
      );
      toast.success('Alert acknowledged');
    } catch (error) {
      toast.error('Failed to acknowledge alert');
    }
  };

  // Handle alert deletion
  const handleDelete = async (alertId) => {
    if (!window.confirm('Are you sure you want to delete this alert?')) return;
    
    try {
      await apiService.deleteAlert(alertId);
      setAlerts(prev => prev.filter(alert => alert.id !== alertId));
      toast.success('Alert deleted');
    } catch (error) {
      toast.error('Failed to delete alert');
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
        return <XCircle className="w-5 h-5 text-red-500" />;
      case 'high':
        return <AlertTriangle className="w-5 h-5 text-orange-500" />;
      case 'medium':
        return <Clock className="w-5 h-5 text-yellow-500" />;
      default:
        return <CheckCircle className="w-5 h-5 text-green-500" />;
    }
  };

  const themeClasses = {
    background: isDark ? 'bg-gray-900' : 'bg-gray-50',
    card: isDark ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200',
    text: isDark ? 'text-gray-100' : 'text-gray-900',
    textSecondary: isDark ? 'text-gray-400' : 'text-gray-600',
    input: isDark ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300',
    button: isDark ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-600 hover:bg-blue-700'
  };

  if (loading) {
    return (
      <div className={`min-h-screen ${themeClasses.background} flex items-center justify-center`}>
        <div className="text-center">
          <RefreshCw className="w-8 h-8 mx-auto mb-4 animate-spin text-blue-500" />
          <p className={themeClasses.text}>Loading alerts...</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`min-h-screen ${themeClasses.background} p-6`}>
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className={`text-3xl font-bold ${themeClasses.text}`}>Security Alerts</h1>
            <p className={themeClasses.textSecondary}>
              Monitor and manage security threats in real-time
            </p>
          </div>
          
          <button
            onClick={loadAlerts}
            className={`px-4 py-2 rounded-lg ${themeClasses.button} text-white flex items-center space-x-2`}
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </button>
        </div>

        {/* Filters and Search */}
        <div className={`${themeClasses.card} rounded-lg border p-4 mb-6`}>
          <div className="flex flex-col sm:flex-row gap-4">
            {/* Filter Dropdown */}
            <div className="flex-1">
              <label className={`block text-sm font-medium ${themeClasses.text} mb-2`}>
                <Filter className="w-4 h-4 inline mr-2" />
                Filter by
              </label>
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className={`w-full px-3 py-2 border rounded-lg ${themeClasses.input}`}
              >
                {filterOptions.map(option => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>

            {/* Search */}
            <div className="flex-1">
              <label className={`block text-sm font-medium ${themeClasses.text} mb-2`}>
                <Search className="w-4 h-4 inline mr-2" />
                Search alerts
              </label>
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search by title or description..."
                className={`w-full px-3 py-2 border rounded-lg ${themeClasses.input}`}
              />
            </div>
          </div>
        </div>

        {/* Alerts List */}
        <div className="space-y-4">
          {filteredAlerts.length === 0 ? (
            <div className={`${themeClasses.card} rounded-lg border p-8 text-center`}>
              <AlertTriangle className={`w-12 h-12 mx-auto mb-4 ${themeClasses.textSecondary}`} />
              <h3 className={`text-lg font-semibold ${themeClasses.text} mb-2`}>
                No alerts found
              </h3>
              <p className={themeClasses.textSecondary}>
                {searchTerm || filter !== 'all' 
                  ? 'Try adjusting your filters or search terms.'
                  : 'All clear! No security alerts at this time.'
                }
              </p>
            </div>
          ) : (
            filteredAlerts.map(alert => (
              <div key={alert.id} className={`${themeClasses.card} rounded-lg border p-6`}>
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4">
                    {getSeverityIcon(alert.severity)}
                    
                    <div className="flex-1">
                      <div className="flex items-center space-x-2 mb-2">
                        <h3 className={`text-lg font-semibold ${themeClasses.text}`}>
                          {alert.title}
                        </h3>
                        
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(alert.severity)}`}>
                          {capitalize(alert.severity)}
                        </span>
                        
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(alert.status)}`}>
                          {capitalize(alert.status)}
                        </span>
                      </div>
                      
                      <p className={`${themeClasses.textSecondary} mb-3`}>
                        {alert.description}
                      </p>
                      
                      <div className="flex items-center space-x-4 text-sm">
                        <span className={themeClasses.textSecondary}>
                          <Clock className="w-4 h-4 inline mr-1" />
                          {formatTimeAgo(alert.created_at)}
                        </span>
                        
                        {alert.source && (
                          <span className={themeClasses.textSecondary}>
                            Source: {alert.source}
                          </span>
                        )}
                        
                        {alert.ip_address && (
                          <span className={themeClasses.textSecondary}>
                            IP: {alert.ip_address}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  
                  {/* Actions */}
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => setSelectedAlert(alert)}
                      className="p-2 text-gray-500 hover:text-blue-500 hover:bg-blue-50 rounded-lg transition-colors"
                      title="View details"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                    
                    {alert.status !== 'acknowledged' && (
                      <button
                        onClick={() => handleAcknowledge(alert.id)}
                        className="p-2 text-gray-500 hover:text-green-500 hover:bg-green-50 rounded-lg transition-colors"
                        title="Acknowledge"
                      >
                        <CheckCircle className="w-4 h-4" />
                      </button>
                    )}
                    
                    {user?.role === 'admin' && (
                      <button
                        onClick={() => handleDelete(alert.id)}
                        className="p-2 text-gray-500 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Alert Details Modal */}
        {selectedAlert && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
            <div className={`${themeClasses.card} rounded-lg border max-w-2xl w-full max-h-[80vh] overflow-y-auto`}>
              <div className="p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    {getSeverityIcon(selectedAlert.severity)}
                    <h2 className={`text-xl font-bold ${themeClasses.text}`}>
                      {selectedAlert.title}
                    </h2>
                  </div>
                  
                  <button
                    onClick={() => setSelectedAlert(null)}
                    className="text-gray-500 hover:text-gray-700"
                  >
                    <XCircle className="w-6 h-6" />
                  </button>
                </div>
                
                <div className="space-y-4">
                  <div>
                    <h3 className={`font-semibold ${themeClasses.text} mb-2`}>Description</h3>
                    <p className={themeClasses.textSecondary}>{selectedAlert.description}</p>
                  </div>
                  
                  {selectedAlert.details && (
                    <div>
                      <h3 className={`font-semibold ${themeClasses.text} mb-2`}>Details</h3>
                      <pre className={`${themeClasses.textSecondary} text-sm bg-gray-100 dark:bg-gray-700 p-3 rounded overflow-x-auto`}>
                        {JSON.stringify(selectedAlert.details, null, 2)}
                      </pre>
                    </div>
                  )}
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <h3 className={`font-semibold ${themeClasses.text} mb-1`}>Severity</h3>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(selectedAlert.severity)}`}>
                        {capitalize(selectedAlert.severity)}
                      </span>
                    </div>
                    
                    <div>
                      <h3 className={`font-semibold ${themeClasses.text} mb-1`}>Status</h3>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(selectedAlert.status)}`}>
                        {capitalize(selectedAlert.status)}
                      </span>
                    </div>
                    
                    <div>
                      <h3 className={`font-semibold ${themeClasses.text} mb-1`}>Created</h3>
                      <p className={themeClasses.textSecondary}>{formatTimeAgo(selectedAlert.created_at)}</p>
                    </div>
                    
                    {selectedAlert.acknowledged_at && (
                      <div>
                        <h3 className={`font-semibold ${themeClasses.text} mb-1`}>Acknowledged</h3>
                        <p className={themeClasses.textSecondary}>{formatTimeAgo(selectedAlert.acknowledged_at)}</p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Alerts;