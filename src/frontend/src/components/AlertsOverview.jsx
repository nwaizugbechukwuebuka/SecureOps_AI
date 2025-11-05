import React from 'react'
import { motion } from 'framer-motion'
import {
  BellIcon,
  ExclamationTriangleIcon,
  ExclamationCircleIcon,
  InformationCircleIcon,
  CheckCircleIcon,
  ClockIcon,
} from '@heroicons/react/24/outline'

const AlertsOverview = ({ data = {} }) => {
  const {
    totalAlerts = 0,
    openAlerts = 0,
    inProgressAlerts = 0,
    resolvedAlerts = 0,
    criticalAlerts = 0,
    highAlerts = 0,
    mediumAlerts = 0,
    lowAlerts = 0,
    recentAlerts = []
  } = data

  const alertsByStatus = [
    {
      label: 'Open',
      count: openAlerts,
      color: 'bg-red-500',
      textColor: 'text-red-600',
      icon: ExclamationTriangleIcon,
    },
    {
      label: 'In Progress',
      count: inProgressAlerts,
      color: 'bg-yellow-500',
      textColor: 'text-yellow-600',
      icon: ClockIcon,
    },
    {
      label: 'Resolved',
      count: resolvedAlerts,
      color: 'bg-green-500',
      textColor: 'text-green-600',
      icon: CheckCircleIcon,
    },
  ]

  const alertsBySeverity = [
    {
      label: 'Critical',
      count: criticalAlerts,
      color: 'bg-red-100 dark:bg-red-900/30 border-red-200 dark:border-red-800',
      textColor: 'text-red-800 dark:text-red-200',
      icon: ExclamationCircleIcon,
    },
    {
      label: 'High',
      count: highAlerts,
      color: 'bg-orange-100 dark:bg-orange-900/30 border-orange-200 dark:border-orange-800',
      textColor: 'text-orange-800 dark:text-orange-200',
      icon: ExclamationTriangleIcon,
    },
    {
      label: 'Medium',
      count: mediumAlerts,
      color: 'bg-yellow-100 dark:bg-yellow-900/30 border-yellow-200 dark:border-yellow-800',
      textColor: 'text-yellow-800 dark:text-yellow-200',
      icon: InformationCircleIcon,
    },
    {
      label: 'Low',
      count: lowAlerts,
      color: 'bg-blue-100 dark:bg-blue-900/30 border-blue-200 dark:border-blue-800',
      textColor: 'text-blue-800 dark:text-blue-200',
      icon: InformationCircleIcon,
    },
  ]

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
      <div className="p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Security Alerts
          </h3>
          <div className="flex items-center space-x-2">
            <BellIcon className="w-5 h-5 text-gray-500 dark:text-gray-400" />
            <span className="text-2xl font-bold text-gray-900 dark:text-white">
              {totalAlerts}
            </span>
          </div>
        </div>

        {/* Alert Status Overview */}
        <div className="mb-6">
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
            Status Distribution
          </h4>
          <div className="space-y-3">
            {alertsByStatus.map((status, index) => (
              <motion.div
                key={status.label}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg"
              >
                <div className="flex items-center space-x-3">
                  <div className={`p-2 rounded-lg ${status.color.replace('bg-', 'bg-').replace('-500', '-100')} dark:bg-opacity-20`}>
                    <status.icon className={`w-4 h-4 ${status.textColor}`} />
                  </div>
                  <span className="font-medium text-gray-900 dark:text-white">
                    {status.label}
                  </span>
                </div>
                <span className="text-lg font-bold text-gray-900 dark:text-white">
                  {status.count}
                </span>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Alert Severity Overview */}
        <div className="mb-6">
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
            Severity Breakdown
          </h4>
          <div className="grid grid-cols-2 gap-3">
            {alertsBySeverity.map((severity, index) => (
              <motion.div
                key={severity.label}
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: index * 0.1 }}
                className={`p-4 rounded-lg border ${severity.color}`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <severity.icon className={`w-4 h-4 ${severity.textColor}`} />
                    <span className={`text-sm font-medium ${severity.textColor}`}>
                      {severity.label}
                    </span>
                  </div>
                  <span className={`text-xl font-bold ${severity.textColor}`}>
                    {severity.count}
                  </span>
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Recent Alerts */}
        {recentAlerts && recentAlerts.length > 0 && (
          <div>
            <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
              Recent Alerts
            </h4>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {recentAlerts.slice(0, 5).map((alert, index) => (
                <motion.div
                  key={alert.id || index}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors cursor-pointer"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <div className={`w-2 h-2 rounded-full ${
                        alert.severity === 'critical' ? 'bg-red-500' :
                        alert.severity === 'high' ? 'bg-orange-500' :
                        alert.severity === 'medium' ? 'bg-yellow-500' :
                        'bg-blue-500'
                      }`} />
                      <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                        {alert.title || 'Security Alert'}
                      </p>
                    </div>
                    <p className="text-xs text-gray-500 dark:text-gray-400 truncate">
                      {alert.description || 'No description available'}
                    </p>
                  </div>
                  <div className="text-right ml-4">
                    <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${
                      alert.status === 'open' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-200' :
                      alert.status === 'in_progress' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-200' :
                      'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-200'
                    }`}>
                      {alert.status?.replace('_', ' ') || 'unknown'}
                    </div>
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                      {alert.created_at ? new Date(alert.created_at).toLocaleDateString() : 'Unknown date'}
                    </p>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        )}

        {/* No Alerts State */}
        {totalAlerts === 0 && (
          <div className="text-center py-8">
            <CheckCircleIcon className="w-12 h-12 text-green-500 mx-auto mb-4" />
            <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              No Active Alerts
            </h4>
            <p className="text-gray-500 dark:text-gray-400">
              All security issues have been resolved
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

export default AlertsOverview