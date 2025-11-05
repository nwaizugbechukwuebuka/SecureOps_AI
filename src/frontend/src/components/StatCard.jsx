import React from 'react'
import { ArrowUpIcon, ArrowDownIcon } from '@heroicons/react/24/outline'
import { motion } from 'framer-motion'

const StatCard = ({ 
  title, 
  value, 
  change, 
  icon: Icon, 
  color = 'blue', 
  subtitle,
  loading = false 
}) => {
  const colorClasses = {
    red: {
      bg: 'bg-red-50 dark:bg-red-900/20',
      icon: 'text-red-600 dark:text-red-400',
      accent: 'border-red-200 dark:border-red-800'
    },
    orange: {
      bg: 'bg-orange-50 dark:bg-orange-900/20',
      icon: 'text-orange-600 dark:text-orange-400',
      accent: 'border-orange-200 dark:border-orange-800'
    },
    blue: {
      bg: 'bg-blue-50 dark:bg-blue-900/20',
      icon: 'text-blue-600 dark:text-blue-400',
      accent: 'border-blue-200 dark:border-blue-800'
    },
    green: {
      bg: 'bg-green-50 dark:bg-green-900/20',
      icon: 'text-green-600 dark:text-green-400',
      accent: 'border-green-200 dark:border-green-800'
    },
    purple: {
      bg: 'bg-purple-50 dark:bg-purple-900/20',
      icon: 'text-purple-600 dark:text-purple-400',
      accent: 'border-purple-200 dark:border-purple-800'
    }
  }
  
  const colors = colorClasses[color] || colorClasses.blue
  const isPositiveChange = change >= 0
  const changeIcon = isPositiveChange ? ArrowUpIcon : ArrowDownIcon
  const changeColor = isPositiveChange ? 'text-green-600' : 'text-red-600'
  
  if (loading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
        <div className="animate-pulse">
          <div className="flex items-center">
            <div className={`p-3 rounded-lg ${colors.bg} flex-shrink-0`}>
              <div className="w-6 h-6 bg-gray-300 dark:bg-gray-600 rounded" />
            </div>
            <div className="ml-4 flex-1">
              <div className="h-4 bg-gray-300 dark:bg-gray-600 rounded w-20 mb-2" />
              <div className="h-6 bg-gray-300 dark:bg-gray-600 rounded w-16" />
            </div>
          </div>
        </div>
      </div>
    )
  }
  
  return (
    <motion.div
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      className={`bg-white dark:bg-gray-800 rounded-lg shadow-sm border ${colors.accent} p-6 cursor-pointer transition-all duration-200 hover:shadow-md`}
    >
      <div className="flex items-center">
        <div className={`p-3 rounded-lg ${colors.bg} flex-shrink-0`}>
          <Icon className={`w-6 h-6 ${colors.icon}`} />
        </div>
        
        <div className="ml-4 flex-1 min-w-0">
          <p className="text-sm font-medium text-gray-600 dark:text-gray-400 truncate">
            {title}
          </p>
          
          <div className="flex items-baseline space-x-2">
            <p className="text-2xl font-bold text-gray-900 dark:text-white">
              {value}
            </p>
            
            {change !== null && change !== undefined && (
              <div className={`flex items-center ${changeColor}`}>
                <changeIcon.type 
                  {...changeIcon.props} 
                  className="w-4 h-4 mr-1" 
                />
                <span className="text-sm font-medium">
                  {Math.abs(change)}%
                </span>
              </div>
            )}
          </div>
          
          {subtitle && (
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 truncate">
              {subtitle}
            </p>
          )}
        </div>
      </div>
      
      {/* Progress bar for percentage values */}
      {typeof value === 'string' && value.includes('%') && (
        <div className="mt-4">
          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${parseInt(value)}%` }}
              transition={{ duration: 1, ease: "easeOut" }}
              className={`h-2 rounded-full ${
                parseInt(value) >= 80 ? 'bg-green-500' :
                parseInt(value) >= 60 ? 'bg-yellow-500' :
                'bg-red-500'
              }`}
            />
          </div>
        </div>
      )}
    </motion.div>
  )
}

export default StatCard