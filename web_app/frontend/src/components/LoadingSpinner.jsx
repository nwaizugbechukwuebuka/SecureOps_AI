import React from 'react';
import { useTheme } from '../utils/theme';

const LoadingSpinner = ({ 
  size = 'medium', 
  text = 'Loading...', 
  showText = true, 
  className = '',
  fullScreen = false 
}) => {
  const { isDark } = useTheme();

  // Size configurations
  const sizeConfig = {
    small: 'w-4 h-4',
    medium: 'w-8 h-8',
    large: 'w-12 h-12',
    xlarge: 'w-16 h-16'
  };

  const textSizeConfig = {
    small: 'text-sm',
    medium: 'text-base',
    large: 'text-lg',
    xlarge: 'text-xl'
  };

  const spinnerSize = sizeConfig[size] || sizeConfig.medium;
  const textSize = textSizeConfig[size] || textSizeConfig.medium;

  const themeClasses = {
    background: isDark ? 'bg-gray-900' : 'bg-white',
    text: isDark ? 'text-gray-300' : 'text-gray-600',
    spinner: isDark ? 'border-blue-400' : 'border-blue-600'
  };

  const SpinnerElement = () => (
    <div className="flex flex-col items-center justify-center space-y-3">
      {/* Spinner */}
      <div className={`${spinnerSize} relative`}>
        <div className={`
          absolute inset-0 rounded-full border-2 border-transparent
          border-t-current border-r-current animate-spin
          ${themeClasses.spinner}
        `}></div>
        <div className={`
          absolute inset-1 rounded-full border-2 border-transparent
          border-b-current border-l-current animate-spin
          ${themeClasses.spinner} opacity-60
        `} style={{ animationDirection: 'reverse', animationDuration: '0.75s' }}></div>
      </div>

      {/* Loading text */}
      {showText && text && (
        <div className={`${textSize} font-medium ${themeClasses.text} animate-pulse`}>
          {text}
        </div>
      )}
    </div>
  );

  if (fullScreen) {
    return (
      <div className={`
        fixed inset-0 z-50 flex items-center justify-center
        ${themeClasses.background} bg-opacity-90 backdrop-blur-sm
        ${className}
      `}>
        <SpinnerElement />
      </div>
    );
  }

  return (
    <div className={`flex items-center justify-center p-4 ${className}`}>
      <SpinnerElement />
    </div>
  );
};

// Skeleton loader for content placeholders
export const SkeletonLoader = ({ 
  lines = 3, 
  height = 'h-4', 
  className = '' 
}) => {
  const { isDark } = useTheme();
  
  const skeletonBg = isDark ? 'bg-gray-700' : 'bg-gray-200';

  return (
    <div className={`animate-pulse space-y-3 ${className}`}>
      {Array.from({ length: lines }, (_, i) => (
        <div
          key={i}
          className={`${height} ${skeletonBg} rounded`}
          style={{
            width: i === lines - 1 ? '75%' : '100%'
          }}
        ></div>
      ))}
    </div>
  );
};

// Card skeleton for dashboard cards
export const CardSkeleton = ({ className = '' }) => {
  const { isDark } = useTheme();
  
  const cardBg = isDark ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const skeletonBg = isDark ? 'bg-gray-700' : 'bg-gray-200';

  return (
    <div className={`${cardBg} border rounded-lg p-6 ${className}`}>
      <div className="animate-pulse">
        {/* Header skeleton */}
        <div className="flex items-center justify-between mb-4">
          <div className={`h-6 ${skeletonBg} rounded w-32`}></div>
          <div className={`h-4 w-4 ${skeletonBg} rounded`}></div>
        </div>
        
        {/* Content skeleton */}
        <div className="space-y-3">
          <div className={`h-8 ${skeletonBg} rounded w-20`}></div>
          <div className={`h-3 ${skeletonBg} rounded w-full`}></div>
          <div className={`h-3 ${skeletonBg} rounded w-3/4`}></div>
        </div>
      </div>
    </div>
  );
};

// Table skeleton for data tables
export const TableSkeleton = ({ 
  rows = 5, 
  columns = 4, 
  className = '' 
}) => {
  const { isDark } = useTheme();
  
  const tableBg = isDark ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
  const skeletonBg = isDark ? 'bg-gray-700' : 'bg-gray-200';

  return (
    <div className={`${tableBg} border rounded-lg overflow-hidden ${className}`}>
      <div className="animate-pulse">
        {/* Table header */}
        <div className={`${isDark ? 'bg-gray-700' : 'bg-gray-50'} px-6 py-3 border-b ${isDark ? 'border-gray-600' : 'border-gray-200'}`}>
          <div className="flex space-x-8">
            {Array.from({ length: columns }, (_, i) => (
              <div key={i} className={`h-4 ${skeletonBg} rounded w-20`}></div>
            ))}
          </div>
        </div>
        
        {/* Table rows */}
        {Array.from({ length: rows }, (_, rowIndex) => (
          <div key={rowIndex} className={`px-6 py-4 border-b ${isDark ? 'border-gray-700' : 'border-gray-200'}`}>
            <div className="flex space-x-8">
              {Array.from({ length: columns }, (_, colIndex) => (
                <div key={colIndex} className={`h-4 ${skeletonBg} rounded w-24`}></div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

// Button loader
export const ButtonLoader = ({ 
  loading = false, 
  children, 
  className = '',
  disabled = false,
  ...props 
}) => {
  const { isDark } = useTheme();

  return (
    <button
      className={`
        relative flex items-center justify-center space-x-2
        ${loading ? 'cursor-wait' : ''}
        ${className}
      `}
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="w-4 h-4 border-2 border-transparent border-t-current border-r-current rounded-full animate-spin"></div>
        </div>
      )}
      
      <span className={loading ? 'opacity-0' : 'opacity-100'}>
        {children}
      </span>
    </button>
  );
};

// Progress bar
export const ProgressBar = ({ 
  progress = 0, 
  showPercentage = true, 
  className = '',
  color = 'blue'
}) => {
  const { isDark } = useTheme();

  const colorClasses = {
    blue: isDark ? 'bg-blue-500' : 'bg-blue-600',
    green: isDark ? 'bg-green-500' : 'bg-green-600',
    yellow: isDark ? 'bg-yellow-500' : 'bg-yellow-600',
    red: isDark ? 'bg-red-500' : 'bg-red-600'
  };

  const bgClass = isDark ? 'bg-gray-700' : 'bg-gray-200';
  const textClass = isDark ? 'text-gray-300' : 'text-gray-600';

  return (
    <div className={className}>
      <div className={`w-full ${bgClass} rounded-full h-2`}>
        <div
          className={`h-2 rounded-full transition-all duration-300 ease-out ${colorClasses[color] || colorClasses.blue}`}
          style={{ width: `${Math.min(Math.max(progress, 0), 100)}%` }}
        ></div>
      </div>
      
      {showPercentage && (
        <div className={`text-sm ${textClass} mt-1 text-right`}>
          {Math.round(progress)}%
        </div>
      )}
    </div>
  );
};

export default LoadingSpinner;