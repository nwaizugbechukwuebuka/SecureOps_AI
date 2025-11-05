import { format, formatDistanceToNow, parseISO, isValid } from 'date-fns';

// Date and time utilities
export const formatDate = (date, formatString = 'MMM dd, yyyy') => {
  try {
    const parsedDate = typeof date === 'string' ? parseISO(date) : date;
    return isValid(parsedDate) ? format(parsedDate, formatString) : 'Invalid date';
  } catch (error) {
    console.error('Error formatting date:', error);
    return 'Invalid date';
  }
};

export const formatDateTime = (date) => {
  return formatDate(date, 'MMM dd, yyyy HH:mm');
};

export const formatTimeAgo = (date) => {
  try {
    const parsedDate = typeof date === 'string' ? parseISO(date) : date;
    return isValid(parsedDate) ? formatDistanceToNow(parsedDate, { addSuffix: true }) : 'Unknown';
  } catch (error) {
    console.error('Error formatting time ago:', error);
    return 'Unknown';
  }
};

// Number formatting utilities
export const formatNumber = (number, options = {}) => {
  if (typeof number !== 'number' || isNaN(number)) return '0';
  
  return new Intl.NumberFormat('en-US', {
    minimumFractionDigits: 0,
    maximumFractionDigits: 2,
    ...options
  }).format(number);
};

export const formatCurrency = (amount, currency = 'USD') => {
  return formatNumber(amount, {
    style: 'currency',
    currency
  });
};

export const formatPercentage = (value, decimals = 1) => {
  return formatNumber(value, {
    style: 'percent',
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals
  });
};

// String utilities
export const truncateText = (text, maxLength = 50, suffix = '...') => {
  if (!text || typeof text !== 'string') return '';
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength).trim() + suffix;
};

export const capitalize = (str) => {
  if (!str || typeof str !== 'string') return '';
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
};

export const capitalizeWords = (str) => {
  if (!str || typeof str !== 'string') return '';
  return str.split(' ').map(word => capitalize(word)).join(' ');
};

export const slugify = (str) => {
  if (!str || typeof str !== 'string') return '';
  return str
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
};

// Array utilities
export const sortBy = (array, key, direction = 'asc') => {
  return [...array].sort((a, b) => {
    const aVal = key.split('.').reduce((obj, k) => obj?.[k], a);
    const bVal = key.split('.').reduce((obj, k) => obj?.[k], b);
    
    if (aVal < bVal) return direction === 'asc' ? -1 : 1;
    if (aVal > bVal) return direction === 'asc' ? 1 : -1;
    return 0;
  });
};

export const groupBy = (array, key) => {
  return array.reduce((result, item) => {
    const group = key.split('.').reduce((obj, k) => obj?.[k], item);
    if (!result[group]) result[group] = [];
    result[group].push(item);
    return result;
  }, {});
};

export const unique = (array, key) => {
  if (!key) return [...new Set(array)];
  
  const seen = new Set();
  return array.filter(item => {
    const value = key.split('.').reduce((obj, k) => obj?.[k], item);
    if (seen.has(value)) return false;
    seen.add(value);
    return true;
  });
};

// Security-specific utilities
export const getSeverityColor = (severity) => {
  const colors = {
    low: 'text-green-600 bg-green-100',
    medium: 'text-yellow-600 bg-yellow-100',
    high: 'text-orange-600 bg-orange-100',
    critical: 'text-red-600 bg-red-100'
  };
  return colors[severity?.toLowerCase()] || colors.medium;
};

export const getStatusColor = (status) => {
  const colors = {
    active: 'text-green-600 bg-green-100',
    inactive: 'text-gray-600 bg-gray-100',
    pending: 'text-yellow-600 bg-yellow-100',
    error: 'text-red-600 bg-red-100',
    success: 'text-green-600 bg-green-100',
    warning: 'text-orange-600 bg-orange-100'
  };
  return colors[status?.toLowerCase()] || colors.inactive;
};

// Debounce utility
export const debounce = (func, wait) => {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
};

// Class name utility
export const classNames = (...classes) => {
  return classes.filter(Boolean).join(' ');
};