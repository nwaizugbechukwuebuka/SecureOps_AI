import React from 'react';
import { 
  LineChart, 
  Line, 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  PieChart, 
  Pie, 
  Cell,
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend,
  ResponsiveContainer 
} from 'recharts';
import { useTheme } from '../utils/theme';
import { TrendingUp, TrendingDown, Activity } from 'lucide-react';

const ChartWidget = ({ 
  title, 
  type = 'line', 
  data = [], 
  dataKey, 
  xAxisKey = 'name',
  height = 300,
  color = '#3b82f6',
  showTrend = false,
  className = ''
}) => {
  const { isDark, colors } = useTheme();

  // Theme-aware colors
  const chartColors = {
    primary: isDark ? '#60a5fa' : '#3b82f6',
    secondary: isDark ? '#818cf8' : '#6366f1',
    success: isDark ? '#34d399' : '#10b981',
    warning: isDark ? '#fbbf24' : '#f59e0b',
    error: isDark ? '#fb7185' : '#ef4444',
    grid: isDark ? '#374151' : '#e5e7eb',
    text: isDark ? '#d1d5db' : '#6b7280'
  };

  // Calculate trend if enabled
  const getTrend = () => {
    if (!showTrend || data.length < 2) return null;
    
    const currentValue = data[data.length - 1]?.[dataKey] || 0;
    const previousValue = data[data.length - 2]?.[dataKey] || 0;
    const change = ((currentValue - previousValue) / previousValue) * 100;
    
    return {
      value: Math.abs(change).toFixed(1),
      isPositive: change > 0,
      icon: change > 0 ? TrendingUp : TrendingDown
    };
  };

  const trend = getTrend();

  // Common chart props
  const commonProps = {
    data,
    margin: { top: 5, right: 30, left: 20, bottom: 5 }
  };

  // Custom tooltip
  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload || !payload.length) return null;

    return (
      <div className={`p-3 rounded-lg shadow-lg border ${
        isDark ? 'bg-gray-800 border-gray-600' : 'bg-white border-gray-200'
      }`}>
        <p className={`font-medium ${isDark ? 'text-white' : 'text-gray-900'}`}>
          {label}
        </p>
        {payload.map((entry, index) => (
          <p key={index} className="text-sm" style={{ color: entry.color }}>
            {entry.name}: {entry.value}
          </p>
        ))}
      </div>
    );
  };

  // Render chart based on type
  const renderChart = () => {
    switch (type) {
      case 'area':
        return (
          <AreaChart {...commonProps}>
            <CartesianGrid strokeDasharray="3 3" stroke={chartColors.grid} />
            <XAxis 
              dataKey={xAxisKey} 
              tick={{ fontSize: 12, fill: chartColors.text }}
              stroke={chartColors.grid}
            />
            <YAxis 
              tick={{ fontSize: 12, fill: chartColors.text }}
              stroke={chartColors.grid}
            />
            <Tooltip content={<CustomTooltip />} />
            <Area
              type="monotone"
              dataKey={dataKey}
              stroke={color || chartColors.primary}
              fill={color || chartColors.primary}
              fillOpacity={0.3}
              strokeWidth={2}
            />
          </AreaChart>
        );

      case 'bar':
        return (
          <BarChart {...commonProps}>
            <CartesianGrid strokeDasharray="3 3" stroke={chartColors.grid} />
            <XAxis 
              dataKey={xAxisKey} 
              tick={{ fontSize: 12, fill: chartColors.text }}
              stroke={chartColors.grid}
            />
            <YAxis 
              tick={{ fontSize: 12, fill: chartColors.text }}
              stroke={chartColors.grid}
            />
            <Tooltip content={<CustomTooltip />} />
            <Bar
              dataKey={dataKey}
              fill={color || chartColors.primary}
              radius={[4, 4, 0, 0]}
            />
          </BarChart>
        );

      case 'pie':
        const COLORS = [
          chartColors.primary,
          chartColors.secondary,
          chartColors.success,
          chartColors.warning,
          chartColors.error
        ];

        return (
          <PieChart {...commonProps}>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              outerRadius={80}
              fill="#8884d8"
              dataKey={dataKey}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        );

      default: // line
        return (
          <LineChart {...commonProps}>
            <CartesianGrid strokeDasharray="3 3" stroke={chartColors.grid} />
            <XAxis 
              dataKey={xAxisKey} 
              tick={{ fontSize: 12, fill: chartColors.text }}
              stroke={chartColors.grid}
            />
            <YAxis 
              tick={{ fontSize: 12, fill: chartColors.text }}
              stroke={chartColors.grid}
            />
            <Tooltip content={<CustomTooltip />} />
            <Line
              type="monotone"
              dataKey={dataKey}
              stroke={color || chartColors.primary}
              strokeWidth={2}
              dot={{ r: 4, fill: color || chartColors.primary }}
              activeDot={{ r: 6, stroke: color || chartColors.primary }}
            />
          </LineChart>
        );
    }
  };

  return (
    <div className={`p-6 rounded-lg border ${
      isDark ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200'
    } ${className}`}>
      {/* Header */}
      {(title || trend) && (
        <div className="flex items-center justify-between mb-4">
          {title && (
            <div className="flex items-center space-x-2">
              <Activity className={`w-5 h-5 ${
                isDark ? 'text-gray-400' : 'text-gray-600'
              }`} />
              <h3 className={`text-lg font-semibold ${
                isDark ? 'text-white' : 'text-gray-900'
              }`}>
                {title}
              </h3>
            </div>
          )}
          
          {trend && (
            <div className={`flex items-center space-x-1 text-sm ${
              trend.isPositive ? 'text-green-600' : 'text-red-600'
            }`}>
              <trend.icon className="w-4 h-4" />
              <span>{trend.value}%</span>
            </div>
          )}
        </div>
      )}

      {/* Chart */}
      <div style={{ height: `${height}px` }}>
        {data.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <Activity className={`w-12 h-12 mx-auto mb-4 ${
                isDark ? 'text-gray-600' : 'text-gray-400'
              }`} />
              <p className={`text-sm ${
                isDark ? 'text-gray-400' : 'text-gray-600'
              }`}>
                No data available
              </p>
            </div>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            {renderChart()}
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
};

export default ChartWidget;