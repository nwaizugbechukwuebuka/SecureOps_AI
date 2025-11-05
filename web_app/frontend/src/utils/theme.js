// Theme utility for dark/light mode functionality
import { useState, useEffect } from 'react';

// Theme constants
export const THEMES = {
  LIGHT: 'light',
  DARK: 'dark',
  SYSTEM: 'system'
};

// Default theme configuration
export const defaultTheme = {
  mode: THEMES.LIGHT,
  colors: {
    light: {
      primary: '#3b82f6',
      secondary: '#6366f1',
      accent: '#f59e0b',
      background: '#ffffff',
      surface: '#f8fafc',
      text: '#1f2937',
      textSecondary: '#6b7280',
      border: '#e5e7eb',
      success: '#10b981',
      warning: '#f59e0b',
      error: '#ef4444',
      info: '#3b82f6'
    },
    dark: {
      primary: '#60a5fa',
      secondary: '#818cf8',
      accent: '#fbbf24',
      background: '#111827',
      surface: '#1f2937',
      text: '#f9fafb',
      textSecondary: '#d1d5db',
      border: '#374151',
      success: '#34d399',
      warning: '#fbbf24',
      error: '#fb7185',
      info: '#60a5fa'
    }
  }
};

// Get system theme preference
export const getSystemTheme = () => {
  if (typeof window !== 'undefined' && window.matchMedia) {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? THEMES.DARK : THEMES.LIGHT;
  }
  return THEMES.LIGHT;
};

// Get stored theme preference
export const getStoredTheme = () => {
  if (typeof window !== 'undefined') {
    return localStorage.getItem('theme') || THEMES.SYSTEM;
  }
  return THEMES.SYSTEM;
};

// Store theme preference
export const storeTheme = (theme) => {
  if (typeof window !== 'undefined') {
    localStorage.setItem('theme', theme);
  }
};

// Apply theme to document
export const applyTheme = (theme) => {
  if (typeof document === 'undefined') return;

  const root = document.documentElement;
  const actualTheme = theme === THEMES.SYSTEM ? getSystemTheme() : theme;
  
  // Remove existing theme classes
  root.classList.remove('light', 'dark');
  
  // Add new theme class
  root.classList.add(actualTheme);
  
  // Update CSS custom properties
  const colors = defaultTheme.colors[actualTheme];
  Object.entries(colors).forEach(([key, value]) => {
    root.style.setProperty(`--color-${key}`, value);
  });

  // Update meta theme-color
  const metaThemeColor = document.querySelector('meta[name="theme-color"]');
  if (metaThemeColor) {
    metaThemeColor.setAttribute('content', colors.primary);
  }
};

// Custom hook for theme management
export const useTheme = () => {
  const [theme, setTheme] = useState(() => getStoredTheme());
  const [actualTheme, setActualTheme] = useState(() => {
    const stored = getStoredTheme();
    return stored === THEMES.SYSTEM ? getSystemTheme() : stored;
  });

  // Apply theme when it changes
  useEffect(() => {
    const newActualTheme = theme === THEMES.SYSTEM ? getSystemTheme() : theme;
    setActualTheme(newActualTheme);
    applyTheme(newActualTheme);
    storeTheme(theme);
  }, [theme]);

  // Listen for system theme changes
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleChange = (e) => {
      if (theme === THEMES.SYSTEM) {
        const newActualTheme = e.matches ? THEMES.DARK : THEMES.LIGHT;
        setActualTheme(newActualTheme);
        applyTheme(newActualTheme);
      }
    };

    mediaQuery.addListener(handleChange);
    return () => mediaQuery.removeListener(handleChange);
  }, [theme]);

  // Initialize theme on mount
  useEffect(() => {
    applyTheme(actualTheme);
  }, []);

  const changeTheme = (newTheme) => {
    setTheme(newTheme);
  };

  const toggleTheme = () => {
    const newTheme = actualTheme === THEMES.DARK ? THEMES.LIGHT : THEMES.DARK;
    setTheme(newTheme);
  };

  const isDark = actualTheme === THEMES.DARK;
  const isLight = actualTheme === THEMES.LIGHT;
  const isSystem = theme === THEMES.SYSTEM;

  return {
    theme,
    actualTheme,
    changeTheme,
    toggleTheme,
    isDark,
    isLight,
    isSystem,
    colors: defaultTheme.colors[actualTheme]
  };
};

// Theme provider component
export const initializeTheme = () => {
  const storedTheme = getStoredTheme();
  const actualTheme = storedTheme === THEMES.SYSTEM ? getSystemTheme() : storedTheme;
  applyTheme(actualTheme);
};

// CSS class utilities
export const getThemeClasses = (isDark) => {
  return {
    background: isDark ? 'bg-gray-900' : 'bg-white',
    surface: isDark ? 'bg-gray-800' : 'bg-gray-50',
    card: isDark ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200',
    text: isDark ? 'text-gray-100' : 'text-gray-900',
    textSecondary: isDark ? 'text-gray-400' : 'text-gray-600',
    border: isDark ? 'border-gray-700' : 'border-gray-200',
    input: isDark ? 'bg-gray-700 border-gray-600 text-white' : 'bg-white border-gray-300 text-gray-900',
    button: {
      primary: isDark ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-600 hover:bg-blue-700',
      secondary: isDark ? 'bg-gray-700 hover:bg-gray-600' : 'bg-gray-200 hover:bg-gray-300',
      danger: isDark ? 'bg-red-600 hover:bg-red-700' : 'bg-red-600 hover:bg-red-700'
    }
  };
};