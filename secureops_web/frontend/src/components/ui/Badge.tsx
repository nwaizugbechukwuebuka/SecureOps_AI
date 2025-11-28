import * as React from 'react';
import { cn } from '../../utils/helpers';

interface BadgeProps {
  children: React.ReactNode;
  color?: 'primary' | 'accent' | 'danger' | 'success' | 'warning';
}

export const Badge: React.FC<BadgeProps> = ({ children, color = 'primary' }) => {
  const colors = {
    primary: 'bg-primary text-white',
    accent: 'bg-accent text-white',
    danger: 'bg-danger text-white',
    success: 'bg-success text-white',
    warning: 'bg-warning text-black',
  };
  return <span className={cn('px-2 py-1 rounded text-xs font-semibold', colors[color])}>{children}</span>;
};
