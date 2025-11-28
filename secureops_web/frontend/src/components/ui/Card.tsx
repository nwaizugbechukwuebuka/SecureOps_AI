import * as React from 'react';
import { cn } from '../../utils/helpers';

interface CardProps {
  children: React.ReactNode;
  className?: string;
}

export const Card: React.FC<CardProps> = ({ children, className }) => (
  <div className={cn('bg-white rounded-lg shadow p-4', className)}>
    {children}
  </div>
);
