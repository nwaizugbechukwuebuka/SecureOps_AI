import * as React from 'react';
import { cn } from '../../utils/helpers';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  children: React.ReactNode;
  title?: string;
}

export const Modal: React.FC<ModalProps> = ({ open, onClose, children, title }) => {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-40">
      <div className={cn('bg-white rounded-lg shadow-lg p-6 w-full max-w-md')}> 
        {title && <h2 className="text-lg font-bold mb-4">{title}</h2>}
        {children}
        <button className="mt-4 px-4 py-2 bg-accent text-white rounded" onClick={onClose}>Close</button>
      </div>
    </div>
  );
};
