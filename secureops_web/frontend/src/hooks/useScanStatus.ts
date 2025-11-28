import { useContext } from 'react';
import { ScanContext } from '../context/ScanContext';

export function useScanStatus() {
  return useContext(ScanContext);
}
