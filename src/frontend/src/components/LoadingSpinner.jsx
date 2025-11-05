import React from 'react';
import { CircularProgress, Box } from '@mui/material';

const LoadingSpinner = ({ size = 'medium' }) => (
  <Box display="flex" alignItems="center" justifyContent="center" height={size === 'large' ? 80 : 40}>
    <CircularProgress size={size === 'large' ? 48 : 24} thickness={4} color="primary" />
    <span style={{ marginLeft: 12, fontSize: size === 'large' ? 20 : 14, color: '#555' }}>Loading...</span>
  </Box>
);

export default LoadingSpinner;
