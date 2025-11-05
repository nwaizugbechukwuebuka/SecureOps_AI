// vite.config.mjs (ESM)
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  
  return {
    plugins: [react()],
    server: {
      port: parseInt(env.VITE_APP_PORT) || 3010,
      strictPort: true,
      host: '0.0.0.0',
      proxy: {
        '/api': {
          target: env.VITE_API_BASE_URL || 'http://localhost:8000',
          changeOrigin: true,
          secure: false,
          rewrite: (path) => path
        },
        '/ws': {
          target: env.VITE_WS_BASE_URL || 'ws://localhost:8000',
          ws: true,
          changeOrigin: true,
          secure: false
        }
      }
    },
    preview: {
      port: parseInt(env.VITE_APP_PORT) || 3010,
      strictPort: true,
      host: '0.0.0.0'
    }
  };
});
