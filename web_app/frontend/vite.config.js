import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  
  return {
    plugins: [react()],
    root: '.',
    build: {
      outDir: '../dist',
      emptyOutDir: true,
    },
    server: {
      port: parseInt(env.VITE_APP_PORT) || 3010,
      strictPort: true,
      host: '0.0.0.0',
      watch: {
        usePolling: true,
      },
      hmr: {
        port: 3010,
      },
      proxy: {
        '/api': {
          target: env.VITE_API_BASE_URL || 'http://localhost:8001',
          changeOrigin: true,
          secure: false,
          rewrite: (path) => path,
          configure: (proxy) => {
            proxy.on('error', (err, _req, _res) => {
              console.log('proxy error', err);
            });
            proxy.on('proxyReq', (proxyReq, req, _res) => {
              console.log('Sending Request to the Target:', req.method, req.url);
            });
            proxy.on('proxyRes', (proxyRes, req, _res) => {
              console.log('Received Response from the Target:', proxyRes.statusCode, req.url);
            });
          },
        },
        '/ws': {
          target: env.VITE_WS_BASE_URL || 'ws://localhost:8001',
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
    },
    resolve: {
      alias: {
        '@': resolve(__dirname, 'src'),
        '@/components': resolve(__dirname, 'src/components'),
        '@/pages': resolve(__dirname, 'src/pages'),
        '@/services': resolve(__dirname, 'src/services'),
        '@/utils': resolve(__dirname, 'src/utils'),
        '@/assets': resolve(__dirname, 'src/assets'),
        '@/styles': resolve(__dirname, 'src/styles')
      }
    }
  };
});