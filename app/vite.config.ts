import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

export default defineConfig({
  plugins: [vue()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      // tudo isso será repassado para o backend em 9090
      '/logs': {
        target: 'http://127.0.0.1:9080',
        changeOrigin: true
      },
      '/log-days': {
        target: 'http://127.0.0.1:9080',
        changeOrigin: true
      },
      '/bytes': {
        target: 'http://127.0.0.1:9080',
        changeOrigin: true
      },
      '/clients': {
        target: 'http://127.0.0.1:9080',
        changeOrigin: true
      },
      '/ignored-domains': {
        target: 'http://127.0.0.1:9080',
        changeOrigin: true
      }
    }
  }
});
