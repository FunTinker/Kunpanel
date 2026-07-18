import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    rollupOptions: {
      output: {
        entryFileNames: 'assets/app.js',
        chunkFileNames: 'assets/app.js',
        assetFileNames: ({ name }) => name && name.endsWith('.css') ? 'assets/app.css' : 'assets/[name][extname]'
      }
    }
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8088'
    }
  }
})
