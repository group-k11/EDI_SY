import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],

  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
      },
    },
  },

  build: {
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks: {
          // React core — changes rarely
          'vendor-react': ['react', 'react-dom'],
          // Recharts — large, load separately
          'vendor-charts': ['recharts'],
          // Lucide icons — tree-shaken but still sizeable
          'vendor-lucide': ['lucide-react'],
          // Axios — network layer
          'vendor-axios': ['axios'],
        },
      },
    },
  },
})
