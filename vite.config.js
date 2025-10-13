import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/', // ✅ use root base for dev
  server: {
    open: true,
    hmr: true
  },
  build: {
    outDir: 'dist'
  }
})
